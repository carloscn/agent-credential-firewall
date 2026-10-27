//! End-to-end and shared conformance tests for the demo provider.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use acf_provider_local::{DemoLocalProvider, LocalProviderConfigError, LocalStoreKey};
use acf_secrets::conformance::{
    ConformanceFailure, ConformanceFixture, SeedSecret, check_admin_conformance,
    check_runtime_conformance,
};
use acf_secrets::{
    AuthSlot, ConnectorName, Environment, Namespace, Origin, SecretAdmin, SecretError,
    SecretMaterial, SecretProvider, SecretRef, SecretUseBinding,
};
use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};

struct TestProvider {
    provider: DemoLocalProvider,
    root: PathBuf,
}

impl Drop for TestProvider {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[async_trait]
impl SecretProvider for TestProvider {
    async fn get(&self, reference: &SecretRef) -> Result<acf_secrets::ResolvedSecret, SecretError> {
        self.provider.get(reference).await
    }
}

#[async_trait]
impl SecretAdmin for TestProvider {
    async fn put(
        &self,
        reference: &SecretRef,
        material: SecretMaterial,
        binding: SecretUseBinding,
    ) -> Result<acf_secrets::SecretVersion, SecretError> {
        self.provider.put(reference, material, binding).await
    }

    async fn delete(&self, reference: &SecretRef) -> Result<(), SecretError> {
        self.provider.delete(reference).await
    }

    async fn list_metadata(
        &self,
        scope: &acf_secrets::SecretScope,
    ) -> Result<Vec<acf_secrets::SecretMetadata>, SecretError> {
        self.provider.list_metadata(scope).await
    }
}

struct Fixture;

impl Fixture {
    fn assigned_namespace() -> Namespace {
        Namespace::new("local-demo").unwrap()
    }

    fn binding() -> SecretUseBinding {
        SecretUseBinding::new(
            [ConnectorName::new("cloudflare").unwrap()].into(),
            [Origin::parse("https://api.cloudflare.com").unwrap()].into(),
            AuthSlot::new("read").unwrap(),
            Environment::new("development").unwrap(),
        )
        .unwrap()
    }
}

#[async_trait]
impl ConformanceFixture for Fixture {
    type Provider = TestProvider;

    fn assigned_namespace(&self) -> Namespace {
        Self::assigned_namespace()
    }

    fn unassigned_namespace(&self) -> Namespace {
        Namespace::new("elsewhere").unwrap()
    }

    fn binding(&self) -> SecretUseBinding {
        Self::binding()
    }

    fn attests_bindings(&self) -> bool {
        true
    }

    async fn provider_with(
        &self,
        secrets: Vec<SeedSecret>,
    ) -> Result<Self::Provider, ConformanceFailure> {
        let root = temporary_path();
        let provider = DemoLocalProvider::initialize(
            &root,
            Self::assigned_namespace(),
            key(7).map_err(fixture_error)?,
        )
        .map_err(fixture_error)?;
        for secret in secrets {
            provider
                .put(&secret.reference, secret.material, secret.binding)
                .await
                .map_err(fixture_error)?;
        }
        Ok(TestProvider { provider, root })
    }
}

#[tokio::test]
async fn passes_runtime_conformance() {
    check_runtime_conformance(&Fixture).await.unwrap();
}

#[tokio::test]
async fn passes_admin_conformance() {
    let provider = Fixture.provider_with(Vec::new()).await.unwrap();
    check_admin_conformance(&Fixture, &provider).await.unwrap();
}

#[tokio::test]
async fn survives_restart_and_plaintext_is_absent_from_files() {
    const CANARY: &str = "ACF-LOCAL-DEMO-CANARY-9a3d";
    let root = temporary_path();
    let reference = SecretRef::parse("secret://local-demo/cloudflare/read").unwrap();
    let provider =
        DemoLocalProvider::initialize(&root, Fixture::assigned_namespace(), key(11).unwrap())
            .unwrap();
    provider
        .put(
            &reference,
            SecretMaterial::from_string(CANARY.to_owned()),
            Fixture::binding(),
        )
        .await
        .unwrap();
    drop(provider);

    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        if path.file_name().unwrap() == ".writer.lock" {
            assert!(bytes.is_empty(), "the writer lock holds no data");
            continue;
        }
        assert!(
            !bytes
                .windows(CANARY.len())
                .any(|part| part == CANARY.as_bytes())
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!json_contains_bytes(&json, CANARY.as_bytes()));
        assert!(
            !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("cloudflare")
        );
    }

    let reopened =
        DemoLocalProvider::open(&root, Fixture::assigned_namespace(), key(11).unwrap()).unwrap();
    let resolved = reopened.get(&reference).await.unwrap();
    assert_eq!(resolved.material.expose_secret(), CANARY.as_bytes());
    assert_eq!(resolved.attested_binding, Some(Fixture::binding()));
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_wrong_key_and_broad_permissions() {
    let root = temporary_path();
    let provider =
        DemoLocalProvider::initialize(&root, Fixture::assigned_namespace(), key(1).unwrap())
            .unwrap();
    drop(provider);
    assert!(matches!(
        DemoLocalProvider::open(&root, Fixture::assigned_namespace(), key(2).unwrap()),
        Err(LocalProviderConfigError::KeyRejected)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            DemoLocalProvider::open(&root, Fixture::assigned_namespace(), key(1).unwrap()),
            Err(LocalProviderConfigError::UnsafeFilesystem)
        ));
    }
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn modified_record_fails_closed_without_leaking_the_value() {
    const CANARY: &str = "ACF-LOCAL-TAMPER-CANARY";
    let root = temporary_path();
    let reference = SecretRef::parse("secret://local-demo/example/read").unwrap();
    let provider =
        DemoLocalProvider::initialize(&root, Fixture::assigned_namespace(), key(3).unwrap())
            .unwrap();
    provider
        .put(
            &reference,
            SecretMaterial::from_string(CANARY.to_owned()),
            Fixture::binding(),
        )
        .await
        .unwrap();

    let record = record_path(&root);
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    let ciphertext = json
        .get_mut("ciphertext")
        .and_then(serde_json::Value::as_array_mut)
        .unwrap();
    let first = ciphertext[0].as_u64().unwrap();
    ciphertext[0] = serde_json::Value::from((first + 1) % 256);
    fs::write(&record, serde_json::to_vec(&json).unwrap()).unwrap();
    let error = provider.get(&reference).await.unwrap_err();
    assert!(matches!(error, SecretError::Corrupted));
    assert!(!error.to_string().contains(CANARY));
    assert!(!format!("{error:?}").contains(CANARY));
    drop(provider);
    fs::remove_dir_all(root).unwrap();
}

fn key(byte: u8) -> Result<LocalStoreKey, LocalProviderConfigError> {
    LocalStoreKey::from_material(SecretMaterial::from_bytes(vec![byte; 32]))
}

fn temporary_path() -> PathBuf {
    let mut random = [0_u8; 12];
    SystemRandom::new().fill(&mut random).unwrap();
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").unwrap();
    }
    std::env::temp_dir().join(format!("acf-local-demo-{suffix}"))
}

fn record_path(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "acf-record")
        })
        .unwrap()
}

fn json_contains_bytes(value: &serde_json::Value, needle: &[u8]) -> bool {
    match value {
        serde_json::Value::Array(values) => {
            let bytes: Option<Vec<u8>> = values
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            bytes.is_some_and(|bytes| bytes.windows(needle.len()).any(|part| part == needle))
                || values
                    .iter()
                    .any(|value| json_contains_bytes(value, needle))
        }
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_contains_bytes(value, needle)),
        serde_json::Value::String(value) => value
            .as_bytes()
            .windows(needle.len())
            .any(|part| part == needle),
        _ => false,
    }
}

fn fixture_error(error: impl std::fmt::Display) -> ConformanceFailure {
    ConformanceFailure {
        check: "fixture",
        detail: error.to_string(),
    }
}

#[test]
fn writes_wait_for_the_cross_process_writer_lock() {
    let root = temporary_path();
    let provider =
        DemoLocalProvider::initialize(&root, Fixture::assigned_namespace(), key(12).unwrap())
            .unwrap();
    // Another process (here: another handle) holds the lock.
    let holder = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".writer.lock"))
        .unwrap();
    holder.lock().unwrap();

    let (done, finished) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let reference = SecretRef::parse("secret://local-demo/cloudflare/read").unwrap();
        runtime
            .block_on(provider.put(
                &reference,
                SecretMaterial::from_string("value".to_owned()),
                Fixture::binding(),
            ))
            .unwrap();
        done.send(()).unwrap();
    });
    assert!(
        finished
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "the write must wait while another writer holds the lock"
    );
    holder.unlock().unwrap();
    finished
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    writer.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}
