//! Provider-neutral conformance tests with no live Bitwarden credentials.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use acf_provider_bitwarden::{
    BitwardenBackend, BitwardenBackendError, BitwardenLocator, BitwardenProvider, BitwardenRecord,
    BitwardenSecretId, SecretMapping,
};
use acf_secrets::conformance::{
    ConformanceFailure, ConformanceFixture, SeedSecret, check_runtime_conformance,
};
use acf_secrets::{
    AuthSlot, ConnectorName, Environment, Namespace, Origin, SecretError, SecretMaterial,
    SecretProvider, SecretRef, SecretUseBinding, SecretVersion,
};
use async_trait::async_trait;
use uuid::Uuid;

struct FakeBackend {
    records: BTreeMap<BitwardenSecretId, (Vec<u8>, SecretVersion)>,
}

#[async_trait]
impl BitwardenBackend for FakeBackend {
    async fn fetch(
        &self,
        locator: BitwardenLocator,
    ) -> Result<BitwardenRecord, BitwardenBackendError> {
        let (bytes, version) = self
            .records
            .get(&locator.secret_id)
            .ok_or(BitwardenBackendError::NotFound)?;
        Ok(BitwardenRecord {
            material: SecretMaterial::from_bytes(bytes.clone()),
            version: *version,
        })
    }
}

struct Fixture;

impl Fixture {
    fn assigned_namespace() -> Namespace {
        Namespace::new("enterprise").unwrap()
    }

    fn binding() -> SecretUseBinding {
        SecretUseBinding::new(
            [ConnectorName::new("cloudflare").unwrap()].into(),
            [Origin::parse("https://api.cloudflare.com").unwrap()].into(),
            AuthSlot::new("read").unwrap(),
            Environment::new("production").unwrap(),
        )
        .unwrap()
    }
}

#[async_trait]
impl ConformanceFixture for Fixture {
    type Provider = BitwardenProvider<FakeBackend>;

    fn assigned_namespace(&self) -> Namespace {
        Self::assigned_namespace()
    }

    fn unassigned_namespace(&self) -> Namespace {
        Namespace::new("production").unwrap()
    }

    fn binding(&self) -> SecretUseBinding {
        Self::binding()
    }

    fn attests_bindings(&self) -> bool {
        false
    }

    async fn provider_with(
        &self,
        secrets: Vec<SeedSecret>,
    ) -> Result<Self::Provider, ConformanceFailure> {
        let mut mappings = Vec::with_capacity(secrets.len());
        let mut records = BTreeMap::new();

        for (index, seed) in secrets.into_iter().enumerate() {
            let id = BitwardenSecretId::from(Uuid::from_u128(u128::try_from(index + 1).map_err(
                |_| ConformanceFailure {
                    check: "fixture",
                    detail: "fixture index did not fit u128".to_owned(),
                },
            )?));
            mappings.push(SecretMapping::new(
                seed.reference,
                BitwardenLocator {
                    secret_id: id,
                    expected_project_id: None,
                },
            ));
            records.insert(
                id,
                (seed.material.expose_secret().to_vec(), SecretVersion::FIRST),
            );
        }

        BitwardenProvider::new(
            Self::assigned_namespace(),
            mappings,
            FakeBackend { records },
        )
        .map_err(|error| ConformanceFailure {
            check: "fixture",
            detail: error.to_string(),
        })
    }
}

#[tokio::test]
async fn passes_runtime_provider_conformance() {
    check_runtime_conformance(&Fixture).await.unwrap();
}

#[tokio::test]
async fn unmapped_reference_does_not_call_the_backend() {
    struct PanicBackend;

    #[async_trait]
    impl BitwardenBackend for PanicBackend {
        async fn fetch(
            &self,
            _locator: BitwardenLocator,
        ) -> Result<BitwardenRecord, BitwardenBackendError> {
            panic!("backend must not be called for an unmapped reference")
        }
    }

    let provider = BitwardenProvider::new(Fixture::assigned_namespace(), [], PanicBackend).unwrap();
    let reference = SecretRef::parse("secret://enterprise/missing").unwrap();
    assert!(matches!(
        provider.get(&reference).await,
        Err(SecretError::NotFound { .. })
    ));
}

#[tokio::test]
async fn provider_never_attests_acf_use_binding() {
    let reference = SecretRef::parse("secret://enterprise/example/read").unwrap();
    let provider = Fixture
        .provider_with(vec![SeedSecret {
            reference: reference.clone(),
            material: SecretMaterial::from_string("ACF-CANARY-bitwarden".to_owned()),
            binding: Fixture::binding(),
        }])
        .await
        .unwrap();

    let resolved = provider.get(&reference).await.unwrap();
    assert!(resolved.attested_binding.is_none());
}
