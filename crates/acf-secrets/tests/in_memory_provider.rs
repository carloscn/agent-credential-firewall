//! The in-memory provider must pass the shared conformance suite.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use acf_secrets::conformance::{
    CANARY_PREFIX, ConformanceFailure, ConformanceFixture, SeedSecret, check_admin_conformance,
    check_runtime_conformance,
};
use acf_secrets::{
    AuthSlot, ConnectorName, Environment, InMemoryProvider, Namespace, Origin, SecretAdmin,
    SecretMaterial, SecretProvider, SecretRef, SecretUseBinding,
};
use async_trait::async_trait;

struct Fixture;

#[async_trait]
impl ConformanceFixture for Fixture {
    type Provider = InMemoryProvider;

    fn assigned_namespace(&self) -> Namespace {
        Namespace::new("development").unwrap()
    }

    fn unassigned_namespace(&self) -> Namespace {
        Namespace::new("production").unwrap()
    }

    fn binding(&self) -> SecretUseBinding {
        SecretUseBinding::new(
            [ConnectorName::new("example-api").unwrap()].into(),
            [Origin::parse("http://127.0.0.1:8080").unwrap()].into(),
            AuthSlot::new("read").unwrap(),
            Environment::new("development").unwrap(),
        )
        .unwrap()
    }

    fn attests_bindings(&self) -> bool {
        true
    }

    async fn provider_with(
        &self,
        secrets: Vec<SeedSecret>,
    ) -> Result<InMemoryProvider, ConformanceFailure> {
        let provider = InMemoryProvider::new([self.assigned_namespace()]);
        for seed in secrets {
            provider
                .put(&seed.reference, seed.material, seed.binding)
                .await
                .map_err(|e| ConformanceFailure {
                    check: "fixture",
                    detail: e.to_string(),
                })?;
        }
        Ok(provider)
    }
}

#[tokio::test]
async fn passes_runtime_conformance() {
    check_runtime_conformance(&Fixture).await.unwrap();
}

#[tokio::test]
async fn passes_admin_conformance() {
    let provider = InMemoryProvider::new([Fixture.assigned_namespace()]);
    check_admin_conformance(&Fixture, &provider).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_and_writes_stay_consistent() {
    let provider = Arc::new(InMemoryProvider::new([Fixture.assigned_namespace()]));
    let reference = SecretRef::parse("secret://development/example-api/read").unwrap();
    provider
        .put(
            &reference,
            SecretMaterial::from_string(format!("{CANARY_PREFIX}-0")),
            Fixture.binding(),
        )
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for i in 1..=8 {
        let provider = Arc::clone(&provider);
        let reference = reference.clone();
        tasks.push(tokio::spawn(async move {
            provider
                .put(
                    &reference,
                    SecretMaterial::from_string(format!("{CANARY_PREFIX}-{i}")),
                    Fixture.binding(),
                )
                .await
                .unwrap();
            let resolved = provider.get(&reference).await.unwrap();
            // Every read returns some complete value, never a torn one.
            let value = std::str::from_utf8(resolved.material.expose_secret()).unwrap();
            assert!(value.starts_with(CANARY_PREFIX));
            resolved.version
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let final_version = provider.get(&reference).await.unwrap().version;
    assert_eq!(final_version.get(), 9);
}

/// Deliberately broken providers, to prove the suite detects each defect.
mod suite_detects_defects {
    use super::*;
    use acf_secrets::{ResolvedSecret, SecretError};

    #[derive(Clone, Copy)]
    enum Defect {
        /// Reports `NotFound` instead of `NotAssigned` for foreign namespaces.
        IgnoresNamespace,
        /// Resolves a reference by string prefix.
        PrefixMatch,
        /// Claims a binding it cannot attest.
        FakeAttestation,
    }

    struct Broken {
        inner: InMemoryProvider,
        defect: Defect,
    }

    #[async_trait]
    impl SecretProvider for Broken {
        async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
            match self.defect {
                Defect::IgnoresNamespace if reference.namespace() != "development" => {
                    Err(SecretError::NotFound {
                        reference: reference.clone(),
                    })
                }
                Defect::PrefixMatch => {
                    let truncated = SecretRef::parse(format!(
                        "secret://{}/conformance/alpha",
                        reference.namespace()
                    ))
                    .unwrap();
                    if reference.path().starts_with("conformance/alph") {
                        self.inner.get(&truncated).await
                    } else {
                        self.inner.get(reference).await
                    }
                }
                _ => self.inner.get(reference).await,
            }
        }
    }

    struct BrokenFixture(Defect);

    #[async_trait]
    impl ConformanceFixture for BrokenFixture {
        type Provider = Broken;

        fn assigned_namespace(&self) -> Namespace {
            Fixture.assigned_namespace()
        }

        fn unassigned_namespace(&self) -> Namespace {
            Fixture.unassigned_namespace()
        }

        fn binding(&self) -> SecretUseBinding {
            Fixture.binding()
        }

        fn attests_bindings(&self) -> bool {
            // The in-memory backend always attests, so a fixture that claims
            // otherwise models a provider returning a binding it cannot back.
            !matches!(self.0, Defect::FakeAttestation)
        }

        async fn provider_with(
            &self,
            secrets: Vec<SeedSecret>,
        ) -> Result<Broken, ConformanceFailure> {
            Ok(Broken {
                inner: Fixture.provider_with(secrets).await?,
                defect: self.0,
            })
        }
    }

    async fn failed_check(defect: Defect) -> &'static str {
        check_runtime_conformance(&BrokenFixture(defect))
            .await
            .expect_err("a defective provider must fail conformance")
            .check
    }

    #[tokio::test]
    async fn detects_namespace_confusion() {
        assert_eq!(
            failed_check(Defect::IgnoresNamespace).await,
            "unassigned_namespace"
        );
    }

    #[tokio::test]
    async fn detects_prefix_resolution() {
        assert_eq!(failed_check(Defect::PrefixMatch).await, "exact_resolution");
    }

    #[tokio::test]
    async fn detects_unbacked_attestation() {
        assert_eq!(
            failed_check(Defect::FakeAttestation).await,
            "attested_binding"
        );
    }
}
