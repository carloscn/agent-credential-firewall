//! Reusable provider conformance suite.
//!
//! Every runtime provider, built in or external, must pass
//! [`check_runtime_conformance`]. Providers that implement [`SecretAdmin`]
//! must also pass [`check_admin_conformance`]. A provider's own test suite
//! supplies a [`ConformanceFixture`] and calls these functions.
//!
//! Checks return a [`ConformanceFailure`] instead of panicking, so callers
//! decide how to report.

use std::fmt;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;

use crate::binding::SecretUseBinding;
use crate::material::SecretMaterial;
use crate::provider::{SecretAdmin, SecretError, SecretProvider, SecretVersion};
use crate::reference::{Namespace, ReferenceError, SecretRef, SecretScope};

/// Canary prefix used for seeded secrets. Any output containing it is a leak.
pub const CANARY_PREFIX: &str = "ACF-CONFORMANCE-CANARY";

/// A failed conformance check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceFailure {
    /// Name of the failed check.
    pub check: &'static str,
    /// What went wrong. Never contains canary material.
    pub detail: String,
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance check `{}` failed: {}",
            self.check, self.detail
        )
    }
}

impl std::error::Error for ConformanceFailure {}

fn ensure(
    condition: bool,
    check: &'static str,
    detail: impl Into<String>,
) -> Result<(), ConformanceFailure> {
    if condition {
        Ok(())
    } else {
        Err(ConformanceFailure {
            check,
            detail: detail.into(),
        })
    }
}

fn fail(check: &'static str, detail: impl Into<String>) -> ConformanceFailure {
    ConformanceFailure {
        check,
        detail: detail.into(),
    }
}

/// A secret to seed into the provider under test.
pub struct SeedSecret {
    /// Where to store it.
    pub reference: SecretRef,
    /// The value.
    pub material: SecretMaterial,
    /// Its use binding.
    pub binding: SecretUseBinding,
}

/// Supplies providers to the conformance suite.
#[async_trait]
pub trait ConformanceFixture: Send + Sync {
    /// Provider type under test.
    type Provider: SecretProvider;

    /// A namespace the provider serves.
    fn assigned_namespace(&self) -> Namespace;

    /// A namespace the provider does not serve.
    fn unassigned_namespace(&self) -> Namespace;

    /// A binding to attach to seeded secrets.
    fn binding(&self) -> SecretUseBinding;

    /// Whether the provider returns an attested binding from `get`.
    fn attests_bindings(&self) -> bool;

    /// Returns a provider that serves only [`Self::assigned_namespace`] and
    /// holds exactly `secrets`.
    async fn provider_with(
        &self,
        secrets: Vec<SeedSecret>,
    ) -> Result<Self::Provider, ConformanceFailure>;
}

fn reference(namespace: &Namespace, path: &str) -> Result<SecretRef, ConformanceFailure> {
    SecretRef::parse(format!("secret://{namespace}/{path}"))
        .map_err(|e: ReferenceError| fail("fixture", format!("invalid test reference: {e}")))
}

fn canary(label: &str) -> String {
    format!("{CANARY_PREFIX}-{label}")
}

fn assert_no_canary(
    check: &'static str,
    surface: &str,
    output: &str,
) -> Result<(), ConformanceFailure> {
    ensure(
        !output.contains(CANARY_PREFIX),
        check,
        format!("canary material appeared in {surface}"),
    )
}

/// Runs every runtime check against providers from `fixture`.
///
/// # Errors
///
/// Returns the first failed check.
pub async fn check_runtime_conformance<F: ConformanceFixture>(
    fixture: &F,
) -> Result<(), ConformanceFailure> {
    let ns = fixture.assigned_namespace();
    let alpha = reference(&ns, "conformance/alpha")?;
    let alpha_beta = reference(&ns, "conformance/alpha-beta")?;
    let nested = reference(&ns, "conformance/alpha/nested")?;

    let seeds = vec![
        SeedSecret {
            reference: alpha.clone(),
            material: SecretMaterial::from_string(canary("alpha")),
            binding: fixture.binding(),
        },
        SeedSecret {
            reference: alpha_beta.clone(),
            material: SecretMaterial::from_string(canary("alpha-beta")),
            binding: fixture.binding(),
        },
        SeedSecret {
            reference: nested.clone(),
            material: SecretMaterial::from_string(canary("nested")),
            binding: fixture.binding(),
        },
    ];
    let provider = fixture.provider_with(seeds).await?;

    check_exact_resolution(
        &provider,
        &[
            (&alpha, "alpha"),
            (&alpha_beta, "alpha-beta"),
            (&nested, "nested"),
        ],
    )
    .await?;
    check_not_found(&provider, &ns).await?;
    check_unassigned(fixture, &provider).await?;
    check_binding(fixture, &provider, &alpha).await?;
    check_redaction(&provider, &alpha, &ns).await?;
    check_cancellation(&provider, &alpha).await?;
    Ok(())
}

async fn check_exact_resolution<P: SecretProvider>(
    provider: &P,
    expected: &[(&SecretRef, &str)],
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "exact_resolution";
    for (reference, label) in expected {
        let resolved = provider
            .get(reference)
            .await
            .map_err(|e| fail(CHECK, format!("get({reference}) failed: {e}")))?;
        ensure(
            resolved.material.expose_secret() == canary(label).as_bytes(),
            CHECK,
            format!("get({reference}) returned a different secret's value"),
        )?;
        ensure(
            resolved.version >= SecretVersion::FIRST,
            CHECK,
            format!("get({reference}) returned version 0"),
        )?;
    }
    Ok(())
}

async fn check_not_found<P: SecretProvider>(
    provider: &P,
    ns: &Namespace,
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "not_found";
    // A missing leaf, a bare prefix of seeded references, a different case,
    // and a sibling that only shares a string prefix must all be NotFound.
    for path in [
        "conformance/missing",
        "conformance",
        "conformance/ALPHA",
        "conformance/alph",
        "conformance/alpha/nested/deeper",
    ] {
        let reference = reference(ns, path)?;
        match provider.get(&reference).await {
            Err(SecretError::NotFound {
                reference: reported,
            }) => ensure(
                reported == reference,
                CHECK,
                format!("NotFound for {reference} reported a different reference"),
            )?,
            Err(e) => {
                return Err(fail(
                    CHECK,
                    format!("get({reference}) returned {e}, expected NotFound"),
                ));
            }
            Ok(_) => {
                return Err(fail(
                    CHECK,
                    format!("get({reference}) resolved; lookup must be exact"),
                ));
            }
        }
    }
    Ok(())
}

async fn check_unassigned<F: ConformanceFixture>(
    fixture: &F,
    provider: &F::Provider,
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "unassigned_namespace";
    let other = reference(&fixture.unassigned_namespace(), "conformance/alpha")?;
    match provider.get(&other).await {
        Err(SecretError::NotAssigned { .. }) => Ok(()),
        Err(e) => Err(fail(
            CHECK,
            format!("get({other}) returned {e}, expected NotAssigned"),
        )),
        Ok(_) => Err(fail(
            CHECK,
            format!("get({other}) resolved a namespace the provider does not serve"),
        )),
    }
}

async fn check_binding<F: ConformanceFixture>(
    fixture: &F,
    provider: &F::Provider,
    alpha: &SecretRef,
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "attested_binding";
    let resolved = provider
        .get(alpha)
        .await
        .map_err(|e| fail(CHECK, format!("get({alpha}) failed: {e}")))?;
    if fixture.attests_bindings() {
        ensure(
            resolved.attested_binding.as_ref() == Some(&fixture.binding()),
            CHECK,
            "attested binding differs from the stored binding",
        )
    } else {
        ensure(
            resolved.attested_binding.is_none(),
            CHECK,
            "provider that cannot attest returned a binding",
        )
    }
}

async fn check_redaction<P: SecretProvider>(
    provider: &P,
    alpha: &SecretRef,
    ns: &Namespace,
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "redaction";
    let resolved = provider
        .get(alpha)
        .await
        .map_err(|e| fail(CHECK, format!("get({alpha}) failed: {e}")))?;
    assert_no_canary(CHECK, "Debug of ResolvedSecret", &format!("{resolved:?}"))?;
    assert_no_canary(
        CHECK,
        "Debug of SecretMaterial",
        &format!("{:?}", resolved.material),
    )?;

    let missing = reference(ns, "conformance/missing")?;
    if let Err(error) = provider.get(&missing).await {
        assert_no_canary(CHECK, "error Display", &error.to_string())?;
        assert_no_canary(CHECK, "error Debug", &format!("{error:?}"))?;
    }
    Ok(())
}

async fn check_cancellation<P: SecretProvider>(
    provider: &P,
    alpha: &SecretRef,
) -> Result<(), ConformanceFailure> {
    const CHECK: &str = "cancellation";
    // Poll a lookup once and drop it, as a cancelled request would. The
    // provider must stay usable afterwards.
    {
        let mut lookup = pin!(provider.get(alpha));
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(Err(e)) = lookup.as_mut().poll(&mut cx) {
            return Err(fail(CHECK, format!("get({alpha}) failed: {e}")));
        }
    }
    provider.get(alpha).await.map(drop).map_err(|e| {
        fail(
            CHECK,
            format!("provider unusable after a dropped lookup: {e}"),
        )
    })
}

/// Runs every administrative check. `provider` must serve
/// `fixture.assigned_namespace()` and start empty.
///
/// # Errors
///
/// Returns the first failed check.
pub async fn check_admin_conformance<F, A>(
    fixture: &F,
    provider: &A,
) -> Result<(), ConformanceFailure>
where
    F: ConformanceFixture,
    A: SecretAdmin + SecretProvider,
{
    let ns = fixture.assigned_namespace();
    let first = reference(&ns, "admin/first")?;
    let latest = check_admin_versioning(fixture, provider, &first).await?;
    check_admin_listing(fixture, provider, &ns, &first).await?;
    check_admin_delete(fixture, provider, &first, latest).await?;

    let unassigned = reference(&fixture.unassigned_namespace(), "admin/first")?;
    ensure(
        matches!(
            provider
                .put(
                    &unassigned,
                    SecretMaterial::from_string(canary("x")),
                    fixture.binding()
                )
                .await,
            Err(SecretError::NotAssigned { .. })
        ),
        "admin_unassigned",
        "put into an unassigned namespace did not return NotAssigned",
    )
}

async fn admin_put<F: ConformanceFixture, A: SecretAdmin>(
    check: &'static str,
    fixture: &F,
    provider: &A,
    reference: &SecretRef,
    label: &str,
) -> Result<SecretVersion, ConformanceFailure> {
    provider
        .put(
            reference,
            SecretMaterial::from_string(canary(label)),
            fixture.binding(),
        )
        .await
        .map_err(|e| fail(check, format!("put({reference}) failed: {e}")))
}

/// Puts two versions and returns the latest.
async fn check_admin_versioning<F, A>(
    fixture: &F,
    provider: &A,
    first: &SecretRef,
) -> Result<SecretVersion, ConformanceFailure>
where
    F: ConformanceFixture,
    A: SecretAdmin + SecretProvider,
{
    const CHECK: &str = "admin_versioning";
    let v1 = admin_put(CHECK, fixture, provider, first, "v1").await?;
    let v2 = admin_put(CHECK, fixture, provider, first, "v2").await?;
    ensure(v2 > v1, CHECK, "put did not advance the version")?;

    let resolved = provider
        .get(first)
        .await
        .map_err(|e| fail(CHECK, format!("get after put failed: {e}")))?;
    ensure(
        resolved.material.expose_secret() == canary("v2").as_bytes() && resolved.version == v2,
        CHECK,
        "get did not return the latest version",
    )?;
    Ok(v2)
}

async fn check_admin_listing<F, A>(
    fixture: &F,
    provider: &A,
    ns: &Namespace,
    first: &SecretRef,
) -> Result<(), ConformanceFailure>
where
    F: ConformanceFixture,
    A: SecretAdmin,
{
    const CHECK: &str = "admin_listing";
    let second = reference(ns, "admin/second")?;
    let elsewhere = reference(ns, "other/third")?;
    for r in [&second, &elsewhere] {
        admin_put(CHECK, fixture, provider, r, "other").await?;
    }
    let scope = SecretScope::with_prefix(ns.clone(), "admin")
        .map_err(|e| fail(CHECK, format!("invalid scope: {e}")))?;
    let listed = provider
        .list_metadata(&scope)
        .await
        .map_err(|e| fail(CHECK, format!("list_metadata failed: {e}")))?;
    let listed_refs: Vec<&SecretRef> = listed.iter().map(|m| &m.reference).collect();
    ensure(
        listed_refs == vec![first, &second],
        CHECK,
        "list_metadata did not return exactly the scoped references in order",
    )?;
    assert_no_canary(CHECK, "metadata Debug", &format!("{listed:?}"))
}

async fn check_admin_delete<F, A>(
    fixture: &F,
    provider: &A,
    first: &SecretRef,
    latest: SecretVersion,
) -> Result<(), ConformanceFailure>
where
    F: ConformanceFixture,
    A: SecretAdmin + SecretProvider,
{
    const CHECK: &str = "admin_delete";
    provider
        .delete(first)
        .await
        .map_err(|e| fail(CHECK, format!("delete failed: {e}")))?;
    ensure(
        matches!(provider.get(first).await, Err(SecretError::NotFound { .. })),
        CHECK,
        "deleted secret still resolves",
    )?;
    ensure(
        matches!(
            provider.delete(first).await,
            Err(SecretError::NotFound { .. })
        ),
        CHECK,
        "deleting a missing secret did not return NotFound",
    )?;
    let recreated = admin_put(CHECK, fixture, provider, first, "v3").await?;
    ensure(
        recreated > latest,
        CHECK,
        "re-created secret reused an old version number",
    )
}
