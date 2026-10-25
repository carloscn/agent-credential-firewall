//! Throwaway ECDSA P-256 PKI for tests and the `dev-pki` example (ADR 0002).
//! Never used by release binaries.

#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

/// A certificate and its PKCS#8 key, in PEM.
pub(crate) struct Issued {
    pub(crate) certificate_pem: String,
    pub(crate) key_pem: String,
    pub(crate) der: Vec<u8>,
}

/// A certificate authority that issues server and client certificates.
pub(crate) struct Pki {
    authority: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    pub(crate) fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        Self {
            authority: CertifiedIssuer::self_signed(params, key).expect("ca cert"),
        }
    }

    pub(crate) fn ca_pem(&self) -> String {
        self.authority.pem()
    }

    fn issue(
        &self,
        names: &[&str],
        common_name: &str,
        usage: ExtendedKeyUsagePurpose,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Issued {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let certificate = params.signed_by(&key, &self.authority).expect("leaf cert");
        Issued {
            certificate_pem: certificate.pem(),
            key_pem: key.serialize_pem(),
            der: certificate.der().to_vec(),
        }
    }

    /// A gateway server certificate for `names`, valid for 90 days.
    pub(crate) fn server(&self, names: &[&str]) -> Issued {
        let now = OffsetDateTime::now_utc();
        self.issue(
            names,
            "acf-gateway",
            ExtendedKeyUsagePurpose::ServerAuth,
            now - Duration::hours(1),
            now + Duration::days(90),
        )
    }

    /// A daemon client certificate, valid for 30 days.
    pub(crate) fn client(&self, name: &str) -> Issued {
        let now = OffsetDateTime::now_utc();
        self.issue(
            &[],
            name,
            ExtendedKeyUsagePurpose::ClientAuth,
            now - Duration::hours(1),
            now + Duration::days(30),
        )
    }

    /// A client certificate that expired yesterday.
    pub(crate) fn expired_client(&self, name: &str) -> Issued {
        let now = OffsetDateTime::now_utc();
        self.issue(
            &[],
            name,
            ExtendedKeyUsagePurpose::ClientAuth,
            now - Duration::days(30),
            now - Duration::days(1),
        )
    }

    /// A certificate for `name` that only allows server authentication.
    pub(crate) fn server_purpose_client(&self, name: &str) -> Issued {
        let now = OffsetDateTime::now_utc();
        self.issue(
            &[],
            name,
            ExtendedKeyUsagePurpose::ServerAuth,
            now - Duration::hours(1),
            now + Duration::days(30),
        )
    }
}
