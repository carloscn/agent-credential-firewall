//! Writes a throwaway development PKI for the mTLS demo (ADR 0002):
//!
//! ```text
//! cargo run -p acf-gateway --features development --example dev-pki -- <dir> [device]
//! ```
//!
//! Produces `ca.pem`, `gateway.pem`/`gateway.key` (for `localhost`),
//! `<device>.pem`/`<device>.key`, and `devices.yaml` enrolling the device as
//! `workload:<device>`. Keys are written with mode 0600. Never use these
//! files outside development.

#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

#[path = "../tests/support/pki.rs"]
mod pki;

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use acf_identity::thumbprint;

fn write(dir: &Path, name: &str, contents: &str, mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dir.join(name))
        .unwrap_or_else(|e| panic!("cannot create {name} (refusing to overwrite): {e}"));
    file.write_all(contents.as_bytes()).expect("write");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: dev-pki <dir> [device]");
    let device = args.next().unwrap_or_else(|| "vps-17".to_owned());
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("create output directory");

    let ca = pki::Pki::new("acf-development-ca");
    let server = ca.server(&["localhost"]);
    let client = ca.client(&device);

    write(dir, "ca.pem", &ca.ca_pem(), 0o644);
    write(dir, "gateway.pem", &server.certificate_pem, 0o644);
    write(dir, "gateway.key", &server.key_pem, 0o600);
    write(
        dir,
        &format!("{device}.pem"),
        &client.certificate_pem,
        0o644,
    );
    write(dir, &format!("{device}.key"), &client.key_pem, 0o600);
    write(
        dir,
        "devices.yaml",
        &format!(
            "schema: acf.devices/v1\ndevices:\n  - device: {device}\n    principal: 'workload:{device}'\n    certificates:\n      - {}\n",
            thumbprint(&client.der)
        ),
        0o644,
    );
    println!(
        "wrote development PKI for device `{device}` to {}",
        dir.display()
    );
}
