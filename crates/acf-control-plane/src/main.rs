//! `acf-control-plane` binary entry point. Behavior belongs in the library crate.

use std::process::ExitCode;

#[expect(
    clippy::print_stderr,
    reason = "the skeleton has no telemetry pipeline yet"
)]
fn main() -> ExitCode {
    // Exit with failure so a skeleton build is never mistaken for a working service.
    eprintln!(
        "acf-control-plane {}: WP-00 skeleton build, not functional",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
