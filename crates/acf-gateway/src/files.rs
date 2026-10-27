//! Reading configuration documents from disk, shared by the gateway and the
//! `acf-store` tool.

use std::path::{Path, PathBuf};

use acf_config::{SourceFile, ValidatedConfig, load_bundle};

/// Reads a file as UTF-8.
///
/// # Errors
///
/// Returns a message naming the file.
pub fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Reads a file.
///
/// # Errors
///
/// Returns a message naming the file.
pub fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// A document and its `.sig`, if one exists.
///
/// # Errors
///
/// Returns a message if the document cannot be read.
pub fn source(path: &Path) -> Result<SourceFile, String> {
    let mut signature_path = path.as_os_str().to_owned();
    signature_path.push(".sig");
    Ok(SourceFile {
        name: path.display().to_string(),
        bytes: read_bytes(path)?,
        signature: std::fs::read(PathBuf::from(signature_path)).ok(),
    })
}

/// A document's text.
///
/// # Errors
///
/// Returns a message if it is not UTF-8.
pub fn text(file: &SourceFile) -> Result<&str, String> {
    std::str::from_utf8(&file.bytes).map_err(|_| format!("{} is not UTF-8", file.name))
}

/// Every `*.yaml` profile in `dir`, in name order, with signatures.
///
/// # Errors
///
/// Returns a message if the directory or a file cannot be read.
pub fn profile_sources(dir: &Path) -> Result<Vec<SourceFile>, String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    paths.sort();
    paths.iter().map(|path| source(path)).collect()
}

/// Loads and validates a bundle with its separately stored profiles.
///
/// # Errors
///
/// Returns every validation problem as one message.
pub fn load_config(
    bundle: &SourceFile,
    profiles: &[SourceFile],
) -> Result<ValidatedConfig, String> {
    let texts = profiles.iter().map(text).collect::<Result<Vec<_>, _>>()?;
    load_bundle(text(bundle)?, &texts).map_err(|e| e.to_string())
}
