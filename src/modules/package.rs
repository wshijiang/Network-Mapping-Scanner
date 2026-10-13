//! Signed directory bundles. Only explicitly listed regular files are copied;
//! archives, links and executable paths outside the bundle are never accepted.
use super::{protocol::IPC_VERSION, registry::ModuleSpec};
use crate::{error::ScannerError, scan::plan::ScanStageKind};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(crate) const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_MANIFEST: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) schema: u16,
    pub(crate) ipc_version: u16,
    pub(crate) release_id: String,
    pub(crate) revision: i64,
    pub(crate) target: String,
    pub(crate) files: Vec<BundleFile>,
    pub(crate) modules: BTreeMap<String, BundleModule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleFile {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) executable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleModule {
    pub(crate) worker: String,
    pub(crate) engine: Option<String>,
    pub(crate) templates: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signature {
    pub(crate) key_id: String,
    pub(crate) signature: String,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn unhex(value: &str) -> Result<Vec<u8>, ScannerError> {
    if !value.len().is_multiple_of(2) {
        return Err(ScannerError::Config("invalid hex length".into()));
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| ScannerError::Config("invalid hex".into()))?;
            u8::from_str_radix(text, 16).map_err(|_| ScannerError::Config("invalid hex".into()))
        })
        .collect()
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub(crate) fn hash_file(path: &Path) -> Result<String, ScannerError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    Ok(hex(&hasher.finalize()))
}

pub(crate) fn relative(path: &str) -> Result<PathBuf, ScannerError> {
    let value = Path::new(path);
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\\')
        || !value
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(ScannerError::Config("invalid bundle path".into()));
    }
    Ok(value.to_path_buf())
}

pub(crate) fn verify(
    raw: &[u8],
    signature: &Signature,
    keys_path: &Path,
) -> Result<Manifest, ScannerError> {
    if raw.len() > MAX_MANIFEST {
        return Err(ScannerError::Config("manifest too large".into()));
    }
    let keys: BTreeMap<String, String> =
        serde_json::from_slice(&read_limited(keys_path, MAX_MANIFEST as u64)?)?;
    let key = unhex(
        keys.get(&signature.key_id)
            .ok_or_else(|| ScannerError::Config("unknown update signing key".into()))?,
    )?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(raw, &unhex(&signature.signature)?)
        .map_err(|_| ScannerError::Config("update signature rejected".into()))?;
    let manifest: Manifest = serde_json::from_slice(raw)?;
    validate(&manifest)?;
    Ok(manifest)
}

pub(crate) fn validate(manifest: &Manifest) -> Result<(), ScannerError> {
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    if manifest.schema != 1
        || manifest.ipc_version != IPC_VERSION
        || manifest.revision <= 0
        || manifest.release_id.is_empty()
        || manifest.release_id.len() > 128
        || manifest.target != target
        || manifest.modules.is_empty()
        || manifest.modules.len() > 4
        || manifest.files.len() > 10000
    {
        return Err(ScannerError::Config("unsupported module manifest".into()));
    }
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for file in &manifest.files {
        relative(&file.path)?;
        if file.sha256.len() != 64
            || unhex(&file.sha256)?.len() != 32
            || files.insert(file.path.as_str(), file).is_some()
        {
            return Err(ScannerError::Config(
                "invalid or duplicate file descriptor".into(),
            ));
        }
        total = total
            .checked_add(file.size)
            .ok_or_else(|| ScannerError::Config("bundle size overflow".into()))?;
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(ScannerError::Config("bundle exceeds capacity".into()));
    }
    for (stage, module) in &manifest.modules {
        let _: ScanStageKind = serde_json::from_value(serde_json::Value::String(stage.clone()))?;
        let worker = files
            .get(module.worker.as_str())
            .ok_or_else(|| ScannerError::Config("worker missing from manifest".into()))?;
        if !worker.executable {
            return Err(ScannerError::Config("worker must be executable".into()));
        }
        if let Some(engine) = &module.engine
            && !files.get(engine.as_str()).is_some_and(|f| f.executable)
        {
            return Err(ScannerError::Config(
                "engine missing or not executable".into(),
            ));
        }
        if stage != "dns_lookup" && module.engine.is_none() {
            return Err(ScannerError::Config("engine is required".into()));
        }
        if let Some(templates) = &module.templates {
            relative(templates)?;
            if !files
                .keys()
                .any(|p| p.starts_with(&format!("{templates}/")))
            {
                return Err(ScannerError::Config("template directory is empty".into()));
            }
        }
        if stage == "vulnerability_detection" && module.templates.is_none() {
            return Err(ScannerError::Config("templates are required".into()));
        }
    }
    // A file cannot also be a parent directory of another file.
    let names: BTreeSet<_> = files.keys().copied().collect();
    for name in &names {
        let mut parent = Path::new(name).parent();
        while let Some(p) = parent {
            if names.contains(p.to_str().unwrap_or("")) {
                return Err(ScannerError::Config("conflicting bundle paths".into()));
            }
            parent = p.parent();
        }
    }
    Ok(())
}

pub(crate) fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, ScannerError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(ScannerError::Config("file exceeds capacity".into()));
    }
    Ok(bytes)
}

pub(crate) fn copy_regular(
    source: &Path,
    destination: &Path,
    expected: &BundleFile,
) -> Result<(), ScannerError> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(ScannerError::Config(
            "bundle source must be a regular file".into(),
        ));
    }
    #[cfg(unix)]
    let mut input = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)?
    };
    #[cfg(not(unix))]
    let mut input = File::open(source)?;
    let parent = destination.parent().unwrap();
    fs::create_dir_all(parent)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let size = std::io::copy(
        &mut std::io::Read::by_ref(&mut input).take(expected.size + 1),
        &mut output,
    )?;
    output.flush()?;
    output.sync_all()?;
    if size != expected.size || hash_file(destination)? != expected.sha256 {
        return Err(ScannerError::Config(
            "bundle file digest/size mismatch".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(if expected.executable { 0o555 } else { 0o444 }),
        )?;
    }
    Ok(())
}

pub(crate) fn specs(
    manifest: &Manifest,
    root: &Path,
    artifact: &str,
) -> BTreeMap<String, ModuleSpec> {
    manifest
        .modules
        .iter()
        .map(|(stage, m)| {
            (
                stage.clone(),
                ModuleSpec {
                    worker_path: root.join(&m.worker),
                    engine_path: m.engine.as_ref().map(|p| root.join(p)),
                    templates_path: m.templates.as_ref().map(|p| root.join(p)),
                    artifact: artifact.into(),
                },
            )
        })
        .collect()
}

#[derive(clap::Parser)]
#[command(
    name = "scanner-package",
    about = "Create and sign immutable scanner module directory bundles"
)]
struct PackageCli {
    #[command(subcommand)]
    command: PackageCommand,
}
#[derive(clap::Subcommand)]
enum PackageCommand {
    /// Generate an Ed25519 PKCS#8 key and a scanner trusted-key JSON file
    Keygen {
        #[arg(long)]
        private: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        key_id: String,
    },
    /// Hash the files in an unsigned manifest, validate it, then sign exact bytes
    Sign {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        private: PathBuf,
        #[arg(long)]
        key_id: String,
    },
}
pub fn package_main() -> std::process::ExitCode {
    use clap::Parser;
    match package_command(PackageCli::parse().command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("package: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<(), ScannerError> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn package_command(command: PackageCommand) -> Result<(), ScannerError> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    match command {
        PackageCommand::Keygen {
            private,
            public,
            key_id,
        } => {
            if key_id.is_empty() || key_id.len() > 128 || private == public {
                return Err(ScannerError::Config("invalid signing-key arguments".into()));
            }
            let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .map_err(|_| ScannerError::Config("key generation failed".into()))?;
            let key = Ed25519KeyPair::from_pkcs8(document.as_ref())
                .map_err(|_| ScannerError::Config("invalid generated key".into()))?;
            // Create the public file first; existing key files are never overwritten.
            private_write(
                &public,
                &serde_json::to_vec_pretty(&BTreeMap::from([(
                    key_id,
                    hex(key.public_key().as_ref()),
                )]))?,
            )?;
            if let Err(error) = private_write(&private, document.as_ref()) {
                let _ = fs::remove_file(&public);
                return Err(error);
            }
        }
        PackageCommand::Sign {
            bundle,
            private,
            key_id,
        } => {
            let key = Ed25519KeyPair::from_pkcs8(&read_limited(&private, 4096)?)
                .map_err(|_| ScannerError::Config("invalid Ed25519 PKCS#8 key".into()))?;
            let root = bundle.canonicalize()?;
            let mut manifest: Manifest = serde_json::from_slice(&read_limited(
                &root.join("manifest.json"),
                MAX_MANIFEST as u64,
            )?)?;
            for file in &mut manifest.files {
                let path = root.join(relative(&file.path)?);
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    return Err(ScannerError::Config(
                        "cannot sign a non-regular file".into(),
                    ));
                }
                file.size = fs::metadata(&path)?.len();
                file.sha256 = hash_file(&path)?;
            }
            validate(&manifest)?;
            let raw = serde_json::to_vec_pretty(&manifest)?;
            let signature = Signature {
                key_id,
                signature: hex(key.sign(&raw).as_ref()),
            };
            // Manifest and signature are generated offline; readers reject any
            // interrupted pair because the signature covers these exact bytes.
            let mut file = File::create(root.join("manifest.json"))?;
            file.write_all(&raw)?;
            file.sync_all()?;
            let mut file = File::create(root.join("manifest.sig"))?;
            file.write_all(&serde_json::to_vec_pretty(&signature)?)?;
            file.sync_all()?;
            File::open(&root)?.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_paths_reject_escape_and_special_components() {
        for path in ["", "../x", "/tmp/x", "a/../b", "a\\b"] {
            assert!(relative(path).is_err(), "{path}");
        }
        assert!(relative("bin/scanner-worker").is_ok());
    }
    #[test]
    fn signature_covers_exact_bytes() {
        use ring::{
            rand::SystemRandom,
            signature::{Ed25519KeyPair, KeyPair},
        };
        let random = SystemRandom::new();
        let key =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&random).unwrap().as_ref())
                .unwrap();
        let root = std::env::temp_dir().join(format!("signed-modules-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("keys.json"),
            serde_json::to_vec(&BTreeMap::from([("test", hex(key.public_key().as_ref()))]))
                .unwrap(),
        )
        .unwrap();
        let signature = Signature {
            key_id: "test".into(),
            signature: hex(key.sign(b"{}").as_ref()),
        };
        assert!(
            verify(b"{} ", &signature, &root.join("keys.json"))
                .unwrap_err()
                .to_string()
                .contains("signature rejected")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
