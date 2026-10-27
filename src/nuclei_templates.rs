//! Seed Docker's writable template directory and optionally update before scanning.
use crate::{error::ScannerError, types::NucleiConfig};
use std::{fs, path::Path, process::Stdio};
use tokio::{
    process::Command,
    time::{Duration, timeout},
};
use uuid::Uuid;

const REVISION: &str = "NM-BUNDLED-REVISION";

struct TemplateLock(fs::File);

impl TemplateLock {
    fn acquire(path: &Path) -> Result<Self, ScannerError> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| {
            ScannerError::Config("template directory is being prepared by another process".into())
        })?;
        Ok(Self(file))
    }
}

impl Drop for TemplateLock {
    fn drop(&mut self) {
        // flock survives closing this file if a concurrent fork temporarily
        // inherited its descriptor. Explicitly unlock on every exit, including
        // errors and cancellation, before closing our copy.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<usize, ScannerError> {
    fs::create_dir_all(destination)?;
    let mut templates = 0;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            templates += copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
            if matches!(
                entry.path().extension().and_then(|v| v.to_str()),
                Some("yaml" | "yml")
            ) {
                templates += 1;
            }
        } else {
            return Err(ScannerError::Config(
                "template trees must contain only regular files and directories".into(),
            ));
        }
    }
    Ok(templates)
}

fn has_templates(root: &Path) -> Result<bool, ScannerError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() && has_templates(&entry.path())? {
            return Ok(true);
        }
        if kind.is_file()
            && matches!(
                entry.path().extension().and_then(|v| v.to_str()),
                Some("yaml" | "yml")
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) async fn prepare(config: &NucleiConfig) -> Result<(), ScannerError> {
    if !config.enabled || (config.bundled_templates_path.is_empty() && !config.update_templates) {
        return Ok(());
    }
    let target = Path::new(&config.templates_path);
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = target.file_name().and_then(|v| v.to_str()).ok_or_else(|| {
        ScannerError::Config("nuclei.templates_path must name a template directory".into())
    })?;
    fs::create_dir_all(parent)?;
    let _lock = TemplateLock::acquire(&parent.join(format!(".{name}.lock")))?;
    let backup = parent.join(format!(".{name}.previous"));
    // Recover an interrupted directory swap before reading or updating templates.
    if backup.exists() {
        if target.exists() {
            fs::remove_dir_all(&backup)?;
        } else {
            fs::rename(&backup, target)?;
        }
    }
    if target
        .symlink_metadata()
        .is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink())
    {
        return Err(ScannerError::Config(
            "managed templates_path must be a real directory".into(),
        ));
    }
    let bundled = Path::new(&config.bundled_templates_path);
    if !config.bundled_templates_path.is_empty() {
        let seed = bundled.canonicalize()?;
        let active = parent.canonicalize()?.join(name);
        if active.starts_with(&seed) || seed.starts_with(&active) {
            return Err(ScannerError::Config(
                "bundled and writable template directories must not overlap".into(),
            ));
        }
    }
    let reseed = if config.bundled_templates_path.is_empty() {
        false
    } else {
        let expected = fs::read(bundled.join(REVISION))?;
        !target.is_dir()
            || fs::read(target.join(REVISION)).ok().as_ref() != Some(&expected)
            || !has_templates(target)?
    };
    if !reseed && !config.update_templates {
        return Ok(());
    }
    let staging = parent.join(format!(".{name}.staging-{}", Uuid::now_v7()));
    let result = async {
        let source = if reseed { bundled } else { target };
        let count = if source.exists() {
            copy_tree(source, &staging)?
        } else {
            fs::create_dir_all(&staging)?;
            0
        };
        if count == 0 && !config.update_templates {
            return Err(ScannerError::Config(
                "template source contains no YAML templates".into(),
            ));
        }
        if config.update_templates {
            crate::scan::engines::nuclei::validate_binary(&config.path)?;
            tracing::info!(
                event = "NucleiTemplateUpdateStarted",
                "updating official Nuclei templates before scanning"
            );
            let mut command = Command::new(&config.path);
            // -disable-update-check would also disable explicit updates in this
            // Nuclei version. It remains mandatory on actual scan commands.
            command
                .args(["-update-templates", "-update-template-dir"])
                .arg(&staging)
                .env("NUCLEI_TEMPLATES_DIR", &staging)
                .kill_on_drop(true)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let status = timeout(
                Duration::from_secs(config.template_update_timeout_seconds),
                async {
                    let mut child = crate::process::spawn(&mut command).await?;
                    child.wait().await
                },
            )
            .await
            .map_err(|_| {
                ScannerError::Config(
                    "Nuclei template update timed out; previous templates were preserved".into(),
                )
            })??;
            if !status.success() {
                return Err(ScannerError::Config(format!(
                    "Nuclei template update failed ({status}); previous templates were preserved"
                )));
            }
            if !has_templates(&staging)? {
                return Err(ScannerError::Config(
                    "updated template directory contains no YAML templates".into(),
                ));
            }
        }
        if target.exists() {
            fs::rename(target, &backup)?;
        }
        if let Err(error) = fs::rename(&staging, target) {
            if backup.exists() {
                fs::rename(&backup, target)?;
            }
            return Err(error.into());
        }
        if backup.exists() {
            fs::remove_dir_all(&backup)?;
        }
        tracing::info!(
            event = "NucleiTemplatesPrepared",
            updated = config.update_templates,
            seeded = reseed,
            "Nuclei templates are ready"
        );
        Ok(())
    }
    .await;
    if staging.exists() {
        let _ = fs::remove_dir_all(staging);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    struct Fixture {
        root: PathBuf,
        config: NucleiConfig,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("template-test-{}", Uuid::now_v7()));
            let seed = root.join("bundled");
            fs::create_dir_all(&seed).unwrap();
            fs::write(seed.join(REVISION), "v1\nsha1\n").unwrap();
            fs::write(seed.join("fixture.yaml"), "old template").unwrap();
            let config = NucleiConfig {
                enabled: true,
                templates_path: root.join("active").to_string_lossy().into(),
                bundled_templates_path: seed.to_string_lossy().into(),
                ..Default::default()
            };
            Self { root, config }
        }
        fn engine(&mut self, body: &str) {
            let engine = self.root.join("nuclei");
            fs::write(&engine, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
            self.config.path = engine.to_string_lossy().into();
        }
        fn active(&self) -> PathBuf {
            PathBuf::from(&self.config.templates_path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn releases_lock_even_when_another_descriptor_is_still_open() {
        let f = Fixture::new();
        let path = f.root.join(".active.lock");
        let lock = TemplateLock::acquire(&path).unwrap();
        // A clone shares the same open file description as a descriptor
        // inherited by a child between fork and exec.
        let inherited = lock.0.try_clone().unwrap();
        assert!(TemplateLock::acquire(&path).is_err());
        drop(lock);
        let next = TemplateLock::acquire(&path).unwrap();
        assert!(TemplateLock::acquire(&path).is_err());
        drop(inherited);
        assert!(TemplateLock::acquire(&path).is_err());
        drop(next);
        TemplateLock::acquire(&path).unwrap();
    }

    #[tokio::test]
    async fn disabled_does_not_write_or_run_engine() {
        let mut f = Fixture::new();
        f.config.enabled = false;
        f.config.update_templates = true;
        f.engine("exit 99");
        prepare(&f.config).await.unwrap();
        assert!(!f.active().exists());
    }
    #[tokio::test]
    async fn seeds_offline_and_reuses_cache_without_running_engine() {
        let mut f = Fixture::new();
        f.engine("exit 99");
        prepare(&f.config).await.unwrap();
        fs::write(f.active().join("fixture.yaml"), "cached").unwrap();
        prepare(&f.config).await.unwrap();
        assert_eq!(
            fs::read_to_string(f.active().join("fixture.yaml")).unwrap(),
            "cached"
        );
    }
    #[tokio::test]
    async fn new_image_seed_replaces_old_cached_bundle() {
        let f = Fixture::new();
        prepare(&f.config).await.unwrap();
        fs::write(
            Path::new(&f.config.bundled_templates_path).join(REVISION),
            "v2\nsha2\n",
        )
        .unwrap();
        prepare(&f.config).await.unwrap();
        assert_eq!(
            fs::read_to_string(f.active().join(REVISION)).unwrap(),
            "v2\nsha2\n"
        );
    }
    #[tokio::test]
    async fn updates_only_when_enabled_and_passes_no_scan_target() {
        let mut f = Fixture::new();
        f.config.update_templates = true;
        f.engine("[ \"$#\" = 3 ] && [ \"$1\" = -update-templates ] && [ \"$2\" = -update-template-dir ] || exit 99\nprintf updated > \"$3/fixture.yaml\"");
        prepare(&f.config).await.unwrap();
        assert_eq!(
            fs::read_to_string(f.active().join("fixture.yaml")).unwrap(),
            "updated"
        );
    }
    #[tokio::test]
    async fn failed_update_preserves_previous_templates() {
        let mut f = Fixture::new();
        prepare(&f.config).await.unwrap();
        f.config.update_templates = true;
        f.engine("printf broken > \"$3/fixture.yaml\"; exit 1");
        assert!(prepare(&f.config).await.is_err());
        assert_eq!(
            fs::read_to_string(f.active().join("fixture.yaml")).unwrap(),
            "old template"
        );
    }
    #[tokio::test]
    async fn timeout_preserves_templates() {
        let mut f = Fixture::new();
        prepare(&f.config).await.unwrap();
        f.config.update_templates = true;
        f.config.template_update_timeout_seconds = 1;
        f.engine("exec sleep 30");
        let error = prepare(&f.config).await.unwrap_err();
        assert!(
            error.to_string().contains("timed out"),
            "expected template update timeout, got: {error:?}"
        );
        assert_eq!(
            fs::read_to_string(f.active().join("fixture.yaml")).unwrap(),
            "old template"
        );
    }
    #[tokio::test]
    async fn recovers_interrupted_swap() {
        let f = Fixture::new();
        prepare(&f.config).await.unwrap();
        fs::rename(f.active(), f.root.join(".active.previous")).unwrap();
        prepare(&f.config).await.unwrap();
        assert!(f.active().join("fixture.yaml").is_file());
    }
    #[tokio::test]
    async fn overlapping_directories_are_rejected() {
        let mut f = Fixture::new();
        f.config.templates_path = f.root.join("bundled/active").to_string_lossy().into();
        assert!(
            prepare(&f.config)
                .await
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
    }
}
