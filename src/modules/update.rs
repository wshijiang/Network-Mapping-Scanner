use super::{
    package::{self, Signature},
    registry::{Registry, UpdateCommand},
};
use crate::error::ScannerError;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, sleep},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct RemoteRelease {
    manifest: String,
    signature: Signature,
    artifact_base_url: String,
}

pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), ScannerError> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub(crate) fn submit(directory: &Path, command: UpdateCommand) -> Result<Uuid, ScannerError> {
    fs::create_dir_all(directory)?;
    let requests = directory.join("requests");
    fs::create_dir_all(&requests)?;
    let id = Uuid::now_v7();
    atomic_json(&requests.join(format!("{id}.json")), &command)?;
    Ok(id)
}

pub(crate) async fn execute(
    registry: &Registry,
    command: UpdateCommand,
) -> Result<(), ScannerError> {
    match command {
        UpdateCommand::Apply { bundle } => {
            registry.apply(&bundle).await?;
        }
        UpdateCommand::Rollback { generation } => {
            registry.rollback(generation).await?;
        }
        UpdateCommand::Gc => {
            registry.gc()?;
        }
    }
    Ok(())
}

pub(crate) fn start(
    registry: Registry,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut next_remote = Instant::now();
        let requests = registry.config.directory.join("requests");
        if let Err(error) = fs::create_dir_all(&requests) {
            tracing::error!(%error,"cannot create update inbox");
            return;
        }
        loop {
            let work = async {
                if let Ok(entries) = fs::read_dir(&requests) {
                    let mut paths = entries
                        .filter_map(Result::ok)
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|e| e == "json"))
                        .collect::<Vec<_>>();
                    paths.sort();
                    for path in paths {
                        let Some(id) = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .filter(|id| Uuid::parse_str(id).is_ok())
                        else {
                            continue;
                        };
                        let result_path = requests.join(format!("{id}.result"));
                        // Durable response precedes inbox removal, so a crash
                        // cannot execute the same administrative request twice.
                        if result_path.exists() {
                            let _ = fs::remove_file(&path);
                            continue;
                        }
                        let result = match package::read_limited(&path, 4096).and_then(|bytes| {
                            serde_json::from_slice::<UpdateCommand>(&bytes).map_err(Into::into)
                        }) {
                            Ok(command) => execute(&registry, command).await,
                            Err(e) => Err(e),
                        };
                        let status = serde_json::json!({"request_id":id,"success":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string),"module_state":registry.report()});
                        let saved = registry
                            .record_deployment(id, &result)
                            .and_then(|_| atomic_json(&result_path, &status));
                        if saved.is_ok() {
                            let _ = fs::remove_file(&path);
                        }
                        if let Err(error) = result {
                            tracing::warn!(event="ModuleUpdateRejected",request_id=id,%error,"module update rejected; active environment retained");
                        }
                    }
                }
                if Instant::now() >= next_remote {
                    next_remote = Instant::now() + Duration::from_secs(60);
                    if let Some(url) = &registry.config.desired_url
                        && let Err(error) = remote_update(&registry, url).await
                    {
                        tracing::warn!(event="ModuleRemoteUpdateFailed",%error,"remote module update failed; current environment retained");
                    }
                }
                if let Ok(Some(generation)) = registry.automatic_rollback_target() {
                    match registry.rollback(generation).await {
                        Ok(environment) => tracing::warn!(
                            event = "ModuleAutomaticRollback",
                            generation = environment.generation,
                            restored_generation = generation,
                            "repeated worker transport/protocol failures triggered rollback"
                        ),
                        Err(error) => {
                            tracing::error!(event="ModuleAutomaticRollbackFailed",%error,"automatic rollback preflight failed")
                        }
                    }
                }
                if let Err(error) = atomic_json(
                    &registry.config.directory.join("status.json"),
                    &registry.report(),
                ) {
                    tracing::warn!(%error,"module status persistence failed");
                }
            };
            tokio::select! {_=work=>{},_=shutdown.changed()=>break}
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {_=sleep(Duration::from_secs(2))=>{},_=shutdown.changed()=>break}
        }
    })
}

async fn remote_update(registry: &Registry, desired_url: &str) -> Result<(), ScannerError> {
    let desired = reqwest::Url::parse(desired_url)
        .map_err(|_| ScannerError::Config("invalid desired URL".into()))?;
    if desired.scheme() != "https" || !desired.username().is_empty() || desired.password().is_some()
    {
        return Err(ScannerError::Config(
            "module desired URL must use HTTPS without embedded credentials".into(),
        ));
    }
    // This client deliberately never receives the node's runtime_token.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| ScannerError::Config(e.to_string()))?;
    let mut response = client
        .get(desired.clone())
        .send()
        .await
        .map_err(|e| ScannerError::Scan(e.to_string()))?
        .error_for_status()
        .map_err(|e| ScannerError::Scan(e.to_string()))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ScannerError::Scan(e.to_string()))?
    {
        if bytes.len() + chunk.len() > package::MAX_MANIFEST * 2 + 4096 {
            return Err(ScannerError::Scan("remote release exceeds capacity".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    let release: RemoteRelease = serde_json::from_slice(&bytes)?;
    let manifest = package::verify(
        release.manifest.as_bytes(),
        &release.signature,
        &registry.config.trusted_keys,
    )?;
    if registry
        .active()?
        .is_some_and(|e| manifest.revision <= e.revision)
    {
        return Ok(());
    }
    let base = reqwest::Url::parse(&release.artifact_base_url)
        .map_err(|_| ScannerError::Config("invalid artifact base URL".into()))?;
    if base.origin() != desired.origin()
        || base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(ScannerError::Config(
            "artifact source must share the configured HTTPS origin".into(),
        ));
    }
    let stage = registry
        .config
        .directory
        .join(format!("download-{}", Uuid::now_v7()));
    fs::create_dir(&stage)?;
    let result = async {
        for file in &manifest.files {
            let relative = package::relative(&file.path)?;
            let mut url = base.clone();
            {
                let mut parts = url
                    .path_segments_mut()
                    .map_err(|_| ScannerError::Config("invalid artifact source".into()))?;
                parts.pop_if_empty();
                for part in relative.components() {
                    parts.push(part.as_os_str().to_str().unwrap());
                }
            }
            let path = stage.join(relative);
            fs::create_dir_all(path.parent().unwrap())?;
            let mut output = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .await?;
            let mut response = client
                .get(url)
                .send()
                .await
                .map_err(|e| ScannerError::Scan(e.to_string()))?
                .error_for_status()
                .map_err(|e| ScannerError::Scan(e.to_string()))?;
            if response.content_length().is_some_and(|n| n != file.size) {
                return Err(ScannerError::Scan(
                    "artifact content length mismatch".into(),
                ));
            }
            let mut count = 0u64;
            use tokio::io::AsyncWriteExt;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| ScannerError::Scan(e.to_string()))?
            {
                count = count.saturating_add(chunk.len() as u64);
                if count > file.size {
                    return Err(ScannerError::Scan(
                        "artifact download exceeds capacity".into(),
                    ));
                }
                output.write_all(&chunk).await?;
            }
            if count != file.size {
                return Err(ScannerError::Scan("artifact download truncated".into()));
            }
            output.sync_all().await?;
        }
        fs::write(stage.join("manifest.json"), &release.manifest)?;
        fs::write(
            stage.join("manifest.sig"),
            serde_json::to_vec(&release.signature)?,
        )?;
        registry.apply(&stage).await?;
        Ok::<_, ScannerError>(())
    }
    .await;
    let _ = fs::remove_dir_all(stage);
    result
}

pub(crate) fn bundle_path(path: PathBuf) -> Result<PathBuf, ScannerError> {
    Ok(path.canonicalize()?)
}
