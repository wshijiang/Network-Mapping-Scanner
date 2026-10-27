//! Independent diagnostics worker. Never await log transfer from the lease heartbeat loop.
mod files;
pub mod protocol;
mod store;

use crate::{
    http_client::{ServerHttpClient, response_error},
    reconnect::{Backoff, ConnectionState, RetryPolicy},
};
use chrono::Utc;
use files::LogDirectory;
use protocol::*;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    time::Duration,
};
use store::Store;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{mpsc, watch},
};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
static BOOT: OnceLock<Uuid> = OnceLock::new();
static CAPTURE: OnceLock<SyncSender<Capture>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

enum Capture {
    Event(Value),
    Flush(SyncSender<()>),
}

pub fn boot_id() -> Uuid {
    *BOOT.get_or_init(Uuid::now_v7)
}

/// Called by the file formatter after its event ID has been added to the log line.
pub fn capture(value: &Value) {
    if value["target"]
        .as_str()
        .is_some_and(|t| t.contains("::diagnostics"))
    {
        return;
    }
    if !matches!(value["level"].as_str(), Some("WARN" | "ERROR"))
        && value.pointer("/fields/event").and_then(Value::as_str)
            != Some("ScannerOperationRecovered")
    {
        return;
    }
    let Some(sender) = CAPTURE.get() else {
        return;
    };
    let mut event = json!({"timestamp":value["timestamp"],"level":value["level"],"fields":{}});
    // Upload only diagnostic fields, never arbitrary log context or configuration objects.
    for key in [
        "event_id",
        "boot_id",
        "event",
        "operation",
        "error_code",
        "error_kind",
        "error_message",
        "message",
        "reason",
        "error",
        "task_id",
        "engine",
        "stage",
        "exit_code",
        "process_id",
        "elapsed_ms",
        "process_elapsed_ms",
        "result_count",
        "invalid_line_count",
        "stderr_bytes",
        "stderr_truncated",
        "http_status",
        "retryable",
        "attempt",
    ] {
        if let Some(field) = value["fields"].get(key) {
            event["fields"][key] = if let Some(s) = field.as_str() {
                Value::String(redact(s))
            } else if field.is_number() || field.is_boolean() || field.is_null() {
                field.clone()
            } else {
                continue;
            };
        }
    }
    if event["fields"].get("task_id").is_none()
        && let Some(task_id) = value.pointer("/span/task_id").and_then(Value::as_str)
        && Uuid::parse_str(task_id).is_ok()
    {
        event["fields"]["task_id"] = json!(task_id);
    }
    if sender.try_send(Capture::Event(event)).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn redact(input: &str) -> String {
    use std::sync::OnceLock;
    static CREDENTIAL: OnceLock<regex::Regex> = OnceLock::new();
    static URL: OnceLock<regex::Regex> = OnceLock::new();
    let credential = CREDENTIAL.get_or_init(|| regex::Regex::new(
        r#"(?i)(?:\b(?:password|passwd|token|secret|authorization|api_key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)|\bbearer\s+[a-z0-9._-]+|nm_(?:run|reg)_[a-z0-9_-]+)"#
    ).expect("constant credential regex"));
    let url = URL.get_or_init(|| {
        regex::Regex::new(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+").expect("constant URL regex")
    });
    let redacted = credential.replace_all(input, "[REDACTED]");
    url.replace_all(&redacted, "[REDACTED]")
        .chars()
        .take(2048)
        .collect()
}

pub async fn flush_capture() {
    let Some(sender) = CAPTURE.get().cloned() else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        let (reply, receiver) = sync_channel(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut command = Capture::Flush(reply);
        loop {
            match sender.try_send(command) {
                Ok(()) => {
                    let _ = receiver.recv_timeout(
                        deadline.saturating_duration_since(std::time::Instant::now()),
                    );
                    break;
                }
                Err(std::sync::mpsc::TrySendError::Full(value))
                    if std::time::Instant::now() < deadline =>
                {
                    command = value;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    })
    .await;
}

#[derive(Clone)]
pub struct DiagnosticsHandle {
    sender: mpsc::Sender<Job>,
    accepting_tasks: Arc<std::sync::atomic::AtomicBool>,
    server_enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl DiagnosticsHandle {
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            supported_versions: vec![VERSION],
            can_list_logs: true,
            can_collect_logs: true,
            can_report_errors: true,
        }
    }
    pub fn health(&self) -> Value {
        let accepting = self.accepting_tasks.load(Ordering::Relaxed);
        let dropped = DROPPED.load(Ordering::Relaxed);
        json!({"accepting_tasks":accepting,"status":if !accepting {"error"}else if dropped > 0 {"degraded"}else{"healthy"},"dropped_events":dropped})
    }
    pub fn set_accepting_tasks(&self, enabled: bool) {
        self.accepting_tasks.store(enabled, Ordering::Relaxed);
    }
    pub fn dispatch(&self, jobs: Vec<Job>, enabled: bool) {
        self.server_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            return;
        }
        for job in jobs.into_iter().take(2) {
            if job.protocol_version == VERSION
                && job.source_file_ids.len() <= MAX_FILES
                && job.source_file_ids.iter().all(|id| valid_digest(id))
            {
                // A full queue leaves the job on the server for the next heartbeat.
                let _ = self.sender.try_send(job);
            }
        }
    }
}

pub struct DiagnosticsRuntime {
    pub handle: DiagnosticsHandle,
    worker: tokio::task::JoinHandle<()>,
    events_worker: tokio::task::JoinHandle<()>,
    store: Store,
}

impl DiagnosticsRuntime {
    pub async fn start(
        directory: &Path,
        database: &Path,
        origin: String,
        scanner: Uuid,
        client: ServerHttpClient,
        connection: watch::Receiver<ConnectionState>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self> {
        let store = Store::open(
            database.with_extension("diagnostics.sqlite3"),
            &origin,
            scanner,
        )?;
        let unclean = store.session_start()?;
        let spool = database.with_extension("diagnostics-spool");
        tokio::fs::create_dir_all(&spool).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o700)).await?;
        }
        let directory = Arc::new(LogDirectory::open(directory)?);
        let (capture_sender, capture_receiver) = sync_channel::<Capture>(1024);
        CAPTURE
            .set(capture_sender)
            .map_err(|_| "diagnostics_already_initialized")?;
        let capture_store = store.clone();
        std::thread::Builder::new()
            .name("diagnostic-outbox".into())
            .spawn(move || {
                while let Ok(command) = capture_receiver.recv() {
                    match command {
                        Capture::Event(value) => {
                            if !capture_store.insert_event(&value).unwrap_or(false) {
                                DROPPED.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Capture::Flush(reply) => {
                            let _ = reply.send(());
                        }
                    }
                }
            })?;
        let (sender, receiver) = mpsc::channel(16);
        let handle = DiagnosticsHandle {
            sender,
            accepting_tasks: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            server_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        if unclean {
            tracing::error!(
                event = "ScannerUncleanRestart",
                error_kind = "process",
                error_code = "unclean_restart",
                operation = "startup",
                "previous scanner instance did not exit cleanly"
            );
        }
        let events_store = store.clone();
        let events_client = client.clone();
        let events_origin = origin.clone();
        let events_connection = connection.clone();
        let events_shutdown = shutdown.clone();
        let server_enabled = handle.server_enabled.clone();
        let events_worker = tokio::spawn(async move {
            run_events(
                events_store,
                events_client,
                events_origin,
                scanner,
                events_connection,
                events_shutdown,
                server_enabled,
            )
            .await;
        });
        let worker_store = store.clone();
        let worker_enabled = handle.server_enabled.clone();
        let worker = tokio::spawn(async move {
            let mut worker = Worker {
                store: worker_store,
                directory,
                spool,
                origin,
                scanner,
                client,
                connection,
                shutdown,
                receiver,
                enabled: worker_enabled,
            };
            worker.run().await;
        });
        Ok(Self {
            handle,
            worker,
            events_worker,
            store,
        })
    }

    pub fn supervisor(&self) -> tokio::task::JoinHandle<()> {
        let worker = self.worker.abort_handle();
        let events = self.events_worker.abort_handle();
        let handle = self.handle.clone();
        tokio::spawn(async move {
            while !crate::stop_requested() {
                if worker.is_finished() || events.is_finished() {
                    handle.set_accepting_tasks(false);
                    tracing::error!(
                        event = "ScannerDiagnosticsWorkerStopped",
                        error_code = "diagnostics_worker_stopped",
                        operation = "diagnostics",
                        "diagnostics worker stopped unexpectedly"
                    );
                    crate::request_failure_stop();
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    }

    pub fn is_finished(&self) -> bool {
        self.worker.is_finished() || self.events_worker.is_finished()
    }

    pub async fn stop(self, clean: bool) {
        flush_capture().await;
        // Shutdown signal also interrupts an in-flight upload. Preserve its snapshot and job.
        stop_worker(self.worker, "diagnostics").await;
        stop_worker(self.events_worker, "diagnostics events").await;
        if clean {
            let _ = self.store.clean_shutdown().await;
        }
    }
}

async fn stop_worker(mut worker: tokio::task::JoinHandle<()>, name: &'static str) {
    let result = match tokio::time::timeout(Duration::from_secs(5), &mut worker).await {
        Ok(result) => result,
        Err(_) => {
            worker.abort();
            worker.await
        }
    };
    if let Err(error) = result
        && error.is_panic()
    {
        tracing::error!(event = "ScannerDiagnosticsWorkerPanicked", worker = name, %error, "diagnostics worker panicked");
        crate::request_failure_stop();
    }
}

struct Worker {
    store: Store,
    directory: Arc<LogDirectory>,
    spool: PathBuf,
    origin: String,
    scanner: Uuid,
    client: ServerHttpClient,
    connection: watch::Receiver<ConnectionState>,
    shutdown: watch::Receiver<bool>,
    receiver: mpsc::Receiver<Job>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl Worker {
    fn endpoint(&self, name: &str) -> String {
        format!("{}/api/scanner/diagnostics/{name}", self.origin)
    }
    async fn post<T: serde::Serialize + ?Sized>(&self, name: &str, body: &T) -> Result<Value> {
        let response = self
            .client
            .post_json(&self.endpoint(name), body, "report scanner diagnostics")
            .await?;
        if !response.status().is_success() {
            return Err(response_error(response, "report scanner diagnostics")
                .await
                .into());
        }
        Ok(response.json().await?)
    }

    async fn build_manifest(&self, job: &Job) -> Result<Manifest> {
        if job.kind == JobKind::ListLogs {
            let directory = self.directory.clone();
            let sources = tokio::task::spawn_blocking(move || directory.list()).await??;
            self.store.save_sources(sources.clone()).await?;
            return Ok(Manifest {
                scanner_id: self.scanner,
                job_id: job.job_id,
                sources,
                files: Vec::new(),
            });
        }
        let mut files = Vec::new();
        let mut total = 0_u64;
        let mut spool_size = 0_u64;
        let mut entries = tokio::fs::read_dir(&self.spool).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                spool_size += entry.metadata().await?.len();
            }
        }
        let result = async {
            for id in &job.source_file_ids {
                let source = self.store.source(id.clone()).await?;
                let file_id = Uuid::now_v7();
                let path = self.spool.join(format!("{file_id}.snapshot"));
                let directory = self.directory.clone();
                let snapshot = tokio::task::spawn_blocking(move || {
                    directory.snapshot(&source, &path, file_id)
                })
                .await??;
                total += snapshot.size_bytes;
                files.push(snapshot);
                if total + spool_size > MAX_JOB_BYTES {
                    return Err("log_job_too_large".into());
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        if let Err(error) = result {
            self.remove_snapshots(&Manifest {
                scanner_id: self.scanner,
                job_id: job.job_id,
                sources: vec![],
                files,
            })
            .await;
            return Err(error);
        }
        Ok(Manifest {
            scanner_id: self.scanner,
            job_id: job.job_id,
            sources: Vec::new(),
            files,
        })
    }

    async fn process(&self, job: &Job, manifest: Option<Manifest>) -> Result<()> {
        self.post(
            "ack",
            &Ack {
                scanner_id: self.scanner,
                job_id: job.job_id,
                status: "accepted".into(),
                error_code: None,
            },
        )
        .await?;
        let manifest = match manifest {
            Some(value) => value,
            None => {
                let manifest = self.build_manifest(job).await?;
                // Snapshot metadata is durable before its first network transmission.
                if let Err(error) = self.store.save_manifest(job.job_id, &manifest).await {
                    self.remove_snapshots(&manifest).await;
                    return Err(error);
                }
                manifest
            }
        };
        self.post("manifest", &manifest).await?;
        if job.kind == JobKind::CollectLogs {
            for snapshot in &manifest.files {
                let transfer = Transfer {
                    scanner_id: self.scanner,
                    job_id: job.job_id,
                    file_id: snapshot.file_id,
                    part_index: 0,
                };
                let base = format!(
                    "scanner_id={}&job_id={}&file_id={}",
                    transfer.scanner_id, transfer.job_id, transfer.file_id
                );
                let response = self
                    .client
                    .get(
                        &format!("{}?{base}", self.endpoint("upload-status")),
                        "get diagnostic upload progress",
                    )
                    .await?;
                if !response.status().is_success() {
                    return Err(response_error(response, "get diagnostic upload progress")
                        .await
                        .into());
                }
                let response: Value = response.json().await?;
                let confirmed: Vec<u32> = serde_json::from_value(response["parts"].clone())?;
                let mut input = tokio::fs::File::open(
                    self.spool.join(format!("{}.snapshot", snapshot.file_id)),
                )
                .await?;
                for part in 0..snapshot.size_bytes.div_ceil(CHUNK_BYTES as u64) as u32 {
                    if confirmed.contains(&part) {
                        continue;
                    }
                    let offset = part as u64 * CHUNK_BYTES as u64;
                    let size = (snapshot.size_bytes - offset).min(CHUNK_BYTES as u64) as usize;
                    input.seek(std::io::SeekFrom::Start(offset)).await?;
                    let mut bytes = vec![0_u8; size];
                    input.read_exact(&mut bytes).await?;
                    let response = self
                        .client
                        .put_bytes(
                            &format!("{}?{base}&part_index={part}", self.endpoint("chunk")),
                            bytes,
                        )
                        .await?;
                    if !response.status().is_success() {
                        return Err(response_error(response, "upload diagnostic log chunk")
                            .await
                            .into());
                    }
                    if *self.shutdown.borrow() {
                        return Err("diagnostics_shutdown".into());
                    }
                }
            }
            self.post(
                "complete",
                &Complete {
                    scanner_id: self.scanner,
                    job_id: job.job_id,
                },
            )
            .await?;
        }
        self.store.done(job.job_id).await?;
        self.remove_snapshots(&manifest).await;
        Ok(())
    }

    async fn remove_snapshots(&self, manifest: &Manifest) {
        for snapshot in &manifest.files {
            let _ =
                tokio::fs::remove_file(self.spool.join(format!("{}.snapshot", snapshot.file_id)))
                    .await;
        }
    }

    async fn cleanup_spool(&self) -> Result<()> {
        let keep = self.store.pending_file_ids().await?;
        let mut entries = tokio::fs::read_dir(&self.spool).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some((prefix, suffix)) = name.split_once('.') else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(prefix) else {
                continue;
            };
            if !entry.file_type().await?.is_file() {
                continue;
            }
            if suffix == "tmp" || (suffix == "snapshot" && !keep.contains(&id)) {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        Ok(())
    }

    async fn run(&mut self) {
        let mut backoff = Backoff::new(RetryPolicy::new(
            Duration::from_secs(3),
            Duration::from_secs(60),
        ));
        let mut next = tokio::time::Instant::now();
        let _ = self.store.prune().await;
        let _ = self.cleanup_spool().await;
        loop {
            if *self.shutdown.borrow() {
                break;
            }
            let _ = self.store.prune().await;
            let _ = self.cleanup_spool().await;
            // Persist notifications even while the server is unavailable.
            while let Ok(job) = self.receiver.try_recv() {
                if let Err(error) = self.store.enqueue(job).await {
                    tracing::error!(%error,"diagnostic job persistence failed");
                }
            }
            if tokio::time::Instant::now() >= next
                && self.enabled.load(Ordering::Relaxed)
                && *self.connection.borrow() == ConnectionState::Online
            {
                next = tokio::time::Instant::now() + Duration::from_secs(3);
                match self.store.next_job().await {
                    Ok(Some((job, manifest))) => {
                        if job.expires_at < Utc::now() {
                            let _ = self.store.done(job.job_id).await;
                            if let Some(m) = manifest {
                                self.remove_snapshots(&m).await;
                            }
                            continue;
                        }
                        let mut shutdown = self.shutdown.clone();
                        let result = tokio::select! {
                            result=self.process(&job,manifest.clone())=>Some(result),
                            _=shutdown.changed()=>None,
                        };
                        if matches!(&result, Some(Ok(()))) {
                            backoff.reset();
                        }
                        if let Some(Err(error)) = result {
                            let source = error.downcast_ref::<crate::error::ServerError>();
                            let closed = source
                                .is_some_and(|e| e.status().is_some_and(|s| s.as_u16() == 409))
                                && error
                                    .to_string()
                                    .contains("diagnostic_job_expired_or_closed");
                            let retry = source.is_some_and(|e| {
                                e.is_retryable()
                                    || matches!(e, crate::error::ServerError::Maintenance { .. })
                            }) || source
                                .is_some_and(|e| e.status().is_some_and(|s| s.as_u16() == 409));
                            if closed {
                                let _ = self.store.done(job.job_id).await;
                                if let Some(m) = &manifest {
                                    self.remove_snapshots(m).await;
                                }
                            } else if retry {
                                next = tokio::time::Instant::now()
                                    + backoff
                                        .next_delay(None, source.and_then(|e| e.retry_after()));
                            } else {
                                let code = if error.to_string().contains("log_file_changed") {
                                    "log_file_changed"
                                } else if error.to_string().contains("log_file_too_large") {
                                    "log_file_too_large"
                                } else {
                                    "log_collection_failed"
                                };
                                if self
                                    .post(
                                        "ack",
                                        &Ack {
                                            scanner_id: self.scanner,
                                            job_id: job.job_id,
                                            status: "failed".into(),
                                            error_code: Some(code.into()),
                                        },
                                    )
                                    .await
                                    .is_ok()
                                {
                                    let _ = self.store.done(job.job_id).await;
                                    if let Some(m) = &manifest {
                                        self.remove_snapshots(m).await;
                                    }
                                }
                            }
                            tracing::warn!(job_id=%job.job_id,%error,"diagnostic log collection deferred or failed");
                        }
                    }
                    Ok(None) => {}
                    Err(error) => tracing::error!(%error,"diagnostic queue read failed"),
                }
                let _ = self.store.prune().await;
                if let Err(error) = self.cleanup_spool().await {
                    tracing::warn!(%error,"diagnostic spool cleanup failed");
                }
            }
            tokio::select! {
                _=tokio::time::sleep(Duration::from_millis(500))=>{},
                _=self.shutdown.changed()=>break,
                job=self.receiver.recv()=>if let Some(job)=job {let _=self.store.enqueue(job).await;},
            }
        }
    }
}

async fn run_events(
    store: Store,
    client: ServerHttpClient,
    origin: String,
    scanner: Uuid,
    connection: watch::Receiver<ConnectionState>,
    mut shutdown: watch::Receiver<bool>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut backoff = Backoff::new(RetryPolicy::new(
        Duration::from_secs(3),
        Duration::from_secs(60),
    ));
    loop {
        if *shutdown.borrow() {
            break;
        }
        let mut delay = Duration::from_secs(3);
        if enabled.load(Ordering::Relaxed) && *connection.borrow() == ConnectionState::Online {
            let send = async {
                let events = store.pending_events().await?;
                if events.is_empty() {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
                let response = client
                    .post_json(
                        &format!("{origin}/api/scanner/diagnostics/events"),
                        &Events {
                            scanner_id: scanner,
                            events,
                        },
                        "report scanner diagnostics",
                    )
                    .await?;
                if !response.status().is_success() {
                    return Err(response_error(response, "report scanner diagnostics")
                        .await
                        .into());
                }
                let response: Value = response.json().await?;
                let ids = serde_json::from_value(response["confirmed"].clone())?;
                store.confirm(ids).await
            };
            let outcome = tokio::select! {result=send=>Some(result),_=shutdown.changed()=>None};
            match outcome {
                Some(Ok(())) => backoff.reset(),
                Some(Err(error)) => {
                    delay = backoff.next_delay(
                        None,
                        error
                            .downcast_ref::<crate::error::ServerError>()
                            .and_then(|e| e.retry_after()),
                    );
                    tracing::warn!(%error,"diagnostic event upload deferred");
                }
                None => break,
            }
        }
        tokio::select! {_=tokio::time::sleep(delay)=>{},_=shutdown.changed()=>break}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn event_redaction_removes_separated_credentials() {
        let text = super::redact(
            "password= secret token: hidden Bearer nm_run_sensitive https://internal.test/path",
        );
        for secret in ["secret", "hidden", "sensitive", "internal.test"] {
            assert!(!text.contains(secret));
        }
    }
}
