use super::{protocol::*, registry::ModuleSpec};
use crate::{
    error::ScannerError,
    journal::ScanJournal,
    scan::{ScanObservation, plan::ScanStageKind},
};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    process::{Child, Command as ProcessCommand},
    sync::mpsc,
    time::{Instant, sleep, timeout},
};

pub(crate) struct StageResult {
    pub(crate) outcome: Outcome,
    pub(crate) observations: Vec<ScanObservation>,
    pub(crate) error: Option<String>,
}

struct Workspace(std::path::PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Process {
    child: Child,
    _workspace: Workspace,
}
impl Drop for Process {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
    }
}

async fn spawn(
    path: &Path,
    stage: ScanStageKind,
    preflight: bool,
) -> Result<Process, ScannerError> {
    let mut command = ProcessCommand::new(path);
    let workspace = std::env::temp_dir().join(format!("scanner-worker-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&workspace)?;
    let workspace = Workspace(workspace);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&workspace.0, std::fs::Permissions::from_mode(0o700))?;
    }
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &workspace.0)
        .env("TMPDIR", &workspace.0);
    command.arg("--stage").arg(stage.name());
    if preflight {
        command.arg("--preflight");
    }
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let child = crate::process::spawn(&mut command).await?;
    Ok(Process {
        child,
        _workspace: workspace,
    })
}

fn check_hello(event: Event, stage: ScanStageKind) -> Result<(), ScannerError> {
    if !event.id.is_nil()
        || event.sequence != 0
        || !matches!(event.body,EventBody::Hello {ipc_version:IPC_VERSION,stage:actual,..} if actual==stage)
    {
        return Err(ScannerError::Scan("worker handshake rejected".into()));
    }
    Ok(())
}

pub(crate) async fn preflight(path: &Path, stage: ScanStageKind) -> Result<(), ScannerError> {
    let mut child = spawn(path, stage, true).await?;
    let mut output = child.child.stdout.take().unwrap();
    timeout(Duration::from_secs(30), async {
        check_hello(read_frame(&mut output).await?, stage)?;
        if !child.child.wait().await?.success() {
            return Err(ScannerError::Scan("worker preflight failed".into()));
        }
        Ok(())
    })
    .await
    .map_err(|_| ScannerError::Scan("worker preflight timed out".into()))?
}

pub(crate) async fn execute(
    spec: &ModuleSpec,
    mut request: Request,
    input: Vec<ScanObservation>,
    journal: Option<&mut ScanJournal<'_>>,
    cancel: &AtomicBool,
    hard_timeout: Duration,
    cancel_grace: Duration,
) -> Result<StageResult, ScannerError> {
    let mut child = spawn(&spec.worker_path, request.stage, false).await?;
    let mut stdout = child.child.stdout.take().unwrap();
    check_hello(
        timeout(Duration::from_secs(30), read_frame(&mut stdout))
            .await
            .map_err(|_| ScannerError::Scan("worker handshake timeout".into()))??,
        request.stage,
    )?;
    let mut stdin = child.child.stdin.take().unwrap();
    let id = request.id;
    let expected_stage = request.stage;
    let endpoint_count = input
        .iter()
        .filter(|o| matches!(o, ScanObservation::Port(_)))
        .count();
    let max_chunks = if input
        .iter()
        .any(|o| matches!(o,ScanObservation::Port(p) if p.protocol=="udp"))
    {
        endpoint_count
    } else {
        endpoint_count.div_ceil(request.service.batch_endpoints.max(1))
    };
    let resume = std::mem::take(&mut request.checkpoint.observations);
    // A dedicated sender avoids pipe deadlock when the child starts emitting
    // output while the last input frame is still being written.
    let (control_tx, mut control_rx) = mpsc::channel::<Command>(4);
    let sender = tokio::spawn(async move {
        write_frame(
            &mut stdin,
            &Command::Execute {
                request: Box::new(request),
            },
        )
        .await?;
        for observation in resume {
            write_frame(
                &mut stdin,
                &Command::Resume {
                    id,
                    observation: Box::new(observation),
                },
            )
            .await?;
        }
        for observation in input {
            write_frame(
                &mut stdin,
                &Command::Input {
                    id,
                    observation: Box::new(observation),
                },
            )
            .await?;
        }
        write_frame(&mut stdin, &Command::InputEnd { id }).await?;
        while let Some(command) = control_rx.recv().await {
            write_frame(&mut stdin, &command).await?;
        }
        Ok::<_, ScannerError>(())
    });
    let deadline = Instant::now() + hard_timeout;
    let mut cancelled_at = None;
    let mut sequence = 1;
    let mut results = Vec::new();
    let mut part = Vec::new();
    let mut total_bytes = 0usize;
    let mut part_bytes = 0usize;
    let mut journal = journal;
    // read_frame must survive timer ticks: cancelling read_exact halfway through
    // a frame loses framing. This single reader owns the stream until EOF.
    let (event_tx, mut event_rx) = mpsc::channel(2);
    let reader = tokio::spawn(async move {
        loop {
            let event = read_frame::<Event>(&mut stdout).await;
            let failed = event.is_err();
            if event_tx.send(event).await.is_err() || failed {
                break;
            }
        }
    });
    let result=async {
        loop {
            if cancel.load(Ordering::Relaxed) && cancelled_at.is_none() {
                cancelled_at=Some(Instant::now());
                let _=control_tx.try_send(Command::Cancel {id});
            }
            if cancelled_at.is_some_and(|at|at.elapsed()>=cancel_grace) { return Ok(StageResult {outcome:Outcome::Cancelled,observations:Vec::new(),error:None}); }
            if Instant::now()>=deadline {return Err(ScannerError::Scan("worker hard runtime limit exceeded".into()));}
            let event=tokio::select! {
                value=event_rx.recv()=>value.ok_or_else(||ScannerError::Scan("worker event channel closed".into()))??,
                _=sleep(Duration::from_millis(100))=>continue,
            };
            if event.id!=id || event.sequence!=sequence {return Err(ScannerError::Scan("worker event identity/order rejected".into()));}
            sequence+=1;
            match event.body {
                EventBody::Observation {observation}=> {
                    total_bytes=total_bytes.saturating_add(serde_json::to_vec(&observation)?.len());
                    if total_bytes>MAX_RESULTS {return Err(ScannerError::Scan("worker result capacity exceeded".into()));}
                    results.push(*observation);
                }
                EventBody::CheckpointPart {observation}=> {
                    if expected_stage != ScanStageKind::ServiceDetection || !matches!(observation.as_ref(), ScanObservation::Service(_)) { return Err(ScannerError::Scan("worker checkpoint kind rejected".into())); }
                    part_bytes=part_bytes.saturating_add(serde_json::to_vec(&observation)?.len());
                    if part_bytes>MAX_RESULTS {return Err(ScannerError::Scan("worker checkpoint capacity exceeded".into()));}
                    part.push(*observation);
                }
                EventBody::CheckpointSave {stage,chunk,elapsed_ms,has_part}=> {
                    if expected_stage != ScanStageKind::ServiceDetection || chunk > max_chunks || (!has_part && !part.is_empty()) { return Err(ScannerError::Scan("worker checkpoint rejected".into())); }
                    if let Some(j)=journal.as_deref_mut() {
                        if stage!=j.state.stage || chunk<j.state.chunk || chunk>j.state.chunk+1 || elapsed_ms<j.state.elapsed_ms {return Err(ScannerError::Scan("invalid worker checkpoint cursor".into()));}
                        j.save(stage,chunk,elapsed_ms,has_part.then_some(&part))?;
                    }
                    if !has_part && !part.is_empty() {return Err(ScannerError::Scan("uncommitted checkpoint part".into()));}
                    part.clear();part_bytes=0;
                    control_tx.send(Command::Ack {id,sequence:event.sequence}).await.map_err(|_|ScannerError::Scan("worker control closed".into()))?;
                }
                EventBody::BlockStarted=> {
                    if expected_stage != ScanStageKind::ServiceDetection { return Err(ScannerError::Scan("worker block event rejected".into())); }
                    if let Some(j)=journal.as_deref_mut() {j.start_block()?;}
                    control_tx.send(Command::Ack {id,sequence:event.sequence}).await.map_err(|_|ScannerError::Scan("worker control closed".into()))?;
                }
                EventBody::Finished {outcome,error}=> {
                    if !part.is_empty() {return Err(ScannerError::Scan("worker ended with uncommitted checkpoint".into()));}
                    if cancelled_at.is_some() {return Ok(StageResult {outcome:Outcome::Cancelled,observations:Vec::new(),error:None});}
                    return Ok(StageResult {outcome,observations:results,error});
                }
                EventBody::Hello {..}=>return Err(ScannerError::Scan("duplicate worker hello".into())),
            }
        }
    }.await;
    reader.abort();
    sender.abort();
    // Reap the direct child after killing its entire process group; even a
    // successful worker must not leave scanner descendants running.
    #[cfg(unix)]
    if let Some(pid) = child.child.id() {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.child.kill().await;
    let _ = child.child.wait().await;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn request() -> Request {
        let local: crate::types::AppConfig =
            toml_edit::de::from_str(include_str!("../../config.toml")).unwrap();
        Request {
            id: uuid::Uuid::now_v7(),
            stage: ScanStageKind::PortDiscovery,
            target: crate::types::TargetParams {
                ip: "192.0.2.1".into(),
                port: "22".into(),
                rate: 1,
                address_family: "ipv4".into(),
            },
            engine_path: String::new(),
            masscan: local.scanner.masscan,
            service: local.service_detection,
            dns: local.dns,
            nuclei: local.nuclei,
            resolvers: Vec::new(),
            checkpoint: Default::default(),
        }
    }
    fn print_event(event: &Event) -> String {
        let bytes = serde_json::to_vec(event).unwrap();
        let header = (bytes.len() as u32)
            .to_be_bytes()
            .iter()
            .map(|b| format!("\\{b:03o}"))
            .collect::<String>();
        format!(
            "printf '{header}'; printf '%s' '{}'\n",
            String::from_utf8(bytes).unwrap()
        )
    }
    fn fixture(body: String) -> (std::path::PathBuf, ModuleSpec) {
        let root = std::env::temp_dir().join(format!("worker-host-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("worker");
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (
            root,
            ModuleSpec {
                worker_path: path,
                engine_path: None,
                templates_path: None,
                artifact: "test".into(),
            },
        )
    }
    fn hello() -> String {
        print_event(&Event {
            id: uuid::Uuid::nil(),
            sequence: 0,
            body: EventBody::Hello {
                ipc_version: crate::modules::protocol::IPC_VERSION,
                stage: ScanStageKind::PortDiscovery,
                version: "test".into(),
            },
        })
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn worker_start_retries_transient_text_file_busy() {
        let (root, spec) = fixture(hello());
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&spec.worker_path)
            .unwrap();
        let release = async {
            sleep(Duration::from_millis(30)).await;
            drop(writer);
        };
        let (result, _) = tokio::join!(
            preflight(&spec.worker_path, ScanStageKind::PortDiscovery),
            release
        );
        result.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn permanent_busy_worker_is_bounded_and_missing_worker_is_not_retried() {
        let (root, spec) = fixture(hello());
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&spec.worker_path)
            .unwrap();
        let started = Instant::now();
        let result = preflight(&spec.worker_path, ScanStageKind::PortDiscovery).await;
        assert!(
            matches!(result, Err(ScannerError::Io(e)) if e.kind() == std::io::ErrorKind::ExecutableFileBusy)
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(writer);
        std::fs::remove_dir_all(root).unwrap();
        let result = preflight(&spec.worker_path, ScanStageKind::PortDiscovery).await;
        assert!(
            matches!(result, Err(ScannerError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound)
        );
    }

    #[tokio::test]
    async fn host_does_not_lose_partial_frame_on_timer_tick() {
        let request = request();
        let event = Event {
            id: request.id,
            sequence: 1,
            body: EventBody::Finished {
                outcome: Outcome::Completed,
                error: None,
            },
        };
        let bytes = serde_json::to_vec(&event).unwrap();
        let header = (bytes.len() as u32).to_be_bytes();
        let body = format!(
            "{}printf '\\{:03o}\\{:03o}'; sleep 0.3; printf '\\{:03o}\\{:03o}'; printf '%s' '{}'\ncat >/dev/null\n",
            hello(),
            header[0],
            header[1],
            header[2],
            header[3],
            String::from_utf8(bytes).unwrap()
        );
        let (root, spec) = fixture(body);
        let result = execute(
            &spec,
            request,
            Vec::new(),
            None,
            &AtomicBool::new(false),
            Duration::from_secs(3),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, Outcome::Completed);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn host_rejects_wrong_request_and_overlarge_frames() {
        for body in [
            format!(
                "{}{}cat >/dev/null\n",
                hello(),
                print_event(&Event {
                    id: uuid::Uuid::now_v7(),
                    sequence: 1,
                    body: EventBody::Finished {
                        outcome: Outcome::Completed,
                        error: None
                    }
                })
            ),
            format!("{}printf '\\377\\377\\377\\377'; cat >/dev/null\n", hello()),
        ] {
            let (root, spec) = fixture(body);
            assert!(
                execute(
                    &spec,
                    request(),
                    Vec::new(),
                    None,
                    &AtomicBool::new(false),
                    Duration::from_secs(3),
                    Duration::from_millis(100)
                )
                .await
                .is_err()
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[tokio::test]
    async fn hung_worker_is_reaped_after_cancellation_grace() {
        let (root, spec) = fixture(format!("{}sleep 30\n", hello()));
        let start = Instant::now();
        let result = execute(
            &spec,
            request(),
            Vec::new(),
            None,
            &AtomicBool::new(true),
            Duration::from_secs(3),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, Outcome::Cancelled);
        assert!(start.elapsed() < Duration::from_secs(2));
        std::fs::remove_dir_all(root).unwrap();
    }
}
