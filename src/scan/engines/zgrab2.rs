use crate::error::ScannerError;
use crate::scan::detection::{
    ProbeAttempt, ProbeEvidence, ProbeKind, aggregate, fallback_attempts, initial_attempts,
};
use crate::scan::{PortObservation, ServiceObservation};
use crate::types::ServiceDetectionConfig;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::process::{ChildStderr, Command};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

const MAX_ZGRAB_STDERR_CHARS: usize = 4096;
const MAX_BANNER_CHARS: usize = 1024;

#[derive(Default)]
struct StderrCapture {
    text: String,
    bytes: usize,
    truncated: bool,
}

pub(crate) enum EngineOutcome {
    Completed(Vec<ServiceObservation>),
    Partial(Vec<ServiceObservation>, String),
    Cancelled,
}

enum ProcessOutcome {
    Completed(Vec<ProbeEvidence>),
    TimedOut(Vec<ProbeEvidence>, &'static str),
    Cancelled,
}

pub(crate) fn validate_binary(path: &str) -> Result<(), ScannerError> {
    if path.trim().is_empty() {
        return Err(ScannerError::Config(
            "service_detection.zgrab_path must not be empty".into(),
        ));
    }

    let configured_path = Path::new(path);
    let resolved = if configured_path.is_absolute() || configured_path.components().count() > 1 {
        configured_path.to_path_buf()
    } else {
        find_in_path(configured_path).ok_or_else(|| {
            ScannerError::Config(format!(
                "service_detection.zgrab_path '{path}' was not found as an executable file in PATH"
            ))
        })?
    };

    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "service detection binary '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "service detection binary '{}' is not a file",
            resolved.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "service detection binary '{}' is not executable",
                resolved.display()
            )));
        }
    }

    tracing::info!(zgrab_path = %resolved.display(), "zgrab2 binary validated");
    Ok(())
}

fn find_in_path(program: &Path) -> Option<PathBuf> {
    let search_path = std::env::var_os("PATH")?;
    std::env::split_paths(&search_path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
pub(crate) async fn run(
    config: &ServiceDetectionConfig,
    open_ports: &[PortObservation],
    address_family: &str,
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    run_with_journal(config, open_ports, address_family, cancel_requested, None).await
}

pub(crate) async fn run_with_journal(
    config: &ServiceDetectionConfig,
    open_ports: &[PortObservation],
    address_family: &str,
    cancel_requested: &AtomicBool,
    mut journal: Option<&mut crate::journal::ScanJournal<'_>>,
) -> Result<EngineOutcome, ScannerError> {
    if open_ports.iter().any(|p| p.protocol == "udp") {
        return super::udp::run(config, open_ports, cancel_requested, journal).await;
    }
    let started = Instant::now();
    let previous_elapsed = journal.as_ref().map_or(0, |j| j.state.elapsed_ms);
    let budget_ms = config.max_runtime_seconds.saturating_mul(1000);
    let deadline = started + Duration::from_millis(budget_ms.saturating_sub(previous_elapsed));
    let mut services = Vec::new();
    let mut service_bytes = 0usize;
    if let Some(j) = journal.as_ref() {
        for observation in &j.state.observations {
            if let crate::scan::ScanObservation::Service(service) = observation {
                service_bytes = service_bytes.saturating_add(serde_json::to_vec(service)?.len());
            }
        }
    }
    let first_chunk = journal.as_ref().map_or(0, |j| j.state.chunk);
    let chunk_count = open_ports.len().div_ceil(config.batch_endpoints);
    tracing::info!(
        event = "ServiceDetectionStarted",
        endpoint_count = open_ports.len(),
        chunk_count,
        resumed_chunk = first_chunk,
        strategy = config.strategy.as_str(),
        senders = config.senders,
        server_rate_limit = config.server_rate_limit,
        max_runtime_seconds = config.max_runtime_seconds,
        idle_timeout_seconds = config.idle_timeout_seconds,
        "service detection started"
    );
    for (chunk_index, ports) in open_ports
        .chunks(config.batch_endpoints)
        .enumerate()
        .skip(first_chunk)
    {
        if cancel_requested.load(Ordering::Relaxed) {
            return Ok(EngineOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(EngineOutcome::Partial(
                services,
                "service_detection_runtime_exceeded".into(),
            ));
        }
        if let Some(j) = journal.as_mut() {
            j.save(
                j.state.stage,
                chunk_index,
                previous_elapsed.saturating_add(started.elapsed().as_millis() as u64),
                None,
            )?;
            j.start_block()?;
        }
        let initial = initial_attempts(ports, config);
        let result =
            run_attempts(config, &initial, address_family, cancel_requested, deadline).await;
        let mut evidence;
        let mut timeout_reason = None;
        match result {
            Ok(ProcessOutcome::Completed(e)) => evidence = e,
            Ok(ProcessOutcome::TimedOut(e, reason)) => {
                evidence = e;
                timeout_reason = Some(reason);
            }
            Ok(ProcessOutcome::Cancelled) => {
                save_elapsed(&mut journal, previous_elapsed, started)?;
                return Ok(EngineOutcome::Cancelled);
            }
            Err(error) => {
                save_elapsed(&mut journal, previous_elapsed, started)?;
                return Err(error);
            }
        }
        let fallback = fallback_attempts(ports, &initial, &evidence, config);
        if timeout_reason.is_none() && !fallback.is_empty() {
            match run_attempts(
                config,
                &fallback,
                address_family,
                cancel_requested,
                deadline,
            )
            .await
            {
                Ok(ProcessOutcome::Completed(mut e)) => evidence.append(&mut e),
                Ok(ProcessOutcome::TimedOut(mut e, reason)) => {
                    evidence.append(&mut e);
                    timeout_reason = Some(reason);
                }
                Ok(ProcessOutcome::Cancelled) => {
                    save_elapsed(&mut journal, previous_elapsed, started)?;
                    return Ok(EngineOutcome::Cancelled);
                }
                Err(error) => {
                    save_elapsed(&mut journal, previous_elapsed, started)?;
                    return Err(error);
                }
            }
        }
        let mut block = aggregate(&evidence, config);
        let mut retained = Vec::new();
        for service in block.drain(..) {
            let bytes = serde_json::to_vec(&service)?.len();
            if service_bytes.saturating_add(bytes) > 64 * 1024 * 1024 {
                timeout_reason = Some("service_detection_result_limit");
                break;
            }
            service_bytes += bytes;
            retained.push(service);
        }
        let block = retained;
        if let Some(reason) = timeout_reason {
            save_elapsed(&mut journal, previous_elapsed, started)?;
            services.extend(block);
            return Ok(EngineOutcome::Partial(services, reason.into()));
        }
        if let Some(j) = journal.as_mut() {
            let observations: Vec<_> = block
                .iter()
                .cloned()
                .map(crate::scan::ScanObservation::Service)
                .collect();
            j.save(
                j.state.stage,
                chunk_index + 1,
                previous_elapsed.saturating_add(started.elapsed().as_millis() as u64),
                Some(&observations),
            )?;
        }
        services.extend(block);
        tracing::info!(
            event = "ServiceDetectionChunkCompleted",
            chunk_index,
            chunk_count,
            endpoint_count = ports.len(),
            service_count = services.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "service detection block completed"
        );
    }
    Ok(EngineOutcome::Completed(services))
}

fn save_elapsed(
    journal: &mut Option<&mut crate::journal::ScanJournal<'_>>,
    previous: u64,
    started: Instant,
) -> Result<(), ScannerError> {
    if let Some(j) = journal.as_mut() {
        j.save(
            j.state.stage,
            j.state.chunk,
            previous.saturating_add(started.elapsed().as_millis() as u64),
            None,
        )?;
    }
    Ok(())
}

// Both engine types share the same stage deadline, block ACK and recovery boundary.
async fn run_attempts(
    config: &ServiceDetectionConfig,
    attempts: &[ProbeAttempt],
    address_family: &str,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<ProcessOutcome, ScannerError> {
    let external: Vec<_> = attempts
        .iter()
        .filter(|a| !a.probe.is_native() && a.probe != ProbeKind::Modbus)
        .cloned()
        .collect();
    // Modbus has its own process so its global pacing does not depend on
    // unrelated zgrab2 workers or their buffered input.
    let modbus: Vec<_> = attempts
        .iter()
        .filter(|a| a.probe == ProbeKind::Modbus)
        .cloned()
        .collect();
    let mut evidence = Vec::new();
    for group in [&external, &modbus] {
        if group.is_empty() {
            continue;
        }
        match run_zgrab_attempts(config, group, address_family, cancel, deadline).await? {
            ProcessOutcome::Completed(mut items) => evidence.append(&mut items),
            ProcessOutcome::TimedOut(mut items, reason) => {
                evidence.append(&mut items);
                return Ok(ProcessOutcome::TimedOut(evidence, reason));
            }
            ProcessOutcome::Cancelled => return Ok(ProcessOutcome::Cancelled),
        }
    }
    let gap = Duration::from_secs_f64(1.0 / f64::from(config.server_rate_limit.max(1)));
    let native: Vec<_> = attempts.iter().filter(|a| a.probe.is_native()).collect();
    let mut running = JoinSet::new();
    let mut completed = Vec::new();
    let mut next = 0;
    let mut next_start = Instant::now() + gap;
    let mut progress = tokio::time::interval(Duration::from_secs(30));
    while next < native.len() || !running.is_empty() {
        if cancel.load(Ordering::Relaxed) {
            return Ok(ProcessOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            completed.sort_by_key(|(index, _)| *index);
            evidence.extend(completed.into_iter().map(|(_, result)| result));
            return Ok(ProcessOutcome::TimedOut(
                evidence,
                "service_detection_runtime_exceeded",
            ));
        }
        tokio::select! {
            _ = tokio::time::sleep_until(next_start), if next < native.len() && running.len() < config.senders.max(1) as usize => {
                let attempt = native[next].clone();
                let probe_config = config.clone();
                let index = next;
                running.spawn(async move { (index, super::native::probe(&attempt, &probe_config, deadline).await) });
                next += 1;
                next_start = Instant::now() + gap;
            }
            result = running.join_next(), if !running.is_empty() => {
                let result = result.expect("nonempty probe set").map_err(|error| ScannerError::Scan(format!("native probe task failed: {error}")))?;
                completed.push(result);
            }
            _ = progress.tick() => tracing::info!(event="ServiceDetectionProgress", completed_probes=completed.len(), total_probes=native.len(), in_flight=running.len(), "native service probes progressing"),
            _ = sleep(Duration::from_millis(20)) => {},
            _ = tokio::time::sleep_until(deadline) => {},
        }
    }
    completed.sort_by_key(|(index, _)| *index);
    evidence.extend(completed.into_iter().map(|(_, result)| result));
    if cancel.load(Ordering::Relaxed) {
        return Ok(ProcessOutcome::Cancelled);
    }
    if Instant::now() >= deadline {
        return Ok(ProcessOutcome::TimedOut(
            evidence,
            "service_detection_runtime_exceeded",
        ));
    }
    Ok(ProcessOutcome::Completed(evidence))
}

async fn run_zgrab_attempts(
    config: &ServiceDetectionConfig,
    attempts: &[ProbeAttempt],
    address_family: &str,
    cancel_requested: &AtomicBool,
    deadline: Instant,
) -> Result<ProcessOutcome, ScannerError> {
    let input = build_zgrab_input(attempts);

    let config_file = TempZgrabConfig::create(config, attempts).await?;
    let started_at = Instant::now();
    tracing::debug!(
        zgrab_path = %config.zgrab_path,
        probe_count = input.lines().count(),
        senders = config.senders,
        server_rate_limit = config.server_rate_limit,
        address_family,
        "spawning zgrab2 service detection"
    );

    let read_limit_kib = config.max_result_bytes.div_ceil(1024).max(1);
    let mut command = Command::new(&config.zgrab_path);
    command
        .args(["--senders", &config.senders.to_string()])
        .args(["--server-rate-limit", &config.server_rate_limit.to_string()])
        .args(["--read-limit-per-host", &read_limit_kib.to_string()])
        .arg("--flush");
    if address_family == "ipv6" {
        command.arg("--resolve-ipv6");
    }
    command
        .arg("multiple")
        .args(["--config-file", config_file.path_string()?])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = crate::process::spawn(&mut command)
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to spawn zgrab2: {error}")))?;
    let process_id = child.id();

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ScannerError::Scan("zgrab2 stderr unavailable".into()))?;

    let paced_modbus = attempts
        .iter()
        .all(|attempt| attempt.probe == ProbeKind::Modbus);
    let permits = paced_modbus.then(|| Arc::new(Semaphore::new(config.senders.max(1) as usize)));
    let (ready_sender, ready_receiver) = oneshot::channel();
    let stderr_handle = tokio::spawn(collect_zgrab_stderr(
        stderr,
        paced_modbus.then_some(ready_sender),
    ));
    let input_permits = permits.clone();
    let gap = Duration::from_secs_f64(1.0 / f64::from(config.server_rate_limit.max(1)));
    let input_handle = tokio::spawn(async move {
        if let Some(permits) = input_permits {
            write_paced_modbus_input(stdin, input, ready_receiver, permits, gap).await
        } else {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await
        }
    });
    let mut reader = BufReader::new(stdout);
    let mut line_buffer = Vec::new();
    let mut last_progress = Instant::now();
    let mut progress = tokio::time::interval(Duration::from_secs(30));
    progress.tick().await;
    let mut output_bytes = 0usize;
    let mut results = Vec::new();
    let mut invalid_lines = 0usize;
    let mut previous_in_flight = 0usize;
    let in_flight = || {
        permits.as_ref().map(|permits| {
            (config.senders.max(1) as usize).saturating_sub(permits.available_permits())
        })
    };
    let idle_timeout = Duration::from_secs(config.idle_timeout_seconds);

    loop {
        if cancel_requested.load(Ordering::Relaxed) {
            tracing::debug!(process_id = ?child.id(), "stopping zgrab2 after cancellation request");
            let _ = child.kill().await;
            let _ = child.wait().await;
            input_handle.abort();
            let _ = finish_zgrab_stderr(stderr_handle).await;
            return Ok(ProcessOutcome::Cancelled);
        }

        let current_in_flight = in_flight();
        if let Some(current) = current_in_flight {
            // A new probe starts a fresh idle interval after a paced pause.
            if previous_in_flight == 0 && current > 0 {
                last_progress = Instant::now();
            }
            previous_in_flight = current;
        }
        // When no Modbus probes are in flight, the writer may intentionally
        // wait up to one rate-limit interval before submitting the next one.
        let pacing_grace = if current_in_flight == Some(0) && !input_handle.is_finished() {
            gap
        } else {
            Duration::ZERO
        };
        let line = tokio::select! {
            line = read_bounded_line(&mut reader, &mut line_buffer, config.max_result_bytes.saturating_mul(32).clamp(65536, 8*1024*1024)) => match line {
                Ok(line) => line,
                Err(error) => {
                    let _ = child.kill().await;
                    input_handle.abort();
                    let _ = finish_zgrab_stderr(stderr_handle).await;
                    return Err(error.into());
                }
            },
            _ = sleep(deadline.saturating_duration_since(Instant::now())) => {
                let _ = child.kill().await;
                input_handle.abort();
                let _ = finish_zgrab_stderr(stderr_handle).await;
                return Ok(ProcessOutcome::TimedOut(results, "service_detection_runtime_exceeded"));
            },
            _ = sleep((idle_timeout + pacing_grace).saturating_sub(last_progress.elapsed())) => {
                // A target can be submitted as the timer fires. Recheck before
                // killing the process so that new work gets its idle interval.
                let current = in_flight();
                if let Some(current) = current {
                    if previous_in_flight == 0 && current > 0 {
                        last_progress = Instant::now();
                    }
                    previous_in_flight = current;
                }
                let grace = if current == Some(0) && !input_handle.is_finished() {
                    gap
                } else {
                    Duration::ZERO
                };
                if last_progress.elapsed() < idle_timeout + grace {
                    continue;
                }
                let _ = child.kill().await;
                input_handle.abort();
                let _ = finish_zgrab_stderr(stderr_handle).await;
                return Ok(ProcessOutcome::TimedOut(results, "service_detection_idle_timeout"));
            },
            _ = progress.tick() => {
                tracing::info!(event="ServiceDetectionProgress", process_id=?process_id,
                    probe_count=attempts.len(), output_count=results.len(), invalid_lines,
                    output_bytes, elapsed_ms=started_at.elapsed().as_millis() as u64,
                    idle_ms=last_progress.elapsed().as_millis() as u64, "service detection progress");
                continue;
            },
            _ = sleep(Duration::from_millis(200)) => continue,
        };
        let Some(line) = line else { break };
        if let Some(permits) = &permits {
            permits.add_permits(1);
        }
        last_progress = Instant::now();
        output_bytes = output_bytes.saturating_add(line.len());
        if output_bytes > 64 * 1024 * 1024 {
            let _ = child.kill().await;
            input_handle.abort();
            let _ = finish_zgrab_stderr(stderr_handle).await;
            return Ok(ProcessOutcome::TimedOut(
                results,
                "service_detection_evidence_limit",
            ));
        }
        match parse_zgrab_line(&line, config.max_result_bytes, config_file.modbus) {
            Ok(mut parsed) => results.append(&mut parsed),
            Err(error) => {
                invalid_lines += 1;
                if invalid_lines == 1 {
                    tracing::warn!(
                        event = "Zgrab2OutputLineIgnored",
                        operation = "parse_zgrab2_output",
                        reason = %error,
                        error_code = "zgrab2_output_invalid",
                        outcome = "invalid_lines_skipped",
                        engine = "zgrab2",
                        invalid_line_count = invalid_lines,
                        "ignored invalid zgrab2 JSON output line"
                    );
                }
            }
        }
    }

    if cancel_requested.load(Ordering::Relaxed) {
        tracing::debug!(process_id = ?child.id(), "zgrab2 exited during cancellation");
        input_handle.abort();
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = finish_zgrab_stderr(stderr_handle).await;
        return Ok(ProcessOutcome::Cancelled);
    }

    let mut input_handle = input_handle;
    let finish = async {
        (&mut input_handle)
            .await
            .map_err(|error| ScannerError::Scan(format!("zgrab2 input writer failed: {error}")))?
            .map_err(|error| {
                ScannerError::Scan(format!("failed to write zgrab2 input: {error}"))
            })?;
        child.wait().await.map_err(ScannerError::Io)
    };
    let finish_result = {
        let finish = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(config.idle_timeout_seconds)),
            finish,
        );
        tokio::pin!(finish);
        loop {
            tokio::select! {
                result = &mut finish => break Some(result),
                _ = sleep(Duration::from_millis(200)) => {
                    if cancel_requested.load(Ordering::Relaxed) { break None; }
                }
            }
        }
    };
    let status = match finish_result {
        Some(Ok(result)) => result?,
        _ => {
            input_handle.abort();
            let _ = child.kill().await;
            let _ = finish_zgrab_stderr(stderr_handle).await;
            if cancel_requested.load(Ordering::Relaxed) {
                return Ok(ProcessOutcome::Cancelled);
            }
            return Ok(ProcessOutcome::TimedOut(
                results,
                "service_detection_process_exit_timeout",
            ));
        }
    };
    let stderr_output = finish_zgrab_stderr(stderr_handle).await;

    if cancel_requested.load(Ordering::Relaxed) {
        tracing::debug!(
            elapsed_ms = started_at.elapsed().as_millis(),
            "zgrab2 completed while cancellation was pending"
        );
        return Ok(ProcessOutcome::Cancelled);
    }

    let blocked = results
        .iter()
        .filter(|item| item.module == "modbus" && item.status == "blocklisted-target")
        .count();
    if blocked > 0 {
        tracing::warn!(
            event = "ModbusTargetsBlocklisted",
            error_code = "zgrab2_target_blocklisted",
            blocked_count = blocked,
            outcome = "modbus_not_identified",
            "zgrab2 blocklist prevented Modbus probes"
        );
    }

    tracing::info!(
        event = "ServiceDetectionCompleted",
        exit_code = ?status.code(),
        success = status.success(),
        elapsed_ms = started_at.elapsed().as_millis(),
        result_count = results.len(),
        invalid_lines,
        "service detection completed"
    );
    if !status.success() {
        let detail = if stderr_output.text.trim().is_empty() {
            "zgrab2 produced no stderr output"
        } else {
            stderr_output.text.trim()
        };
        return Err(ScannerError::external_process(
            "zgrab2",
            "process_exit",
            "zgrab2_nonzero_exit",
            format!("zgrab2 exited with {status}: {detail}"),
            process_id,
            status.code(),
            started_at.elapsed().as_millis() as u64,
            results.len(),
            invalid_lines,
            stderr_output.bytes,
            stderr_output.truncated,
        ));
    }

    Ok(ProcessOutcome::Completed(results))
}

async fn write_paced_modbus_input<W: AsyncWrite + Unpin>(
    mut writer: W,
    input: String,
    ready: oneshot::Receiver<()>,
    permits: Arc<Semaphore>,
    gap: Duration,
) -> std::io::Result<()> {
    // The pinned binary emits this only after its CLI and module configuration
    // have initialized. Do not build a queue while the process is starting.
    ready
        .await
        .map_err(|_| std::io::Error::other("zgrab2 did not signal startup"))?;
    let mut next = Instant::now();
    for line in input.lines() {
        tokio::time::sleep_until(next).await;
        let permit = permits
            .acquire()
            .await
            .map_err(|_| std::io::Error::other("zgrab2 input closed"))?;
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        permit.forget();
        next = Instant::now() + gap;
    }
    writer.shutdown().await
}

fn build_zgrab_input(attempts: &[ProbeAttempt]) -> String {
    let mut input = String::new();
    for attempt in attempts {
        input.push_str(&format!(
            "{},,{},{}\n",
            attempt.ip,
            attempt.probe.name(),
            attempt.port
        ));
    }
    input
}

fn parse_zgrab_line(
    line: &str,
    max_result_bytes: usize,
    modbus: Option<ModbusContext>,
) -> Result<Vec<ProbeEvidence>, ScannerError> {
    let root: Value = serde_json::from_str(line)?;
    let ip = root
        .get("ip")
        .and_then(Value::as_str)
        .ok_or_else(|| ScannerError::Scan("zgrab2 output is missing ip".into()))?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| ScannerError::Scan("zgrab2 output is missing data".into()))?;

    let mut results = Vec::new();
    for (module, module_data) in data {
        let Some(port) = module_data
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
        else {
            tracing::warn!(%ip, %module, "zgrab2 module result is missing a valid port");
            continue;
        };
        let upstream_status = module_data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let (status, detail) =
            if module == "modbus" && matches!(upstream_status, "success" | "application-error") {
                let normalized = modbus.and_then(|context| {
                    super::modbus::normalize(
                        module_data.get("result")?,
                        upstream_status,
                        context.request_id,
                        context.unit,
                    )
                });
                match normalized {
                    Some(result) => ("success", json!({"status":"success","result":result})),
                    None => (
                        "protocol-error",
                        json!({"status":"protocol-error",
                    "error":"invalid_modbus_response"}),
                    ),
                }
            } else {
                (upstream_status, module_data.clone())
            };
        let banner = (status == "success")
            .then(|| extract_banner(module_data))
            .flatten();
        results.push(ProbeEvidence {
            ip: ip.to_owned(),
            port,
            module: module.to_owned(),
            status: status.to_owned(),
            banner,
            detail: bounded_detail(&detail, max_result_bytes),
        });
    }
    Ok(results)
}

fn extract_banner(module_data: &Value) -> Option<String> {
    for pointer in [
        "/result/banner",
        "/result/server_id/raw",
        "/result/server",
        "/result/response/status_line",
    ] {
        if let Some(value) = module_data.pointer(pointer)
            && let Some(text) = banner_text(value)
        {
            return Some(strip_nul(text).chars().take(MAX_BANNER_CHARS).collect());
        }
    }
    None
}

fn banner_text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("raw").and_then(Value::as_str))
}

// 服务端 PostgreSQL 的 text/jsonb 不接受 NUL 字节（22P05），抓取到的
// 原始 banner/响应体常含 NUL，上传前必须剔除，否则服务端写库报错。
fn strip_nul(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(strip_nul(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (strip_nul(&key), sanitize_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

pub(super) fn bounded_detail(module_data: &Value, max_result_bytes: usize) -> Value {
    let mut module_data = sanitize_json_value(module_data.clone());
    let serialized_bytes = serde_json::to_vec(&module_data)
        .map(|value| value.len())
        .unwrap_or(0);
    if serialized_bytes <= max_result_bytes {
        return module_data;
    }

    // Keep the HTTP envelope (including TLS evidence) and as much of the body
    // as fits in the serialized JSON budget. Wire bytes and JSON bytes differ
    // because quotes, control characters and backslashes require escaping.
    if let Some(body) = module_data
        .pointer("/result/response/body")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        module_data["result"]["response"]["body"] = json!("");
        module_data["result"]["response"]["body_truncated"] = json!(true);
        let envelope_bytes = serde_json::to_vec(&module_data)
            .map(|value| value.len())
            .unwrap_or(usize::MAX);
        if envelope_bytes <= max_result_bytes {
            let budget = max_result_bytes - envelope_bytes;
            let mut used = 0;
            let mut end = 0;
            for (offset, character) in body.char_indices() {
                let encoded = match character {
                    '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
                    '\u{00}'..='\u{1f}' => 6,
                    _ => character.len_utf8(),
                };
                if used + encoded > budget {
                    break;
                }
                used += encoded;
                end = offset + character.len_utf8();
            }
            module_data["result"]["response"]["body"] = json!(&body[..end]);
            return module_data;
        }
    }

    let mut summary = json!({
        "status": module_data.get("status").and_then(Value::as_str).map(|s|s.chars().take(32).collect::<String>()),
        "error": module_data.get("error").and_then(Value::as_str).map(|s|s.chars().take(64).collect::<String>()),
        "truncated": true,
        "original_bytes": serialized_bytes,
        "result": {},
    });
    // A large certificate or protocol extension must not discard the small
    // platform fields needed by server-side inference. Keep original paths and
    // fit every addition to the same JSON byte budget.
    for path in [
        "/banner",
        "/server_id/raw",
        "/server_id/software",
        "/native_os",
        "/smb/native_os",
        "/session_setup/native_os",
        "/server_os",
        "/selected_protocol",
        "/failure_code",
        "/ntlm/os_version",
        "/ntlm/target_name",
        "/ntlm/netbios_computer_name",
        "/ntlm/netbios_domain_name",
        "/ntlm/dns_computer_name",
        "/ntlm/dns_domain_name",
        "/ntlm/forest_name",
    ] {
        if let Some(text) = module_data
            .pointer(&format!("/result{path}"))
            .and_then(Value::as_str)
        {
            retain_compact_field(
                &mut summary,
                path,
                json!(text.chars().take(256).collect::<String>()),
                max_result_bytes,
            );
        }
    }
    if let Some(flags) = module_data.pointer("/result/negotiation_flags") {
        retain_compact_field(
            &mut summary,
            "/negotiation_flags",
            flags.clone(),
            max_result_bytes,
        );
    }
    if let Some(headers) = module_data
        .pointer("/result/response/headers")
        .and_then(Value::as_object)
    {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("server") {
                continue;
            }
            let values: Vec<String> = if let Some(text) = value.as_str() {
                vec![text.chars().take(128).collect()]
            } else {
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(2)
                    .filter_map(Value::as_str)
                    .map(|s| s.chars().take(128).collect())
                    .collect()
            };
            retain_compact_field(
                &mut summary,
                "/response/headers/server",
                json!(values),
                max_result_bytes,
            );
        }
    }
    summary
}

fn retain_compact_field(summary: &mut Value, path: &str, value: Value, budget: usize) {
    let previous = summary.clone();
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let mut target = &mut summary["result"];
    for part in &parts[..parts.len() - 1] {
        target = &mut target[*part];
    }
    target[parts[parts.len() - 1]] = value;
    if serde_json::to_vec(&*summary).map_or(true, |bytes| bytes.len() > budget) {
        *summary = previous;
    }
}

#[derive(Clone, Copy)]
struct ModbusContext {
    request_id: u16,
    unit: u8,
}

struct TempZgrabConfig {
    path: PathBuf,
    modbus: Option<ModbusContext>,
}

impl TempZgrabConfig {
    async fn create(
        config: &ServiceDetectionConfig,
        attempts: &[ProbeAttempt],
    ) -> Result<Self, ScannerError> {
        let modbus = if attempts
            .iter()
            .any(|attempt| attempt.probe == ProbeKind::Modbus)
        {
            let mut request_id = [0; 2];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut request_id)
                .map_err(|_| ScannerError::Scan("platform random source unavailable".into()))?;
            Some(ModbusContext {
                request_id: u16::from_be_bytes(request_id),
                unit: config.probe_options.modbus_unit_id.unwrap_or(1),
            })
        } else {
            None
        };
        let path = std::env::temp_dir().join(format!(
            "network-mapping-zgrab2-{}-{}.ini",
            std::process::id(),
            Uuid::now_v7()
        ));
        tokio::fs::write(
            &path,
            zgrab_config(
                config,
                attempts.iter().map(|a| a.probe),
                modbus.map_or(0, |context| context.request_id),
            ),
        )
        .await?;
        Ok(Self { path, modbus })
    }

    fn path_string(&self) -> Result<&str, ScannerError> {
        self.path.to_str().ok_or_else(|| {
            ScannerError::Config("temporary zgrab2 config path is not valid UTF-8".into())
        })
    }
}

impl Drop for TempZgrabConfig {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                event = "Zgrab2TempConfigCleanupFailed",
                operation = "remove_zgrab2_temp_config",
                reason = %error,
                outcome = "temporary_file_retained",
                engine = "zgrab2",
                path = %self.path.display(),
                "failed to remove temporary zgrab2 config"
            );
        }
    }
}

fn zgrab_config(
    config: &ServiceDetectionConfig,
    probes: impl IntoIterator<Item = ProbeKind>,
    modbus_request_id: u16,
) -> String {
    let timeout = format!(
        "connect-timeout=\"{}s\"\ntarget-timeout=\"{}s\"\n",
        config.connect_timeout_seconds, config.target_timeout_seconds
    );
    let mut output = String::from("[Application Options]\n\n");
    let mut seen = std::collections::HashSet::new();
    for probe in probes
        .into_iter()
        .filter(|p| !p.is_native() && seen.insert(*p))
    {
        let extra = if probe == ProbeKind::Modbus {
            format!(
                "unit-id={}\nrequest-id={}\n",
                config.probe_options.modbus_unit_id.unwrap_or(1),
                modbus_request_id,
            )
        } else {
            probe.extra_config().to_owned()
        };
        output.push_str(&format!(
            "[{}]\nname=\"{}\"\ntrigger=\"{}\"\nport={}\n{timeout}{}\n",
            probe.section(),
            probe.name(),
            probe.name(),
            probe.default_port(),
            extra,
        ));
    }
    output
}

// The buffer survives select cancellation, so progress ticks cannot corrupt JSON lines.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<Option<String>> {
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            if buffer.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(std::mem::take(buffer))
                .map(Some)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
        let end = bytes.iter().position(|&b| b == b'\n').map(|p| p + 1);
        let count = end.unwrap_or(bytes.len());
        if buffer.len().saturating_add(count) > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zgrab2 output line exceeds byte limit",
            ));
        }
        buffer.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return String::from_utf8(std::mem::take(buffer))
                .map(Some)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    }
}

async fn collect_zgrab_stderr(
    mut stderr: ChildStderr,
    mut ready: Option<oneshot::Sender<()>>,
) -> StderrCapture {
    let mut capture = StderrCapture::default();
    let mut chunk = [0u8; 8192];
    let mut startup_tail = String::new();
    while let Ok(count) = stderr.read(&mut chunk).await {
        if count == 0 {
            break;
        }
        capture.bytes = capture.bytes.saturating_add(count);
        let remaining = MAX_ZGRAB_STDERR_CHARS.saturating_sub(capture.text.chars().count());
        let text = String::from_utf8_lossy(&chunk[..count]);
        if ready.is_some() {
            startup_tail.push_str(&text);
            if startup_tail.contains("started grab at") {
                if let Some(sender) = ready.take() {
                    let _ = sender.send(());
                }
            } else if startup_tail.len() > 128 {
                startup_tail = startup_tail
                    .chars()
                    .rev()
                    .take(128)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
            }
        }
        capture.text.extend(text.chars().take(remaining));
        capture.truncated |= text.chars().count() > remaining;
    }
    capture
}

async fn finish_zgrab_stderr(mut handle: JoinHandle<StderrCapture>) -> StderrCapture {
    let result = tokio::time::timeout(Duration::from_secs(5), &mut handle).await;
    if result.is_err() {
        handle.abort();
        return StderrCapture::default();
    }
    match result.unwrap_or_else(|_| unreachable!("timeout handled above")) {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!(
                event = "Zgrab2StderrReaderFailed",
                operation = "join_zgrab2_stderr_reader",
                reason = %error,
                outcome = "stderr_unavailable",
                engine = "zgrab2",
                "zgrab2 stderr reader task failed"
            );
            StderrCapture::default()
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[tokio::test]
    async fn continuous_output_cannot_extend_total_runtime_budget() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("scanner-runtime-{}", uuid::Uuid::now_v7()));
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile true; do printf '{}\n'; sleep 0.05; done\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = super::ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            max_runtime_seconds: 1,
            idle_timeout_seconds: 5,
            ..Default::default()
        };
        let outcome = super::run(
            &config,
            &[open_port("192.0.2.1", 22, "tcp")],
            "ipv4",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome,super::EngineOutcome::Partial(_,reason) if reason=="service_detection_runtime_exceeded")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn oversized_output_line_is_rejected_before_allocation() {
        let mut reader = tokio::io::BufReader::new(&b"123456789\n"[..]);
        let mut buffer = Vec::new();
        assert!(
            super::read_bounded_line(&mut reader, &mut buffer, 4)
                .await
                .is_err()
        );
        assert!(buffer.len() <= 4);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn idle_child_is_terminated_and_reports_partial_results() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("scanner-idle-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, "#!/bin/sh\nexec sleep 60\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = super::ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            idle_timeout_seconds: 1,
            max_runtime_seconds: 5,
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let outcome = super::run(
            &config,
            &[open_port("192.0.2.1", 22, "tcp")],
            "ipv4",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome,super::EngineOutcome::Partial(_,reason) if reason=="service_detection_idle_timeout")
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn closing_stdout_does_not_bypass_process_exit_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("scanner-eof-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, "#!/bin/sh\nexec 1>&-\nexec sleep 60\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = super::ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            idle_timeout_seconds: 1,
            max_runtime_seconds: 5,
            ..Default::default()
        };
        let outcome = super::run(
            &config,
            &[open_port("192.0.2.1", 22, "tcp")],
            "ipv4",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome,super::EngineOutcome::Partial(_,reason) if reason=="service_detection_process_exit_timeout")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn exhausted_checkpoint_budget_does_not_spawn_another_child() {
        let path = std::env::temp_dir().join(format!("scanner-budget-{}", uuid::Uuid::now_v7()));
        let store = crate::storage::StateStore::open(path.clone()).unwrap();
        let key = format!("{}|config", uuid::Uuid::now_v7());
        store
            .save_checkpoint("origin", &key, 1, 0, 1000, None)
            .unwrap();
        let mut journal = crate::journal::ScanJournal::open(&store, "origin", key).unwrap();
        let config = super::ServiceDetectionConfig {
            zgrab_path: "/missing/binary".into(),
            max_runtime_seconds: 1,
            ..Default::default()
        };
        let outcome = super::run_with_journal(
            &config,
            &[open_port("192.0.2.1", 22, "tcp")],
            "ipv4",
            &std::sync::atomic::AtomicBool::new(false),
            Some(&mut journal),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome,super::EngineOutcome::Partial(_,reason) if reason=="service_detection_runtime_exceeded")
        );
        drop(journal);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    use super::*;
    use std::sync::atomic::AtomicBool;

    fn open_port(ip: &str, port: u16, protocol: &str) -> PortObservation {
        PortObservation {
            ip: ip.into(),
            port,
            protocol: protocol.into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at: 1,
        }
    }

    #[test]
    fn input_tags_each_probe_and_overrides_its_port() {
        let input = build_zgrab_input(&[
            ProbeAttempt {
                ip: "192.0.2.1".into(),
                port: 2222,
                probe: ProbeKind::Ssh,
            },
            ProbeAttempt {
                ip: "2001:db8::1".into(),
                port: 10443,
                probe: ProbeKind::Https,
            },
        ]);
        assert_eq!(input, "192.0.2.1,,ssh,2222\n2001:db8::1,,https,10443\n");
    }

    #[test]
    fn successful_http_result_is_normalized() {
        let line = r#"{"ip":"192.0.2.1","data":{"http":{"status":"success","protocol":"http","port":8080,"result":{"response":{"status_line":"HTTP/1.1 200 OK"}}}}}"#;
        let results = parse_zgrab_line(line, 65_536, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].module, "http");
        assert_eq!(results[0].status, "success");
        assert_eq!(results[0].banner.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(results[0].detail["status"], "success");
    }

    #[test]
    fn modbus_exception_is_confirmed_only_after_response_correlation() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let context = ModbusContext {
            request_id: 0x1234,
            unit: 7,
        };
        let make_line = |raw: &[u8]| {
            json!({"ip":"192.0.2.1","data":{"modbus":{
                "status":"application-error", "port":502, "result":{"raw":STANDARD.encode(raw)}
            }}})
            .to_string()
        };
        let line = make_line(&[0x12, 0x34, 0, 0, 0, 3, 7, 0xab, 2]);
        let evidence = parse_zgrab_line(&line, 65_536, Some(context)).unwrap();
        let observations = aggregate(&evidence, &ServiceDetectionConfig::default());
        assert_eq!(observations[0].service.as_deref(), Some("modbus"));
        assert_eq!(observations[0].source, "zgrab2");
        assert_eq!(
            observations[0].data.as_ref().unwrap()["evidence"][0]["result"]["exception_code"],
            2
        );
        assert_eq!(
            observations[0].data.as_ref().unwrap()["evidence"][0]["result"]["upstream_status"],
            "application-error"
        );

        let line = make_line(&[0x12, 0x35, 0, 0, 0, 3, 7, 0xab, 2]);
        let evidence = parse_zgrab_line(&line, 65_536, Some(context)).unwrap();
        assert_eq!(evidence[0].status, "protocol-error");
        assert_eq!(
            aggregate(&evidence, &ServiceDetectionConfig::default())[0].service,
            None
        );
        assert_eq!(
            parse_zgrab_line(&line, 65_536, None).unwrap()[0].status,
            "protocol-error"
        );
    }

    #[test]
    fn failed_probe_preserves_status_and_detail() {
        let line = r#"{"ip":"192.0.2.2","data":{"ssh":{"status":"connection-timeout","protocol":"ssh","port":22,"error":"timeout"}}}"#;
        let results = parse_zgrab_line(line, 65_536, None).unwrap();
        assert_eq!(results[0].port, 22);
        assert_eq!(results[0].status, "connection-timeout");
        assert_eq!(results[0].detail["status"], "connection-timeout");
    }

    #[test]
    fn oversized_detail_is_replaced_with_summary() {
        let line = format!(
            r#"{{"ip":"192.0.2.3","data":{{"banner":{{"status":"success","protocol":"banner","port":9000,"result":{{"banner":"{}"}}}}}}}}"#,
            "x".repeat(2048)
        );
        let results = parse_zgrab_line(&line, 1024, None).unwrap();
        assert_eq!(results[0].detail["truncated"], true);
    }

    #[test]
    fn oversized_http_keeps_body_prefix_and_tls_within_json_budget() {
        for suffix in ["x", "中", "\\\"\n\u{01}"] {
            let detail = json!({
                "status": "success", "port": 443,
                "result": {
                    "response": {
                        "status_line": "HTTP/1.1 200 OK",
                        "body": format!("<title>Camera</title>{}", suffix.repeat(70_000))
                    },
                    "tls": {"handshake_log": {"server_certificates": {"subject_dn": "CN=camera"}}}
                }
            });
            let line = json!({"ip": "192.0.2.1", "data": {"https": detail}}).to_string();
            let probes = parse_zgrab_line(&line, 65_536, None).unwrap();
            let retained = &probes[0].detail;
            assert!(serde_json::to_vec(retained).unwrap().len() <= 65_536);
            assert_eq!(
                retained.pointer("/result/response/body_truncated"),
                Some(&json!(true))
            );
            assert!(
                retained
                    .pointer("/result/response/body")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .starts_with("<title>Camera</title>")
            );
            assert_eq!(
                retained.pointer("/result/tls"),
                detail.pointer("/result/tls")
            );
            let observations = aggregate(&probes, &ServiceDetectionConfig::default());
            assert_eq!(observations[0].service.as_deref(), Some("https"));
            assert_eq!(
                observations[0].data.as_ref().unwrap()["evidence"][0]["truncated"],
                true
            );
            assert_eq!(
                observations[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .pointer("/evidence/0/result/response/body_truncated"),
                Some(&json!(true))
            );
        }
    }

    #[test]
    fn http_envelope_exceeding_budget_still_reports_truncation() {
        let detail = json!({"status": "success", "result": {"response": {
            "body": "<title>Camera</title>", "headers": {"large": "x".repeat(2048)}
        }}});
        let bounded = bounded_detail(&detail, 1024);
        assert_eq!(bounded["truncated"], true);
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= 1024);
    }

    #[tokio::test]
    #[ignore = "requires ZGRAB2_TEST_BINARY built at the pinned revision"]
    async fn real_zgrab_accepts_all_generated_modules() {
        let binary = std::env::var("ZGRAB2_TEST_BINARY").expect("zgrab2 binary");
        let attempts: Vec<_> = ProbeKind::ALL
            .into_iter()
            .map(|probe| ProbeAttempt {
                ip: "127.0.0.1".into(),
                port: probe.default_port(),
                probe,
            })
            .collect();
        let config = TempZgrabConfig::create(&ServiceDetectionConfig::default(), &attempts)
            .await
            .unwrap();
        let output = Command::new(binary)
            .args([
                "--blocklist-file",
                "/dev/null",
                "--input-file",
                "/dev/null",
                "--senders",
                "1",
                "multiple",
                "--config-file",
                config.path_string().unwrap(),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires ZGRAB2_TEST_BINARY built at the pinned revision"]
    async fn real_zgrab_identifies_https_when_http_also_succeeds() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::TcpListener;
        use tokio_rustls::{
            TlsAcceptor,
            rustls::{
                self,
                pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
            },
        };

        std::env::var("ZGRAB2_TEST_BINARY").expect("zgrab2 binary");
        let cert =
            CertificateDer::pem_slice_iter(include_bytes!("encrypted_dns_fixtures/server.pem"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("encrypted_dns_fixtures/server.key"))
                .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let plain_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tls_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_plain = plain_requests.clone();
        let server_tls = tls_requests.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let plain = server_plain.clone();
                let tls = server_tls.clone();
                tokio::spawn(async move {
                    let mut first = [0; 1];
                    if stream.peek(&mut first).await.ok() != Some(1) {
                        return;
                    }
                    let response =
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let mut request = [0; 4096];
                    if first[0] == 0x16 {
                        if let Ok(mut stream) = acceptor.accept(stream).await
                            && matches!(stream.read(&mut request).await, Ok(n) if n > 0)
                        {
                            tls.fetch_add(1, Ordering::Relaxed);
                            let _ = stream.write_all(response).await;
                        }
                    } else if matches!(stream.read(&mut request).await, Ok(n) if n > 0) {
                        plain.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.write_all(response).await;
                    }
                });
            }
        });

        let wrapper = std::env::temp_dir().join(format!("zgrab-web-test-{}", Uuid::now_v7()));
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$ZGRAB2_TEST_BINARY\" --blocklist-file /dev/null \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ServiceDetectionConfig {
            required_services: vec!["http".into(), "https".into(), "tls".into()],
            zgrab_path: wrapper.to_string_lossy().into_owned(),
            connect_timeout_seconds: 2,
            target_timeout_seconds: 5,
            ..Default::default()
        };
        let endpoint = open_port("127.0.0.1", port, "tcp");
        let attempts = initial_attempts(std::slice::from_ref(&endpoint), &config);
        let ProcessOutcome::Completed(raw) = run_attempts(
            &config,
            &attempts,
            "ipv4",
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(15),
        )
        .await
        .unwrap() else {
            panic!("raw web probes did not complete")
        };
        for module in ["http", "https", "tls"] {
            assert!(
                raw.iter()
                    .any(|e| e.module == module && e.status == "success")
            );
        }
        let outcome = run(&config, &[endpoint], "ipv4", &AtomicBool::new(false))
            .await
            .unwrap();
        server.abort();
        std::fs::remove_file(wrapper).unwrap();
        let EngineOutcome::Completed(results) = outcome else {
            panic!("web probes did not complete")
        };
        assert_eq!(plain_requests.load(Ordering::Relaxed), 2);
        assert_eq!(tls_requests.load(Ordering::Relaxed), 2);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service.as_deref(), Some("https"));
        let data = results[0].data.as_ref().unwrap();
        assert_eq!(data["attempt_count"], 3);
        assert_eq!(data["selected_probe"], "https");
        assert_eq!(data["evidence"][0]["module"], "https");
        assert_eq!(data["evidence"][1]["module"], "tls");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires ZGRAB2_TEST_BINARY built at the pinned revision"]
    async fn real_zgrab_modbus_preserves_confirmation_and_rejects_bad_frames() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::TcpListener;

        std::env::var("ZGRAB2_TEST_BINARY").expect("zgrab2 binary");
        let wrapper = std::env::temp_dir().join(format!("zgrab-modbus-test-{}", Uuid::now_v7()));
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$ZGRAB2_TEST_BINARY\" --blocklist-file /dev/null \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        for mode in ["identity", "exception", "wrong_unit", "bad_object"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 11];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[2..], &[0, 0, 0, 5, 7, 0x2b, 0x0e, 1, 0]);
                let payload: &[u8] = match mode {
                    "exception" => &[0xab, 2],
                    "bad_object" => &[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 2, b'A'],
                    _ => &[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 2, b'A', b'B'],
                };
                let mut response = request[..7].to_vec();
                response[4..6].copy_from_slice(&((payload.len() + 1) as u16).to_be_bytes());
                if mode == "wrong_unit" {
                    response[6] = 8;
                }
                response.extend_from_slice(payload);
                for byte in response {
                    stream.write_all(&[byte]).await.unwrap();
                }
            });
            let config = ServiceDetectionConfig {
                required_services: vec!["modbus".into()],
                probe_options: crate::types::ServiceProbeOptions {
                    modbus_unit_id: Some(7),
                    ..Default::default()
                },
                zgrab_path: wrapper.to_string_lossy().into_owned(),
                server_rate_limit: 1,
                idle_timeout_seconds: 1,
                target_timeout_seconds: 3,
                connect_timeout_seconds: 1,
                ..Default::default()
            };
            let outcome = run(
                &config,
                &[open_port("127.0.0.1", port, "tcp")],
                "ipv4",
                &AtomicBool::new(false),
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            let EngineOutcome::Completed(results) = outcome else {
                panic!("incomplete")
            };
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].source, "zgrab2");
            if matches!(mode, "identity" | "exception") {
                assert_eq!(results[0].service.as_deref(), Some("modbus"));
                let result = &results[0].data.as_ref().unwrap()["evidence"][0]["result"];
                if mode == "identity" {
                    assert_eq!(result["identity"]["vendor"], "AB");
                } else {
                    assert_eq!(result["exception_code"], 2);
                }
            } else {
                assert_eq!(results[0].service, None);
            }
        }

        // Exercise the idle watchdog between two real, rate-limited probes.
        let mut endpoints = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            endpoints.push(open_port(
                "127.0.0.1",
                listener.local_addr().unwrap().port(),
                "tcp",
            ));
            servers.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 11];
                stream.read_exact(&mut request).await.unwrap();
                let mut response = request[..7].to_vec();
                response[4..6].copy_from_slice(&3u16.to_be_bytes());
                response.extend_from_slice(&[0xab, 2]);
                stream.write_all(&response).await.unwrap();
            }));
        }
        let config = ServiceDetectionConfig {
            required_services: vec!["modbus".into()],
            zgrab_path: wrapper.to_string_lossy().into_owned(),
            server_rate_limit: 1,
            idle_timeout_seconds: 1,
            target_timeout_seconds: 3,
            connect_timeout_seconds: 1,
            senders: 2,
            ..Default::default()
        };
        let started = Instant::now();
        let outcome = run(&config, &endpoints, "ipv4", &AtomicBool::new(false))
            .await
            .unwrap();
        for server in servers {
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }
        let EngineOutcome::Completed(results) = outcome else {
            panic!("rate-limited Modbus probes must not hit the idle timeout")
        };
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|result| result.service.as_deref() == Some("modbus"))
        );
        assert!(started.elapsed() >= Duration::from_millis(900));
        std::fs::remove_file(wrapper).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires ZGRAB2_TEST_BINARY built at the pinned revision"]
    async fn real_zgrab_rdp_rejection_and_partial_tls_are_identified() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::TcpListener;
        std::env::var("ZGRAB2_TEST_BINARY").expect("zgrab2 binary");
        let wrapper = std::env::temp_dir().join(format!("zgrab-rdp-test-{}", Uuid::now_v7()));
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$ZGRAB2_TEST_BINARY\" --blocklist-file /dev/null \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        for partial_tls in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..2], &[3, 0]);
                let n = u16::from_be_bytes([header[2], header[3]]) as usize;
                assert!((19..=1024).contains(&n));
                let mut body = vec![0; n - 4];
                stream.read_exact(&mut body).await.unwrap();
                let mut response = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 3, 0, 8, 0, 5, 0, 0, 0];
                if partial_tls {
                    response[11] = 2;
                    response[15] = 1;
                }
                for byte in response {
                    stream.write_all(&[byte]).await.unwrap();
                }
                if partial_tls {
                    let mut tls = [0; 5];
                    stream.read_exact(&mut tls).await.unwrap();
                    assert_eq!(tls[0], 22); // TLS handshake, then fixture closes.
                }
            });
            let config = ServiceDetectionConfig {
                required_services: vec!["rdp".into()],
                zgrab_path: wrapper.to_string_lossy().into_owned(),
                target_timeout_seconds: 3,
                connect_timeout_seconds: 1,
                ..Default::default()
            };
            let outcome = run(
                &config,
                &[open_port("127.0.0.1", port, "tcp")],
                "ipv4",
                &AtomicBool::new(false),
            )
            .await
            .unwrap();
            server.await.unwrap();
            let EngineOutcome::Completed(results) = outcome else {
                panic!("incomplete");
            };
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].service.as_deref(), Some("rdp"), "{results:?}");
            assert_eq!(results[0].source, "zgrab2");
            let evidence = &results[0].data.as_ref().unwrap()["evidence"][0];
            if partial_tls {
                assert_ne!(evidence["status"], "success");
                assert_eq!(evidence["result"]["selected_protocol"], "ssl");
            } else {
                assert_eq!(
                    evidence["result"]["failure_code"],
                    "hybrid_required_by_server"
                );
            }
        }
        std::fs::remove_file(wrapper).unwrap();
    }

    #[test]
    fn oversized_rdp_retains_negotiation_and_ntlm_fields() {
        let data = json!({"status":"handshake-error","result":{"selected_protocol":"hybrid",
            "negotiation_flags":{"extended_client_data_supported":true},
            "ntlm":{"os_version":"10.0.19045","dns_computer_name":"host.example"},
            "tls":{"certificate":"x".repeat(8192)}}});
        let bounded = bounded_detail(&data, 1024);
        assert_eq!(bounded["truncated"], true);
        assert_eq!(bounded["result"]["selected_protocol"], "hybrid");
        assert_eq!(bounded["result"]["ntlm"]["os_version"], "10.0.19045");
        assert_eq!(
            bounded["result"]["negotiation_flags"]["extended_client_data_supported"],
            true
        );
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= 1024);
    }

    #[test]
    fn config_contains_only_requested_external_modules_once() {
        let config = zgrab_config(
            &ServiceDetectionConfig::default(),
            [
                ProbeKind::Http,
                ProbeKind::Http,
                ProbeKind::Rdp,
                ProbeKind::Dns,
            ],
            0,
        );
        assert_eq!(config.matches("[http]").count(), 1);
        for section in ["[dns]", "[ssh]", "[ftp]"] {
            assert!(!config.contains(section));
        }
        let all = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL, 0);
        assert!(all.contains("[rdp]"));
    }

    #[tokio::test]
    async fn modbus_config_uses_task_unit_and_per_process_request_id() {
        let config = ServiceDetectionConfig {
            probe_options: crate::types::ServiceProbeOptions {
                modbus_unit_id: Some(7),
                ..Default::default()
            },
            ..Default::default()
        };
        let attempt = ProbeAttempt {
            ip: "192.0.2.1".into(),
            port: 1502,
            probe: ProbeKind::Modbus,
        };
        let temp = TempZgrabConfig::create(&config, &[attempt]).await.unwrap();
        let context = temp.modbus.unwrap();
        let ini = tokio::fs::read_to_string(&temp.path).await.unwrap();
        assert!(ini.contains("[modbus]\nname=\"modbus\"\ntrigger=\"modbus\""));
        assert!(ini.contains("unit-id=7\n"));
        assert!(ini.contains(&format!("request-id={}\n", context.request_id)));
        assert_eq!(context.unit, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn modbus_input_waits_for_engine_and_bounds_rate_and_in_flight() {
        let (writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        let (ready, started) = oneshot::channel();
        let permits = Arc::new(Semaphore::new(2));
        let task = tokio::spawn(write_paced_modbus_input(
            writer,
            "first\nsecond\nthird\n".into(),
            started,
            permits.clone(),
            Duration::from_secs(1),
        ));
        ready.send(()).unwrap();
        tokio::task::yield_now().await;
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "first\n");
        line.clear();
        tokio::time::advance(Duration::from_secs(1)).await;
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "second\n");
        line.clear();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1), reader.read_line(&mut line))
                .await
                .is_err()
        );
        permits.add_permits(1);
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "third\n");
        task.await.unwrap().unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn modbus_task_uses_external_engine_and_normalizes_its_exception() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("fake-zgrab-modbus-{}", Uuid::now_v7()));
        std::fs::write(
            &path,
            r##"#!/usr/bin/env python3
import base64, json, sys
print('started grab at test', file=sys.stderr, flush=True)
path = sys.argv[sys.argv.index('--config-file') + 1]
config = open(path, encoding='utf-8').read().splitlines()
assert '[modbus]' in config
options = dict(line.split('=', 1) for line in config if '=' in line)
request_id = int(options['request-id'])
unit = int(options['unit-id'])
for line in sys.stdin:
    ip, _, tag, port = line.strip().split(',')
    assert tag == 'modbus'
    if ip.endswith('.2'):
        print(json.dumps({'ip': ip, 'data': {'modbus': {'status': 'blocklisted-target',
            'port': int(port)}}}), flush=True)
        continue
    raw = request_id.to_bytes(2, 'big') + b'\0\0\0\3' + bytes([unit, 0xab, 2])
    print(json.dumps({'ip': ip, 'data': {'modbus': {'status': 'application-error',
        'port': int(port), 'result': {'raw': base64.b64encode(raw).decode()}}}}), flush=True)
"##,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ServiceDetectionConfig {
            required_services: vec!["modbus".into()],
            probe_options: crate::types::ServiceProbeOptions {
                modbus_unit_id: Some(7),
                ..Default::default()
            },
            zgrab_path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let outcome = run(
            &config,
            &[
                open_port("192.0.2.1", 1502, "tcp"),
                open_port("192.0.2.2", 1502, "tcp"),
            ],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let EngineOutcome::Completed(results) = outcome else {
            panic!("incomplete")
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].service.as_deref(), Some("modbus"));
        assert_eq!(results[0].source, "zgrab2");
        let evidence = &results[0].data.as_ref().unwrap()["evidence"][0]["result"];
        assert_eq!(evidence["unit_id"], 7);
        assert_eq!(evidence["exception_code"], 2);
        assert_eq!(results[1].service, None);
        assert_eq!(results[1].source, "zgrab2");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn responsive_modbus_targets_survive_idle_timeout_during_pacing() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("paced-zgrab-{}", Uuid::now_v7()));
        std::fs::write(
            &path,
            r##"#!/usr/bin/env python3
import base64, json, sys
print('started grab at test', file=sys.stderr, flush=True)
path = sys.argv[sys.argv.index('--config-file') + 1]
options = dict(line.strip().split('=', 1) for line in open(path, encoding='utf-8') if '=' in line)
request_id, unit = int(options['request-id']), int(options['unit-id'])
for line in sys.stdin:
    ip, _, tag, port = line.strip().split(',')
    raw = request_id.to_bytes(2, 'big') + b'\0\0\0\3' + bytes([unit, 0xab, 2])
    print(json.dumps({'ip': ip, 'data': {tag: {'status': 'application-error',
        'port': int(port), 'result': {'raw': base64.b64encode(raw).decode()}}}}), flush=True)
"##,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            required_services: vec!["modbus".into()],
            server_rate_limit: 1,
            idle_timeout_seconds: 1,
            max_runtime_seconds: 5,
            ..Default::default()
        };
        let started = Instant::now();
        let outcome = run(
            &config,
            &[
                open_port("192.0.2.1", 502, "tcp"),
                open_port("192.0.2.2", 502, "tcp"),
            ],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let EngineOutcome::Completed(results) = outcome else {
            panic!("responsive Modbus targets must not hit the idle timeout")
        };
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|item| item.service.as_deref() == Some("modbus"))
        );
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stalled_modbus_engine_still_hits_idle_timeout_during_pacing() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("stalled-zgrab-{}", Uuid::now_v7()));
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf 'started grab at test\\n' >&2\nread -r line\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            required_services: vec!["modbus".into()],
            server_rate_limit: 1,
            idle_timeout_seconds: 1,
            max_runtime_seconds: 5,
            senders: 2,
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let outcome = run(
            &config,
            &[
                open_port("192.0.2.1", 502, "tcp"),
                open_port("192.0.2.2", 502, "tcp"),
                open_port("192.0.2.3", 502, "tcp"),
            ],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            matches!(outcome, EngineOutcome::Partial(_, reason) if reason == "service_detection_idle_timeout")
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn modbus_timeout_preserves_earlier_external_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("fake-zgrab-timeout-{}", Uuid::now_v7()));
        std::fs::write(
            &path,
            r##"#!/usr/bin/env python3
import json, sys, time
path = sys.argv[sys.argv.index('--config-file') + 1]
config = open(path, encoding='utf-8').read()
if '[modbus]' in config:
    print('started grab at test', file=sys.stderr, flush=True)
    sys.stdin.readline()
    time.sleep(60)
else:
    for line in sys.stdin:
        ip, _, tag, port = line.strip().split(',')
        print(json.dumps({'ip': ip, 'data': {tag: {'status': 'success', 'port': int(port),
            'result': {'banner': 'SSH-2.0-example'}}}}), flush=True)
"##,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ServiceDetectionConfig {
            zgrab_path: path.to_string_lossy().into_owned(),
            idle_timeout_seconds: 5,
            ..Default::default()
        };
        let attempts = [
            ProbeAttempt {
                ip: "192.0.2.1".into(),
                port: 22,
                probe: ProbeKind::Ssh,
            },
            ProbeAttempt {
                ip: "192.0.2.1".into(),
                port: 502,
                probe: ProbeKind::Modbus,
            },
        ];
        let outcome = run_attempts(
            &config,
            &attempts,
            "ipv4",
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let ProcessOutcome::TimedOut(evidence, reason) = outcome else {
            panic!("expected timeout")
        };
        assert_eq!(reason, "service_detection_runtime_exceeded");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].module, "ssh");
        assert_eq!(evidence[0].status, "success");
    }

    #[test]
    fn native_identity_is_safe_for_jsonb_and_obeys_result_budget() {
        let identity = json!({"result":{"identity":{"vendor":"PLC\u{0000} vendor"},
            "product_name":"device\u{0000}name"},"truncated":false});
        let clean = bounded_detail(&identity, 1024);
        assert_eq!(clean["result"]["product_name"], "devicename");
        assert_eq!(clean["result"]["identity"]["vendor"], "PLC vendor");
        let large = json!({"result":{"identity": "x".repeat(4096)},"truncated":false});
        let bounded = bounded_detail(&large, 1024);
        assert_eq!(bounded["truncated"], true);
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= 1024);
    }

    #[test]
    fn generated_config_routes_http_and_https_separately() {
        let config = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL, 0);
        assert!(config.contains("name=\"http\""));
        assert!(config.contains("name=\"https\""));
        assert!(config.contains("use-https=true"));
        assert!(config.contains("connect-timeout=\"5s\""));
    }

    #[test]
    fn generated_config_enables_implicit_tls_application_modules() {
        let config = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL, 0);
        assert!(config.contains("[smtp]\nname=\"smtps\""));
        assert!(config.contains("smtps=true"));
        assert!(config.contains("[ftp]\nname=\"ftps\""));
        assert!(config.contains("implicit-tls=true"));
        assert!(config.contains("[pop3]\nname=\"pop3s\""));
        assert!(config.contains("pop3s=true"));
        assert!(config.contains("[imap]\nname=\"imaps\""));
        assert!(config.contains("imaps=true"));
        assert!(!config.contains("[mqtt]")); // MQTT uses the bounded native CONNECT implementation.
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zgrab_process_receives_tagged_targets_and_returns_enrichment() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-fake-zgrab2-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(
            &path,
            br#"#!/bin/sh
while IFS=',' read -r ip domain tag port; do
  printf '{"ip":"%s","data":{"%s":{"status":"success","protocol":"%s","port":%s,"result":{"banner":"identified"}}}}\n' "$ip" "$tag" "$tag" "$port"
done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let config = ServiceDetectionConfig {
            enabled: true,
            zgrab_path: path.to_string_lossy().into_owned(),
            strategy: crate::types::ServiceDetectionStrategy::Standard,
            ..ServiceDetectionConfig::default()
        };
        let outcome = run(
            &config,
            &[
                open_port("192.0.2.10", 22, "tcp"),
                open_port("192.0.2.11", 8080, "tcp"),
            ],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        let EngineOutcome::Completed(results) = outcome else {
            panic!("service detection must complete");
        };
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|item| item.service.as_deref() == Some("ssh"))
        );
        assert!(
            results
                .iter()
                .any(|item| item.service.as_deref() == Some("http"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn adaptive_fallback_identifies_mysql_on_a_nonstandard_port() {
        use crate::types::ServiceDetectionStrategy;
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-fake-adaptive-zgrab2-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(
            &path,
            br#"#!/bin/sh
while IFS=',' read -r ip domain tag port; do
  if [ "$tag" = "mysql" ]; then
    status=success
  else
    status=protocol-error
  fi
  printf '{"ip":"%s","data":{"%s":{"status":"%s","protocol":"%s","port":%s,"result":{"banner":"mysql identified"}}}}\n' "$ip" "$tag" "$status" "$tag" "$port"
done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let config = ServiceDetectionConfig {
            enabled: true,
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 8,
            zgrab_path: path.to_string_lossy().into_owned(),
            ..ServiceDetectionConfig::default()
        };
        let outcome = run(
            &config,
            &[open_port("192.0.2.20", 13306, "tcp")],
            "ipv4",
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        let EngineOutcome::Completed(results) = outcome else {
            panic!("service detection must complete");
        };
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].port, 13306);
        assert_eq!(results[0].service.as_deref(), Some("mysql"));
        assert_eq!(results[0].data.as_ref().unwrap()["attempt_count"], 8);
    }

    #[test]
    fn strip_nul_removes_nul_characters() {
        assert_eq!(strip_nul("a\u{0}b\u{0}c"), "abc");
        assert_eq!(strip_nul("clean"), "clean");
    }

    #[test]
    fn bounded_detail_strips_nul_from_nested_data() {
        let module_data = json!({
            "status": "success",
            "result": {
                "response": {"body": "bin\u{0}ary"},
                "banner": "telnet\u{0}banner",
            }
        });
        let detail = bounded_detail(&module_data, 1024);
        assert_eq!(detail["result"]["response"]["body"], "binary");
        assert_eq!(detail["result"]["banner"], "telnetbanner");
    }
    #[test]
    fn oversized_handshakes_keep_platform_fields_within_budget() {
        let cases = [
            (
                json!({"server_id":{"raw":"SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu0.11"},"extensions":"x".repeat(9000)}),
                "/result/server_id/raw",
            ),
            (
                json!({"response":{"headers":{"Server":["Microsoft-IIS/10.0"]},"body":"small"},"certificate":"x".repeat(9000)}),
                "/result/response/headers/server/0",
            ),
            (
                json!({"native_os":"Windows Server 2019","extra":"x".repeat(9000)}),
                "/result/native_os",
            ),
        ];
        for (result, path) in cases {
            let detail = bounded_detail(&json!({"status":"success","result":result}), 1024);
            assert_eq!(detail["truncated"], true);
            assert!(detail.pointer(path).and_then(Value::as_str).is_some());
            assert!(serde_json::to_vec(&detail).unwrap().len() <= 1024);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn native_probe_cannot_complete_after_the_stage_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = ProbeAttempt {
            ip: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            probe: ProbeKind::Vnc,
        };
        let config = ServiceDetectionConfig {
            server_rate_limit: 1000,
            target_timeout_seconds: 10,
            ..Default::default()
        };
        for _ in 0..16 {
            let deadline = Instant::now() + Duration::from_millis(30);
            let result = run_attempts(
                &config,
                std::slice::from_ref(&a),
                "ipv4",
                &AtomicBool::new(false),
                deadline,
            )
            .await
            .unwrap();
            assert!(matches!(
                result,
                ProcessOutcome::TimedOut(_, "service_detection_runtime_exceeded")
            ));
        }
    }

    #[tokio::test]
    async fn native_probes_run_concurrently_when_an_endpoint_stalls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let (mut second, _) = listener.accept().await.unwrap();
            first.write_all(b"RFB 003.008\n").await.unwrap();
            second.write_all(b"RFB 003.008\n").await.unwrap();
        });
        let attempt = ProbeAttempt {
            ip: "127.0.0.1".into(),
            port,
            probe: ProbeKind::Vnc,
        };
        let config = ServiceDetectionConfig {
            senders: 2,
            server_rate_limit: 1000,
            target_timeout_seconds: 5,
            ..Default::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_attempts(
                &config,
                &[attempt.clone(), attempt],
                "ipv4",
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
            ),
        )
        .await
        .expect("both probes should start before either finishes")
        .unwrap();
        let ProcessOutcome::Completed(evidence) = result else {
            panic!("probes did not complete")
        };
        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().all(|item| item.status == "success"));
        server.await.unwrap();
    }
}
