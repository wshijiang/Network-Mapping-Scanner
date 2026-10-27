use crate::error::ScannerError;
use crate::scan::detection::{
    ProbeAttempt, ProbeEvidence, ProbeKind, aggregate, fallback_attempts, initial_attempts,
};
use crate::scan::{PortObservation, ServiceObservation};
use crate::types::ServiceDetectionConfig;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
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
        .filter(|a| !a.probe.is_native())
        .cloned()
        .collect();
    let mut evidence = if external.is_empty() {
        Vec::new()
    } else {
        match run_zgrab_attempts(config, &external, address_family, cancel, deadline).await? {
            ProcessOutcome::Completed(e) => e,
            other => return Ok(other),
        }
    };
    let gap = Duration::from_secs_f64(1.0 / f64::from(config.server_rate_limit.max(1)));
    let mut progress = tokio::time::interval(Duration::from_secs(30));
    for attempt in attempts.iter().filter(|a| a.probe.is_native()) {
        let wait = async {
            sleep(gap).await;
            super::native::probe(attempt, config, deadline).await
        };
        tokio::pin!(wait);
        let result = loop {
            if cancel.load(Ordering::Relaxed) {
                return Ok(ProcessOutcome::Cancelled);
            }
            tokio::select! {
                result = &mut wait => break result,
                _ = progress.tick() => tracing::info!(event="ServiceDetectionProgress", completed_probes=evidence.len(), "native service probes progressing"),
                _ = sleep(Duration::from_millis(20)) => {},
                _ = tokio::time::sleep_until(deadline) => return Ok(ProcessOutcome::TimedOut(evidence, "service_detection_runtime_exceeded")),
            }
        };
        evidence.push(result);
        // The probe and scheduler timers may both become ready at the stage
        // deadline. Completion cannot turn stage expiry into a target timeout.
        if cancel.load(Ordering::Relaxed) {
            return Ok(ProcessOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(ProcessOutcome::TimedOut(
                evidence,
                "service_detection_runtime_exceeded",
            ));
        }
        if evidence.len().is_multiple_of(100) {
            tracing::info!(
                event = "ServiceDetectionProgress",
                native_probes = evidence.len(),
                "native service probes progressing"
            );
        }
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

    let input_handle = tokio::spawn(async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    });
    let stderr_handle = tokio::spawn(collect_zgrab_stderr(stderr));
    let mut reader = BufReader::new(stdout);
    let mut line_buffer = Vec::new();
    let mut last_progress = Instant::now();
    let mut progress = tokio::time::interval(Duration::from_secs(30));
    progress.tick().await;
    let mut output_bytes = 0usize;
    let mut results = Vec::new();
    let mut invalid_lines = 0usize;

    loop {
        if cancel_requested.load(Ordering::Relaxed) {
            tracing::debug!(process_id = ?child.id(), "stopping zgrab2 after cancellation request");
            let _ = child.kill().await;
            let _ = child.wait().await;
            input_handle.abort();
            let _ = finish_zgrab_stderr(stderr_handle).await;
            return Ok(ProcessOutcome::Cancelled);
        }

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
            _ = sleep(Duration::from_secs(config.idle_timeout_seconds).saturating_sub(last_progress.elapsed())) => {
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
        match parse_zgrab_line(&line, config.max_result_bytes) {
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
        let status = module_data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let banner = (status == "success")
            .then(|| extract_banner(module_data))
            .flatten();
        results.push(ProbeEvidence {
            ip: ip.to_owned(),
            port,
            module: module.to_owned(),
            status: status.to_owned(),
            banner,
            detail: bounded_detail(module_data, max_result_bytes),
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

struct TempZgrabConfig {
    path: PathBuf,
}

impl TempZgrabConfig {
    async fn create(
        config: &ServiceDetectionConfig,
        attempts: &[ProbeAttempt],
    ) -> Result<Self, ScannerError> {
        let path = std::env::temp_dir().join(format!(
            "network-mapping-zgrab2-{}-{}.ini",
            std::process::id(),
            Uuid::now_v7()
        ));
        tokio::fs::write(
            &path,
            zgrab_config(config, attempts.iter().map(|a| a.probe)),
        )
        .await?;
        Ok(Self { path })
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
        output.push_str(&format!(
            "[{}]\nname=\"{}\"\ntrigger=\"{}\"\nport={}\n{timeout}{}\n",
            probe.section(),
            probe.name(),
            probe.name(),
            probe.default_port(),
            probe.extra_config(),
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

async fn collect_zgrab_stderr(mut stderr: ChildStderr) -> StderrCapture {
    let mut capture = StderrCapture::default();
    let mut chunk = [0u8; 8192];
    while let Ok(count) = stderr.read(&mut chunk).await {
        if count == 0 {
            break;
        }
        capture.bytes = capture.bytes.saturating_add(count);
        let remaining = MAX_ZGRAB_STDERR_CHARS.saturating_sub(capture.text.chars().count());
        let text = String::from_utf8_lossy(&chunk[..count]);
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
        let results = parse_zgrab_line(line, 65_536).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].module, "http");
        assert_eq!(results[0].status, "success");
        assert_eq!(results[0].banner.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(results[0].detail["status"], "success");
    }

    #[test]
    fn failed_probe_preserves_status_and_detail() {
        let line = r#"{"ip":"192.0.2.2","data":{"ssh":{"status":"connection-timeout","protocol":"ssh","port":22,"error":"timeout"}}}"#;
        let results = parse_zgrab_line(line, 65_536).unwrap();
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
        let results = parse_zgrab_line(&line, 1024).unwrap();
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
            let probes = parse_zgrab_line(&line, 65_536).unwrap();
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
        );
        assert_eq!(config.matches("[http]").count(), 1);
        for section in ["[dns]", "[ssh]", "[ftp]"] {
            assert!(!config.contains(section));
        }
        let all = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL);
        assert!(all.contains("[rdp]"));
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
        let config = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL);
        assert!(config.contains("name=\"http\""));
        assert!(config.contains("name=\"https\""));
        assert!(config.contains("use-https=true"));
        assert!(config.contains("connect-timeout=\"5s\""));
    }

    #[test]
    fn generated_config_enables_implicit_tls_application_modules() {
        let config = zgrab_config(&ServiceDetectionConfig::default(), ProbeKind::ALL);
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
}
