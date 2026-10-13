use crate::error::ScannerError;
use crate::scan::PortObservation;
use crate::types::{MasscanConfig, MasscanOutputMode, TargetParams};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tokio::time::{Duration, sleep, timeout};

const MAX_SCANNER_STDERR_BYTES: usize = 4096;
const MAX_SCANNER_LINE_BYTES: usize = 4096;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) enum EngineOutcome {
    Completed(Vec<PortObservation>),
    Cancelled,
}

#[derive(Default)]
struct StderrCapture {
    data: Vec<u8>,
    bytes: usize,
    truncated: bool,
}

impl StderrCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// Validate that the configured scanner resolves to an executable file.
///
/// Explicit paths are checked directly. A bare command name is resolved
/// through `PATH`, matching the way `std::process::Command` locates programs.
pub(crate) fn validate_scanner_binary(scanner_path: &str) -> Result<(), ScannerError> {
    if scanner_path.trim().is_empty() {
        return Err(ScannerError::Config(
            "scanner.scanner_path must not be empty".into(),
        ));
    }

    let configured_path = Path::new(scanner_path);
    let resolved = if is_explicit_path(configured_path) {
        configured_path.to_path_buf()
    } else {
        find_in_path(configured_path).ok_or_else(|| {
            ScannerError::Config(format!(
                "scanner.scanner_path '{scanner_path}' was not found as an executable file in PATH"
            ))
        })?
    };

    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "scanner.scanner_path '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;

    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "scanner.scanner_path '{}' is not a file",
            resolved.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "scanner.scanner_path '{}' is not executable",
                resolved.display()
            )));
        }
    }

    tracing::info!(scanner_path = %resolved.display(), "scanner binary validated");
    Ok(())
}

fn is_explicit_path(path: &Path) -> bool {
    path.is_absolute() || path.components().count() > 1
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

pub(crate) async fn run(
    path: &str,
    config: &MasscanConfig,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    if cancel_requested.load(Ordering::Relaxed) {
        return Ok(EngineOutcome::Cancelled);
    }
    tracing::debug!(
        scanner_path = path,
        targets = %target.ip,
        ports = %target.port,
        rate = target.rate,
        output_mode = ?config.output_mode,
        wait_seconds = config.wait_seconds,
        max_runtime_seconds = config.max_runtime_seconds,
        banner_scan = false,
        "spawning masscan process"
    );
    let started_at = Instant::now();
    let mut child = scanner_command(path, config, target)
        .spawn()
        .map_err(|e| ScannerError::Scan(format!("failed to spawn scanner: {e}")))?;
    let process_id = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ScannerError::Scan("scanner stdout unavailable".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ScannerError::Scan("scanner stderr unavailable".into()))?;
    let mut reader = BufReader::new(stdout);
    let mut observations = CollectedPorts::default();
    let mut stderr_output = StderrCapture::default();

    // All three operations are polled together. The readers stay in this scope so
    // an early failure can still kill/reap the child and collect remaining stderr.
    let outcome = {
        let execution = async {
            let (_, _, status) = tokio::try_join!(
                collect_stdout(&mut reader, config.output_mode, &mut observations),
                collect_stderr(&mut stderr, &mut stderr_output),
                async {
                    child.wait().await.map_err(|error| ProcessFailure {
                        stage: "process_exit",
                        code: "masscan_wait_failed",
                        detail: format!("failed to wait for masscan: {error}"),
                    })
                }
            )?;
            Ok::<_, ProcessFailure>(status)
        };
        tokio::pin!(execution);
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancel_requested) => ProcessOutcome::Cancelled,
            _ = sleep(Duration::from_secs(config.max_runtime_seconds)) => {
                ProcessOutcome::Failed(ProcessFailure {
                    stage: "runtime_limit",
                    code: "masscan_runtime_limit_exceeded",
                    detail: format!("masscan exceeded the {} second runtime limit", config.max_runtime_seconds),
                })
            }
            result = &mut execution => match result {
                Ok(status) => ProcessOutcome::Exited(status),
                Err(error) => ProcessOutcome::Failed(error),
            },
        }
    };

    let outcome = if matches!(outcome, ProcessOutcome::Exited(_)) {
        outcome
    } else {
        let cleanup = stop_child(&mut child).await;
        // A descendant retaining stderr must not block cancellation indefinitely.
        let drain = timeout(
            CLEANUP_TIMEOUT,
            collect_stderr(&mut stderr, &mut stderr_output),
        )
        .await;
        if !matches!(drain, Ok(Ok(()))) {
            stderr_output.truncated = true;
            tracing::warn!(
                event = "MasscanStderrDrainIncomplete",
                "masscan stderr cleanup did not finish"
            );
        }
        match cleanup {
            Ok(()) => outcome,
            Err(detail) => ProcessOutcome::Failed(ProcessFailure {
                stage: "cleanup",
                code: "masscan_cleanup_failed",
                detail,
            }),
        }
    };

    let (status, failure) = match outcome {
        ProcessOutcome::Cancelled => {
            tracing::info!(
                event = "PortDiscoveryCancelled",
                result_count = observations.results.len(),
                "masscan cancelled"
            );
            return Ok(EngineOutcome::Cancelled);
        }
        ProcessOutcome::Failed(error) => (None, Some(error)),
        ProcessOutcome::Exited(status) if !status.success() => (
            Some(status),
            Some(ProcessFailure {
                stage: "process_exit",
                code: "masscan_nonzero_exit",
                detail: format!("masscan exited with {status}"),
            }),
        ),
        ProcessOutcome::Exited(status) => (Some(status), None),
    };
    tracing::info!(
        event = "PortDiscoveryCompleted",
        exit_code = ?status.and_then(|s| s.code()),
        success = failure.is_none(),
        elapsed_ms = started_at.elapsed().as_millis(),
        output_mode = ?config.output_mode,
        discovered_count = observations.discovered_count,
        unknown_count = observations.unknown_count,
        invalid_line_count = observations.invalid_count,
        filtered_count = observations.filtered_count,
        duplicate_count = observations.duplicate_count,
        result_count = observations.results.len(),
        "port discovery finished"
    );
    if let Some(error) = failure {
        let stderr_text = stderr_output.text();
        let detail = if stderr_text.trim().is_empty() {
            error.detail
        } else {
            format!("{}; stderr: {}", error.detail, stderr_text.trim())
        };
        return Err(ScannerError::external_process(
            "masscan",
            error.stage,
            error.code,
            detail,
            process_id,
            status.and_then(|s| s.code()),
            started_at.elapsed().as_millis() as u64,
            observations.results.len(),
            observations.invalid_count,
            stderr_output.bytes,
            stderr_output.truncated,
        ));
    }
    // A lease can be revoked just as the process/readers finish.
    if cancel_requested.load(Ordering::Relaxed) {
        return Ok(EngineOutcome::Cancelled);
    }
    Ok(EngineOutcome::Completed(observations.results))
}

fn scanner_command(path: &str, config: &MasscanConfig, target: &TargetParams) -> Command {
    let mut command = Command::new(path);
    command
        .arg(&target.ip)
        .args(["-p", &target.port])
        .args(["--rate", &target.rate.to_string()])
        .args(["--output-format", "list"])
        .args(["--output-filename", "-"]);
    if config.output_mode == MasscanOutputMode::StandardList {
        command
            .args(["--nointeractive", "--open-only"])
            .args(["--wait", &config.wait_seconds.to_string()]);
    }
    // Compatible mode intentionally retains the old fork's argument contract.
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

struct ProcessFailure {
    stage: &'static str,
    code: &'static str,
    detail: String,
}

enum ProcessOutcome {
    Exited(std::process::ExitStatus),
    Failed(ProcessFailure),
    Cancelled,
}

async fn wait_for_cancellation(cancel_requested: &AtomicBool) {
    while !cancel_requested.load(Ordering::Relaxed) {
        sleep(Duration::from_millis(100)).await;
    }
}

async fn stop_child(child: &mut Child) -> Result<(), String> {
    child
        .start_kill()
        .map_err(|e| format!("failed to stop masscan: {e}"))?;
    timeout(CLEANUP_TIMEOUT, child.wait())
        .await
        .map_err(|_| "timed out reaping masscan".to_owned())?
        .map_err(|e| format!("failed to reap masscan: {e}"))?;
    Ok(())
}

#[derive(Default)]
struct CollectedPorts {
    results: Vec<PortObservation>,
    // The boolean records whether the retained timestamp came from list output.
    endpoints: HashMap<(String, String, u16), (usize, bool)>,
    discovered_count: usize,
    duplicate_count: usize,
    invalid_count: usize,
    filtered_count: usize,
    unknown_count: usize,
}

impl CollectedPorts {
    fn insert(&mut self, observation: PortObservation, has_timestamp: bool) {
        self.discovered_count += 1;
        let key = (
            observation.ip.clone(),
            observation.protocol.clone(),
            observation.port,
        );
        if let Some(&(index, previous_has_timestamp)) = self.endpoints.get(&key) {
            self.duplicate_count += 1;
            if has_timestamp && !previous_has_timestamp {
                self.results[index] = observation;
                self.endpoints.insert(key, (index, true));
            }
        } else {
            self.endpoints
                .insert(key, (self.results.len(), has_timestamp));
            self.results.push(observation);
        }
    }
}

async fn collect_stdout<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    mode: MasscanOutputMode,
    observations: &mut CollectedPorts,
) -> Result<(), ProcessFailure> {
    let mut buffer = Vec::new();
    loop {
        let line = read_bounded_line(reader, &mut buffer)
            .await
            .map_err(|error| {
                observations.invalid_count += 1;
                ProcessFailure {
                    stage: "read_stdout",
                    code: "masscan_stdout_read_failed",
                    detail: format!("failed to read masscan output: {error}"),
                }
            })?;
        let Some(line) = line else { return Ok(()) };
        match MasscanLine::parse(&line, mode) {
            Ok(MasscanLine::Discovered(record, has_timestamp)) => {
                observations.insert(record, has_timestamp)
            }
            Ok(MasscanLine::Ignored) => {}
            Ok(MasscanLine::Filtered) => observations.filtered_count += 1,
            Ok(MasscanLine::CompletionMarker) => {
                tracing::debug!(
                    "legacy completion marker received; waiting for EOF and process exit"
                );
            }
            Ok(MasscanLine::Unknown) => {
                observations.unknown_count += 1;
                if observations.unknown_count == 1 {
                    tracing::warn!(event = "MasscanOutputLineIgnored", output_mode = ?mode, "unrecognized compatibility output line ignored");
                }
            }
            Err(detail) => {
                observations.invalid_count += 1;
                return Err(ProcessFailure {
                    stage: "parse_output",
                    code: "masscan_invalid_output",
                    detail,
                });
            }
        }
    }
}

// Keep allocations bounded even if a subprocess never emits a newline.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            if buffer.is_empty() {
                return Ok(None);
            }
            break;
        }
        let end = bytes.iter().position(|&b| b == b'\n').map(|p| p + 1);
        let count = end.unwrap_or(bytes.len());
        if buffer.len().saturating_add(count) > MAX_SCANNER_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "masscan output line exceeds 4096 bytes",
            ));
        }
        buffer.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            break;
        }
    }
    String::from_utf8(std::mem::take(buffer))
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn collect_stderr(
    stderr: &mut ChildStderr,
    capture: &mut StderrCapture,
) -> Result<(), ProcessFailure> {
    let mut chunk = [0u8; 8192];
    loop {
        let count = stderr
            .read(&mut chunk)
            .await
            .map_err(|error| ProcessFailure {
                stage: "read_stderr",
                code: "masscan_stderr_read_failed",
                detail: format!("failed to read masscan stderr: {error}"),
            })?;
        if count == 0 {
            return Ok(());
        }
        capture.bytes = capture.bytes.saturating_add(count);
        let remaining = MAX_SCANNER_STDERR_BYTES.saturating_sub(capture.data.len());
        capture
            .data
            .extend_from_slice(&chunk[..count.min(remaining)]);
        capture.truncated |= count > remaining;
    }
}

// ---- Masscan line parser ------------------------------------------------

#[derive(Debug)]
enum MasscanLine {
    Discovered(PortObservation, bool),
    Ignored,
    Filtered,
    CompletionMarker,
    Unknown,
}

impl MasscanLine {
    fn parse(line: &str, mode: MasscanOutputMode) -> Result<Self, String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(Self::Ignored);
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields[0] {
            "open" | "closed" | "up" | "unknown" => parse_list(&fields),
            "Discovered" if mode == MasscanOutputMode::Compatible => parse_discovered(&fields),
            "COMPLETE" | "DONE_OK" if mode == MasscanOutputMode::Compatible => {
                Ok(Self::CompletionMarker)
            }
            marker if marker.starts_with("ERROR") => Err(format!("masscan error marker: {line}")),
            _ if mode == MasscanOutputMode::StandardList || line.starts_with(['[', '{', '<']) => {
                Err("unexpected masscan output; expected standard list format".into())
            }
            _ => Ok(Self::Unknown),
        }
    }
}

fn parse_list(fields: &[&str]) -> Result<MasscanLine, String> {
    if fields.len() != 5 {
        return Err(
            "masscan list record must contain state, protocol, port, IP and timestamp".into(),
        );
    }
    let timestamp = fields[4]
        .parse::<i64>()
        .ok()
        .filter(|&value| value >= 0)
        .and_then(|value| value.checked_mul(1000))
        .ok_or_else(|| "invalid masscan Unix timestamp".to_owned())?;
    parse_endpoint(fields[0], fields[1], fields[2], fields[3], timestamp, true)
}

fn parse_discovered(fields: &[&str]) -> Result<MasscanLine, String> {
    let now = chrono::Utc::now().timestamp_millis();
    if fields.len() == 6 && fields[2] == "port" && fields[4] == "on" {
        let (port, protocol) = fields[3]
            .split_once('/')
            .ok_or_else(|| "invalid masscan console port/protocol".to_owned())?;
        if !matches!(fields[1], "open" | "closed") {
            return Err("invalid masscan console port state".into());
        }
        parse_endpoint(fields[1], protocol, port, fields[5], now, false)
    } else if fields.len() == 4 {
        parse_endpoint("open", fields[2], fields[1], fields[3], now, false)
    } else {
        Err("invalid masscan Discovered record".into())
    }
}

fn parse_endpoint(
    state: &str,
    protocol: &str,
    port: &str,
    ip: &str,
    observed_at: i64,
    has_timestamp: bool,
) -> Result<MasscanLine, String> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| "invalid masscan IP address".to_owned())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid masscan port".to_owned())?;
    if !matches!(protocol, "tcp" | "udp" | "sctp" | "icmp" | "arp") {
        return Err("invalid masscan protocol".into());
    }
    if state != "open" || !matches!(protocol, "tcp" | "udp") {
        return Ok(MasscanLine::Filtered);
    }
    Ok(MasscanLine::Discovered(
        PortObservation {
            ip: ip.to_string(),
            port,
            protocol: protocol.into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at,
        },
        has_timestamp,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn nonzero_scanner_exit_returns_error_with_stderr() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "scanner-rs-failing-scanner-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(
            &path,
            b"#!/bin/sh\nprintf 'args:%s\\n' \"$*\" >&2\nprintf 'permission denied by test scanner\\n' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = TargetParams {
            ip: "192.0.2.1/32".into(),
            port: "80".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let cancel_requested = AtomicBool::new(false);
        let result = run(
            path.to_str().unwrap(),
            &MasscanConfig::default(),
            &target,
            &cancel_requested,
        )
        .await;
        std::fs::remove_file(&path).unwrap();

        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("non-zero scanner exit must not be reported as completed"),
        };
        assert!(error.contains("exit status: 1"), "{error}");
        assert!(
            error.contains("permission denied by test scanner"),
            "{error}"
        );
        assert!(!error.contains("--source-port"));
    }

    #[test]
    fn validate_scanner_binary_accepts_current_executable() {
        let executable = std::env::current_exe().expect("current executable path");

        assert!(validate_scanner_binary(executable.to_str().unwrap()).is_ok());
    }

    #[test]
    fn validate_scanner_binary_rejects_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "scanner-rs-missing-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));

        let error = validate_scanner_binary(path.to_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("cannot be accessed"));
        assert!(error.to_string().contains(path.to_str().unwrap()));
    }

    #[test]
    fn validate_scanner_binary_rejects_directory() {
        let directory = std::env::temp_dir();

        let error = validate_scanner_binary(directory.to_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("is not a file"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_scanner_binary_rejects_file_without_execute_permission() {
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("scanner-rs-not-executable-{}", std::process::id()));
        std::fs::write(&path, b"not executable").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = validate_scanner_binary(path.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert!(error.to_string().contains("is not executable"));
    }

    fn record(line: &str, mode: MasscanOutputMode) -> (PortObservation, bool) {
        match MasscanLine::parse(line, mode).unwrap() {
            MasscanLine::Discovered(record, has_timestamp) => (record, has_timestamp),
            other => panic!("expected port observation, got {other:?}"),
        }
    }

    #[test]
    fn list_records_preserve_unix_time_and_normalize_ipv6() {
        let (r, has_timestamp) = record(
            "\topen  tcp  443  2001:0DB8:0:0::10  1720000000\r\n",
            MasscanOutputMode::StandardList,
        );
        assert_eq!(r.ip, "2001:db8::10");
        assert_eq!(r.port, 443);
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.observed_at, 1_720_000_000_000);
        assert_eq!(r.source, "masscan");
        assert!(has_timestamp);
        let (udp, _) = record("open udp 53 192.0.2.1 1", MasscanOutputMode::StandardList);
        assert_eq!(udp.protocol, "udp");
    }

    #[test]
    fn compatible_supports_both_console_and_modified_discovered_records() {
        for line in [
            "Discovered  80 tcp 192.0.2.1",
            "Discovered open port 80/tcp on 192.0.2.1",
        ] {
            let (r, has_timestamp) = record(line, MasscanOutputMode::Compatible);
            assert_eq!(
                (r.port, r.ip.as_str(), r.state.as_str()),
                (80, "192.0.2.1", "open")
            );
            assert!(!has_timestamp);
            assert!(r.observed_at > 0);
            assert!(MasscanLine::parse(line, MasscanOutputMode::StandardList).is_err());
        }
    }

    #[test]
    fn list_parser_distinguishes_comments_filtered_records_and_invalid_output() {
        for line in ["", " \r\n", "#masscan", "# end"] {
            assert!(matches!(
                MasscanLine::parse(line, MasscanOutputMode::StandardList),
                Ok(MasscanLine::Ignored)
            ));
        }
        for line in [
            "closed tcp 80 192.0.2.1 1",
            "up arp 0 192.0.2.1 1",
            "open sctp 80 192.0.2.1 1",
        ] {
            assert!(matches!(
                MasscanLine::parse(line, MasscanOutputMode::StandardList),
                Ok(MasscanLine::Filtered)
            ));
        }
        for line in [
            "open tcp 80 192.0.2.1",
            "open tcp 80 192.0.2.1 1 extra",
            "open tcp 65536 192.0.2.1 1",
            "open tcp x 192.0.2.1 1",
            "open tcp 80 hostname 1",
            "open bad 80 192.0.2.1 1",
            "open tcp 80 192.0.2.1 -1",
            "open tcp 80 192.0.2.1 invalid",
            "open tcp 80 192.0.2.1 9223372036854776",
            "Discovered open port invalid on 192.0.2.1",
            "Discovered open port 80/tcp on invalid",
            "Discovered 80 tcp",
            "[",
            "{\"ip\":\"192.0.2.1\"}",
            "<nmaprun>",
            "ERROR permission denied",
            "ERROR: permission denied",
        ] {
            assert!(
                MasscanLine::parse(line, MasscanOutputMode::Compatible).is_err(),
                "accepted {line}"
            );
            assert!(
                MasscanLine::parse(line, MasscanOutputMode::StandardList).is_err(),
                "accepted {line}"
            );
        }
        assert!(matches!(
            MasscanLine::parse("Starting masscan", MasscanOutputMode::Compatible),
            Ok(MasscanLine::Unknown)
        ));
        assert!(MasscanLine::parse("Starting masscan", MasscanOutputMode::StandardList).is_err());
    }

    #[test]
    fn only_exact_legacy_marker_tokens_are_recognized() {
        for line in ["COMPLETE", "DONE_OK details"] {
            assert!(matches!(
                MasscanLine::parse(line, MasscanOutputMode::Compatible),
                Ok(MasscanLine::CompletionMarker)
            ));
            assert!(MasscanLine::parse(line, MasscanOutputMode::StandardList).is_err());
        }
        assert!(matches!(
            MasscanLine::parse("COMPLETEgarbage", MasscanOutputMode::Compatible),
            Ok(MasscanLine::Unknown)
        ));
    }

    #[test]
    fn duplicate_endpoints_prefer_standard_timestamp_in_both_orders() {
        for lines in [
            [
                "Discovered open port 80/tcp on 192.0.2.1",
                "open tcp 80 192.0.2.1 1",
            ],
            ["open tcp 80 192.0.2.1 1", "Discovered 80 tcp 192.0.2.1"],
        ] {
            let mut collected = CollectedPorts::default();
            for line in lines {
                let (r, timestamp) = record(line, MasscanOutputMode::Compatible);
                collected.insert(r, timestamp);
            }
            assert_eq!(collected.results.len(), 1);
            assert_eq!(collected.results[0].observed_at, 1000);
            assert_eq!(collected.duplicate_count, 1);
        }
    }

    #[tokio::test]
    async fn reader_accepts_final_record_without_newline_and_rejects_invalid_utf8() {
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(&b"open tcp 80 192.0.2.1 1"[..]);
        assert_eq!(
            read_bounded_line(&mut reader, &mut buffer)
                .await
                .unwrap()
                .unwrap(),
            "open tcp 80 192.0.2.1 1"
        );
        assert!(
            read_bounded_line(&mut reader, &mut buffer)
                .await
                .unwrap()
                .is_none()
        );
        let mut reader = BufReader::new(&b"\xff\n"[..]);
        assert!(read_bounded_line(&mut reader, &mut buffer).await.is_err());
    }

    #[cfg(unix)]
    struct TestScanner {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TestScanner {
        fn new(script: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let path =
                std::env::temp_dir().join(format!("masscan-contract-{}", uuid::Uuid::now_v7()));
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        async fn run(
            &self,
            config: &MasscanConfig,
            cancel: &AtomicBool,
        ) -> Result<EngineOutcome, ScannerError> {
            timeout(
                Duration::from_secs(8),
                super::run(
                    self.path.to_str().unwrap(),
                    config,
                    &TargetParams {
                        ip: "192.0.2.1/32".into(),
                        port: "80,443".into(),
                        rate: 100,
                        address_family: "ipv4".into(),
                    },
                    cancel,
                ),
            )
            .await
            .expect("scanner must not hang")
        }

        async fn wait_for_pid(&self) -> i32 {
            let deadline = Instant::now();
            loop {
                if let Ok(pid) = std::fs::read_to_string(self.path.with_extension("pid"))
                    && let Ok(pid) = pid.trim().parse()
                {
                    return pid;
                }
                assert!(
                    deadline.elapsed() < Duration::from_secs(3),
                    "test child did not start"
                );
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    #[cfg(unix)]
    impl Drop for TestScanner {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("pid"));
        }
    }

    fn standard_config() -> MasscanConfig {
        MasscanConfig {
            output_mode: MasscanOutputMode::StandardList,
            wait_seconds: 0,
            max_runtime_seconds: 5,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn standard_command_and_headerless_eof_work_without_modified_markers() {
        let scanner = TestScanner::new(
            r#"
[ "$*" = '192.0.2.1/32 -p 80,443 --rate 100 --output-format list --output-filename - --nointeractive --open-only --wait 0' ] || exit 9
printf '#masscan\nopen tcp 80 192.0.2.1 1720000000\nopen tcp 80 192.0.2.1 1720000001\nopen tcp 443 2001:db8::1 1720000000\n# end\n'
"#,
        );
        let EngineOutcome::Completed(results) = scanner
            .run(&standard_config(), &AtomicBool::new(false))
            .await
            .unwrap()
        else {
            panic!("must complete")
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].observed_at, 1_720_000_000_000);
        assert_eq!(results[1].ip, "2001:db8::1");
        let scanner = TestScanner::new("printf 'open tcp 80 192.0.2.1 1'");
        assert!(
            matches!(scanner.run(&standard_config(), &AtomicBool::new(false)).await.unwrap(), EngineOutcome::Completed(results) if results.len() == 1)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_arguments_and_trailing_records_after_markers_are_preserved() {
        let scanner = TestScanner::new(
            r#"
[ "$*" = '192.0.2.1/32 -p 80,443 --rate 100 --output-format list --output-filename -' ] || exit 9
printf 'Discovered 80 tcp 192.0.2.1\nCOMPLETE\nDONE_OK\n'
i=0
while [ "$i" -lt 3000 ]; do printf 'open tcp 443 192.0.2.1 1\n'; i=$((i + 1)); done
"#,
        );
        assert!(
            matches!(scanner.run(&MasscanConfig::default(), &AtomicBool::new(false)).await.unwrap(), EngineOutcome::Completed(results) if results.len() == 2)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn empty_and_comment_only_output_are_successful_zero_results() {
        for script in ["exit 0", "printf '#masscan\n# end\n'"] {
            let scanner = TestScanner::new(script);
            assert!(
                matches!(scanner.run(&standard_config(), &AtomicBool::new(false)).await.unwrap(), EngineOutcome::Completed(results) if results.is_empty())
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn damaged_output_is_an_error_even_after_valid_results() {
        for script in [
            "printf 'open tcp 80 192.0.2.1 1\nopen tcp broken 192.0.2.1 1\n'",
            "printf 'open tcp 80 192.0.2.1 1\nDONE_OK\n'",
            "printf '[\n]\n'",
            "printf '\\377\\n'",
            "i=0; while [ \"$i\" -lt 5000 ]; do printf x; i=$((i + 1)); done",
        ] {
            let scanner = TestScanner::new(script);
            let Err(ScannerError::ExternalProcess {
                code,
                invalid_line_count,
                ..
            }) = scanner
                .run(&standard_config(), &AtomicBool::new(false))
                .await
            else {
                panic!("invalid output must fail")
            };
            assert!(matches!(
                code,
                "masscan_invalid_output" | "masscan_stdout_read_failed"
            ));
            assert_eq!(invalid_line_count, 1);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nonzero_exit_keeps_partial_count_and_bounded_stderr() {
        let scanner = TestScanner::new(
            r#"
printf 'open tcp 80 192.0.2.1 1\n'
printf 'permission denied\n' >&2
i=0
while [ "$i" -lt 6000 ]; do printf 'long stderr progress\r' >&2; i=$((i + 1)); done
exit 7
"#,
        );
        let outcome = scanner
            .run(&standard_config(), &AtomicBool::new(false))
            .await;
        let Err(ScannerError::ExternalProcess {
            exit_code,
            result_count,
            stderr_bytes,
            stderr_truncated,
            detail,
            ..
        }) = outcome
        else {
            panic!("expected nonzero exit, got {outcome:?}")
        };
        assert_eq!(exit_code, Some(7));
        assert_eq!(result_count, 1);
        assert!(stderr_bytes > 100_000);
        assert!(stderr_truncated);
        assert!(detail.contains("permission denied"));
        assert!(detail.len() < 9000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fragmented_records_and_long_quiet_periods_do_not_lose_results() {
        let scanner = TestScanner::new(
            "printf 'open tcp 80 '; sleep 0.3; printf '192.0.2.1 1\\n'; sleep 0.3; printf 'open tcp 443 192.0.2.1 2\\n'",
        );
        assert!(
            matches!(scanner.run(&standard_config(), &AtomicBool::new(false)).await.unwrap(), EngineOutcome::Completed(results) if results.len() == 2)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_reaps_child_during_reading_and_after_stdout_eof() {
        for close_stdout in [false, true] {
            let scanner = TestScanner::new(&format!(
                "{}\nprintf '%s' \"$$\" > \"$0.pid\"\nexec sleep 60",
                if close_stdout {
                    "exec 1>&-"
                } else {
                    "printf 'open tcp 80 192.0.2.1 1\\n'"
                }
            ));
            let cancel = AtomicBool::new(false);
            let config = standard_config();
            let started = Instant::now();
            let (outcome, pid) = tokio::join!(scanner.run(&config, &cancel), async {
                let pid = scanner.wait_for_pid().await;
                sleep(Duration::from_millis(150)).await;
                cancel.store(true, Ordering::Relaxed);
                pid
            });
            assert!(matches!(outcome.unwrap(), EngineOutcome::Cancelled));
            assert!(started.elapsed() < Duration::from_secs(3));
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                -1,
                "cancelled child still running"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_limit_reaps_child_even_after_stdout_eof() {
        for prefix in ["exec 1>&-", "printf 'open tcp 80 192.0.2.1 1\\n'"] {
            let scanner = TestScanner::new(&format!(
                "{prefix}\nprintf '%s' \"$$\" > \"$0.pid\"\nexec sleep 60"
            ));
            let config = MasscanConfig {
                max_runtime_seconds: 1,
                ..standard_config()
            };
            let started = Instant::now();
            let Err(ScannerError::ExternalProcess { code, .. }) =
                scanner.run(&config, &AtomicBool::new(false)).await
            else {
                panic!("must time out")
            };
            assert_eq!(code, "masscan_runtime_limit_exceeded");
            assert!(started.elapsed() < Duration::from_secs(3));
            let pid: i32 = std::fs::read_to_string(scanner.path.with_extension("pid"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn error_marker_does_not_wait_for_a_stuck_process() {
        let scanner = TestScanner::new(
            "printf '%s' \"$$\" > \"$0.pid\"; printf 'ERROR failed\\n'; exec sleep 60",
        );
        let Err(ScannerError::ExternalProcess { code, .. }) = scanner
            .run(&MasscanConfig::default(), &AtomicBool::new(false))
            .await
        else {
            panic!("must fail")
        };
        assert_eq!(code, "masscan_invalid_output");
        let pid: i32 = std::fs::read_to_string(scanner.path.with_extension("pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }
}
