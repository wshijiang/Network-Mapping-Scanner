use crate::error::ScannerError;
use crate::scan::{PortObservation, ServiceObservation, VulnerabilityObservation};
use crate::types::NucleiConfig;
use serde_json::Value;
use std::collections::BTreeSet;

#[path = "nuclei_selection.rs"]
mod selection;
use selection::{Selection, build_batches};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

const MAX_STDERR_CHARS: usize = 4_096;

#[derive(Default)]
struct StderrCapture {
    text: String,
    bytes: usize,
    truncated: bool,
}

pub(crate) enum EngineOutcome {
    Completed(Vec<VulnerabilityObservation>),
    Cancelled,
}

pub(crate) fn validate_binary(path: &str) -> Result<(), ScannerError> {
    if path.trim().is_empty() {
        return Err(ScannerError::Config("nuclei.path must not be empty".into()));
    }
    let configured = Path::new(path);
    let resolved = if configured.is_absolute() || configured.components().count() > 1 {
        configured.to_path_buf()
    } else {
        find_in_path(configured).ok_or_else(|| {
            ScannerError::Config(format!(
                "nuclei.path '{path}' was not found as an executable file in PATH"
            ))
        })?
    };
    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        ScannerError::Config(format!(
            "nuclei binary '{}' cannot be accessed: {error}",
            resolved.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ScannerError::Config(format!(
            "nuclei binary '{}' is not a file",
            resolved.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ScannerError::Config(format!(
                "nuclei binary '{}' is not executable",
                resolved.display()
            )));
        }
    }
    tracing::info!(nuclei_path = %resolved.display(), "nuclei binary validated");
    Ok(())
}

pub(crate) fn validate_templates(path: &str) -> Result<(), ScannerError> {
    let templates = Path::new(path);
    let metadata = std::fs::metadata(templates).map_err(|error| {
        ScannerError::Config(format!(
            "nuclei.templates_path '{}' cannot be accessed: {error}",
            templates.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ScannerError::Config(format!(
            "nuclei.templates_path '{}' is not a directory",
            templates.display()
        )));
    }
    tracing::info!(templates_path = %templates.display(), "nuclei template directory validated");
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

pub(crate) async fn run(
    config: &NucleiConfig,
    ports: &[PortObservation],
    services: &[ServiceObservation],
    cancel_requested: &AtomicBool,
) -> Result<EngineOutcome, ScannerError> {
    let started_at = Instant::now();
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for (selection, targets) in build_batches(ports, services, config.port_fallback) {
        if cancel_requested.load(Ordering::Relaxed) {
            return Ok(EngineOutcome::Cancelled);
        }
        match run_batch(
            config,
            &selection,
            &targets,
            cancel_requested,
            started_at,
            findings.len(),
        )
        .await?
        {
            EngineOutcome::Cancelled => return Ok(EngineOutcome::Cancelled),
            EngineOutcome::Completed(results) => {
                for finding in results {
                    let key = (
                        finding.ip.clone(),
                        finding.port,
                        finding.protocol.clone(),
                        finding.template_id.clone(),
                        finding.matcher_name.clone(),
                        finding.matched_at.clone(),
                    );
                    if seen.insert(key) {
                        findings.push(finding);
                    }
                }
            }
        }
    }
    Ok(EngineOutcome::Completed(findings))
}

// -severity would exclude the informational templates required to initialize -as.
// Permit fingerprint templates during execution, but retain only configured severities.
fn web_template_condition(severities: &[String]) -> String {
    let mut clauses = vec![
        "contains(tags, 'tech')".to_owned(),
        "contains(tags, 'detect')".to_owned(),
        "contains(tags, 'favicon')".to_owned(),
    ];
    // Use fixed tokens even if this helper is called with unvalidated configuration.
    for severity in ["info", "low", "medium", "high", "critical"] {
        if severities.iter().any(|value| value == severity) {
            clauses.push(format!("severity == '{severity}'"));
        }
    }
    clauses.join(" || ")
}

async fn run_batch(
    config: &NucleiConfig,
    selection: &Selection,
    targets: &[String],
    cancel_requested: &AtomicBool,
    started_at: Instant,
    previous_findings: usize,
) -> Result<EngineOutcome, ScannerError> {
    if started_at.elapsed() >= Duration::from_secs(config.max_runtime_seconds) {
        return Err(ScannerError::Scan(
            "nuclei stage runtime limit exceeded".into(),
        ));
    }
    let target_path = std::env::temp_dir().join(format!(
        "network-mapping-nuclei-targets-{}-{}.txt",
        std::process::id(),
        Uuid::now_v7()
    ));
    tokio::fs::write(&target_path, targets.join("\n"))
        .await
        .map_err(|error| ScannerError::Scan(format!("failed to write nuclei targets: {error}")))?;

    let mut command = Command::new(&config.path);
    command.args(selection.args());
    if matches!(selection, Selection::Web) {
        command
            .arg("-template-condition")
            .arg(web_template_condition(&config.severities));
    } else {
        command.arg("-severity").arg(config.severities.join(","));
    }
    // Automatic scan also searches the active template root, not just -templates.
    // Set both so a curated template directory remains the only source.
    command.env("NUCLEI_TEMPLATES_DIR", &config.templates_path);
    command
        .arg("-update-template-dir")
        .arg(&config.templates_path);
    command.kill_on_drop(true);
    command
        .arg("-list")
        .arg(&target_path)
        .arg("-templates")
        .arg(&config.templates_path)
        .arg("-jsonl")
        .arg("-silent")
        .arg("-no-interactsh")
        .arg("-disable-unsigned-templates")
        .arg("-disable-update-check")
        .arg("-rate-limit")
        .arg(config.rate_limit.to_string())
        .arg("-bulk-size")
        .arg(config.bulk_size.to_string())
        .arg("-concurrency")
        .arg(config.concurrency.to_string())
        .arg("-timeout")
        .arg(config.timeout_seconds.to_string())
        .arg("-retries")
        .arg(config.retries.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    tracing::info!(
        event = "VulnerabilityScanStarted",
        selection = ?selection,
        target_count = targets.len(),
        rate_limit = config.rate_limit,
        concurrency = config.concurrency,
        "starting nuclei vulnerability scan"
    );
    let mut child = match crate::process::spawn(&mut command).await {
        Ok(child) => child,
        Err(error) => {
            let _ = tokio::fs::remove_file(&target_path).await;
            return Err(ScannerError::Scan(format!(
                "failed to spawn nuclei: {error}"
            )));
        }
    };
    let process_id = child.id();
    let result = async {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ScannerError::Scan("nuclei stdout unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ScannerError::Scan("nuclei stderr unavailable".into()))?;
        let stderr_handle = tokio::spawn(collect_stderr(stderr));
        let mut lines = BufReader::new(stdout).lines();
        let mut findings = Vec::new();
        let mut invalid_lines = 0usize;

        loop {
            let timed_out = started_at.elapsed() >= Duration::from_secs(config.max_runtime_seconds);
            if cancel_requested.load(Ordering::Relaxed) || timed_out {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let stderr_output = finish_stderr(stderr_handle).await;
                let _ = tokio::fs::remove_file(&target_path).await;
                if timed_out {
                    return Err(ScannerError::external_process(
                        "nuclei",
                        "runtime_limit",
                        "nuclei_runtime_limit_exceeded",
                        format!(
                            "nuclei exceeded the {} second runtime limit",
                            config.max_runtime_seconds
                        ),
                        process_id,
                        None,
                        started_at.elapsed().as_millis() as u64,
                        findings.len(),
                        invalid_lines,
                        stderr_output.bytes,
                        stderr_output.truncated,
                    ));
                }
                return Ok(EngineOutcome::Cancelled);
            }
            let line = tokio::select! {
                line = lines.next_line() => line
                    .map_err(|error| ScannerError::Scan(format!("failed to read nuclei output: {error}")))?,
                _ = sleep(Duration::from_millis(200)) => continue,
            };
            let Some(line) = line else { break };
            if line.len() > config.max_result_bytes {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let stderr_output = finish_stderr(stderr_handle).await;
                let _ = tokio::fs::remove_file(&target_path).await;
                return Err(ScannerError::external_process(
                    "nuclei",
                    "read_stdout",
                    "nuclei_result_size_limit_exceeded",
                    "nuclei result exceeded max_result_bytes".into(),
                    process_id,
                    None,
                    started_at.elapsed().as_millis() as u64,
                    findings.len(),
                    invalid_lines,
                    stderr_output.bytes,
                    stderr_output.truncated,
                ));
            }
            match parse_result(&line) {
                Ok(finding) if config.severities.contains(&finding.severity) => {
                    findings.push(finding)
                }
                Ok(_) => {} // Automatic scan emits fingerprint findings as well.
                Err(error) => {
                    invalid_lines += 1;
                    if invalid_lines == 1 {
                        tracing::warn!(
                            event = "NucleiOutputLineIgnored",
                            operation = "parse_nuclei_output",
                            reason = %error,
                            error_code = "nuclei_output_invalid",
                            outcome = "invalid_lines_skipped",
                            engine = "nuclei",
                            invalid_line_count = invalid_lines,
                            "ignored invalid nuclei JSONL output line"
                        );
                    }
                }
            }
            if previous_findings + findings.len() > config.max_findings {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let stderr_output = finish_stderr(stderr_handle).await;
                let _ = tokio::fs::remove_file(&target_path).await;
                return Err(ScannerError::external_process(
                    "nuclei",
                    "result_limit",
                    "nuclei_finding_limit_exceeded",
                    format!("nuclei exceeded the {} finding limit", config.max_findings),
                    process_id,
                    None,
                    started_at.elapsed().as_millis() as u64,
                    findings.len(),
                    invalid_lines,
                    stderr_output.bytes,
                    stderr_output.truncated,
                ));
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|error| ScannerError::Scan(format!("failed to wait for nuclei: {error}")))?;
        let stderr_output = finish_stderr(stderr_handle).await;
        let _ = tokio::fs::remove_file(&target_path).await;
        if !status.success() {
            let detail = if stderr_output.text.trim().is_empty() {
                "nuclei produced no stderr output"
            } else {
                stderr_output.text.trim()
            };
            return Err(ScannerError::external_process(
                "nuclei",
                "process_exit",
                "nuclei_nonzero_exit",
                format!("nuclei exited with {status}: {detail}"),
                process_id,
                status.code(),
                started_at.elapsed().as_millis() as u64,
                findings.len(),
                invalid_lines,
                stderr_output.bytes,
                stderr_output.truncated,
            ));
        }
        if invalid_lines > 0 {
            return Err(ScannerError::external_process(
                "nuclei",
                "parse_output",
                "nuclei_invalid_output",
                format!("nuclei produced {invalid_lines} invalid JSONL result line(s)"),
                process_id,
                status.code(),
                started_at.elapsed().as_millis() as u64,
                findings.len(),
                invalid_lines,
                stderr_output.bytes,
                stderr_output.truncated,
            ));
        }
        tracing::info!(
            event = "VulnerabilityScanCompleted",
            elapsed_ms = started_at.elapsed().as_millis(),
            finding_count = findings.len(),
            "nuclei vulnerability scan completed"
        );
        Ok(EngineOutcome::Completed(findings))
    };
    tokio::pin!(result);
    let outcome = loop {
        tokio::select! {
            result = &mut result => break result,
            _ = sleep(Duration::from_millis(100)) => {
                if cancel_requested.load(Ordering::Relaxed) {
                    break Ok(EngineOutcome::Cancelled);
                }
                if started_at.elapsed() >= Duration::from_secs(config.max_runtime_seconds) {
                    break Err(ScannerError::Scan("nuclei stage runtime limit exceeded".into()));
                }
            }
        }
    };
    // kill_on_drop terminates the child on every early return; remove the input on errors too.
    let _ = tokio::fs::remove_file(&target_path).await;
    outcome
}

fn parse_result(line: &str) -> Result<VulnerabilityObservation, ScannerError> {
    let root: Value = serde_json::from_str(line)?;
    let info = root.get("info").unwrap_or(&Value::Null);
    let template_id = required_text(&root, "template-id")?;
    let name = required_text(info, "name")?;
    let severity = required_text(info, "severity")?.to_ascii_lowercase();
    let matched_at = required_text(&root, "matched-at")?;
    let scheme = root
        .get("scheme")
        .and_then(Value::as_str)
        .or_else(|| matched_at.split_once("://").map(|(scheme, _)| scheme))
        .unwrap_or_else(|| root.get("type").and_then(Value::as_str).unwrap_or("tcp"));
    let ip = root
        .get("ip")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| extract_host(&matched_at))
        .ok_or_else(|| ScannerError::Scan("nuclei result is missing ip".into()))?;
    let port = root
        .get("port")
        .and_then(|value| {
            value
                .as_str()
                .and_then(|value| value.parse::<u16>().ok())
                .or_else(|| value.as_u64().and_then(|value| u16::try_from(value).ok()))
        })
        .or_else(|| extract_port(&matched_at))
        .or(match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        })
        .ok_or_else(|| ScannerError::Scan("nuclei result is missing port".into()))?;
    let observed_at = root
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp_millis())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    Ok(VulnerabilityObservation {
        ip: clean_text(&ip, 253),
        port,
        protocol: clean_text(scheme, 16),
        template_id: clean_text(&template_id, 256),
        name: clean_text(&name, 512),
        severity: clean_text(&severity, 16),
        matcher_name: optional_text(&root, "matcher-name").map(|value| clean_text(&value, 256)),
        matched_at: clean_text(&matched_at, 4_096),
        description: optional_text(info, "description").map(|value| clean_text(&value, 8_192)),
        remediation: optional_text(info, "remediation").map(|value| clean_text(&value, 8_192)),
        tags: string_list(info.get("tags"), 128, 128),
        references: string_list(info.get("reference"), 64, 2_048)
            .into_iter()
            .filter(|reference| {
                reference.starts_with("https://") || reference.starts_with("http://")
            })
            .collect(),
        classification: info.get("classification").cloned(),
        extracted_results: string_list(root.get("extracted-results"), 64, 2_048),
        source: "nuclei".into(),
        observed_at,
    })
}

fn required_text(value: &Value, field: &str) -> Result<String, ScannerError> {
    optional_text(value, field)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ScannerError::Scan(format!("nuclei result is missing {field}")))
}

fn optional_text(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn string_list(value: Option<&Value>, max_items: usize, max_chars: usize) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .take(max_items)
            .map(|item| clean_text(item, max_chars))
            .collect(),
        Some(Value::String(items)) => items
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .take(max_items)
            .map(|item| clean_text(item, max_chars))
            .collect(),
        _ => Vec::new(),
    }
}

fn clean_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| *character != '\0')
        .take(max_chars)
        .collect()
}

fn extract_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split('/')
        .next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().map(str::to_owned);
    }
    Some(
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
            .to_owned(),
    )
}

fn extract_port(value: &str) -> Option<u16> {
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split('/')
        .next()?;
    if let Some((_, remainder)) = authority.rsplit_once(']') {
        return remainder.strip_prefix(':')?.parse().ok();
    }
    authority.rsplit_once(':')?.1.parse().ok()
}

async fn collect_stderr(stderr: ChildStderr) -> StderrCapture {
    let mut lines = BufReader::new(stderr).lines();
    let mut captured = String::new();
    let mut captured_chars = 0usize;
    let mut bytes = 0usize;
    let mut truncated = false;
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(line_bytes = line.len(), "nuclei stderr received");
        bytes = bytes.saturating_add(line.len()).saturating_add(1);
        if captured_chars < MAX_STDERR_CHARS {
            if !captured.is_empty() && captured_chars < MAX_STDERR_CHARS {
                captured.push('\n');
                captured_chars += 1;
            }
            let remaining = MAX_STDERR_CHARS.saturating_sub(captured_chars);
            let line_chars = line.chars().count();
            captured.extend(line.chars().take(remaining));
            captured_chars += line_chars.min(remaining);
            truncated |= line_chars > remaining;
        } else {
            truncated = true;
        }
    }
    StderrCapture {
        text: captured,
        bytes,
        truncated,
    }
}

async fn finish_stderr(handle: JoinHandle<StderrCapture>) -> StderrCapture {
    handle.await.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_filter_preserves_detection_and_restricts_vulnerability_severity() {
        assert_eq!(
            web_template_condition(&["high".into()]),
            "contains(tags, 'tech') || contains(tags, 'detect') || contains(tags, 'favicon') || severity == 'high'"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn web_batch_uses_automatic_scan_and_discards_fingerprint_findings() {
        let (dir, config) = fake_engine(
            r#"
[ "$1" = "-as" ] || exit 10
for arg in "$@"; do [ "$arg" != "-severity" ] || exit 11; done
printf '%s\n' '{"template-id":"tech","info":{"name":"tech","severity":"info"},"matched-at":"http://192.0.2.1:80","type":"http"}'
printf '%s\n' '{"template-id":"vuln","info":{"name":"vuln","severity":"high"},"matched-at":"http://192.0.2.1:80","type":"http"}'
"#,
        );
        let outcome = run_batch(
            &config,
            &Selection::Web,
            &["http://192.0.2.1:80".into()],
            &AtomicBool::new(false),
            Instant::now(),
            0,
        )
        .await
        .unwrap();
        let EngineOutcome::Completed(findings) = outcome else {
            panic!("unexpected cancellation")
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "vuln");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    fn fake_engine(script: &str) -> (PathBuf, NucleiConfig) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nuclei-test-{}", Uuid::now_v7()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("engine");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = NucleiConfig {
            path: path.to_string_lossy().into_owned(),
            templates_path: dir.to_string_lossy().into_owned(),
            ..NucleiConfig::default()
        };
        (dir, config)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn batches_pass_isolated_tags_and_enforce_total_findings() {
        let (dir, mut config) = fake_engine(
            r#"
[ "$1" = "-tags" ] || exit 10
printf '%s\n' "$2" >> "$NUCLEI_TEMPLATES_DIR/calls"
while [ "$1" != "-list" ]; do shift; done
shift
printf '%s\n' "$1" >> "$NUCLEI_TEMPLATES_DIR/inputs"
target=$(cat "$1")
printf '{"template-id":"test","info":{"name":"test","severity":"high"},"matched-at":"%s","type":"tcp"}\n' "$target"
"#,
        );
        config.max_findings = 1;
        let ports = [3306, 6379].map(|port| PortObservation {
            ip: "192.0.2.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "test".into(),
            observed_at: 0,
        });
        let error = run(&config, &ports, &[], &AtomicBool::new(false))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("finding limit"));
        assert_eq!(
            std::fs::read_to_string(dir.join("calls")).unwrap(),
            "mysql\nredis\n"
        );
        for path in std::fs::read_to_string(dir.join("inputs")).unwrap().lines() {
            assert!(!Path::new(path).exists());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_covers_child_that_closes_stdout_without_exiting() {
        let (dir, mut config) = fake_engine("exec 1>&-\nexec sleep 30");
        config.max_runtime_seconds = 1;
        let started = Instant::now();
        let result = run_batch(
            &config,
            &Selection::Web,
            &["http://192.0.2.1:80".into()],
            &AtomicBool::new(false),
            started,
            0,
        )
        .await;
        assert!(result.err().unwrap().to_string().contains("runtime limit"));
        assert!(started.elapsed() < Duration::from_secs(5));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_interrupts_running_child() {
        let (dir, config) = fake_engine("exec sleep 30");
        let cancel = AtomicBool::new(false);
        let cancel_later = async {
            sleep(Duration::from_millis(50)).await;
            cancel.store(true, Ordering::Relaxed);
        };
        let targets = ["http://192.0.2.1:80".into()];
        let (result, _) = tokio::join!(
            run_batch(
                &config,
                &Selection::Web,
                &targets,
                &cancel,
                Instant::now(),
                0
            ),
            cancel_later
        );
        assert!(matches!(result.unwrap(), EngineOutcome::Cancelled));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parses_jsonl_without_retaining_raw_request_or_response() {
        let result = parse_result(r#"{"template-id":"cve-test","info":{"name":"Example","severity":"high","tags":["cve"],"reference":["https://example.test/advisory"]},"type":"http","host":"https://192.0.2.1:8443","port":"8443","scheme":"https","matched-at":"https://192.0.2.1:8443/login","ip":"192.0.2.1","timestamp":"2026-09-03T00:00:00Z","request":"secret","response":"secret"}"#).unwrap();
        assert_eq!(result.ip, "192.0.2.1");
        assert_eq!(result.port, 8443);
        assert_eq!(result.template_id, "cve-test");
        assert_eq!(result.severity, "high");
        assert_eq!(result.tags, vec!["cve"]);
    }
}
