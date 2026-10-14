use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

fn maintenance_enabled_by_default() -> bool {
    true
}

fn default_maintenance_retry_seconds() -> u64 {
    600
}

fn default_result_upload_grace_hours() -> u64 {
    24
}

fn default_maintenance_task_action() -> String {
    "finish_and_cache".into()
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct MaintenanceInfo {
    #[serde(default = "maintenance_enabled_by_default")]
    pub(crate) enabled: bool,
    #[serde(default, alias = "maintenance_id")]
    pub(crate) id: Option<uuid::Uuid>,
    pub(crate) phase: String,
    #[serde(default)]
    pub(crate) message: String,
    #[serde(default)]
    pub(crate) started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) expected_end_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default = "default_maintenance_retry_seconds")]
    pub(crate) retry_after_seconds: u64,
    #[serde(default = "default_maintenance_task_action")]
    pub(crate) task_action: String,
    #[serde(default = "default_result_upload_grace_hours")]
    pub(crate) result_upload_grace_hours: u64,
    #[serde(default)]
    pub(crate) revision: i64,
}

impl MaintenanceInfo {
    pub(crate) fn retry_delay(&self) -> Duration {
        Duration::from_secs(self.retry_after_seconds.clamp(60, 86_400))
    }

    pub(crate) fn result_upload_grace_ttl(&self) -> Duration {
        Duration::from_secs(
            self.result_upload_grace_hours
                .clamp(1, 24 * 7)
                .saturating_mul(60 * 60),
        )
    }
}

#[derive(Error, Debug)]
pub(crate) enum ServerError {
    #[error("{operation} paused for system maintenance: {detail}")]
    Maintenance {
        operation: &'static str,
        detail: String,
        info: Box<MaintenanceInfo>,
        request_id: Option<Uuid>,
    },

    #[error("{operation} timed out: {detail}")]
    Timeout {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} could not connect: {detail}")]
    Connect {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} transport failed: {detail}")]
    Transport {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} returned retryable status {status}: {detail}")]
    RetryableStatus {
        operation: &'static str,
        status: StatusCode,
        detail: String,
        retry_after: Option<Duration>,
        request_id: Option<Uuid>,
    },

    #[error("{operation} rejected the runtime token: {detail}")]
    AuthRejected {
        operation: &'static str,
        detail: String,
        request_id: Option<Uuid>,
    },

    #[error("{operation} was blocked by server policy: {detail}")]
    PolicyBlocked {
        operation: &'static str,
        detail: String,
        request_id: Option<Uuid>,
    },

    #[error("{operation} returned {status}: {detail}")]
    Rejected {
        operation: &'static str,
        status: StatusCode,
        detail: String,
        request_id: Option<Uuid>,
    },

    #[error("{operation} requires execution recovery: {detail}")]
    UploadIdentityConflict {
        operation: &'static str,
        detail: String,
        request_id: Option<Uuid>,
    },

    #[error("{operation} returned an invalid response: {detail}")]
    InvalidResponse {
        operation: &'static str,
        detail: String,
    },

    #[error("{operation} could not build a valid request: {detail}")]
    InvalidRequest {
        operation: &'static str,
        detail: String,
    },

    #[error("failed to build server HTTP client: {0}")]
    ClientBuild(String),
}

impl ServerError {
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::Connect { .. }
                | Self::Transport { .. }
                | Self::RetryableStatus { .. }
        )
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Maintenance { info, .. } => Some(info.retry_delay()),
            Self::RetryableStatus { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub(crate) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Maintenance { .. } => Some(StatusCode::SERVICE_UNAVAILABLE),
            Self::RetryableStatus { status, .. } | Self::Rejected { status, .. } => Some(*status),
            Self::UploadIdentityConflict { .. } => Some(StatusCode::BAD_REQUEST),
            Self::AuthRejected { .. } => Some(StatusCode::UNAUTHORIZED),
            Self::PolicyBlocked { .. } => Some(StatusCode::FORBIDDEN),
            _ => None,
        }
    }

    pub(crate) fn request_id(&self) -> Option<Uuid> {
        match self {
            Self::Maintenance { request_id, .. }
            | Self::RetryableStatus { request_id, .. }
            | Self::AuthRejected { request_id, .. }
            | Self::PolicyBlocked { request_id, .. }
            | Self::Rejected { request_id, .. }
            | Self::UploadIdentityConflict { request_id, .. } => *request_id,
            _ => None,
        }
    }

    pub(crate) fn operation(&self) -> &'static str {
        match self {
            Self::Maintenance { operation, .. }
            | Self::Timeout { operation, .. }
            | Self::Connect { operation, .. }
            | Self::Transport { operation, .. }
            | Self::RetryableStatus { operation, .. }
            | Self::AuthRejected { operation, .. }
            | Self::PolicyBlocked { operation, .. }
            | Self::Rejected { operation, .. }
            | Self::UploadIdentityConflict { operation, .. }
            | Self::InvalidResponse { operation, .. }
            | Self::InvalidRequest { operation, .. } => operation,
            Self::ClientBuild(_) => "build_server_http_client",
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Maintenance { .. } => "maintenance",
            Self::Timeout { .. } => "timeout",
            Self::Connect { .. } => "connect",
            Self::Transport { .. } => "transport",
            Self::RetryableStatus { .. } | Self::Rejected { .. } => "http_status",
            Self::UploadIdentityConflict { .. } => "upload_identity",
            Self::AuthRejected { .. } => "authentication",
            Self::PolicyBlocked { .. } => "policy",
            Self::InvalidResponse { .. } => "response_decode",
            Self::InvalidRequest { .. } => "request_build",
            Self::ClientBuild(_) => "client_build",
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Maintenance { .. } => "server_maintenance",
            Self::Timeout { .. } => "server_request_timeout",
            Self::Connect { .. } => "server_connect_failed",
            Self::Transport { .. } => "server_transport_failed",
            Self::RetryableStatus { .. } => "server_retryable_status",
            Self::AuthRejected { .. } => "runtime_token_rejected",
            Self::PolicyBlocked { .. } => "server_policy_blocked",
            Self::Rejected { .. } => "server_request_rejected",
            Self::UploadIdentityConflict { .. } => "execution_upload_id_conflict",
            Self::InvalidResponse { .. } => "invalid_server_response",
            Self::InvalidRequest { .. } => "invalid_server_request",
            Self::ClientBuild(_) => "server_http_client_build_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UploadBatchContext {
    pub(crate) scanner_id: Uuid,
    pub(crate) task_id: Uuid,
    pub(crate) upload_id: Uuid,
    pub(crate) batch_index: u32,
    pub(crate) is_final: bool,
    pub(crate) protocol_version: u16,
    pub(crate) observation_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScanFailureDiagnostics {
    pub(crate) error_kind: &'static str,
    pub(crate) error_code: &'static str,
    pub(crate) engine: Option<&'static str>,
    pub(crate) stage: Option<&'static str>,
    pub(crate) process_id: Option<u32>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) elapsed_ms: Option<u64>,
    pub(crate) result_count: Option<usize>,
    pub(crate) invalid_line_count: Option<usize>,
    pub(crate) stderr_bytes: Option<usize>,
    pub(crate) stderr_truncated: Option<bool>,
}

#[derive(Error, Debug)]
pub(crate) enum ScannerError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("SQLite state database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("{0}")]
    Toml(String),

    #[error("{0}")]
    Http(String),

    #[error("{0}")]
    Upload(String),

    #[error(
        "result upload failed for task {context_task_id}, upload {context_upload_id}, batch {context_batch_index}: {source}",
        context_task_id = .context.task_id,
        context_upload_id = .context.upload_id,
        context_batch_index = .context.batch_index,
    )]
    UploadBatch {
        context: UploadBatchContext,
        #[source]
        source: Box<ServerError>,
    },

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Scan(String),

    #[error("{engine} {stage} failed: {detail}")]
    ExternalProcess {
        engine: &'static str,
        stage: &'static str,
        code: &'static str,
        detail: String,
        process_id: Option<u32>,
        exit_code: Option<i32>,
        elapsed_ms: u64,
        result_count: usize,
        invalid_line_count: usize,
        stderr_bytes: usize,
        stderr_truncated: bool,
    },

    #[error("{engine} {stage} failed: {source}")]
    EngineStage {
        engine: &'static str,
        stage: &'static str,
        code: &'static str,
        #[source]
        source: Box<ScannerError>,
    },

    #[error(transparent)]
    Server(#[from] ServerError),
}

impl ScannerError {
    pub(crate) fn is_route_failure(&self) -> bool {
        match self {
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::HostUnreachable
            ),
            Self::EngineStage { source, .. } => source.is_route_failure(),
            // Engine stderr has no typed errno. Only explicit OS route errors
            // are recognized; generic timeouts and empty discovery never match.
            Self::ExternalProcess { detail, .. } | Self::Scan(detail) => {
                let text = detail.to_ascii_lowercase();
                [
                    "network is unreachable",
                    "no route to host",
                    "cannot assign requested address",
                ]
                .iter()
                .any(|reason| text.contains(reason))
            }
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn external_process(
        engine: &'static str,
        stage: &'static str,
        code: &'static str,
        detail: String,
        process_id: Option<u32>,
        exit_code: Option<i32>,
        elapsed_ms: u64,
        result_count: usize,
        invalid_line_count: usize,
        stderr_bytes: usize,
        stderr_truncated: bool,
    ) -> Self {
        Self::ExternalProcess {
            engine,
            stage,
            code,
            detail,
            process_id,
            exit_code,
            elapsed_ms,
            result_count,
            invalid_line_count,
            stderr_bytes,
            stderr_truncated,
        }
    }

    pub(crate) fn engine_stage(
        engine: &'static str,
        stage: &'static str,
        code: &'static str,
        source: ScannerError,
    ) -> Self {
        Self::EngineStage {
            engine,
            stage,
            code,
            source: Box::new(source),
        }
    }

    pub(crate) fn scan_diagnostics(&self) -> ScanFailureDiagnostics {
        match self {
            Self::ExternalProcess {
                engine,
                stage,
                code,
                process_id,
                exit_code,
                elapsed_ms,
                result_count,
                invalid_line_count,
                stderr_bytes,
                stderr_truncated,
                ..
            } => ScanFailureDiagnostics {
                error_kind: "external_process",
                error_code: code,
                engine: Some(engine),
                stage: Some(stage),
                process_id: *process_id,
                exit_code: *exit_code,
                elapsed_ms: Some(*elapsed_ms),
                result_count: Some(*result_count),
                invalid_line_count: Some(*invalid_line_count),
                stderr_bytes: Some(*stderr_bytes),
                stderr_truncated: Some(*stderr_truncated),
            },
            Self::EngineStage {
                engine,
                stage,
                code,
                source,
            } => {
                let source_diagnostics = source.scan_diagnostics();
                if source_diagnostics.engine.is_some() {
                    source_diagnostics
                } else {
                    ScanFailureDiagnostics {
                        error_kind: "scan_engine",
                        error_code: code,
                        engine: Some(engine),
                        stage: Some(stage),
                        ..source_diagnostics
                    }
                }
            }
            _ => ScanFailureDiagnostics {
                error_kind: "scan",
                error_code: "scan_plan_failed",
                engine: None,
                stage: None,
                process_id: None,
                exit_code: None,
                elapsed_ms: None,
                result_count: None,
                invalid_line_count: None,
                stderr_bytes: None,
                stderr_truncated: None,
            },
        }
    }
}

impl From<toml_edit::de::Error> for ScannerError {
    fn from(e: toml_edit::de::Error) -> Self {
        Self::Toml(e.to_string())
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{ScannerError, ServerError, UploadBatchContext};
    use uuid::Uuid;

    #[test]
    fn upload_batch_error_preserves_identity_and_server_classification() {
        let context = UploadBatchContext {
            scanner_id: Uuid::now_v7(),
            task_id: Uuid::now_v7(),
            upload_id: Uuid::now_v7(),
            batch_index: 7,
            is_final: true,
            protocol_version: 3,
            observation_count: 42,
        };
        let request_id = Uuid::now_v7();
        let error = ScannerError::UploadBatch {
            context,
            source: Box::new(ServerError::Rejected {
                operation: "upload results",
                status: reqwest::StatusCode::CONFLICT,
                detail: "batch checksum conflict".into(),
                request_id: Some(request_id),
            }),
        };

        let ScannerError::UploadBatch {
            context: actual,
            source,
        } = error
        else {
            panic!("expected upload batch error");
        };
        assert_eq!(actual, context);
        assert_eq!(source.code(), "server_request_rejected");
        assert_eq!(source.request_id(), Some(request_id));
    }

    #[test]
    fn engine_stage_error_exposes_stable_scan_diagnostics() {
        let error = ScannerError::engine_stage(
            "nuclei",
            "vulnerability_detection",
            "vulnerability_detection_failed",
            ScannerError::Scan("process exited unsuccessfully".into()),
        );

        let diagnostics = error.scan_diagnostics();
        assert_eq!(diagnostics.error_kind, "scan_engine");
        assert_eq!(diagnostics.error_code, "vulnerability_detection_failed");
        assert_eq!(diagnostics.engine, Some("nuclei"));
        assert_eq!(diagnostics.stage, Some("vulnerability_detection"));
    }

    #[test]
    fn external_process_error_preserves_bounded_failure_metadata() {
        let error = ScannerError::external_process(
            "masscan",
            "process_exit",
            "masscan_nonzero_exit",
            "permission denied".into(),
            Some(42),
            Some(1),
            250,
            17,
            2,
            4_096,
            true,
        );

        let diagnostics = error.scan_diagnostics();
        assert_eq!(diagnostics.error_kind, "external_process");
        assert_eq!(diagnostics.error_code, "masscan_nonzero_exit");
        assert_eq!(diagnostics.engine, Some("masscan"));
        assert_eq!(diagnostics.stage, Some("process_exit"));
        assert_eq!(diagnostics.process_id, Some(42));
        assert_eq!(diagnostics.exit_code, Some(1));
        assert_eq!(diagnostics.elapsed_ms, Some(250));
        assert_eq!(diagnostics.result_count, Some(17));
        assert_eq!(diagnostics.invalid_line_count, Some(2));
        assert_eq!(diagnostics.stderr_bytes, Some(4_096));
        assert_eq!(diagnostics.stderr_truncated, Some(true));
    }
}
