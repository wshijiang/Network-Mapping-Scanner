use crate::error::{MaintenanceInfo, ServerError};
use crate::types::AssignedTask;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;

const USER_AGENT: &str = "Scanner/1.0";

pub(crate) enum FetchTaskOutcome {
    Task(Box<AssignedTask>),
    NoTask,
    RecoveryRequired,
}

#[derive(Clone)]
pub(crate) struct ServerHttpClient {
    client: Client,
    runtime_token: String,
    failed_operations: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<&'static str>>>,
}

impl ServerHttpClient {
    pub(crate) fn new(
        verify_tls: bool,
        runtime_token: String,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ServerError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .danger_accept_invalid_certs(!verify_tls)
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|error| ServerError::ClientBuild(error.to_string()))?;
        Ok(Self {
            client,
            runtime_token,
            failed_operations: Default::default(),
        })
    }

    pub(crate) async fn get(
        &self,
        url: &str,
        operation: &'static str,
    ) -> Result<Response, ServerError> {
        self.execute(
            self.client.get(url).bearer_auth(&self.runtime_token),
            operation,
        )
        .await
    }

    pub(crate) async fn post_json<T: Serialize + ?Sized>(
        &self,
        url: &str,
        payload: &T,
        operation: &'static str,
    ) -> Result<Response, ServerError> {
        self.execute(
            self.client
                .post(url)
                .bearer_auth(&self.runtime_token)
                .json(payload),
            operation,
        )
        .await
    }

    pub(crate) async fn post_json_with_headers<T: Serialize + ?Sized>(
        &self,
        url: &str,
        payload: &T,
        headers: HeaderMap,
        operation: &'static str,
    ) -> Result<Response, ServerError> {
        self.execute(
            self.client
                .post(url)
                .bearer_auth(&self.runtime_token)
                .headers(headers)
                .json(payload),
            operation,
        )
        .await
    }

    async fn execute(
        &self,
        request: RequestBuilder,
        operation: &'static str,
    ) -> Result<Response, ServerError> {
        let result = request
            .send()
            .await
            .map_err(|error| request_error(error, operation));
        if !operation.contains("diagnostic")
            && let Ok(mut failed) = self.failed_operations.lock()
        {
            if result
                .as_ref()
                .is_ok_and(|response| response.status().is_success())
            {
                if failed.remove(operation) {
                    tracing::info!(
                        event = "ScannerOperationRecovered",
                        operation,
                        "scanner operation recovered"
                    );
                }
            } else if result
                .as_ref()
                .map(|response| {
                    response.status().as_u16() == 429 || response.status().is_server_error()
                })
                .unwrap_or(true)
            {
                failed.insert(operation);
            }
        }
        result
    }

    pub(crate) async fn put_bytes(
        &self,
        url: &str,
        bytes: Vec<u8>,
    ) -> Result<Response, ServerError> {
        self.execute(
            self.client
                .put(url)
                .bearer_auth(&self.runtime_token)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .timeout(Duration::from_secs(60))
                .body(bytes),
            "upload diagnostic log chunk",
        )
        .await
    }
}

pub(crate) async fn fetch_task(
    client: &ServerHttpClient,
    url: &str,
) -> Result<FetchTaskOutcome, ServerError> {
    fetch_task_from_endpoint(client, url, "fetch task", true).await
}

pub(crate) async fn recover_task(
    client: &ServerHttpClient,
    url: &str,
) -> Result<FetchTaskOutcome, ServerError> {
    fetch_task_from_endpoint(client, url, "recover task", false).await
}

async fn fetch_task_from_endpoint(
    client: &ServerHttpClient,
    url: &str,
    operation: &'static str,
    conflict_requires_recovery: bool,
) -> Result<FetchTaskOutcome, ServerError> {
    tracing::debug!(url, operation, "requesting scan task");
    let response = client.get(url, operation).await?;
    let status = response.status();
    tracing::debug!(%status, operation, "task endpoint responded");

    if let Some(outcome) = task_outcome_without_body(status, conflict_requires_recovery) {
        return Ok(outcome);
    }
    match status {
        StatusCode::OK => {
            let task = response_json::<AssignedTask>(response, operation).await?;
            tracing::debug!(
                task_id = %task.task_id,
                target_count = task.task_target.len(),
                ports = %task.task_port,
                "task response decoded"
            );
            Ok(FetchTaskOutcome::Task(Box::new(task)))
        }
        _ => Err(response_error(response, operation).await),
    }
}

fn task_outcome_without_body(
    status: StatusCode,
    conflict_requires_recovery: bool,
) -> Option<FetchTaskOutcome> {
    match status {
        StatusCode::NOT_FOUND | StatusCode::NO_CONTENT => Some(FetchTaskOutcome::NoTask),
        StatusCode::CONFLICT if conflict_requires_recovery => {
            Some(FetchTaskOutcome::RecoveryRequired)
        }
        _ => None,
    }
}

pub(crate) async fn validate_credentials(
    client: &ServerHttpClient,
    url: &str,
) -> Result<(), ServerError> {
    tracing::debug!(url, "validating runtime credentials");
    let response = client.get(url, "validate credentials").await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(response_error(response, "validate credentials").await)
    }
}

pub(crate) async fn response_error(response: Response, operation: &'static str) -> ServerError {
    let status = response.status();
    let retry_after = parse_retry_after(response.headers());
    let request_id = response
        .headers()
        .get("X-Request-ID")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let maintenance_version = response
        .headers()
        .get("NM-Maintenance-Version")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response_body(response).await;
    let detail = response_detail(&body);
    if let Some(info) = parse_maintenance_response(status, maintenance_version.as_deref(), &body) {
        return ServerError::Maintenance {
            operation,
            detail,
            info: Box::new(info),
            request_id,
        };
    }
    if status == StatusCode::BAD_REQUEST
        && parse_error_code(&body).as_deref() == Some("execution_upload_id_conflict")
    {
        return ServerError::UploadIdentityConflict {
            operation,
            detail,
            request_id,
        };
    }
    classify_status(status, detail, retry_after, request_id, operation)
}

pub(crate) async fn response_json<T: DeserializeOwned>(
    response: Response,
    operation: &'static str,
) -> Result<T, ServerError> {
    // reqwest marks both body-read and JSON-deserialization failures as decode
    // errors. Read first so a broken connection remains retryable.
    let bytes = response
        .bytes()
        .await
        .map_err(|error| request_error(error, operation))?;
    serde_json::from_slice(&bytes).map_err(|error| ServerError::InvalidResponse {
        operation,
        detail: error.to_string(),
    })
}

fn request_error(error: reqwest::Error, operation: &'static str) -> ServerError {
    let detail = error.to_string();
    if error.is_builder() {
        ServerError::InvalidRequest { operation, detail }
    } else if error.is_timeout() {
        ServerError::Timeout { operation, detail }
    } else if error.is_connect() {
        ServerError::Connect { operation, detail }
    } else {
        ServerError::Transport { operation, detail }
    }
}

fn classify_status(
    status: StatusCode,
    detail: String,
    retry_after: Option<Duration>,
    request_id: Option<uuid::Uuid>,
    operation: &'static str,
) -> ServerError {
    match status {
        StatusCode::UNAUTHORIZED => ServerError::AuthRejected {
            operation,
            detail,
            request_id,
        },
        StatusCode::FORBIDDEN => ServerError::PolicyBlocked {
            operation,
            detail,
            request_id,
        },
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
            ServerError::RetryableStatus {
                operation,
                status,
                detail,
                retry_after,
                request_id,
            }
        }
        status if status.is_server_error() => ServerError::RetryableStatus {
            operation,
            status,
            detail,
            retry_after,
            request_id,
        },
        status => ServerError::Rejected {
            operation,
            status,
            detail,
            request_id,
        },
    }
}

#[derive(Deserialize)]
struct MaintenanceEnvelope {
    code: String,
    maintenance: MaintenanceInfo,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    code: String,
}

fn parse_error_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .map(|envelope| envelope.code)
}

fn parse_maintenance_response(
    status: StatusCode,
    version: Option<&str>,
    body: &[u8],
) -> Option<MaintenanceInfo> {
    if status != StatusCode::SERVICE_UNAVAILABLE || version != Some("1") {
        return None;
    }
    let envelope: MaintenanceEnvelope = serde_json::from_slice(body).ok()?;
    (envelope.code == "system_maintenance").then_some(envelope.maintenance)
}

async fn response_body(mut response: Response) -> Vec<u8> {
    const RESPONSE_BODY_LIMIT: usize = 4_096;
    let mut body = Vec::new();
    while body.len() < RESPONSE_BODY_LIMIT {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => break,
        };
        let remaining = RESPONSE_BODY_LIMIT - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    body
}

fn response_detail(body: &[u8]) -> String {
    let body = String::from_utf8_lossy(body);
    let detail: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(256)
        .collect();
    if detail.is_empty() {
        "empty response body".into()
    } else {
        detail
    }
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let retry_at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let seconds = retry_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    (seconds > 0).then(|| Duration::from_secs(seconds as u64))
}

#[cfg(test)]
mod tests {
    use super::{
        FetchTaskOutcome, ServerHttpClient, classify_status, fetch_task, parse_error_code,
        parse_maintenance_response, parse_retry_after, response_json, task_outcome_without_body,
    };
    use crate::error::ServerError;
    use reqwest::StatusCode;
    use reqwest::header::RETRY_AFTER;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn fixture_response(body: &'static str, content_length: usize) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = socket.read(&mut request).await.unwrap();
            assert!(received > 0);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n{body}"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        format!("http://{address}/")
    }

    fn test_client() -> ServerHttpClient {
        ServerHttpClient::new(
            true,
            "token".into(),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn interrupted_task_response_is_retryable_transport_error() {
        // Declaring more bytes than sent simulates a connection closing while
        // the server's successful response is still being read.
        let url = fixture_response("{\"task_id\":", 100).await;
        let error = match fetch_task(&test_client(), &url).await {
            Err(error) => error,
            Ok(_) => panic!("truncated response must fail"),
        };
        assert!(matches!(error, ServerError::Transport { .. }));
        assert!(error.is_retryable());
    }

    #[tokio::test]
    async fn complete_invalid_json_remains_a_non_retryable_protocol_error() {
        let body = "{invalid}";
        let url = fixture_response(body, body.len()).await;
        let error = match fetch_task(&test_client(), &url).await {
            Err(error) => error,
            Ok(_) => panic!("invalid response must fail"),
        };
        assert!(matches!(error, ServerError::InvalidResponse { .. }));
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn complete_json_is_deserialized_after_body_read() {
        let body = "{\"success\":true}";
        let url = fixture_response(body, body.len()).await;
        let response = test_client().get(&url, "test").await.unwrap();
        let value: serde_json::Value = response_json(response, "test").await.unwrap();
        assert_eq!(value["success"], true);
    }

    #[test]
    fn retry_after_delta_seconds_are_parsed() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(RETRY_AFTER, "17".parse().unwrap());

        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(17)));
    }

    #[test]
    fn response_statuses_have_actionable_retry_classes() {
        assert!(matches!(
            classify_status(
                StatusCode::UNAUTHORIZED,
                "bad token".into(),
                None,
                None,
                "test"
            ),
            ServerError::AuthRejected { .. }
        ));
        assert!(matches!(
            classify_status(
                StatusCode::TOO_MANY_REQUESTS,
                "slow down".into(),
                Some(Duration::from_secs(7)),
                None,
                "test"
            ),
            ServerError::RetryableStatus {
                retry_after: Some(delay),
                ..
            } if delay == Duration::from_secs(7)
        ));
        assert!(matches!(
            classify_status(
                StatusCode::CONFLICT,
                "lease lost".into(),
                None,
                None,
                "test"
            ),
            ServerError::Rejected { .. }
        ));
    }

    #[test]
    fn response_errors_preserve_server_request_id_and_stable_classification() {
        let request_id = uuid::Uuid::now_v7();
        let error = classify_status(
            StatusCode::BAD_REQUEST,
            "invalid upload".into(),
            None,
            Some(request_id),
            "upload results",
        );
        assert_eq!(error.request_id(), Some(request_id));
        assert_eq!(error.operation(), "upload results");
        assert_eq!(error.kind(), "http_status");
        assert_eq!(error.code(), "server_request_rejected");
        assert!(!error.is_retryable());
    }

    #[test]
    fn structured_upload_identity_conflict_has_a_stable_code() {
        let body = br#"{
            "success":false,
            "code":"execution_upload_id_conflict",
            "action":"recover_execution"
        }"#;
        assert_eq!(
            parse_error_code(body).as_deref(),
            Some("execution_upload_id_conflict")
        );
        assert_eq!(parse_error_code(b"plain text"), None);
    }

    #[test]
    fn maintenance_requires_versioned_structured_response() {
        let body = br#"{
            "code":"system_maintenance",
            "maintenance":{"phase":"active","message":"upgrade","retry_after_seconds":600}
        }"#;
        let info = parse_maintenance_response(StatusCode::SERVICE_UNAVAILABLE, Some("1"), body)
            .expect("valid maintenance response");
        assert!(info.enabled);
        assert_eq!(info.phase, "active");
        assert_eq!(info.retry_delay(), Duration::from_secs(600));
        assert!(parse_maintenance_response(StatusCode::SERVICE_UNAVAILABLE, None, body).is_none());
        assert!(
            parse_maintenance_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("1"),
                br#"{"code":"other"}"#,
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn malformed_urls_are_not_classified_as_transient_transport_errors() {
        let client = ServerHttpClient::new(
            true,
            "token".into(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let error = client.get(":not-a-url", "test").await.unwrap_err();
        assert!(matches!(error, ServerError::InvalidRequest { .. }));
    }

    #[test]
    fn task_statuses_preserve_recovery_before_claiming() {
        assert!(matches!(
            task_outcome_without_body(StatusCode::NO_CONTENT, false),
            Some(FetchTaskOutcome::NoTask)
        ));
        assert!(matches!(
            task_outcome_without_body(StatusCode::CONFLICT, true),
            Some(FetchTaskOutcome::RecoveryRequired)
        ));
        assert!(task_outcome_without_body(StatusCode::CONFLICT, false).is_none());
        assert!(task_outcome_without_body(StatusCode::OK, true).is_none());
        assert!(matches!(
            task_outcome_without_body(StatusCode::NOT_FOUND, false),
            Some(FetchTaskOutcome::NoTask)
        ));
    }
}
