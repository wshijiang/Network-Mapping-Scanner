use crate::error::{ScannerError, ServerError};
use crate::http_client::{ServerHttpClient, response_error, response_json};
use std::time::Duration;

#[derive(Debug, serde::Serialize)]
struct RegisterRequest {
    scanner_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct RegisterResponse {
    runtime_token: String,
}

pub(crate) enum RegisterOutcome {
    Registered { runtime_token: String },
    Unauthorized,
}

pub(crate) async fn register(
    c_server: &str,
    c_port: i64,
    verify_tls: bool,
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
    scanner_id: &str,
    token: &str,
) -> Result<RegisterOutcome, ScannerError> {
    let url = format!("https://{}:{}/api/scanner/register", c_server, c_port);
    let body = RegisterRequest {
        scanner_id: scanner_id.to_string(),
    };

    tracing::debug!(url, scanner_id, verify_tls, "starting scanner registration");

    let client = ServerHttpClient::new(
        verify_tls,
        token.to_owned(),
        Duration::from_secs(connect_timeout_seconds),
        Duration::from_secs(request_timeout_seconds),
    )?;

    let response = client.post_json(&url, &body, "register scanner").await?;

    tracing::debug!(status = %response.status(), "registration endpoint responded");

    match response.status().as_u16() {
        200 => {
            let response: RegisterResponse = response_json(response, "register scanner").await?;
            if response.runtime_token.is_empty() {
                return Err(ServerError::InvalidResponse {
                    operation: "register scanner",
                    detail: "registration response contained an empty runtime token".into(),
                }
                .into());
            }
            tracing::info!("scanner registered successfully (id={})", scanner_id);
            Ok(RegisterOutcome::Registered {
                runtime_token: response.runtime_token,
            })
        }
        401 => {
            tracing::warn!("registration rejected: invalid credentials (401)");
            Ok(RegisterOutcome::Unauthorized)
        }
        _ => Err(response_error(response, "register scanner").await.into()),
    }
}
