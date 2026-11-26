use crate::error::ServerError;
use crate::http_client::{ServerHttpClient, drain_acknowledgement, response_error};
use crate::types::ScannerResultBatchUpload;

/// Uploader encapsulates the idempotent result-reporting pipeline.
pub(crate) struct Uploader {
    endpoint: String,
    client: ServerHttpClient,
}

impl Uploader {
    pub(crate) fn new(endpoint: String, client: ServerHttpClient) -> Self {
        Self { endpoint, client }
    }

    pub(crate) async fn upload(
        &self,
        payload: &ScannerResultBatchUpload<&[crate::scan::ScanObservation]>,
    ) -> Result<(), ServerError> {
        let started = std::time::Instant::now();
        tracing::debug!(
            endpoint = %self.endpoint,
            scanner_id = %payload.scanner_id,
            task_id = %payload.task_id,
            upload_id = %payload.upload_id,
            batch_index = payload.batch_index,
            is_final = payload.is_final,
            observation_count = payload.observations.len(),
            "starting result upload"
        );
        let response = self
            .client
            .post_json(&self.endpoint, payload, "upload results")
            .await?;
        let status = response.status();
        tracing::debug!(task_id = %payload.task_id, %status, "upload endpoint responded");
        if !status.is_success() {
            return Err(response_error(response, "upload results").await);
        }
        drain_acknowledgement(response, "upload results").await?;
        tracing::info!(
            event = "ResultBatchUploaded",
            elapsed_ms = started.elapsed().as_millis(),
            task_id = %payload.task_id,
            upload_id = %payload.upload_id,
            batch_index = payload.batch_index,
            is_final = payload.is_final,
            observation_count = payload.observations.len(),
            endpoint = %self.endpoint,
            "scan result batch uploaded"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read, Write};
    use std::time::Duration;

    #[tokio::test]
    async fn fragmented_acknowledgements_reuse_one_connection_for_two_batches() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = std::io::BufReader::new(socket);
            for index in 0..2 {
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(value["batch_index"], index);
                reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{")
                    .unwrap();
                // Keep part of the body off the wire until after headers arrive.
                std::thread::sleep(Duration::from_millis(25));
                reader.get_mut().write_all(b"\"success\":true}").unwrap();
            }
        });
        let client = ServerHttpClient::new(
            true,
            "test-token".into(),
            Duration::from_secs(1),
            Duration::from_secs(3),
        )
        .unwrap();
        let uploader = Uploader::new(endpoint, client);
        let mut payload = ScannerResultBatchUpload {
            protocol_version: 3,
            scanner_id: uuid::Uuid::nil(),
            task_id: uuid::Uuid::nil(),
            upload_id: uuid::Uuid::nil(),
            batch_index: 0,
            is_final: false,
            observations: &[] as &[crate::scan::ScanObservation],
        };
        uploader.upload(&payload).await.unwrap();
        payload.batch_index = 1;
        payload.is_final = true;
        uploader.upload(&payload).await.unwrap();
        server.join().unwrap();
    }
}
