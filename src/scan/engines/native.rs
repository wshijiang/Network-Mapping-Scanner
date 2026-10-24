//! Bounded application confirmation for protocols not delegated to zgrab2.
use crate::scan::detection::{ProbeAttempt, ProbeEvidence, ProbeKind};
use crate::types::ServiceDetectionConfig;
use crate::udp_probe::{Request, UdpService};
use serde_json::{Value, json};
use std::{io, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, timeout_at};

pub(crate) async fn probe(
    attempt: &ProbeAttempt,
    config: &ServiceDetectionConfig,
    stage_deadline: Instant,
) -> ProbeEvidence {
    let deadline =
        stage_deadline.min(Instant::now() + Duration::from_secs(config.target_timeout_seconds));
    let response = timeout_at(deadline, async {
        if matches!(
            attempt.probe,
            ProbeKind::Dot | ProbeKind::Doh | ProbeKind::Mqtts
        ) {
            super::encrypted_dns::probe(attempt, config)
                .await
                .map(|result| (None, result))
        } else {
            handshake(attempt, config, deadline).await
        }
    })
    .await;
    let (status, banner, result) = match response {
        Ok(Ok((banner, result))) => ("success", banner, result),
        Ok(Err(error)) => (
            match error.kind() {
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => "protocol-error",
                io::ErrorKind::TimedOut => "connection-timeout",
                io::ErrorKind::PermissionDenied => "tls-error",
                _ => "connection-error",
            },
            None,
            json!({"error_code": if error.kind()==io::ErrorKind::PermissionDenied { "tls_validation_or_handshake_failed" } else { "probe_failed" }}),
        ),
        Err(_) => ("connection-timeout", None, Value::Null),
    };
    ProbeEvidence {
        ip: attempt.ip.clone(),
        port: attempt.port,
        module: attempt.probe.name().into(),
        status: status.into(),
        banner,
        detail: json!({"result":result,"truncated":false}),
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid protocol response")
}

async fn handshake(
    attempt: &ProbeAttempt,
    config: &ServiceDetectionConfig,
    deadline: Instant,
) -> io::Result<(Option<String>, Value)> {
    let address = attempt
        .ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| invalid())?
        .to_canonical();
    if attempt.port == 0
        || address.is_unspecified()
        || address.is_multicast()
        || matches!(address, std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(invalid());
    }
    let connect_deadline =
        deadline.min(Instant::now() + Duration::from_secs(config.connect_timeout_seconds));
    let mut stream = timeout_at(
        connect_deadline,
        TcpStream::connect(SocketAddr::new(address, attempt.port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
    match attempt.probe {
        ProbeKind::Modbus
        | ProbeKind::Enip
        | ProbeKind::S7
        | ProbeKind::Opcua
        | ProbeKind::Mqtt => super::industrial::handshake(&mut stream, attempt, config)
            .await
            .map(|r| (None, r)),
        ProbeKind::Dns => {
            let request = Request::new(UdpService::Dns)?;
            stream
                .write_all(&(request.bytes.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&request.bytes).await?;
            let length = stream.read_u16().await? as usize;
            if length < 12 || length > config.max_result_bytes.min(8192) {
                return Err(invalid());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            let mut result = request.identify(&bytes).ok_or_else(invalid)?;
            result["transport"] = json!("tcp");
            result["query_type"] = json!("SOA");
            Ok((None, result))
        }
        ProbeKind::Vnc => {
            // Server-first: never authenticate or enter a desktop session.
            let mut greeting = [0; 12];
            stream.read_exact(&mut greeting).await?;
            if !matches!(
                &greeting,
                b"RFB 003.003\n" | b"RFB 003.007\n" | b"RFB 003.008\n"
            ) {
                return Err(invalid());
            }
            let banner = String::from_utf8(greeting.to_vec()).map_err(|_| invalid())?;
            let version = banner[4..11].to_owned();
            Ok((
                Some(banner),
                json!({"protocol_version":version,"confirmation":"server_greeting"}),
            ))
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::net::TcpListener;

    async fn fixture(kind: ProbeKind, bad: bool) -> (ProbeEvidence, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if kind == ProbeKind::Dns {
                let length = stream.read_u16().await.unwrap();
                let mut request = vec![0; length as usize];
                stream.read_exact(&mut request).await.unwrap();
                request[2] = 0x80;
                request[3] = 5; // REFUSED still confirms the protocol, not recursive access.
                if bad {
                    request[0] ^= 1;
                }
                stream
                    .write_all(&(request.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                // Force fragmented DNS framing.
                for byte in request {
                    stream.write_all(&[byte]).await.unwrap();
                }
            } else {
                stream
                    .write_all(if bad {
                        b"HTTP/1.1 200"
                    } else {
                        b"RFB 003.008\n"
                    })
                    .await
                    .unwrap();
            }
        });
        let result = probe(
            &ProbeAttempt {
                ip: "127.0.0.1".into(),
                port: address.port(),
                probe: kind,
            },
            &ServiceDetectionConfig::default(),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        (result, server)
    }

    #[tokio::test]
    async fn dns_correlates_fragmented_errors_and_rejects_wrong_transaction() {
        for bad in [false, true] {
            let (evidence, server) = fixture(ProbeKind::Dns, bad).await;
            server.await.unwrap();
            assert_eq!(
                evidence.status,
                if bad { "protocol-error" } else { "success" }
            );
            if !bad {
                assert_eq!(evidence.detail["result"]["response_code"], 5);
            }
        }
    }

    #[tokio::test]
    async fn vnc_requires_complete_supported_rfb_greeting() {
        for bad in [false, true] {
            let (evidence, server) = fixture(ProbeKind::Vnc, bad).await;
            server.await.unwrap();
            assert_eq!(
                evidence.status,
                if bad { "protocol-error" } else { "success" }
            );
            if !bad {
                assert_eq!(evidence.detail["result"]["protocol_version"], "003.008");
            }
        }
    }

    #[tokio::test]
    async fn shared_runner_identifies_nonstandard_vnc_without_zgrab_and_cancels_stalled_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"RFB 003.003\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0); // No authentication attempt.
        });
        let config = ServiceDetectionConfig {
            required_services: vec!["vnc".into()],
            zgrab_path: "/missing/zgrab2".into(),
            ..Default::default()
        };
        let ports = [crate::scan::PortObservation {
            ip: "127.0.0.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "fixture".into(),
            observed_at: 1,
        }];
        let cancel = AtomicBool::new(false);
        let outcome = super::super::zgrab2::run(&config, &ports, "ipv4", &cancel)
            .await
            .unwrap();
        let super::super::zgrab2::EngineOutcome::Completed(results) = outcome else {
            panic!("incomplete");
        };
        assert_eq!(results[0].service.as_deref(), Some("vnc"));
        assert_eq!(results[0].source, "native");
        server.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut ports = ports;
        ports[0].port = listener.local_addr().unwrap().port();
        let task = super::super::zgrab2::run(&config, &ports, "ipv4", &cancel);
        let canceller = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        };
        let (result, _) = tokio::join!(task, canceller);
        assert!(matches!(
            result.unwrap(),
            super::super::zgrab2::EngineOutcome::Cancelled
        ));
    }
    #[tokio::test]
    #[ignore = "requires SCANNER_WORKER_TEST_BINARY built from this checkout"]
    async fn real_worker_confirms_vnc_through_checkpoint_ack_protocol() {
        use crate::modules::{
            host,
            protocol::{Outcome, Request as WorkerRequest},
            registry::ModuleSpec,
        };
        use crate::scan::{ScanObservation, plan::ScanStageKind};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"RFB 003.008\n").await.unwrap();
        });
        let request = WorkerRequest {
            id: uuid::Uuid::now_v7(),
            stage: ScanStageKind::ServiceDetection,
            target: crate::types::TargetParams {
                ip: "127.0.0.1".into(),
                port: port.to_string(),
                rate: 1,
                address_family: "ipv4".into(),
            },
            engine_path: "/missing/zgrab2".into(),
            masscan: Default::default(),
            service: ServiceDetectionConfig {
                enabled: true,
                required_services: vec!["vnc".into()],
                ..Default::default()
            },
            dns: Default::default(),
            nuclei: Default::default(),
            resolvers: vec![],
            checkpoint: Default::default(),
        };
        let spec = ModuleSpec {
            worker_path: std::env::var("SCANNER_WORKER_TEST_BINARY")
                .expect("worker path")
                .into(),
            engine_path: None,
            templates_path: None,
            artifact: "test".into(),
        };
        let input = vec![ScanObservation::Port(crate::scan::PortObservation {
            ip: "127.0.0.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "fixture".into(),
            observed_at: 1,
        })];
        let result = host::execute(
            &spec,
            request,
            input,
            None,
            &AtomicBool::new(false),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, Outcome::Completed);
        assert!(
            matches!(&result.observations[0],ScanObservation::Service(s) if s.service.as_deref()==Some("vnc") && s.source=="native")
        );
        server.await.unwrap();
    }
}
