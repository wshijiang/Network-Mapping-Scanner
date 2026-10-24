//! Authenticated DNS transports pinned to the explicitly selected endpoint.
use crate::{
    scan::detection::{ProbeAttempt, ProbeKind},
    types::ServiceDetectionConfig,
    udp_probe::{Request, UdpService},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid encrypted DNS response")
}
fn tls_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("TLS validation or handshake failed: {error}"),
    )
}

fn http_error(error: reqwest::Error) -> io::Error {
    if error.is_timeout() {
        return io::Error::new(io::ErrorKind::TimedOut, "HTTP timeout");
    }
    let mut cause = std::error::Error::source(&error);
    while let Some(e) = cause {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return tls_error("certificate or TLS handshake failed");
        }
        cause = e.source();
    }
    io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP connection failed")
}
fn tls_config(config: &ServiceDetectionConfig) -> io::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = &config.probe_options.tls_ca_pem {
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.map_err(tls_error)?).map_err(tls_error)?;
            count += 1;
        }
        if count == 0 {
            return Err(tls_error("empty CA bundle"));
        }
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(tls_error)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
fn tls_evidence(cert: Option<&[u8]>) -> Value {
    let fingerprint = cert.map(|der| format!("{:x}", Sha256::digest(der)));
    json!({"implicit_tls":true,"certificate_verified":true,"handshake_log":{"server_certificates":{"certificate":{"parsed":{"fingerprint_sha256":fingerprint}}}}})
}
pub(super) async fn dns_frame<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    limit: usize,
) -> io::Result<Value> {
    let request = Request::new(UdpService::Dns)?;
    stream
        .write_all(&(request.bytes.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&request.bytes).await?;
    let length = stream.read_u16().await? as usize;
    if !(12..=limit.min(8192)).contains(&length) {
        return Err(invalid());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    request.identify(&bytes).ok_or_else(invalid)
}
pub(super) async fn probe(
    attempt: &ProbeAttempt,
    config: &ServiceDetectionConfig,
) -> io::Result<Value> {
    config.probe_options.validate().map_err(|_| invalid())?;
    let ip = attempt
        .ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| invalid())?
        .to_canonical();
    if attempt.port == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip,std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(invalid());
    }
    let target = SocketAddr::new(ip, attempt.port);
    let host = config
        .probe_options
        .server_name
        .clone()
        .unwrap_or_else(|| ip.to_string());
    let tls = tls_config(config)?;
    if matches!(attempt.probe, ProbeKind::Dot | ProbeKind::Mqtts) {
        let stream = tokio::time::timeout(
            Duration::from_secs(config.connect_timeout_seconds),
            tokio::net::TcpStream::connect(target),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
        let name = ServerName::try_from(host).map_err(tls_error)?;
        let mut stream = TlsConnector::from(Arc::new(tls))
            .connect(name, stream)
            .await
            .map_err(tls_error)?;
        let connection = stream.get_ref().1;
        let cert = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref());
        let mut security = tls_evidence(cert);
        security["handshake_log"]["server_hello"] = json!({"version":{"name":format!("{:?}",connection.protocol_version().unwrap())},"cipher_suite":{"name":format!("{:?}",connection.negotiated_cipher_suite().unwrap().suite())}});
        if attempt.probe == ProbeKind::Mqtts {
            let mut result = super::industrial::mqtt(
                &mut stream,
                config.probe_options.mqtt_version.unwrap_or(4),
            )
            .await?;
            result["tls"] = security;
            return Ok(result);
        }
        let mut dns = dns_frame(&mut stream, config.max_result_bytes).await?;
        dns["transport"] = json!("tls");
        dns["tls"] = security;
        return Ok(dns);
    }
    // Reuse the production HTTP parser, but disable proxy inheritance, redirects and retries.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .https_only(true)
        .tls_backend_preconfigured(tls)
        .tls_info(true)
        .connect_timeout(Duration::from_secs(config.connect_timeout_seconds))
        .timeout(Duration::from_secs(config.target_timeout_seconds))
        .resolve(&host, target)
        .build()
        .map_err(tls_error)?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let mut url = reqwest::Url::parse(&format!("https://{authority}:{}", attempt.port))
        .map_err(|_| invalid())?;
    let path = config
        .probe_options
        .doh_path
        .as_deref()
        .unwrap_or("/dns-query");
    url.set_path(path);
    let request = Request::new(UdpService::Dns)?;
    let mut response = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("accept-encoding", "identity")
        .body(request.bytes.clone())
        .send()
        .await
        .map_err(http_error)?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').next())
            .is_none_or(|s| !s.trim().eq_ignore_ascii_case("application/dns-message"))
    {
        return Err(invalid());
    }
    let security = tls_evidence(
        response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|i| i.peer_certificate()),
    );
    let mut headers = json!({"content_type":["application/dns-message"]});
    if let Some(server) = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
    {
        headers["server"] = json!([server.chars().take(256).collect::<String>()]);
    }
    let mut body = Vec::new();
    let limit = config.max_result_bytes.min(8192);
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(invalid());
    }
    while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
        if body.len() + chunk.len() > limit {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
    }
    let dns = request.identify(&body).ok_or_else(invalid)?;
    Ok(
        json!({"dns":dns,"method":"POST","path":path,"tls":security,"response":{"status_line":"HTTP 200 OK","headers":headers,"body_truncated":false}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan::detection::ProbeEvidence, types::ServiceProbeOptions};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, rustls::pki_types::PrivateKeyDer};
    const CA: &str = include_str!("encrypted_dns_fixtures/ca.pem");
    fn acceptor() -> TlsAcceptor {
        let cert =
            CertificateDer::pem_slice_iter(include_bytes!("encrypted_dns_fixtures/server.pem"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("encrypted_dns_fixtures/server.key"))
                .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
    async fn fixture(
        kind: ProbeKind,
        mode: &'static str,
        trust: bool,
        name: &str,
    ) -> ProbeEvidence {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor().accept(socket).await else {
                return;
            };
            if kind == ProbeKind::Dot {
                let n = stream.read_u16().await.unwrap();
                let mut msg = vec![0; n as usize];
                stream.read_exact(&mut msg).await.unwrap();
                msg[2] = 0x80;
                msg[3] = 5;
                if mode == "wrong-id" {
                    msg[0] ^= 1;
                }
                let _ = stream.write_all(&(msg.len() as u16).to_be_bytes()).await;
                let _ = stream.write_all(&msg).await;
            } else {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                    assert!(header.len() < 8192);
                }
                let text = String::from_utf8(header).unwrap();
                assert!(text.starts_with("POST /custom-query HTTP/1.1"));
                assert!(text.to_ascii_lowercase().contains("host: probe.test:"));
                let length = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|s| s.parse::<usize>().ok())
                    })
                    .unwrap();
                let mut msg = vec![0; length];
                stream.read_exact(&mut msg).await.unwrap();
                msg[2] = 0x80;
                msg[3] = 5;
                if mode == "wrong-id" {
                    msg[0] ^= 1;
                }
                let content_type = if mode == "html" {
                    "text/html"
                } else {
                    "application/dns-message"
                };
                let status = if mode == "redirect" {
                    "302 Found"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nLocation: https://unrelated.invalid/\r\nConnection: close\r\n\r\n",
                    msg.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&msg).await;
            }
        });
        let config = ServiceDetectionConfig {
            probe_options: ServiceProbeOptions {
                server_name: Some(name.into()),
                doh_path: Some("/custom-query".into()),
                tls_ca_pem: trust.then(|| CA.into()),
                ..Default::default()
            },
            target_timeout_seconds: 2,
            ..Default::default()
        };
        let result = super::super::native::probe(
            &ProbeAttempt {
                ip: "127.0.0.1".into(),
                port,
                probe: kind,
            },
            &config,
            tokio::time::Instant::now() + Duration::from_secs(3),
        )
        .await;
        server.await.unwrap();
        result
    }
    #[tokio::test]
    async fn dot_confirms_correlated_dns_over_verified_tls_and_rejects_untrusted_or_wrong_names() {
        assert_eq!(
            fixture(ProbeKind::Dot, "ok", true, "probe.test")
                .await
                .status,
            "success"
        );
        assert_eq!(
            fixture(ProbeKind::Dot, "wrong-id", true, "probe.test")
                .await
                .status,
            "protocol-error"
        );
        assert_eq!(
            fixture(ProbeKind::Dot, "ok", false, "probe.test")
                .await
                .status,
            "tls-error"
        );
        assert_eq!(
            fixture(ProbeKind::Dot, "ok", true, "other.test")
                .await
                .status,
            "tls-error"
        );
    }
    #[tokio::test]
    async fn doh_pins_the_ip_preserves_sni_and_rejects_html_redirects_and_wrong_dns() {
        let ok = fixture(ProbeKind::Doh, "ok", true, "probe.test").await;
        assert_eq!(ok.status, "success");
        assert_eq!(ok.detail["result"]["tls"]["certificate_verified"], true);
        for mode in ["html", "redirect", "wrong-id"] {
            assert_eq!(
                fixture(ProbeKind::Doh, mode, true, "probe.test")
                    .await
                    .status,
                "protocol-error"
            );
        }
    }
}
