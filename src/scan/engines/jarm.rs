//! Opt-in TLS configuration fingerprinting. No DNS resolution, application
//! requests, retries or new targets: every connection uses the observed socket.
use crate::{scan::ServiceObservation, types::ServiceDetectionConfig};
use netfp::tls::{ServerHelloDecoder, TlsContentType, TlsRecord, TlsServerHello};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    task::JoinSet,
    time::{Duration, Instant, sleep, sleep_until, timeout_at},
};

const PROBES: usize = 10;
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_EVIDENCE_BYTES: usize = 4096;

fn eligible(service: &ServiceObservation) -> bool {
    if service.protocol != "tcp" || service.port == 0 {
        return false;
    }
    let Some(data) = service.data.as_ref().filter(|d| d["schema_version"] == 2) else {
        return false;
    };
    let Some(evidence) = data["evidence"].as_array() else {
        return false;
    };
    if evidence.iter().any(|e| e["module"] == "jarm") {
        return false;
    }
    // Require observed TLS handshake material, including a failed mTLS handshake.
    // A port number, redirect destination or plain-text banner is insufficient.
    evidence.iter().take(64).any(|e| {
        let result = &e["result"];
        let tls = match e["module"].as_str() {
            Some("tls") => result.get("tls").unwrap_or(result),
            Some("https") => {
                let response = result["redirect_response_chain"]
                    .as_array()
                    .and_then(|c| c.first())
                    .unwrap_or(&result["response"]);
                response.pointer("/request/tls_log").unwrap_or(&Value::Null)
            }
            _ => result.get("tls").unwrap_or(&Value::Null),
        };
        tls.get("handshake_log").is_some_and(|h| {
            ["server_hello", "server_certificates"].iter().any(|key| {
                let value = &h[*key];
                value.as_object().is_some_and(|object| !object.is_empty())
                    || value.as_array().is_some_and(|array| !array.is_empty())
            })
        })
    })
}

async fn probe(address: SocketAddr, hello: &[u8]) -> Result<Option<TlsServerHello>, &'static str> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|_| "connect_error")?;
    stream.write_all(hello).await.map_err(|_| "write_error")?;
    let mut decoder = ServerHelloDecoder::new();
    let mut total = 0;
    loop {
        let mut header = [0; 5];
        // Read the first byte separately: clean EOF before any TLS bytes is a
        // rejection; a truncated record must never become a fingerprint slot.
        let n = stream
            .read(&mut header[..1])
            .await
            .map_err(|_| "read_error")?;
        if n == 0 {
            return if total == 0 {
                Ok(None)
            } else {
                Err("truncated")
            };
        }
        stream
            .read_exact(&mut header[1..])
            .await
            .map_err(|_| "truncated")?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        total += 5 + size;
        if size > 16_384 || total > MAX_RESPONSE_BYTES {
            return Err("response_limit");
        }
        let mut record = header.to_vec();
        record.resize(5 + size, 0);
        stream
            .read_exact(&mut record[5..])
            .await
            .map_err(|_| "truncated")?;
        let (parsed, _) = TlsRecord::try_from_bytes(&record).map_err(|_| "malformed")?;
        if parsed.content_type() == &TlsContentType(21) {
            return if size == 2 {
                Ok(None)
            } else {
                Err("malformed")
            };
        }
        if parsed.content_type() != &TlsContentType::HANDSHAKE {
            return Err("unexpected_record");
        }
        if let Some(hello) = decoder.push_record(&parsed).map_err(|_| "malformed")? {
            return Ok(Some(hello));
        }
    }
}

async fn collect(
    address: SocketAddr,
    sni: String,
    config: crate::types::JarmConfig,
    deadline: Instant,
    pacing: Arc<Mutex<Instant>>,
    rate: u32,
) -> Value {
    let Ok(probes) = netfp::generate_jarm_probes(&sni) else {
        return json!({"module":"jarm", "status":"error", "error":"invalid_sni"});
    };
    let mut responses = Vec::with_capacity(PROBES);
    let mut statuses = Vec::with_capacity(PROBES);
    let mut completed = 0;
    let mut attempted = 0;
    for hello in probes.iter().take(PROBES) {
        // Serialize launch scheduling per IP, also across distinct ports. The
        // schedule begins where the base service probes left off.
        let mut next = pacing.lock().await;
        if *next >= deadline {
            break;
        }
        sleep_until(*next).await;
        if Instant::now() >= deadline {
            break;
        }
        *next = Instant::now() + Duration::from_secs_f64(1.0 / f64::from(rate.max(1)));
        drop(next);
        attempted += 1;
        let probe_deadline =
            deadline.min(Instant::now() + Duration::from_secs(config.probe_timeout_seconds));
        match timeout_at(probe_deadline, probe(address, hello)).await {
            Ok(Ok(response)) => {
                statuses.push(if response.is_some() {
                    "server_hello"
                } else {
                    "rejected"
                });
                responses.push(response);
                completed += 1;
            }
            Ok(Err(reason)) => {
                statuses.push(reason);
                responses.push(None);
            }
            Err(_) => {
                statuses.push("timeout");
                responses.push(None);
            }
        }
    }
    let has_hello = responses.iter().any(Option::is_some);
    let fingerprint =
        (completed == PROBES && has_hello).then(|| netfp::jarm_fingerprint(&responses));
    json!({
        "module": "jarm",
        "status": if fingerprint.is_some() { "success" } else if completed == PROBES { "no_response" } else { "partial" },
        "result": {"fingerprint": fingerprint, "expected_probes": PROBES,
            "attempted_probes": attempted, "completed_probes": completed, "probe_statuses": statuses,
            "active_probe": true, "profile": "salesforce-jarm", "collector": "netfp/0.2.1",
            "sni": sni, "observed_at": chrono::Utc::now().timestamp_millis()}
    })
}

pub(crate) async fn enrich_block(
    config: &ServiceDetectionConfig,
    block: &mut [ServiceObservation],
    deadline: Instant,
    cancel: &AtomicBool,
    pacing: &mut HashMap<String, Instant>,
    byte_budget: usize,
) -> usize {
    if !config.jarm.enabled
        || config.jarm.validate().is_err()
        || config.probe_options.validate().is_err()
        || cancel.load(Ordering::Relaxed)
    {
        return 0;
    }
    let deadline =
        deadline.min(Instant::now() + Duration::from_secs(config.jarm.max_stage_seconds));
    let mut seen = HashSet::new();
    let mut pending = VecDeque::new();
    for (index, service) in block.iter().enumerate() {
        let Ok(ip) = service.ip.parse::<IpAddr>() else {
            continue;
        };
        if eligible(service) && seen.insert((ip, service.port)) {
            pending.push_back((index, SocketAddr::new(ip, service.port)));
        }
    }
    let mut schedules = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut added = 0usize;
    let mut reserved = 0usize;
    loop {
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
            break;
        }
        while tasks.len() < config.jarm.concurrency && !pending.is_empty() {
            // Reserve output space before opening a connection, not afterwards.
            if added
                .saturating_add(reserved)
                .saturating_add(MAX_EVIDENCE_BYTES)
                > byte_budget
            {
                pending.clear();
                break;
            }
            let (index, address) = pending.pop_front().unwrap();
            let ip = address.ip().to_string();
            let schedule = schedules
                .entry(ip.clone())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(
                        pacing.get(&ip).copied().unwrap_or_else(Instant::now),
                    ))
                })
                .clone();
            let sni = config
                .probe_options
                .server_name
                .clone()
                .unwrap_or_else(|| ip.clone());
            let options = config.jarm.clone();
            let rate = config.server_rate_limit;
            reserved += MAX_EVIDENCE_BYTES;
            tasks.spawn(async move {
                (
                    index,
                    collect(address, sni, options, deadline, schedule, rate).await,
                )
            });
        }
        if tasks.is_empty() {
            break;
        }
        tokio::select! {
            result = tasks.join_next() => {
                reserved = reserved.saturating_sub(MAX_EVIDENCE_BYTES);
                if let Some(Ok((index, evidence))) = result {
                    let bytes = serde_json::to_vec(&evidence).map_or(MAX_EVIDENCE_BYTES + 1, |b| b.len() + 1);
                    if bytes <= MAX_EVIDENCE_BYTES && let Some(entries) = block[index].data.as_mut().and_then(|d| d["evidence"].as_array_mut()) {
                        entries.push(evidence); added += bytes;
                    }
                }
            }
            _ = sleep(Duration::from_millis(25)) => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for (ip, schedule) in schedules {
        pacing.insert(ip, *schedule.lock().await);
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn options() -> ServiceDetectionConfig {
        let mut config = ServiceDetectionConfig::default();
        config.jarm.enabled = true;
        config.server_rate_limit = 1000;
        config.probe_options.server_name = Some("inventory.invalid".into());
        config
    }
    fn service(address: SocketAddr) -> ServiceObservation {
        ServiceObservation {
            ip: address.ip().to_string(),
            port: address.port(),
            protocol: "tcp".into(),
            service: Some("tls".into()),
            banner: None,
            source: "zgrab2".into(),
            observed_at: 1234,
            data: Some(
                json!({"schema_version":2,"evidence":[{"module":"tls","status":"success","result":{"handshake_log":{"server_hello":{"version":{"name":"TLSv1.2"}}}}}]}),
            ),
        }
    }
    fn server_hello() -> Vec<u8> {
        // Synthetic deterministic TLS 1.3 ServerHello with ALPN h2. The
        // expected hash is also checked by netfp's upstream reference vector.
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0x13, 1, 0]);
        let extensions = [0, 0x2b, 0, 2, 3, 4, 0, 0x10, 0, 5, 0, 3, 2, b'h', b'2'];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![2, 0, 0, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
    async fn fixture(listener: TcpListener, response: Vec<u8>) -> Vec<Instant> {
        let mut launches = vec![];
        for _ in 0..PROBES {
            let (mut socket, _) = listener.accept().await.unwrap();
            launches.push(Instant::now());
            let mut header = [0; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            let mut hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            socket.read_exact(&mut hello).await.unwrap();
            assert!(
                hello
                    .windows(b"inventory.invalid".len())
                    .any(|w| w == b"inventory.invalid")
            );
            // Exercise fragmented reads, including TLS record headers.
            socket.write_all(&response[..2]).await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(&response[2..]).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err(),
            "unexpected extra connection"
        );
        launches
    }
    #[test]
    fn client_hello_profiles_match_official_v1_order_and_parameters() {
        use sha2::{Digest, Sha256};
        // Reference hashes were generated offline with Salesforce JARM v1.0
        // packet_building. Randoms, session IDs, key bytes and GREASE values
        // are normalized; all profile versions, ciphers, extension order,
        // ALPN and supported-version lists remain part of the comparison.
        let expected: Vec<String> =
            serde_json::from_str(include_str!("fixtures/jarm_probe_reference.json")).unwrap();
        let probes = netfp::generate_jarm_probes("inventory.invalid").unwrap();
        assert_eq!(probes.len(), PROBES);
        fn grease(data: &mut [u8], pos: usize) {
            if data[pos] == data[pos + 1] && data[pos] & 15 == 10 {
                data[pos..pos + 2].copy_from_slice(&[10, 10]);
            }
        }
        for (mut data, expected) in probes.into_iter().zip(expected) {
            data[11..43].fill(0);
            let sid = data[43] as usize;
            data[44..44 + sid].fill(0);
            let mut pos = 44 + sid;
            let n = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            for at in (pos..pos + n).step_by(2) {
                grease(&mut data, at);
            }
            pos += n;
            pos += 1 + data[pos] as usize;
            pos += 2;
            while pos < data.len() {
                grease(&mut data, pos);
                let kind = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let n = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                let start = pos + 4;
                if kind == 0x2b {
                    for at in (start + 1..start + n).step_by(2) {
                        grease(&mut data, at);
                    }
                }
                if kind == 0x33 {
                    let mut at = start + 2;
                    while at < start + n {
                        grease(&mut data, at);
                        let length = u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
                        at += 4;
                        data[at..at + length].fill(0);
                        at += length;
                    }
                }
                pos = start + n;
            }
            let actual: String = Sha256::digest(&data)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }
    #[tokio::test]
    async fn collects_ten_ordered_probes_with_pinned_ip_sni_and_shared_pacing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(fixture(listener, server_hello()));
        let mut config = options();
        config.server_rate_limit = 50;
        let started = Instant::now();
        let mut pacing = HashMap::from([(
            address.ip().to_string(),
            started + Duration::from_millis(40),
        )]);
        let mut block = vec![service(address)];
        let bytes = enrich_block(
            &config,
            &mut block,
            started + Duration::from_secs(5),
            &AtomicBool::new(false),
            &mut pacing,
            4096,
        )
        .await;
        assert!(bytes > 0 && bytes <= MAX_EVIDENCE_BYTES);
        let launches = server.await.unwrap();
        assert!(launches[0].duration_since(started) >= Duration::from_millis(35));
        for pair in launches.windows(2) {
            assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(15));
        }
        assert!(pacing[&address.ip().to_string()] >= launches[9]);
        let evidence = &block[0].data.as_ref().unwrap()["evidence"][1];
        assert_eq!(evidence["status"], "success");
        assert_eq!(evidence["result"]["completed_probes"], 10);
        assert_eq!(
            evidence["result"]["fingerprint"],
            "41d41d41d41d41d41d41d41d41d41da0bfb9dc5a7a50dfa51c2a70be11dda8"
        );
    }
    #[tokio::test]
    async fn concurrent_ports_on_one_ip_share_the_connection_rate() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut block = vec![
            service(first.local_addr().unwrap()),
            service(second.local_addr().unwrap()),
        ];
        let one = tokio::spawn(fixture(first, server_hello()));
        let two = tokio::spawn(fixture(second, server_hello()));
        let mut config = options();
        config.jarm.concurrency = 2;
        config.server_rate_limit = 50;
        let bytes = enrich_block(
            &config,
            &mut block,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            &mut HashMap::new(),
            8192,
        )
        .await;
        assert!(bytes > 0);
        let mut launches = one.await.unwrap();
        launches.extend(two.await.unwrap());
        launches.sort();
        assert_eq!(launches.len(), 20);
        for pair in launches.windows(2) {
            assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(15));
        }
        assert!(
            block
                .iter()
                .all(|s| s.data.as_ref().unwrap()["evidence"][1]["status"] == "success")
        );
    }
    #[tokio::test]
    async fn rejection_has_no_zero_hash_and_truncation_is_incomplete() {
        for (response, status, completed) in [
            (vec![21, 3, 3, 0, 2, 2, 40], "no_response", 10),
            (vec![22, 3, 3, 0, 9, 2], "partial", 0),
            (vec![22, 3, 3, 255, 255], "partial", 0),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(fixture(listener, response));
            let result = collect(
                address,
                "inventory.invalid".into(),
                options().jarm,
                Instant::now() + Duration::from_secs(3),
                Arc::new(Mutex::new(Instant::now())),
                1000,
            )
            .await;
            server.await.unwrap();
            assert_eq!(result["status"], status);
            assert_eq!(result["result"]["completed_probes"], completed);
            assert_eq!(result["result"]["attempted_probes"], 10);
            assert!(result["result"]["fingerprint"].is_null());
        }
    }
    #[tokio::test]
    async fn disabled_unobserved_duplicate_and_no_output_budget_do_not_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        for case in 0..5 {
            let mut config = options();
            let mut block = vec![service(address)];
            let mut budget = 4096;
            match case {
                0 => config.jarm.enabled = false,
                1 => {
                    block[0].data = Some(
                        json!({"schema_version":2,"evidence":[{"module":"http","result":{"response":{"status_code":200}}}]}),
                    )
                }
                2 => block[0].data.as_mut().unwrap()["evidence"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"module":"jarm"})),
                3 => budget = 4095,
                _ => config.probe_options.server_name = Some("https://untrusted.invalid/".into()),
            }
            assert_eq!(
                enrich_block(
                    &config,
                    &mut block,
                    Instant::now() + Duration::from_secs(1),
                    &AtomicBool::new(false),
                    &mut HashMap::new(),
                    budget
                )
                .await,
                0
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        assert!(!crate::types::JarmConfig::default().enabled);
    }
    #[tokio::test]
    async fn deadline_and_cancellation_stop_inflight_connections() {
        for cancel_midway in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let cancel = AtomicBool::new(false);
            let mut block = vec![service(address)];
            let started = Instant::now();
            let deadline = started + Duration::from_millis(if cancel_midway { 500 } else { 60 });
            let mut pacing = HashMap::new();
            let config = options();
            let collection =
                enrich_block(&config, &mut block, deadline, &cancel, &mut pacing, 4096);
            let server = async {
                let (_socket, _) = listener.accept().await.unwrap();
                if cancel_midway {
                    cancel.store(true, Ordering::Relaxed);
                }
                sleep(Duration::from_millis(100)).await;
            };
            let (bytes, ()) = tokio::join!(collection, server);
            if bytes > 0 {
                let evidence = &block[0].data.as_ref().unwrap()["evidence"][1];
                assert_eq!(evidence["status"], "partial");
                assert!(evidence["result"]["fingerprint"].is_null());
            }
            assert!(started.elapsed() < Duration::from_millis(250));
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
    #[test]
    fn tls_scope_excludes_redirect_destinations_and_keeps_failed_mtls() {
        let address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut service = service(address);
        service.data = Some(
            json!({"schema_version":2,"evidence":[{"module":"https","result":{"redirect_response_chain":[{"request":{}}],"response":{"request":{"tls_log":{"handshake_log":{"server_hello":{"version":{"name":"TLSv1.2"}}}}}}}}]}),
        );
        assert!(!eligible(&service));
        service.data = Some(
            json!({"schema_version":2,"evidence":[{"module":"tls","status":"error","result":{"tls":{"handshake_log":{"server_certificates":{"certificate":{"parsed":{"subject_dn":"CN=local-test"}}}}}}}]}),
        );
        assert!(eligible(&service));
        service.protocol = "udp".into();
        assert!(!eligible(&service));
    }
}
