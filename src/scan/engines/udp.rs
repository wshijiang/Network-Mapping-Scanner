//! Explicit, bounded UDP service discovery. Silence is never an open/closed assertion.
use super::{industrial, zgrab2::EngineOutcome};
use crate::{
    error::ScannerError,
    scan::{PortObservation, ScanObservation, ServiceObservation},
    types::{ServiceDetectionConfig, TargetParams},
    udp_probe::{Request, UdpService},
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{
    net::UdpSocket,
    time::{Duration, Instant, sleep, timeout_at},
};
fn invalid(message: &str) -> ScannerError {
    ScannerError::Scan(message.into())
}
/// Version 2 uses a UDP-only profile, so transport is explicit even on custom ports.
pub(crate) fn targets(target: &TargetParams) -> Result<Vec<PortObservation>, ScannerError> {
    let mut ips = std::collections::BTreeSet::new();
    for part in target.ip.split([',', ' ', '\n']).filter(|s| !s.is_empty()) {
        let net: ipnet::IpNet = part
            .parse()
            .or_else(|_| part.parse::<IpAddr>().map(Into::into))
            .map_err(|_| invalid("invalid UDP target"))?;
        // Include subnet endpoints: these are explicit addresses, not an implicit broadcast request.
        let count = match net {
            ipnet::IpNet::V4(n) => 1u128 << (32 - n.prefix_len()),
            ipnet::IpNet::V6(n) => 1u128
                .checked_shl((128 - n.prefix_len()) as u32)
                .unwrap_or(u128::MAX),
        };
        if count > 256 || count + ips.len() as u128 > 256 {
            return Err(invalid(
                "UDP inventory supports at most 256 target addresses",
            ));
        }
        for ip in net.hosts() {
            if ip.is_unspecified()
                || ip.is_multicast()
                || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
            {
                return Err(invalid("UDP target must be unicast"));
            }
            ips.insert(ip);
        }
    }
    let mut ports = std::collections::BTreeSet::new();
    for part in target.port.split(',') {
        let mut range = part.trim().split('-');
        let first: u16 = range
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| invalid("invalid UDP port"))?;
        let last: u16 = range
            .next()
            .map(str::parse)
            .transpose()
            .map_err(|_| invalid("invalid UDP port range"))?
            .unwrap_or(first);
        if range.next().is_some() || first == 0 || last < first || last - first > 31 {
            return Err(invalid("UDP inventory supports at most 32 explicit ports"));
        }
        ports.extend(first..=last);
        if ports.len() > 32 {
            return Err(invalid("UDP inventory supports at most 32 explicit ports"));
        }
    }
    if ips.is_empty() || ports.is_empty() {
        return Err(invalid("empty UDP targets"));
    }
    Ok(ips
        .into_iter()
        .flat_map(|ip| {
            ports.iter().map(move |port| PortObservation {
                ip: ip.to_string(),
                port: *port,
                protocol: "udp".into(),
                state: "unknown".into(),
                source: "udp_target".into(),
                observed_at: 0,
            })
        })
        .collect())
}
fn bacnet_response(p: &[u8]) -> Option<Value> {
    // BVLC Original-Unicast-NPDU only; no BBMD forwarded address attribution.
    if p.len() < 15
        || p[..2] != [0x81, 0x0a]
        || u16::from_be_bytes([p[2], p[3]]) as usize != p.len()
        || p[4..8] != [1, 0, 0x10, 0]
    {
        return None;
    }
    let mut at = 8;
    if *p.get(at)? != 0xc4 {
        return None;
    }
    at += 1;
    let object = u32::from_be_bytes(p.get(at..at + 4)?.try_into().ok()?);
    at += 4;
    if object >> 22 != 8 {
        return None;
    }
    fn unsigned(p: &[u8], at: &mut usize, tag: u8) -> Option<u32> {
        let h = *p.get(*at)?;
        *at += 1;
        let n = (h & 7) as usize;
        if h >> 4 != tag || h & 8 != 0 || !(1..=4).contains(&n) {
            return None;
        }
        let mut v = 0u32;
        for b in p.get(*at..*at + n)? {
            v = (v << 8) | *b as u32;
        }
        *at += n;
        Some(v)
    }
    let max_apdu = unsigned(p, &mut at, 2)?;
    let segmentation = unsigned(p, &mut at, 9)?;
    let vendor = unsigned(p, &mut at, 2)?;
    if at != p.len() || max_apdu < 50 || segmentation > 3 || vendor > 65535 {
        return None;
    }
    Some(
        json!({"device_instance":object&0x3fffff,"vendor_id":vendor,"max_apdu":max_apdu,"segmentation":segmentation,"correlation":"peer_and_receive_window","transaction_id_available":false}),
    )
}
async fn probe(
    address: SocketAddr,
    service: &str,
    deadline: Instant,
) -> std::io::Result<Option<Value>> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(address).await?; // kernel filters response source IP and port
    let dns = if service == "dns_udp" {
        Some(Request::new(UdpService::Dns)?)
    } else {
        None
    };
    let request = match service {
        "dns_udp" => dns.as_ref().unwrap().bytes.clone(),
        "enip_udp" => industrial::enip_request()?,
        "bacnet" => vec![0x81, 0x0a, 0, 8, 1, 0, 0x10, 8],
        _ => return Ok(None),
    };
    socket.send(&request).await?;
    let mut bytes = [0u8; 8193];
    for _ in 0..32 {
        let n = match timeout_at(deadline, socket.recv(&mut bytes)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(None),
        };
        if n > 8192 {
            continue;
        }
        let result = match service {
            "dns_udp" => dns.as_ref().unwrap().identify(&bytes[..n]),
            "enip_udp" => industrial::enip_response(&request, &bytes[..n]),
            "bacnet" => bacnet_response(&bytes[..n]),
            _ => None,
        };
        if result.is_some() {
            return Ok(result);
        }
    }
    Ok(None)
}
pub(crate) async fn run(
    config: &ServiceDetectionConfig,
    ports: &[PortObservation],
    cancel: &AtomicBool,
    mut journal: Option<&mut crate::journal::ScanJournal<'_>>,
) -> Result<EngineOutcome, ScannerError> {
    if config
        .required_services
        .iter()
        .any(|s| matches!(s.as_str(), "opcua_pubsub" | "enip_io"))
    {
        return super::passive::run(config, ports, cancel, journal).await;
    }
    if ports.iter().any(|p| p.protocol != "udp")
        || config.required_services.is_empty()
        || config
            .required_services
            .iter()
            .any(|s| !matches!(s.as_str(), "dns_udp" | "enip_udp" | "bacnet"))
    {
        return Err(invalid("UDP inventory requires explicit UDP protocols"));
    }
    let start = Instant::now();
    let prior = journal.as_ref().map_or(0, |j| j.state.elapsed_ms);
    let deadline = start
        + Duration::from_millis(
            config
                .max_runtime_seconds
                .saturating_mul(1000)
                .saturating_sub(prior),
        );
    let first = journal.as_ref().map_or(0, |j| j.state.chunk);
    let mut results = Vec::new();
    for (index, port) in ports.iter().enumerate().skip(first) {
        if cancel.load(Ordering::Relaxed) {
            return Ok(EngineOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(EngineOutcome::Partial(
                results,
                "udp_inventory_runtime_exceeded".into(),
            ));
        }
        if let Some(j) = journal.as_mut() {
            j.save(
                j.state.stage,
                index,
                prior + start.elapsed().as_millis() as u64,
                None,
            )?;
            j.start_block()?;
        }
        let ip: IpAddr = port.ip.parse().map_err(|_| invalid("invalid UDP IP"))?;
        if port.port == 0
            || ip.is_multicast()
            || ip.is_unspecified()
            || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(invalid("invalid UDP endpoint"));
        }
        let mut part = Vec::new();
        for service in &config.required_services {
            if Instant::now() >= deadline {
                return Ok(EngineOutcome::Partial(
                    results,
                    "udp_inventory_runtime_exceeded".into(),
                ));
            }
            if service == "bacnet" && ip.is_ipv6() {
                // Automatic inventory includes BACnet/IP, whose classic
                // transport applies only to IPv4 endpoints.
                continue;
            }
            let end =
                deadline.min(Instant::now() + Duration::from_secs(config.target_timeout_seconds));
            let future = probe(SocketAddr::new(ip, port.port), service, end);
            tokio::pin!(future);
            let result = loop {
                tokio::select! { result=&mut future=>break result, _=sleep(Duration::from_millis(20))=>{if cancel.load(Ordering::Relaxed){return Ok(EngineOutcome::Cancelled);}}}
            };
            if Instant::now() >= deadline {
                if let Some(j) = journal.as_mut() {
                    j.save(
                        j.state.stage,
                        index,
                        prior + start.elapsed().as_millis() as u64,
                        None,
                    )?;
                }
                return Ok(EngineOutcome::Partial(
                    results,
                    "udp_inventory_runtime_exceeded".into(),
                ));
            }
            if let Ok(Some(result)) = result {
                let name = match service.as_str() {
                    "dns_udp" => "dns",
                    "enip_udp" => "enip",
                    _ => "bacnet",
                };
                part.push(ScanObservation::Service(ServiceObservation{ip:port.ip.clone(),port:port.port,protocol:"udp".into(),service:Some(name.into()),banner:None,source:"native_udp".into(),data:Some(json!({"schema_version":2,"confidence":100,"selected_probe":service,"evidence":[{"role":"application_handshake","module":service,"result":result,"truncated":false}]})),observed_at:chrono::Utc::now().timestamp_millis()}));
            }
            // Per-target protocols remain serial; both global and per-IP maximum rate apply.
            let rate = config.server_rate_limit.clamp(1, 5);
            let end = (Instant::now() + Duration::from_secs_f64(1.0 / rate as f64)).min(deadline);
            while Instant::now() < end {
                if cancel.load(Ordering::Relaxed) {
                    return Ok(EngineOutcome::Cancelled);
                }
                sleep(Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())))
                    .await;
            }
        }
        if let Some(j) = journal.as_mut() {
            j.save(
                j.state.stage,
                index + 1,
                prior + start.elapsed().as_millis() as u64,
                Some(&part),
            )?;
        }
        results.extend(part.into_iter().filter_map(|o| {
            if let ScanObservation::Service(s) = o {
                Some(s)
            } else {
                None
            }
        }));
    }
    Ok(EngineOutcome::Completed(results))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_and_transport_are_explicit() {
        let t = TargetParams {
            ip: "127.0.0.1".into(),
            port: "53,44818,47808".into(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let p = targets(&t).unwrap();
        assert_eq!(p.len(), 3);
        assert!(
            p.iter()
                .all(|p| p.protocol == "udp" && p.state == "unknown")
        );
        assert!(
            targets(&TargetParams {
                port: "1-65535".into(),
                ..t.clone()
            })
            .is_err()
        );
        assert!(
            targets(&TargetParams {
                ip: "10.0.0.0/16".into(),
                ..t
            })
            .is_err()
        );
    }
    #[test]
    fn bacnet_rejects_forwarding_and_bad_object() {
        let mut p = vec![
            0x81, 0x0a, 0, 20, 1, 0, 0x10, 0, 0xc4, 2, 0, 0, 1, 0x22, 1, 0xe0, 0x91, 3, 0x21, 5,
        ];
        assert_eq!(bacnet_response(&p).unwrap()["device_instance"], 1);
        p[1] = 4;
        assert!(bacnet_response(&p).is_none());
        p[1] = 10;
        p[9] = 0;
        assert!(bacnet_response(&p).is_none());
    }
    #[tokio::test]
    async fn dns_matches_peer_and_transaction_and_silence_is_no_service() {
        for bad in [false, true] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let mut b = [0; 1024];
                let (n, from) = socket.recv_from(&mut b).await.unwrap();
                b[2] = 0x80;
                b[3] = 5;
                if bad {
                    b[0] ^= 1;
                }
                socket.send_to(&b[..n], from).await.unwrap();
            });
            let v = probe(addr, "dns_udp", Instant::now() + Duration::from_millis(100))
                .await
                .unwrap();
            assert_eq!(v.is_some(), !bad);
            peer.await.unwrap();
        }
    }
    #[tokio::test(start_paused = true)]
    async fn final_udp_timeout_exhausts_stage_without_committing_endpoint() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ports = targets(&TargetParams {
            ip: "127.0.0.1".into(),
            port: socket.local_addr().unwrap().port().to_string(),
            rate: 1,
            address_family: "ipv4".into(),
        })
        .unwrap();
        let config = ServiceDetectionConfig {
            required_services: vec!["dns_udp".into()],
            max_runtime_seconds: 1,
            target_timeout_seconds: 10,
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!("udp-stage-{}.sqlite3", uuid::Uuid::new_v4()));
        let store = crate::storage::StateStore::open(path.clone()).unwrap();
        let key = format!("{}|configuration", uuid::Uuid::new_v4());
        let mut journal = crate::journal::ScanJournal::open(&store, "origin", key.clone()).unwrap();
        let result = run(&config, &ports, &AtomicBool::new(false), Some(&mut journal))
            .await
            .unwrap();
        assert!(
            matches!(result,EngineOutcome::Partial(_,ref reason) if reason=="udp_inventory_runtime_exceeded")
        );
        let state = store.load_checkpoint("origin", &key).unwrap().unwrap();
        assert_eq!(state.chunk, 0);
        assert!(state.elapsed_ms >= 1000);
        assert!(state.observations.is_empty());
        drop(journal);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
