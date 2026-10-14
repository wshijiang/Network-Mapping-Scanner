//! Small bounded samples against endpoints already found open by this task.
//! Timeout and zero discovered ports do not establish target unreachability.
use crate::scan::{DnsObservation, ScanObservation};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Debug, Serialize)]
pub(crate) struct Performance {
    pub(crate) elapsed_ms: u64,
    pub(crate) connections: Vec<ConnectionSample>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    resolved_targets: Vec<ResolvedTarget>,
}
#[derive(Debug, Serialize)]
struct ResolvedTarget {
    domain: String,
    ip: String,
}
#[derive(Debug, Serialize)]
pub(crate) struct ConnectionSample {
    ip: String,
    port: u16,
    elapsed_ms: u32,
    outcome: &'static str,
}

fn in_scope(ip: IpAddr, target: &str) -> bool {
    let (address, prefix) = target
        .split_once('/')
        .map_or((target, None), |(ip, p)| (ip, Some(p)));
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    match (ip, address) {
        (IpAddr::V4(ip), IpAddr::V4(address)) => {
            let Some(prefix) = prefix
                .map_or(Some(32), |p| p.parse::<u32>().ok())
                .filter(|p| *p <= 32)
            else {
                return false;
            };
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(ip) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(address)) => {
            let Some(prefix) = prefix
                .map_or(Some(128), |p| p.parse::<u32>().ok())
                .filter(|p| *p <= 128)
            else {
                return false;
            };
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(ip) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}
fn port_in_scope(port: u16, ports: &str) -> bool {
    ports.split(',').any(|part| {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            a.parse::<u16>()
                .ok()
                .zip(b.parse::<u16>().ok())
                .is_some_and(|(a, b)| a <= port && port <= b)
        } else {
            part.parse::<u16>().ok() == Some(port)
        }
    })
}
fn endpoints(
    observations: &[ScanObservation],
    target: &crate::types::TargetParams,
    dns: &[DnsObservation],
) -> (Vec<SocketAddr>, Vec<ResolvedTarget>) {
    let domains: BTreeSet<_> = target
        .ip
        .split(',')
        .map(str::trim)
        .filter(|target| target.parse::<IpAddr>().is_err() && !target.contains('/'))
        .map(canonical_domain)
        .collect();
    let mut resolved = BTreeMap::new();
    for observation in dns {
        let domain = canonical_domain(&observation.question.name);
        if observation.response_code != "NOERROR" || !domains.contains(&domain) {
            continue;
        }
        for answer in &observation.answers {
            if let Ok(ip) = answer.value.parse::<IpAddr>()
                && matches!(
                    (answer.record_type.as_str(), ip),
                    ("A", IpAddr::V4(_)) | ("AAAA", IpAddr::V6(_))
                )
            {
                resolved.entry(ip).or_insert_with(|| domain.clone());
            }
        }
    }
    let mut endpoints = BTreeSet::new();
    let mut selected_resolutions = BTreeMap::new();
    for observation in observations {
        if let ScanObservation::Port(p) = observation
            && p.state == "open"
            && p.protocol == "tcp"
            && p.port > 0
            && let Ok(ip) = p.ip.parse::<IpAddr>()
            && (target.ip.split(',').any(|t| in_scope(ip, t.trim())) || resolved.contains_key(&ip))
            && port_in_scope(p.port, &target.port)
        {
            endpoints.insert(SocketAddr::new(ip, p.port));
            if let Some(domain) = resolved.get(&ip) {
                selected_resolutions.insert(ip, domain.clone());
            }
            if endpoints.len() >= 8 {
                break;
            }
        }
    }
    (
        endpoints.into_iter().collect(),
        selected_resolutions
            .into_iter()
            .map(|(ip, domain)| ResolvedTarget {
                domain,
                ip: ip.to_string(),
            })
            .collect(),
    )
}
fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
fn classify(error: &std::io::Error) -> &'static str {
    if error.kind() == std::io::ErrorKind::ConnectionRefused {
        "refused"
    } else if error.kind() == std::io::ErrorKind::TimedOut {
        "timeout"
    } else if matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
    ) {
        "route_error"
    } else {
        "other_error"
    }
}
pub(crate) async fn collect(
    observations: &[ScanObservation],
    target: &crate::types::TargetParams,
    elapsed_ms: u64,
    dns: &[DnsObservation],
) -> Performance {
    let (endpoints, resolved_targets) = endpoints(observations, target, dns);
    let measurements = endpoints.into_iter().map(|endpoint| async move {
        let start = Instant::now();
        let outcome = match tokio::time::timeout(
            Duration::from_millis(800),
            tokio::net::TcpStream::connect(endpoint),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                "connected"
            }
            Ok(Err(error)) => classify(&error),
            Err(_) => "timeout",
        };
        ConnectionSample {
            ip: endpoint.ip().to_string(),
            port: endpoint.port(),
            elapsed_ms: start.elapsed().as_millis().min(10000) as u32,
            outcome,
        }
    });
    // The JoinSet is bounded to eight concurrent connections; probes cannot delay
    // a task by eight sequential timeout periods.
    let mut connections = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    for measurement in measurements {
        tasks.spawn(measurement);
    }
    while let Some(result) = tasks.join_next().await {
        if let Ok(sample) = result {
            connections.push(sample);
        }
    }
    connections.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
    Performance {
        elapsed_ms,
        connections,
        resolved_targets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dns(domain: &str, answers: serde_json::Value) -> DnsObservation {
        serde_json::from_value(serde_json::json!({"observed_at":1,"question":{"name":domain,"type":"A","class":"IN"},"response_code":"NOERROR","answers":answers})).unwrap()
    }
    fn port(ip: &str, port: u16) -> ScanObservation {
        serde_json::from_value(serde_json::json!({"kind":"port","ip":ip,"port":port,"protocol":"tcp","state":"open","source":"masscan","observed_at":1})).unwrap()
    }

    #[tokio::test]
    async fn dns_port_tasks_measure_resolved_endpoints_and_attach_bounded_scope() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let target = crate::types::TargetParams {
            ip: "EXAMPLE.COM.".into(),
            port: tcp_port.to_string(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let resolutions = vec![
            dns(
                "example.com",
                serde_json::json!([{"type":"A","value":"127.0.0.1","ttl":60},{"type":"TXT","value":"127.0.0.2","ttl":60}]),
            ),
            dns(
                "outside.example.com",
                serde_json::json!([{"type":"A","value":"127.0.0.2","ttl":60}]),
            ),
        ];
        let measured = collect(
            &[
                port("127.0.0.1", tcp_port),
                port("127.0.0.1", tcp_port),
                port("127.0.0.2", tcp_port),
            ],
            &target,
            123,
            &resolutions,
        )
        .await;
        assert_eq!(measured.connections.len(), 1);
        assert_eq!(measured.connections[0].outcome, "connected");
        let payload = serde_json::to_value(measured).unwrap();
        assert_eq!(
            payload["resolved_targets"],
            serde_json::json!([{"domain":"example.com","ip":"127.0.0.1"}])
        );
    }

    #[test]
    fn dns_scope_keeps_a_and_aaaa_answers_and_rejects_unresolved_ips_and_ports() {
        let target = crate::types::TargetParams {
            ip: "example.com".into(),
            port: "443".into(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let resolutions = vec![dns(
            "example.com",
            serde_json::json!([{"type":"A","value":"192.0.2.1","ttl":60},{"type":"AAAA","value":"2001:db8::1","ttl":60}]),
        )];
        let observations = vec![
            port("192.0.2.1", 443),
            port("2001:db8::1", 443),
            port("192.0.2.1", 22),
            port("198.51.100.1", 443),
        ];
        let (selected, scope) = endpoints(&observations, &target, &resolutions);
        assert_eq!(selected.len(), 2);
        assert_eq!(scope.len(), 2);
        assert!(endpoints(&observations, &target, &[]).0.is_empty());
        let literal_ip = crate::types::TargetParams {
            ip: "198.51.100.1/32".into(),
            ..target.clone()
        };
        let unrelated = vec![dns(
            "198.51.100.1/32",
            serde_json::json!([{"type":"A","value":"192.0.2.1","ttl":60}]),
        )];
        assert!(
            endpoints(&[port("192.0.2.1", 443)], &literal_ip, &unrelated)
                .0
                .is_empty()
        );
        let many = (1..=20).map(|i| port("192.0.2.1", i)).collect::<Vec<_>>();
        let all_ports = crate::types::TargetParams {
            port: "1-65535".into(),
            ..target
        };
        assert_eq!(endpoints(&many, &all_ports, &resolutions).0.len(), 8);
    }
    #[tokio::test]
    async fn empty_scan_has_no_negative_reachability_samples() {
        let target = crate::types::TargetParams {
            ip: "192.0.2.1".into(),
            port: "443".into(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let p = collect(&[], &target, 100, &[]).await;
        assert!(p.connections.is_empty());
        assert_eq!(p.elapsed_ms, 100);
    }
    #[test]
    fn refusal_and_timeout_are_not_route_failures() {
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            "refused"
        );
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
            "timeout"
        );
        assert_eq!(
            classify(&std::io::Error::from_raw_os_error(101)),
            "route_error"
        );
    }
    #[test]
    fn samples_are_confined_to_task_addresses_and_ports() {
        assert!(in_scope("192.0.2.1".parse().unwrap(), "192.0.2.0/24"));
        assert!(!in_scope("198.51.100.1".parse().unwrap(), "192.0.2.0/24"));
        assert!(in_scope("2001:db8::1".parse().unwrap(), "2001:db8::/64"));
        assert!(!in_scope("2001:db9::1".parse().unwrap(), "2001:db8::/64"));
        assert!(!in_scope("192.0.2.1".parse().unwrap(), "example.com"));
        assert!(port_in_scope(443, "80,440-450"));
        assert!(!port_in_scope(22, "80,443"));
    }
    #[tokio::test]
    async fn measures_a_real_connection_only_once_for_duplicate_observations() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let observation:ScanObservation=serde_json::from_value(serde_json::json!({"kind":"port","ip":"127.0.0.1","port":port,"protocol":"tcp","state":"open","source":"masscan","observed_at":1})).unwrap();
        let target = crate::types::TargetParams {
            ip: "127.0.0.1/32".into(),
            port: port.to_string(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let measured = collect(&[observation.clone(), observation], &target, 123, &[]).await;
        assert_eq!(measured.connections.len(), 1);
        assert_eq!(measured.connections[0].outcome, "connected");
        assert_eq!(measured.connections[0].port, port);
        assert_eq!(measured.elapsed_ms, 123);
    }
}
