use crate::scan::{PortObservation, ServiceObservation};
use crate::types::{ServiceDetectionConfig, ServiceDetectionStrategy};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProbeKind {
    Ftp,
    Ftps,
    Ssh,
    Telnet,
    Smtp,
    Smtps,
    Http,
    Pop3,
    Pop3s,
    Imap,
    Imaps,
    Https,
    Smb,
    Tls,
    Mqtt,
    Mqtts,
    Mysql,
    Rdp,
    Postgres,
    Redis,
    Memcached,
    Mongodb,
    Banner,
}

impl ProbeKind {
    pub(crate) const ALL: [Self; 23] = [
        Self::Banner,
        Self::Tls,
        Self::Http,
        Self::Https,
        Self::Ssh,
        Self::Ftp,
        Self::Telnet,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
        Self::Redis,
        Self::Mysql,
        Self::Postgres,
        Self::Mongodb,
        Self::Mqtt,
        Self::Mqtts,
        Self::Smb,
        Self::Rdp,
        Self::Memcached,
        Self::Smtps,
        Self::Ftps,
        Self::Pop3s,
        Self::Imaps,
    ];

    const ADAPTIVE_FALLBACK: [Self; 14] = [
        Self::Redis,
        Self::Mysql,
        Self::Postgres,
        Self::Mongodb,
        Self::Mqtt,
        Self::Smb,
        Self::Rdp,
        Self::Memcached,
        Self::Ssh,
        Self::Ftp,
        Self::Telnet,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
    ];

    const ADAPTIVE_TLS_FALLBACK: [Self; 5] = [
        Self::Mqtts,
        Self::Smtps,
        Self::Imaps,
        Self::Pop3s,
        Self::Ftps,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
            Self::Ssh => "ssh",
            Self::Telnet => "telnet",
            Self::Smtp => "smtp",
            Self::Smtps => "smtps",
            Self::Http => "http",
            Self::Pop3 => "pop3",
            Self::Pop3s => "pop3s",
            Self::Imap => "imap",
            Self::Imaps => "imaps",
            Self::Https => "https",
            Self::Smb => "smb",
            Self::Tls => "tls",
            Self::Mqtt => "mqtt",
            Self::Mqtts => "mqtts",
            Self::Mysql => "mysql",
            Self::Rdp => "rdp",
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Memcached => "memcached",
            Self::Mongodb => "mongodb",
            Self::Banner => "banner",
        }
    }

    pub(crate) fn section(self) -> &'static str {
        match self {
            Self::Https => "http",
            Self::Ftps => "ftp",
            Self::Smtps => "smtp",
            Self::Pop3s => "pop3",
            Self::Imaps => "imap",
            Self::Mqtts => "mqtt",
            value => value.name(),
        }
    }

    pub(crate) fn default_port(self) -> u16 {
        match self {
            Self::Ftp => 21,
            Self::Ftps => 990,
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Smtp => 25,
            Self::Smtps => 465,
            Self::Http | Self::Banner => 80,
            Self::Pop3 => 110,
            Self::Pop3s => 995,
            Self::Imap => 143,
            Self::Imaps => 993,
            Self::Https | Self::Tls => 443,
            Self::Smb => 445,
            Self::Mqtt => 1883,
            Self::Mqtts => 8883,
            Self::Mysql => 3306,
            Self::Rdp => 3389,
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Memcached => 11211,
            Self::Mongodb => 27017,
        }
    }

    pub(crate) fn extra_config(self) -> &'static str {
        match self {
            Self::Http => "endpoint=\"/\"\nmax-redirects=0\n",
            Self::Https => "use-https=true\nendpoint=\"/\"\nmax-redirects=0\n",
            Self::Ftps => "implicit-tls=true\n",
            Self::Smtps => "smtps=true\n",
            Self::Pop3s => "pop3s=true\n",
            Self::Imaps => "imaps=true\n",
            Self::Mqtts => "tls=true\n",
            _ => "",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|probe| probe.name() == name)
    }

    fn service(self) -> Option<&'static str> {
        (self != Self::Banner).then(|| self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProbeAttempt {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) probe: ProbeKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeEvidence {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) module: String,
    pub(crate) status: String,
    pub(crate) banner: Option<String>,
    pub(crate) detail: Value,
}

#[derive(Debug, Clone)]
struct Candidate {
    service: String,
    score: u8,
    evidence_index: usize,
    reason: &'static str,
}

pub(crate) fn initial_attempts(
    open_ports: &[PortObservation],
    config: &ServiceDetectionConfig,
) -> Vec<ProbeAttempt> {
    let endpoints = unique_tcp_endpoints(open_ports);
    let mut attempts = Vec::new();
    for (ip, port) in endpoints {
        let probes = match config.strategy {
            ServiceDetectionStrategy::Standard => vec![primary_probe(port)],
            ServiceDetectionStrategy::Adaptive => {
                let mut probes = vec![primary_probe(port)];
                for probe in [
                    ProbeKind::Banner,
                    ProbeKind::Tls,
                    ProbeKind::Http,
                    ProbeKind::Https,
                ] {
                    push_unique(&mut probes, probe);
                }
                probes.truncate(config.max_probes_per_endpoint);
                probes
            }
            ServiceDetectionStrategy::Exhaustive => ProbeKind::ALL.to_vec(),
        };
        attempts.extend(probes.into_iter().map(|probe| ProbeAttempt {
            ip: ip.clone(),
            port,
            probe,
        }));
    }
    attempts
}

pub(crate) fn fallback_attempts(
    open_ports: &[PortObservation],
    completed: &[ProbeAttempt],
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> Vec<ProbeAttempt> {
    if config.strategy != ServiceDetectionStrategy::Adaptive {
        return Vec::new();
    }

    let confident = confident_endpoints(evidence, config);
    let completed: HashSet<_> = completed.iter().cloned().collect();
    let counts = completed
        .iter()
        .fold(HashMap::new(), |mut counts, attempt| {
            *counts
                .entry((attempt.ip.clone(), attempt.port))
                .or_insert(0usize) += 1;
            counts
        });
    let mut attempts = Vec::new();
    for (ip, port) in unique_tcp_endpoints(open_ports) {
        if confident.contains(&(ip.clone(), port)) {
            continue;
        }
        let mut remaining = config
            .max_probes_per_endpoint
            .saturating_sub(*counts.get(&(ip.clone(), port)).unwrap_or(&0));
        // Banner already covers server-first text protocols well, so spend the
        // bounded fallback budget on binary/client-first protocols first.
        let tls_succeeded = evidence.iter().any(|item| {
            item.ip == ip
                && item.port == port
                && item.module == ProbeKind::Tls.name()
                && item.status == "success"
        });
        let fallback_probes: &[ProbeKind] = if tls_succeeded {
            &ProbeKind::ADAPTIVE_TLS_FALLBACK
        } else {
            &ProbeKind::ADAPTIVE_FALLBACK
        };
        for &probe in fallback_probes {
            if remaining == 0 {
                break;
            }
            let attempt = ProbeAttempt {
                ip: ip.clone(),
                port,
                probe,
            };
            if completed.contains(&attempt) {
                continue;
            }
            attempts.push(attempt);
            remaining -= 1;
        }
    }
    attempts
}

pub(crate) fn aggregate(
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> Vec<ServiceObservation> {
    let mut grouped: BTreeMap<(String, u16), Vec<&ProbeEvidence>> = BTreeMap::new();
    for item in evidence {
        grouped
            .entry((item.ip.clone(), item.port))
            .or_default()
            .push(item);
    }

    grouped
        .into_iter()
        .map(|((ip, port), evidence)| {
            let candidates = candidates_for(&evidence, config.strategy);
            let selected = select_candidate(&candidates, config.confidence_threshold);
            let selected_evidence = selected.map(|candidate| evidence[candidate.evidence_index]);
            let banner = selected_evidence
                .and_then(|item| item.banner.clone())
                .or_else(|| {
                    evidence
                        .iter()
                        .find(|item| item.module == ProbeKind::Banner.name())
                        .and_then(|item| item.banner.clone())
                });
            let mut retained_evidence = selected_evidence
                .map(|item| vec![retained_handshake(item)])
                .unwrap_or_default();
            if selected_evidence.is_some_and(|item| item.module == ProbeKind::Https.name())
                && let Some(tls) = evidence
                    .iter()
                    .find(|item| item.module == ProbeKind::Tls.name() && item.status == "success")
            {
                retained_evidence.push(retained_handshake(tls));
            }
            let data = json!({
                "schema_version": 2,
                "confidence": selected.map(|candidate| candidate.score).unwrap_or(0),
                "selected_probe": selected_evidence.map(|item| item.module.as_str()),
                "attempt_count": evidence.len(),
                "selection_reason": selected.map(|candidate| candidate.reason),
                "evidence": retained_evidence,
            });
            ServiceObservation {
                ip,
                port,
                protocol: "tcp".into(),
                service: selected.map(|candidate| candidate.service.clone()),
                banner,
                source: "zgrab2".into(),
                data: Some(data),
                observed_at: chrono::Utc::now().timestamp_millis(),
            }
        })
        .collect()
}

fn retained_handshake(item: &ProbeEvidence) -> Value {
    let role = match ProbeKind::from_name(&item.module) {
        Some(ProbeKind::Tls) => "transport_security",
        Some(ProbeKind::Banner) => "banner",
        _ => "application_handshake",
    };
    let result = item
        .detail
        .get("result")
        .cloned()
        .unwrap_or_else(|| item.detail.clone());
    json!({
        "role": role,
        "module": item.module,
        "result": result,
        "truncated": item.detail.get("truncated").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn unique_tcp_endpoints(open_ports: &[PortObservation]) -> Vec<(String, u16)> {
    let mut seen = HashSet::new();
    open_ports
        .iter()
        .filter(|item| item.protocol == "tcp")
        .filter(|item| seen.insert((item.ip.clone(), item.port)))
        .map(|item| (item.ip.clone(), item.port))
        .collect()
}

fn push_unique(probes: &mut Vec<ProbeKind>, probe: ProbeKind) {
    if !probes.contains(&probe) {
        probes.push(probe);
    }
}

fn primary_probe(port: u16) -> ProbeKind {
    match port {
        21 => ProbeKind::Ftp,
        22 => ProbeKind::Ssh,
        23 => ProbeKind::Telnet,
        25 | 587 => ProbeKind::Smtp,
        80 | 8000 | 8008 | 8080 | 8081 | 8888 => ProbeKind::Http,
        110 => ProbeKind::Pop3,
        143 => ProbeKind::Imap,
        443 | 4443 | 8443 | 9443 => ProbeKind::Https,
        445 => ProbeKind::Smb,
        465 => ProbeKind::Smtps,
        636 | 853 | 989 => ProbeKind::Tls,
        990 => ProbeKind::Ftps,
        993 => ProbeKind::Imaps,
        995 => ProbeKind::Pop3s,
        1883 => ProbeKind::Mqtt,
        8883 => ProbeKind::Mqtts,
        3306 => ProbeKind::Mysql,
        3389 => ProbeKind::Rdp,
        5432 => ProbeKind::Postgres,
        6379 => ProbeKind::Redis,
        11211 => ProbeKind::Memcached,
        27017 => ProbeKind::Mongodb,
        _ => ProbeKind::Banner,
    }
}

fn confident_endpoints(
    evidence: &[ProbeEvidence],
    config: &ServiceDetectionConfig,
) -> HashSet<(String, u16)> {
    let mut grouped: HashMap<(String, u16), Vec<&ProbeEvidence>> = HashMap::new();
    for item in evidence {
        grouped
            .entry((item.ip.clone(), item.port))
            .or_default()
            .push(item);
    }
    grouped
        .into_iter()
        .filter_map(|(endpoint, evidence)| {
            let candidates = candidates_for(&evidence, config.strategy);
            let selected = select_candidate(&candidates, config.confidence_threshold)?;
            if selected.service == ProbeKind::Tls.name()
                && primary_probe(endpoint.1) != ProbeKind::Tls
            {
                None
            } else {
                Some(endpoint)
            }
        })
        .collect()
}

fn candidates_for(
    evidence: &[&ProbeEvidence],
    strategy: ServiceDetectionStrategy,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (index, item) in evidence.iter().enumerate() {
        if item.status != "success" {
            continue;
        }
        let probe = ProbeKind::from_name(&item.module);
        if let Some(service) = probe.and_then(ProbeKind::service) {
            let base_score: u8 = if probe == Some(ProbeKind::Tls) {
                85
            } else {
                100
            };
            let score = if probe == Some(primary_probe(item.port)) {
                base_score.saturating_add(3).min(100)
            } else {
                base_score
            };
            candidates.push(Candidate {
                service: service.into(),
                score,
                evidence_index: index,
                reason: "protocol_handshake",
            });
        }
        if strategy != ServiceDetectionStrategy::Standard
            && probe == Some(ProbeKind::Banner)
            && let Some((service, score)) = item.banner.as_deref().and_then(classify_banner)
        {
            candidates.push(Candidate {
                service: service.into(),
                score,
                evidence_index: index,
                reason: "banner_signature",
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.service.cmp(&right.service))
    });
    let mut seen_services = HashSet::new();
    candidates.retain(|candidate| seen_services.insert(candidate.service.clone()));
    candidates
}

fn select_candidate(candidates: &[Candidate], threshold: u8) -> Option<&Candidate> {
    let selected = candidates
        .first()
        .filter(|candidate| candidate.score >= threshold)?;
    if candidates.get(1).is_some_and(|runner_up| {
        runner_up.score == selected.score && runner_up.service != selected.service
    }) {
        return None;
    }
    Some(selected)
}

fn classify_banner(banner: &str) -> Option<(&'static str, u8)> {
    let trimmed = banner.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.starts_with("SSH-") {
        Some(("ssh", 99))
    } else if trimmed.starts_with("HTTP/") {
        Some(("http", 98))
    } else if trimmed.starts_with("220") && lower.contains("smtp") {
        Some(("smtp", 95))
    } else if trimmed.starts_with("220") && lower.contains("ftp") {
        Some(("ftp", 95))
    } else if trimmed.starts_with("+OK") && lower.contains("pop") {
        Some(("pop3", 95))
    } else if trimmed.starts_with("* OK") && lower.contains("imap") {
        Some(("imap", 95))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(port: u16) -> PortObservation {
        PortObservation {
            ip: "192.0.2.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at: 1,
        }
    }

    fn evidence(module: &str, port: u16, status: &str, banner: Option<&str>) -> ProbeEvidence {
        ProbeEvidence {
            ip: "192.0.2.1".into(),
            port,
            module: module.into(),
            status: status.into(),
            banner: banner.map(str::to_owned),
            detail: json!({
                "status": status,
                "result": {"banner": banner},
            }),
        }
    }

    #[test]
    fn standard_strategy_keeps_single_port_mapped_probe() {
        let attempts =
            initial_attempts(&[port(22), port(9000)], &ServiceDetectionConfig::default());
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].probe, ProbeKind::Ssh);
        assert_eq!(attempts[1].probe, ProbeKind::Banner);
    }

    #[test]
    fn standard_strategy_uses_application_probes_for_implicit_tls_ports() {
        let attempts = initial_attempts(
            &[port(465), port(990), port(993), port(995), port(8883)],
            &ServiceDetectionConfig::default(),
        );
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.probe)
                .collect::<Vec<_>>(),
            vec![
                ProbeKind::Smtps,
                ProbeKind::Ftps,
                ProbeKind::Imaps,
                ProbeKind::Pop3s,
                ProbeKind::Mqtts,
            ]
        );
    }

    #[test]
    fn adaptive_strategy_schedules_bounded_initial_and_fallback_probes() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 7,
            ..ServiceDetectionConfig::default()
        };
        let initial = initial_attempts(&[port(9000)], &config);
        assert_eq!(initial.len(), 4);
        let fallback = fallback_attempts(&[port(9000)], &initial, &[], &config);
        assert_eq!(fallback.len(), 3);
        assert!(fallback.iter().all(|attempt| !initial.contains(attempt)));
        assert_eq!(fallback[0].probe, ProbeKind::Redis);
        assert_eq!(fallback[1].probe, ProbeKind::Mysql);
    }

    #[test]
    fn banner_signature_identifies_ssh_on_nonstandard_port() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[evidence(
                "banner",
                2222,
                "success",
                Some("SSH-2.0-OpenSSH_9.6"),
            )],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("ssh"));
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 99);
    }

    #[test]
    fn application_protocol_wins_over_tls_wrapper() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("tls", 10443, "success", None),
                evidence("https", 10443, "success", Some("HTTP/1.1 200 OK")),
            ],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("https"));
        let retained = results[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0]["role"], "application_handshake");
        assert_eq!(retained[1]["role"], "transport_security");
    }

    #[test]
    fn implicit_tls_application_keeps_one_self_contained_handshake() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let mut smtps = evidence("smtps", 465, "success", Some("220 mail.example"));
        smtps.detail["result"]["tls"] = json!({"handshake_log": {}});
        let results = aggregate(&[smtps, evidence("tls", 465, "success", None)], &config);
        assert_eq!(results[0].service.as_deref(), Some("smtps"));
        let retained = results[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0]["module"], "smtps");
        assert!(retained[0]["result"]["tls"].is_object());
    }

    #[test]
    fn smtp_starttls_keeps_the_negotiated_tls_handshake() {
        let config = ServiceDetectionConfig::default();
        let mut smtp = evidence("smtp", 587, "success", Some("220 mail.example ESMTP"));
        smtp.detail["result"]["starttls"] = json!("220 Ready to start TLS");
        smtp.detail["result"]["tls"] = json!({
            "handshake_log": {
                "server_certificates": {
                    "certificate": {"parsed": {"subject_dn": "CN=mail.example"}}
                }
            }
        });

        let results = aggregate(&[smtp], &config);
        assert_eq!(results[0].service.as_deref(), Some("smtp"));
        let retained = results[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0]["module"], "smtp");
        assert_eq!(
            retained[0]["result"]["tls"]["handshake_log"]["server_certificates"]["certificate"]["parsed"]
                ["subject_dn"],
            "CN=mail.example"
        );
    }

    #[test]
    fn failed_probes_are_aggregated_without_claiming_a_service() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("http", 9000, "protocol-error", None),
                evidence("tls", 9000, "connection-timeout", None),
            ],
            &config,
        );
        assert!(results[0].service.is_none());
        assert_eq!(results[0].data.as_ref().unwrap()["attempt_count"], 2);
        assert!(
            results[0].data.as_ref().unwrap()["evidence"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn equal_strength_conflicting_handshakes_remain_unidentified() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("http", 9000, "success", Some("HTTP/1.1 200 OK")),
                evidence("mysql", 9000, "success", None),
            ],
            &config,
        );
        assert!(results[0].service.is_none());
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 0);
        assert!(
            results[0].data.as_ref().unwrap()["evidence"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn duplicate_evidence_for_one_service_keeps_the_strongest_candidate() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let results = aggregate(
            &[
                evidence("banner", 2222, "success", Some("SSH-2.0-OpenSSH_9.6")),
                evidence("ssh", 2222, "success", Some("SSH-2.0-OpenSSH_9.6")),
            ],
            &config,
        );
        assert_eq!(results[0].service.as_deref(), Some("ssh"));
        assert_eq!(results[0].data.as_ref().unwrap()["confidence"], 100);
        assert_eq!(
            results[0].data.as_ref().unwrap()["evidence"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            results[0].data.as_ref().unwrap()["evidence"][0]["module"],
            "ssh"
        );
    }

    #[test]
    fn confident_first_round_result_skips_fallback() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 8,
            ..ServiceDetectionConfig::default()
        };
        let ports = [port(2222)];
        let initial = initial_attempts(&ports, &config);
        let evidence = [evidence(
            "banner",
            2222,
            "success",
            Some("SSH-2.0-OpenSSH_9.6"),
        )];
        assert!(fallback_attempts(&ports, &initial, &evidence, &config).is_empty());
    }

    #[test]
    fn tls_on_nonstandard_port_prioritizes_secure_application_fallbacks() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 7,
            ..ServiceDetectionConfig::default()
        };
        let ports = [port(10465)];
        let initial = initial_attempts(&ports, &config);
        let evidence = [evidence("tls", 10465, "success", None)];
        let fallback = fallback_attempts(&ports, &initial, &evidence, &config);
        assert_eq!(fallback.len(), 3);
        assert_eq!(fallback[0].probe, ProbeKind::Mqtts);
        assert_eq!(fallback[1].probe, ProbeKind::Smtps);
        assert_eq!(fallback[2].probe, ProbeKind::Imaps);
    }

    #[test]
    fn tls_on_known_generic_tls_port_is_a_terminal_result() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Adaptive,
            ..ServiceDetectionConfig::default()
        };
        let ports = [port(636)];
        let initial = initial_attempts(&ports, &config);
        let evidence = [evidence("tls", 636, "success", None)];
        assert!(fallback_attempts(&ports, &initial, &evidence, &config).is_empty());
    }

    #[test]
    fn exhaustive_strategy_schedules_every_probe_once() {
        let config = ServiceDetectionConfig {
            strategy: ServiceDetectionStrategy::Exhaustive,
            max_probes_per_endpoint: 1,
            ..ServiceDetectionConfig::default()
        };
        let attempts = initial_attempts(&[port(9000), port(9000)], &config);
        assert_eq!(attempts.len(), ProbeKind::ALL.len());
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.probe)
                .collect::<HashSet<_>>()
                .len(),
            ProbeKind::ALL.len()
        );
    }
}
