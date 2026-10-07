use super::engines::{dns, masscan, nuclei, zgrab2};
use super::observation::ScanObservation;
use super::plan::{ScanPlan, ScanStageKind};
use crate::error::ScannerError;
use crate::types::{DnsConfig, MasscanConfig, NucleiConfig, ServiceDetectionConfig, TargetParams};
use std::sync::atomic::AtomicBool;

pub(crate) enum ScanOutcome {
    Completed(Vec<ScanObservation>),
    Cancelled,
}

pub(crate) struct ScanRuntimeConfig<'a> {
    pub(crate) journal: Option<crate::journal::ScanJournal<'a>>,
    pub(crate) scanner_path: &'a str,
    pub(crate) masscan: &'a MasscanConfig,
    pub(crate) service_detection: &'a ServiceDetectionConfig,
    pub(crate) dns: &'a DnsConfig,
    pub(crate) nuclei: &'a NucleiConfig,
    pub(crate) dns_resolvers: &'a [crate::types::DnsResolver],
    pub(crate) ipv4_ready: bool,
    pub(crate) ipv6_ready: bool,
}

/// Execute the configured scan pipeline.
///
/// Engines own process execution and output parsing. This orchestrator owns
/// stage ordering, cancellation propagation, and stage-level failure policy.
pub(crate) async fn run_scan(
    mut config: ScanRuntimeConfig<'_>,
    plan: &ScanPlan,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    plan.validate()?;
    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut dns_observations = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut resolved_ips = Vec::new();
    let resumed_stage = config.journal.as_ref().map_or(0, |j| j.state.stage);
    if let Some(j) = &config.journal {
        for observation in &j.state.observations {
            match observation {
                ScanObservation::Port(p) => ports.push(p.clone()),
                ScanObservation::Service(s) => services.push(s.clone()),
                ScanObservation::Dns(d) => dns_observations.push(d.clone()),
                ScanObservation::Vulnerability(v) => vulnerabilities.push(v.clone()),
            }
        }
        resolved_ips = dns_observations
            .iter()
            .flat_map(|d| d.answers.iter())
            .filter(|a| matches!(a.record_type.as_str(), "A" | "AAAA"))
            .filter_map(|a| a.value.parse().ok())
            .collect();
        tracing::info!(
            event = "ScanCheckpointRecovered",
            stage = resumed_stage,
            chunk = j.state.chunk,
            observation_count = j.state.observations.len(),
            "scan checkpoint loaded"
        );
    }
    for (stage_index, stage) in plan.stages.iter().enumerate() {
        if stage_index < resumed_stage {
            continue;
        }
        match stage.kind {
            ScanStageKind::PortDiscovery => {
                let port_targets = if matches!(plan.profile.as_str(), "dns_ports" | "dns_full") {
                    if resolved_ips.is_empty() {
                        tracing::info!("DNS task has no A/AAAA answers; skipping port discovery");
                        continue;
                    }
                    dns_port_targets(&resolved_ips, target, config.ipv4_ready, config.ipv6_ready)
                } else {
                    vec![target.clone()]
                };
                ports.clear();
                for port_target in port_targets {
                    match masscan::run(
                        config.scanner_path,
                        config.masscan,
                        &port_target,
                        cancel_requested,
                    )
                    .await
                    .map_err(|source| {
                        ScannerError::engine_stage(
                            "masscan",
                            "port_discovery",
                            "port_discovery_failed",
                            source,
                        )
                    })? {
                        masscan::EngineOutcome::Completed(results) => ports.extend(results),
                        masscan::EngineOutcome::Cancelled => return Ok(ScanOutcome::Cancelled),
                    }
                }
            }
            ScanStageKind::ServiceDetection if ports.is_empty() => {}
            ScanStageKind::ServiceDetection if !config.service_detection.enabled => {
                if plan.profile == "legacy" || !stage.required {
                    tracing::debug!(
                        "legacy service detection stage skipped by local configuration"
                    );
                    continue;
                }
                return Err(ScannerError::Scan(
                    "task requires service_detection but this scanner has it disabled".into(),
                ));
            }
            ScanStageKind::ServiceDetection => {
                let required = if plan.profile == "legacy" {
                    config.service_detection.required
                } else {
                    stage.required
                };
                match zgrab2::run_with_journal(
                    config.service_detection,
                    &ports,
                    &target.address_family,
                    cancel_requested,
                    config.journal.as_mut(),
                )
                .await
                {
                    Ok(zgrab2::EngineOutcome::Completed(enrichment)) => services.extend(enrichment),
                    Ok(zgrab2::EngineOutcome::Partial(enrichment, reason)) => {
                        if required {
                            return Err(ScannerError::Scan(reason));
                        }
                        tracing::warn!(event="ServiceDetectionIncomplete", error_code=%reason,
                            outcome="partial_services_and_ports_preserved", "optional service detection stopped before completion");
                        services.extend(enrichment);
                    }
                    Ok(zgrab2::EngineOutcome::Cancelled) => return Ok(ScanOutcome::Cancelled),
                    Err(error) if required => {
                        return Err(ScannerError::engine_stage(
                            "zgrab2",
                            "service_detection",
                            "service_detection_failed",
                            error,
                        ));
                    }
                    Err(error) => {
                        tracing::warn!(
                            event = "OptionalServiceDetectionFailed",
                            operation = "run_service_detection",
                            reason = %error,
                            error_code = "optional_service_detection_failed",
                            outcome = "port_results_preserved",
                            engine = "zgrab2",
                            stage = "service_detection",
                            port_count = ports.len(),
                            "optional service detection stage failed; preserving port results"
                        );
                    }
                }
            }
            ScanStageKind::DnsLookup if !config.dns.enabled => {
                return Err(ScannerError::Scan(
                    "task requires dns_lookup but this scanner has DNS disabled".into(),
                ));
            }
            ScanStageKind::DnsLookup => {
                match dns::run(config.dns, target, config.dns_resolvers, cancel_requested)
                    .await
                    .map_err(|source| {
                        ScannerError::engine_stage("dns", "dns_lookup", "dns_lookup_failed", source)
                    })? {
                    Some(results) => {
                        dns_observations = results.observations;
                        resolved_ips = results.resolved_ips;
                    }
                    None => return Ok(ScanOutcome::Cancelled),
                }
            }
            ScanStageKind::VulnerabilityDetection if !config.nuclei.enabled => {
                return Err(ScannerError::Scan(
                    "task requires vulnerability_detection but this scanner has nuclei disabled"
                        .into(),
                ));
            }
            ScanStageKind::VulnerabilityDetection => {
                match nuclei::run(config.nuclei, &ports, &services, cancel_requested)
                    .await
                    .map_err(|source| {
                        ScannerError::engine_stage(
                            "nuclei",
                            "vulnerability_detection",
                            "vulnerability_detection_failed",
                            source,
                        )
                    })? {
                    nuclei::EngineOutcome::Completed(results) => vulnerabilities = results,
                    nuclei::EngineOutcome::Cancelled => return Ok(ScanOutcome::Cancelled),
                }
            }
        }
        if let Some(j) = config.journal.as_mut() {
            let part: Vec<_> = match stage.kind {
                ScanStageKind::PortDiscovery => {
                    ports.iter().cloned().map(ScanObservation::Port).collect()
                }
                ScanStageKind::ServiceDetection => services
                    .iter()
                    .cloned()
                    .map(ScanObservation::Service)
                    .collect(),
                ScanStageKind::DnsLookup => dns_observations
                    .iter()
                    .cloned()
                    .map(ScanObservation::Dns)
                    .collect(),
                ScanStageKind::VulnerabilityDetection => vulnerabilities
                    .iter()
                    .cloned()
                    .map(ScanObservation::Vulnerability)
                    .collect(),
            };
            j.save(stage_index + 1, 0, 0, Some(&part))?;
        }
    }
    let mut observations = Vec::with_capacity(
        ports.len() + services.len() + dns_observations.len() + vulnerabilities.len(),
    );
    if plan.profile != "dns_ports" {
        observations.extend(dns_observations.into_iter().map(ScanObservation::Dns));
    }
    observations.extend(ports.into_iter().map(ScanObservation::Port));
    observations.extend(services.into_iter().map(ScanObservation::Service));
    observations.extend(
        vulnerabilities
            .into_iter()
            .map(ScanObservation::Vulnerability),
    );
    let mut identities = std::collections::HashSet::new();
    observations.retain(|o| identities.insert(o.identity()));
    Ok(ScanOutcome::Completed(observations))
}

fn dns_port_targets(
    resolved_ips: &[std::net::IpAddr],
    target: &TargetParams,
    ipv4_ready: bool,
    ipv6_ready: bool,
) -> Vec<TargetParams> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut skipped_ipv4 = 0usize;
    let mut skipped_ipv6 = 0usize;
    for address in resolved_ips {
        match address {
            std::net::IpAddr::V4(_) if ipv4_ready => ipv4.push(address.to_string()),
            std::net::IpAddr::V6(_) if ipv6_ready => ipv6.push(address.to_string()),
            std::net::IpAddr::V4(_) => skipped_ipv4 += 1,
            std::net::IpAddr::V6(_) => skipped_ipv6 += 1,
        }
    }
    if skipped_ipv4 > 0 {
        tracing::warn!(
            skipped_target_count = skipped_ipv4,
            "skipping DNS-resolved IPv4 targets because IPv4 is unavailable"
        );
    }
    if skipped_ipv6 > 0 {
        tracing::warn!(
            skipped_target_count = skipped_ipv6,
            "skipping DNS-resolved IPv6 targets because IPv6 is unavailable"
        );
    }
    [("ipv4", ipv4), ("ipv6", ipv6)]
        .into_iter()
        .filter(|(_, addresses)| !addresses.is_empty())
        .map(|(address_family, addresses)| TargetParams {
            ip: addresses.join(","),
            port: target.port.clone(),
            rate: target.rate,
            address_family: address_family.into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_reuses_ports_and_completed_service_blocks() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("scanner-checkpoint-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&directory).unwrap();
        let masscan = directory.join("masscan");
        let zgrab = directory.join("zgrab");
        let marker = directory.join("marker");
        let gate = directory.join("fail");
        std::fs::write(&gate, "").unwrap();
        std::fs::write(&masscan,format!("#!/bin/sh\nprintf 'masscan\n' >> '{}'\nprintf 'open tcp 22 192.0.2.1 1\nopen tcp 23 192.0.2.1 1\n'\n",marker.display())).unwrap();
        std::fs::write(&zgrab,format!(r#"#!/bin/sh
while IFS=',' read -r ip domain tag port; do
  printf '%s\n' "$port" >> '{}'
  if [ "$port" = 23 ] && [ -f '{}' ]; then exit 4; fi
  printf '{{"ip":"%s","data":{{"%s":{{"status":"success","protocol":"%s","port":%s,"result":{{"banner":"identified"}}}}}}}}\n' "$ip" "$tag" "$tag" "$port"
done
"#,marker.display(),gate.display())).unwrap();
        for path in [&masscan, &zgrab] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = crate::storage::StateStore::open(directory.join("state.sqlite3")).unwrap();
        let key = format!("{}|same-config", uuid::Uuid::now_v7());
        let service = crate::types::ServiceDetectionConfig {
            enabled: true,
            required: true,
            batch_endpoints: 1,
            zgrab_path: zgrab.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let plan = super::ScanPlan::legacy(&service);
        let target = crate::types::TargetParams {
            ip: "192.0.2.1".into(),
            port: "22-23".into(),
            rate: 10,
            address_family: "ipv4".into(),
        };
        for attempt in 0..2 {
            let journal = crate::journal::ScanJournal::open(&store, "origin", key.clone()).unwrap();
            let result = super::run_scan(
                super::ScanRuntimeConfig {
                    journal: Some(journal),
                    scanner_path: masscan.to_str().unwrap(),
                    masscan: &MasscanConfig::default(),
                    service_detection: &service,
                    dns: &crate::types::DnsConfig::default(),
                    nuclei: &crate::types::NucleiConfig::default(),
                    dns_resolvers: &[],
                    ipv4_ready: true,
                    ipv6_ready: false,
                },
                &plan,
                &target,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .await;
            if attempt == 0 {
                assert!(result.is_err());
                std::fs::remove_file(&gate).unwrap();
            } else {
                let super::ScanOutcome::Completed(results) = result.unwrap() else {
                    panic!("recovered scan must complete");
                };
                assert_eq!(results.len(), 4);
            }
        }
        let markers = std::fs::read_to_string(marker).unwrap();
        assert_eq!(markers.lines().filter(|&line| line == "masscan").count(), 1);
        assert_eq!(markers.lines().filter(|&line| line == "22").count(), 1);
        assert_eq!(markers.lines().filter(|&line| line == "23").count(), 2);
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    use super::*;
    use crate::scan::plan::{SCAN_PLAN_VERSION, ScanStageSpec};
    use std::sync::atomic::AtomicBool;
    use uuid::Uuid;

    #[test]
    fn dns_targets_skip_unavailable_ipv6_and_never_mix_families() {
        let target = TargetParams {
            ip: "example.com".into(),
            port: "443".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let resolved = vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];

        let ipv4_only = dns_port_targets(&resolved, &target, true, false);
        assert_eq!(ipv4_only.len(), 1);
        assert_eq!(ipv4_only[0].address_family, "ipv4");
        assert_eq!(ipv4_only[0].ip, "192.0.2.10");

        let dual_stack = dns_port_targets(&resolved, &target, true, true);
        assert_eq!(dual_stack.len(), 2);
        assert_eq!(dual_stack[0].ip, "192.0.2.10");
        assert_eq!(dual_stack[1].ip, "2001:db8::10");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn port_only_plan_never_invokes_service_engine() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-port-only-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(&path, "#!/bin/sh\nprintf 'open tcp 443 192.0.2.1 1\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = TargetParams {
            ip: "192.0.2.1".into(),
            port: "443".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let service = ServiceDetectionConfig {
            enabled: true,
            zgrab_path: "/definitely/not/invoked".into(),
            ..ServiceDetectionConfig::default()
        };
        let plan = ScanPlan {
            version: SCAN_PLAN_VERSION,
            profile: "port_only".into(),
            stages: vec![ScanStageSpec {
                kind: ScanStageKind::PortDiscovery,
                required: true,
            }],
        };

        let outcome = run_scan(
            ScanRuntimeConfig {
                journal: None,
                scanner_path: path.to_str().unwrap(),
                masscan: &MasscanConfig {
                    output_mode: crate::types::MasscanOutputMode::StandardList,
                    ..Default::default()
                },
                service_detection: &service,
                dns: &DnsConfig::default(),
                nuclei: &NucleiConfig::default(),
                dns_resolvers: &[],
                ipv4_ready: true,
                ipv6_ready: false,
            },
            &plan,
            &target,
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let ScanOutcome::Completed(results) = outcome else {
            panic!("port-only scan must complete");
        };
        assert_eq!(results.len(), 1);
        let ScanObservation::Port(port) = &results[0] else {
            panic!("port-only plan must produce a port observation");
        };
        assert_eq!(port.port, 443);
        assert_eq!(port.observed_at, 1000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_plan_preserves_local_required_failure_policy() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "scanner-rs-legacy-required-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::write(&path, "#!/bin/sh\nprintf 'open tcp 443 192.0.2.1 1\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = TargetParams {
            ip: "192.0.2.1".into(),
            port: "443".into(),
            rate: 100,
            address_family: "ipv4".into(),
        };
        let service = ServiceDetectionConfig {
            enabled: true,
            required: true,
            zgrab_path: "/definitely/missing/zgrab2".into(),
            ..ServiceDetectionConfig::default()
        };
        let plan: ScanPlan = serde_json::from_value(serde_json::json!({
            "version": 1,
            "profile": "legacy",
            "stages": [
                {"type": "port_discovery", "required": true},
                {"type": "service_detection", "required": false}
            ]
        }))
        .unwrap();

        let result = run_scan(
            ScanRuntimeConfig {
                journal: None,
                scanner_path: path.to_str().unwrap(),
                masscan: &MasscanConfig::default(),
                service_detection: &service,
                dns: &DnsConfig::default(),
                nuclei: &NucleiConfig::default(),
                dns_resolvers: &[],
                ipv4_ready: true,
                ipv6_ready: false,
            },
            &plan,
            &target,
            &AtomicBool::new(false),
        )
        .await;
        std::fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
