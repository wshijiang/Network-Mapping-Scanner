use super::engines::{dns, masscan, nuclei, zgrab2};
use super::observation::ScanObservation;
use super::plan::{ScanPlan, ScanStageKind};
use crate::error::ScannerError;
use crate::types::{DnsConfig, MasscanConfig, NucleiConfig, ServiceDetectionConfig, TargetParams};
use std::sync::atomic::AtomicBool;

pub(crate) enum ScanOutcome {
    // Keep DNS evidence even when dns_ports omits DNS from the result stream.
    Completed(
        Vec<ScanObservation>,
        Vec<super::observation::DnsObservation>,
    ),
    Cancelled,
}

pub(crate) struct ScanRuntimeConfig<'a> {
    pub(crate) environment: Option<&'a crate::modules::registry::Environment>,
    pub(crate) modules_config: Option<&'a crate::modules::ModulesConfig>,
    pub(crate) registry: Option<&'a crate::modules::registry::Registry>,
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
    config: ScanRuntimeConfig<'_>,
    plan: &ScanPlan,
    target: &TargetParams,
    cancel_requested: &AtomicBool,
) -> Result<ScanOutcome, ScannerError> {
    plan.validate()?;
    if plan.required_services.len() > config.service_detection.max_probes_per_endpoint {
        return Err(ScannerError::Scan(
            "required service probes exceed endpoint budget".into(),
        ));
    }
    let mut service_detection = config.service_detection.clone();
    service_detection.required_services = plan.required_services.clone();
    service_detection.probe_options = plan.service_probe_options.clone();
    let mut config = ScanRuntimeConfig {
        service_detection: &service_detection,
        ..config
    };
    let mut ports = if matches!(plan.profile.as_str(), "udp_inventory" | "udp_passive") {
        super::engines::udp::targets(target)?
    } else {
        Vec::new()
    };
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
                    match run_ports(&mut config, &port_target, cancel_requested)
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
                match run_services(&mut config, &ports, target, cancel_requested).await {
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
                match run_dns(&mut config, target, cancel_requested)
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
                match run_vulnerabilities(&mut config, &ports, &services, target, cancel_requested)
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
        observations.extend(dns_observations.iter().cloned().map(ScanObservation::Dns));
    }
    observations.extend(
        ports
            .into_iter()
            .filter(|p| p.source != "udp_target")
            .map(ScanObservation::Port),
    );
    observations.extend(services.into_iter().map(ScanObservation::Service));
    observations.extend(
        vulnerabilities
            .into_iter()
            .map(ScanObservation::Vulnerability),
    );
    let mut identities = std::collections::HashSet::new();
    observations.retain(|o| identities.insert(o.identity()));
    Ok(ScanOutcome::Completed(observations, dns_observations))
}

async fn module_stage(
    config: &mut ScanRuntimeConfig<'_>,
    stage: ScanStageKind,
    target: &TargetParams,
    input: Vec<ScanObservation>,
    cancel: &AtomicBool,
) -> Result<crate::modules::host::StageResult, ScannerError> {
    let environment = config
        .environment
        .ok_or_else(|| ScannerError::Scan("module environment missing".into()))?;
    let spec = environment
        .modules
        .get(stage.name())
        .ok_or_else(|| ScannerError::Scan(format!("module {} unavailable", stage.name())))?;
    let settings = config
        .modules_config
        .ok_or_else(|| ScannerError::Scan("module configuration missing".into()))?;
    let request = crate::modules::protocol::Request {
        id: uuid::Uuid::now_v7(),
        stage,
        target: target.clone(),
        engine_path: spec
            .engine_path
            .as_ref()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned()),
        masscan: config.masscan.clone(),
        service: config.service_detection.clone(),
        dns: config.dns.clone(),
        nuclei: config.nuclei.clone(),
        resolvers: config.dns_resolvers.to_vec(),
        checkpoint: if stage == ScanStageKind::ServiceDetection {
            config
                .journal
                .as_ref()
                .map_or_else(Default::default, |j| j.state.clone())
        } else {
            Default::default()
        },
    };
    let journal = if stage == ScanStageKind::ServiceDetection {
        config.journal.as_mut()
    } else {
        None
    };
    let result = crate::modules::host::execute(
        spec,
        request,
        input,
        journal,
        cancel,
        std::time::Duration::from_secs(settings.stage_timeout_seconds),
        std::time::Duration::from_secs(settings.cancel_grace_seconds),
    )
    .await;
    process_worker_result(
        stage,
        result,
        config.registry,
        environment.generation,
        cancel.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// Validate the entire result before a Completed outcome can reset health.
/// A well-formed observation for another stage is a worker protocol failure.
pub(crate) fn process_worker_result(
    stage: ScanStageKind,
    result: Result<crate::modules::host::StageResult, ScannerError>,
    registry: Option<&crate::modules::registry::Registry>,
    generation: i64,
    cancelled: bool,
) -> Result<crate::modules::host::StageResult, ScannerError> {
    let result = result.and_then(|result| {
        let valid = result.observations.iter().all(|observation| {
            matches!(
                (stage, observation),
                (ScanStageKind::PortDiscovery, ScanObservation::Port(_))
                    | (ScanStageKind::ServiceDetection, ScanObservation::Service(_))
                    | (ScanStageKind::DnsLookup, ScanObservation::Dns(_))
                    | (
                        ScanStageKind::VulnerabilityDetection,
                        ScanObservation::Vulnerability(_)
                    )
            )
        });
        if valid {
            Ok(result)
        } else {
            Err(ScannerError::Scan(format!(
                "worker observation kind rejected for {}",
                stage.name()
            )))
        }
    });
    if !cancelled && let Some(registry) = registry {
        let unsafe_failure = match &result {
            Err(ScannerError::Io(error)) => matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::PermissionDenied
            ),
            Err(ScannerError::Json(_)) => true,
            Err(ScannerError::Scan(error)) => {
                error.contains("worker")
                    && (error.contains("limit")
                        || error.contains("rejected")
                        || error.contains("handshake")
                        || error.contains("identity/order"))
            }
            _ => false,
        };
        if unsafe_failure
            || result
                .as_ref()
                .is_ok_and(|r| r.outcome == crate::modules::protocol::Outcome::Completed)
        {
            registry.observe_worker(generation, stage.name(), unsafe_failure)?;
        }
    }
    result
}

fn stage_failed(result: &crate::modules::host::StageResult) -> ScannerError {
    ScannerError::Scan(
        result
            .error
            .clone()
            .unwrap_or_else(|| "worker stage failed".into()),
    )
}
fn invalid_output() -> ScannerError {
    ScannerError::Scan("worker returned an observation for the wrong stage".into())
}

async fn run_ports(
    config: &mut ScanRuntimeConfig<'_>,
    target: &TargetParams,
    cancel: &AtomicBool,
) -> Result<masscan::EngineOutcome, ScannerError> {
    if config.environment.is_none() {
        return masscan::run(config.scanner_path, config.masscan, target, cancel).await;
    }
    let result = module_stage(
        config,
        ScanStageKind::PortDiscovery,
        target,
        Vec::new(),
        cancel,
    )
    .await?;
    use crate::modules::protocol::Outcome;
    match result.outcome {
        Outcome::Cancelled => Ok(masscan::EngineOutcome::Cancelled),
        Outcome::Completed => Ok(masscan::EngineOutcome::Completed(
            result
                .observations
                .into_iter()
                .map(|o| {
                    if let ScanObservation::Port(p) = o {
                        Ok(p)
                    } else {
                        Err(invalid_output())
                    }
                })
                .collect::<Result<_, _>>()?,
        )),
        _ => Err(stage_failed(&result)),
    }
}
async fn run_services(
    config: &mut ScanRuntimeConfig<'_>,
    ports: &[crate::scan::PortObservation],
    target: &TargetParams,
    cancel: &AtomicBool,
) -> Result<zgrab2::EngineOutcome, ScannerError> {
    if config.environment.is_none() {
        return zgrab2::run_with_journal(
            config.service_detection,
            ports,
            &target.address_family,
            cancel,
            config.journal.as_mut(),
        )
        .await;
    }
    let result = module_stage(
        config,
        ScanStageKind::ServiceDetection,
        target,
        ports.iter().cloned().map(ScanObservation::Port).collect(),
        cancel,
    )
    .await?;
    use crate::modules::protocol::Outcome;
    if result.outcome == Outcome::Cancelled {
        return Ok(zgrab2::EngineOutcome::Cancelled);
    }
    if result.outcome == Outcome::Failed {
        return Err(stage_failed(&result));
    }
    let observations = result
        .observations
        .into_iter()
        .map(|o| {
            if let ScanObservation::Service(s) = o {
                Ok(s)
            } else {
                Err(invalid_output())
            }
        })
        .collect::<Result<_, _>>()?;
    Ok(if result.outcome == Outcome::Partial {
        zgrab2::EngineOutcome::Partial(
            observations,
            result
                .error
                .unwrap_or_else(|| "service_detection_incomplete".into()),
        )
    } else {
        zgrab2::EngineOutcome::Completed(observations)
    })
}
async fn run_dns(
    config: &mut ScanRuntimeConfig<'_>,
    target: &TargetParams,
    cancel: &AtomicBool,
) -> Result<Option<dns::DnsLookupResult>, ScannerError> {
    if config.environment.is_none() {
        return dns::run(config.dns, target, config.dns_resolvers, cancel).await;
    }
    let result = module_stage(config, ScanStageKind::DnsLookup, target, Vec::new(), cancel).await?;
    use crate::modules::protocol::Outcome;
    if result.outcome == Outcome::Cancelled {
        return Ok(None);
    }
    if result.outcome != Outcome::Completed {
        return Err(stage_failed(&result));
    }
    let observations: Vec<_> = result
        .observations
        .into_iter()
        .map(|o| {
            if let ScanObservation::Dns(d) = o {
                Ok(d)
            } else {
                Err(invalid_output())
            }
        })
        .collect::<Result<_, _>>()?;
    let resolved_ips = observations
        .iter()
        .flat_map(|d| &d.answers)
        .filter(|a| matches!(a.record_type.as_str(), "A" | "AAAA"))
        .filter_map(|a| a.value.parse().ok())
        .collect();
    Ok(Some(dns::DnsLookupResult {
        observations,
        resolved_ips,
    }))
}
async fn run_vulnerabilities(
    config: &mut ScanRuntimeConfig<'_>,
    ports: &[crate::scan::PortObservation],
    services: &[crate::scan::ServiceObservation],
    target: &TargetParams,
    cancel: &AtomicBool,
) -> Result<nuclei::EngineOutcome, ScannerError> {
    if config.environment.is_none() {
        return nuclei::run(config.nuclei, ports, services, cancel).await;
    }
    let input = ports
        .iter()
        .cloned()
        .map(ScanObservation::Port)
        .chain(services.iter().cloned().map(ScanObservation::Service))
        .collect();
    let result = module_stage(
        config,
        ScanStageKind::VulnerabilityDetection,
        target,
        input,
        cancel,
    )
    .await?;
    use crate::modules::protocol::Outcome;
    match result.outcome {
        Outcome::Cancelled => Ok(nuclei::EngineOutcome::Cancelled),
        Outcome::Completed => Ok(nuclei::EngineOutcome::Completed(
            result
                .observations
                .into_iter()
                .map(|o| {
                    if let ScanObservation::Vulnerability(v) = o {
                        Ok(v)
                    } else {
                        Err(invalid_output())
                    }
                })
                .collect::<Result<_, _>>()?,
        )),
        _ => Err(stage_failed(&result)),
    }
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
    #[test]
    fn worker_results_validate_every_observation_kind_before_success() {
        use super::*;
        use crate::modules::{host::StageResult, protocol::Outcome};
        let observations: Vec<ScanObservation> = vec![
            serde_json::json!({"kind":"port","ip":"192.0.2.1","port":22,"protocol":"tcp","state":"open","source":"test","observed_at":1}),
            serde_json::json!({"kind":"service","ip":"192.0.2.1","port":22,"protocol":"tcp","service":"ssh","source":"test","observed_at":1}),
            serde_json::json!({"kind":"dns","question":{"name":"example.com","type":"A"},"response_code":"NOERROR","observed_at":1}),
            serde_json::json!({"kind":"vulnerability","ip":"192.0.2.1","port":22,"protocol":"tcp","template_id":"test","name":"test","severity":"low","matched_at":"192.0.2.1:22","source":"test","observed_at":1}),
        ].into_iter().map(|value| serde_json::from_value(value).unwrap()).collect();
        let stages = [
            ScanStageKind::PortDiscovery,
            ScanStageKind::ServiceDetection,
            ScanStageKind::DnsLookup,
            ScanStageKind::VulnerabilityDetection,
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            for (observation_index, observation) in observations.iter().enumerate() {
                let result = process_worker_result(
                    stage,
                    Ok(StageResult {
                        outcome: Outcome::Completed,
                        observations: vec![observation.clone()],
                        error: None,
                    }),
                    None,
                    1,
                    false,
                );
                assert_eq!(
                    result.is_ok(),
                    index == observation_index,
                    "{} returned variant {observation_index}",
                    stage.name()
                );
            }
            assert!(
                process_worker_result(
                    stage,
                    Ok(StageResult {
                        outcome: Outcome::Completed,
                        observations: Vec::new(),
                        error: None
                    }),
                    None,
                    1,
                    false
                )
                .is_ok()
            );
        }
        // A valid first item must not hide a later wrong-stage observation.
        assert!(
            process_worker_result(
                ScanStageKind::PortDiscovery,
                Ok(StageResult {
                    outcome: Outcome::Completed,
                    observations: observations[..2].to_vec(),
                    error: None
                }),
                None,
                1,
                false
            )
            .is_err()
        );
        assert!(
            process_worker_result(
                ScanStageKind::ServiceDetection,
                Ok(StageResult {
                    outcome: Outcome::Partial,
                    observations: vec![observations[0].clone()],
                    error: Some("incomplete".into())
                }),
                None,
                1,
                false
            )
            .is_err()
        );
    }

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
            strategy: crate::types::ServiceDetectionStrategy::Standard,
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
                    environment: None,
                    modules_config: None,
                    registry: None,
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
                let super::ScanOutcome::Completed(results, _) = result.unwrap() else {
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
            service_probe_options: Default::default(),
            required_services: Vec::new(),
            version: SCAN_PLAN_VERSION,
            profile: "port_only".into(),
            stages: vec![ScanStageSpec {
                kind: ScanStageKind::PortDiscovery,
                required: true,
            }],
        };

        let outcome = run_scan(
            ScanRuntimeConfig {
                environment: None,
                modules_config: None,
                registry: None,
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
        let ScanOutcome::Completed(results, _) = outcome else {
            panic!("port-only scan must complete");
        };
        assert_eq!(results.len(), 1);
        let ScanObservation::Port(port) = &results[0] else {
            panic!("port-only plan must produce a port observation");
        };
        assert_eq!(port.port, 443);
        assert_eq!(port.observed_at, 1000);
    }

    #[tokio::test]
    async fn recovered_dns_ports_keep_resolution_evidence_outside_the_result_stream() {
        let directory =
            std::env::temp_dir().join(format!("scanner-dns-quality-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let store = crate::storage::StateStore::open(directory.join("state.sqlite3")).unwrap();
        let mut journal =
            crate::journal::ScanJournal::open(&store, "origin", "quality-task".into()).unwrap();
        let dns:ScanObservation=serde_json::from_value(serde_json::json!({"kind":"dns","observed_at":1,"question":{"name":"example.com","type":"A","class":"IN"},"response_code":"NOERROR","answers":[{"type":"A","value":"192.0.2.1","ttl":60}]})).unwrap();
        let port:ScanObservation=serde_json::from_value(serde_json::json!({"kind":"port","ip":"192.0.2.1","port":443,"protocol":"tcp","state":"open","source":"masscan","observed_at":1})).unwrap();
        journal.save(2, 0, 100, Some(&[dns, port])).unwrap();
        drop(journal);
        let journal =
            crate::journal::ScanJournal::open(&store, "origin", "quality-task".into()).unwrap();
        let plan = ScanPlan {
            service_probe_options: Default::default(),
            required_services: Vec::new(),
            version: SCAN_PLAN_VERSION,
            profile: "dns_ports".into(),
            stages: vec![
                ScanStageSpec {
                    kind: ScanStageKind::DnsLookup,
                    required: true,
                },
                ScanStageSpec {
                    kind: ScanStageKind::PortDiscovery,
                    required: true,
                },
            ],
        };
        let target = TargetParams {
            ip: "example.com".into(),
            port: "443".into(),
            rate: 1,
            address_family: "ipv4".into(),
        };
        let result = run_scan(
            ScanRuntimeConfig {
                environment: None,
                modules_config: None,
                registry: None,
                journal: Some(journal),
                scanner_path: "unused",
                masscan: &MasscanConfig::default(),
                service_detection: &ServiceDetectionConfig::default(),
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
        let ScanOutcome::Completed(observations, resolutions) = result else {
            panic!("checkpoint must complete")
        };
        assert_eq!(observations.len(), 1);
        assert!(matches!(observations[0], ScanObservation::Port(_)));
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].question.name, "example.com");
        assert_eq!(resolutions[0].answers[0].value, "192.0.2.1");
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
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
                environment: None,
                modules_config: None,
                registry: None,
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
