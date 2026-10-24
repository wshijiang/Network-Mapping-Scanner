use crate::error::ScannerError;
use crate::types::{DnsConfig, NucleiConfig, ServiceDetectionConfig};

pub(crate) const SCAN_PLAN_VERSION: u16 = 1;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct ScanPlan {
    #[serde(default)]
    pub(crate) service_probe_options: crate::types::ServiceProbeOptions,
    #[serde(default)]
    pub(crate) required_services: Vec<String>,
    pub(crate) version: u16,
    pub(crate) profile: String,
    pub(crate) stages: Vec<ScanStageSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct ScanStageSpec {
    #[serde(rename = "type")]
    pub(crate) kind: ScanStageKind,
    pub(crate) required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanStageKind {
    PortDiscovery,
    ServiceDetection,
    DnsLookup,
    VulnerabilityDetection,
}

impl ScanStageKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::PortDiscovery => "port_discovery",
            Self::ServiceDetection => "service_detection",
            Self::DnsLookup => "dns_lookup",
            Self::VulnerabilityDetection => "vulnerability_detection",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScanCapabilities {
    pub(crate) plan_versions: Vec<u16>,
    pub(crate) profiles: Vec<&'static str>,
    pub(crate) stages: Vec<&'static str>,
    pub(crate) explicit_dns_resolvers: bool,
    pub(crate) max_service_probes: usize,
    pub(crate) service_protocols: Vec<&'static str>,
}

impl ScanCapabilities {
    pub(crate) fn from_config(
        service: &ServiceDetectionConfig,
        dns: &DnsConfig,
        nuclei: &NucleiConfig,
    ) -> Self {
        let mut profiles = vec!["legacy", "port_only"];
        let mut stages = vec!["port_discovery"];
        if service.enabled {
            profiles.extend(["service_inventory", "udp_inventory", "udp_passive"]);
            stages.push("service_detection");
        }
        if dns.enabled {
            profiles.extend(["dns_records", "dns_ports", "dns_full"]);
            stages.push("dns_lookup");
        }
        if nuclei.enabled {
            profiles.push("vulnerability_scan");
            stages.push("vulnerability_detection");
        }
        Self {
            plan_versions: vec![SCAN_PLAN_VERSION, 2],
            profiles,
            stages,
            explicit_dns_resolvers: dns.enabled,
            max_service_probes: if service.enabled {
                service.max_probes_per_endpoint
            } else {
                0
            },
            service_protocols: if service.enabled {
                vec![
                    "dns",
                    "vnc",
                    "dot",
                    "doh",
                    "modbus",
                    "enip",
                    "s7",
                    "opcua",
                    "mqtt",
                    "mqtts",
                    "dns_udp",
                    "enip_udp",
                    "bacnet",
                    "opcua_pubsub",
                    "enip_io",
                ]
            } else {
                vec![]
            },
        }
    }
}

impl ScanPlan {
    pub(crate) fn legacy(service: &ServiceDetectionConfig) -> Self {
        let mut stages = vec![ScanStageSpec {
            kind: ScanStageKind::PortDiscovery,
            required: true,
        }];
        if service.enabled {
            stages.push(ScanStageSpec {
                kind: ScanStageKind::ServiceDetection,
                required: service.required,
            });
        }
        Self {
            service_probe_options: Default::default(),
            required_services: Vec::new(),
            version: SCAN_PLAN_VERSION,
            profile: "legacy".into(),
            stages,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ScannerError> {
        self.service_probe_options
            .validate()
            .map_err(ScannerError::Scan)?;
        if self.profile == "udp_passive" {
            super::engines::passive::validate_options(&self.service_probe_options)?;
            if self.version != 2
                || self.stages.len() != 1
                || self.stages[0].kind != ScanStageKind::ServiceDetection
                || !self.stages[0].required
                || self.required_services.is_empty()
                || self.required_services.len() > 2
                || self
                    .required_services
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != self.required_services.len()
                || self
                    .required_services
                    .iter()
                    .any(|s| !matches!(s.as_str(), "opcua_pubsub" | "enip_io"))
            {
                return Err(ScannerError::Scan("invalid UDP passive plan".into()));
            }
            return Ok(());
        }
        if self.service_probe_options.passive_bind.is_some()
            || self.service_probe_options.passive_group.is_some()
            || self.service_probe_options.passive_interface.is_some()
            || self.service_probe_options.passive_window_seconds.is_some()
        {
            return Err(ScannerError::Scan(
                "passive options require udp_passive profile".into(),
            ));
        }
        if self.profile == "udp_inventory" {
            if self.version != 2
                || self.stages.len() != 1
                || self.stages[0].kind != ScanStageKind::ServiceDetection
                || !self.stages[0].required
                || self.required_services.is_empty()
                || self.required_services.len() > 3
                || self
                    .required_services
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != self.required_services.len()
                || self
                    .required_services
                    .iter()
                    .any(|s| !matches!(s.as_str(), "dns_udp" | "enip_udp" | "bacnet"))
                || self.service_probe_options != crate::types::ServiceProbeOptions::default()
            {
                return Err(ScannerError::Scan(
                    "invalid version 2 UDP inventory plan".into(),
                ));
            }
            return Ok(());
        }
        if self
            .required_services
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != self.required_services.len()
            || self.required_services.len() > 10
            || self.required_services.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "dns"
                        | "vnc"
                        | "dot"
                        | "doh"
                        | "modbus"
                        | "enip"
                        | "s7"
                        | "opcua"
                        | "mqtt"
                        | "mqtts"
                )
            })
            || (!self.required_services.is_empty()
                && !self
                    .stages
                    .iter()
                    .any(|s| s.kind == ScanStageKind::ServiceDetection))
        {
            return Err(ScannerError::Scan(
                "unsupported required service protocols".into(),
            ));
        }
        if self.version != SCAN_PLAN_VERSION {
            return Err(ScannerError::Scan(format!(
                "unsupported scan plan version {}; expected {}",
                self.version, SCAN_PLAN_VERSION
            )));
        }
        if !matches!(
            self.profile.as_str(),
            "legacy"
                | "port_only"
                | "service_inventory"
                | "vulnerability_scan"
                | "dns_records"
                | "dns_ports"
                | "dns_full"
        ) {
            return Err(ScannerError::Scan(format!(
                "unsupported scan profile '{}'",
                self.profile
            )));
        }
        let port_discovery_count = self
            .stages
            .iter()
            .filter(|stage| stage.kind == ScanStageKind::PortDiscovery)
            .count();
        let service_detection_count = self
            .stages
            .iter()
            .filter(|stage| stage.kind == ScanStageKind::ServiceDetection)
            .count();
        let dns_lookup_count = self
            .stages
            .iter()
            .filter(|stage| stage.kind == ScanStageKind::DnsLookup)
            .count();
        let vulnerability_count = self
            .stages
            .iter()
            .filter(|stage| stage.kind == ScanStageKind::VulnerabilityDetection)
            .count();
        if self.stages.is_empty()
            || (matches!(
                self.profile.as_str(),
                "dns_records" | "dns_ports" | "dns_full"
            ) && (dns_lookup_count != 1
                || port_discovery_count != usize::from(self.profile != "dns_records")
                || service_detection_count != 0
                || vulnerability_count != 0))
            || (!matches!(
                self.profile.as_str(),
                "dns_records" | "dns_ports" | "dns_full"
            ) && (self.stages[0].kind != ScanStageKind::PortDiscovery
                || port_discovery_count != 1
                || service_detection_count > 1
                || dns_lookup_count != 0
                || vulnerability_count > 1))
        {
            return Err(ScannerError::Scan(
                "scan plan has unsupported stage ordering or duplication".into(),
            ));
        }
        match self.profile.as_str() {
            "port_only" if self.stages.len() != 1 => {
                return Err(ScannerError::Scan(
                    "port_only profile may contain only port_discovery".into(),
                ));
            }
            "service_inventory"
                if self.stages.len() != 2
                    || self.stages[1].kind != ScanStageKind::ServiceDetection
                    || !self.stages[1].required =>
            {
                return Err(ScannerError::Scan(
                    "service_inventory profile requires port_discovery followed by required service_detection".into(),
                ));
            }
            "vulnerability_scan"
                if self.stages.len() != 3
                    || self.stages[0].kind != ScanStageKind::PortDiscovery
                    || self.stages[1].kind != ScanStageKind::ServiceDetection
                    || self.stages[1].required
                    || self.stages[2].kind != ScanStageKind::VulnerabilityDetection
                    || !self.stages[2].required =>
            {
                return Err(ScannerError::Scan(
                    "vulnerability_scan requires port discovery, optional service detection, and required vulnerability detection".into(),
                ));
            }
            "dns_records"
                if self.stages.len() != 1 || self.stages[0].kind != ScanStageKind::DnsLookup =>
            {
                return Err(ScannerError::Scan(
                    "dns_records profile requires only dns_lookup".into(),
                ));
            }
            "dns_ports" | "dns_full"
                if self.stages.len() != 2
                    || self.stages[0].kind != ScanStageKind::DnsLookup
                    || self.stages[1].kind != ScanStageKind::PortDiscovery =>
            {
                return Err(ScannerError::Scan(
                    "DNS port profiles require dns_lookup followed by port_discovery".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_supported_linear_plan() {
        let plan: ScanPlan = serde_json::from_value(serde_json::json!({
            "version": 1,
            "profile": "port_only",
            "stages": [{"type": "port_discovery", "required": true}]
        }))
        .unwrap();
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn validates_dns_only_plan() {
        let plan: ScanPlan = serde_json::from_value(serde_json::json!({
            "version": 1,
            "profile": "dns_records",
            "stages": [{"type": "dns_lookup", "required": true}]
        }))
        .unwrap();
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn validates_dns_then_port_plans() {
        for profile in ["dns_ports", "dns_full"] {
            let plan: ScanPlan = serde_json::from_value(serde_json::json!({
                "version": 1,
                "profile": profile,
                "stages": [
                    {"type": "dns_lookup", "required": true},
                    {"type": "port_discovery", "required": true}
                ]
            }))
            .unwrap();
            assert!(plan.validate().is_ok());
        }
    }

    #[test]
    fn rejects_out_of_order_or_future_plans() {
        let mut plan = ScanPlan {
            service_probe_options: Default::default(),
            required_services: Vec::new(),
            version: 2,
            profile: "port_only".into(),
            stages: vec![],
        };
        assert!(plan.validate().is_err());
        plan.version = 1;
        assert!(plan.validate().is_err());

        plan.profile = "port_only".into();
        plan.stages = vec![
            ScanStageSpec {
                kind: ScanStageKind::PortDiscovery,
                required: true,
            },
            ScanStageSpec {
                kind: ScanStageKind::ServiceDetection,
                required: false,
            },
        ];
        assert!(plan.validate().is_err());
    }

    #[test]
    fn capabilities_follow_local_engine_configuration() {
        let default_capabilities = ScanCapabilities::from_config(
            &ServiceDetectionConfig::default(),
            &DnsConfig::default(),
            &NucleiConfig::default(),
        );
        assert!(default_capabilities.profiles.contains(&"port_only"));
        assert!(default_capabilities.profiles.contains(&"dns_records"));
        assert!(!default_capabilities.profiles.contains(&"service_inventory"));
        assert!(default_capabilities.explicit_dns_resolvers);

        let service = ServiceDetectionConfig {
            enabled: true,
            ..ServiceDetectionConfig::default()
        };
        let inventory = ScanCapabilities::from_config(
            &service,
            &DnsConfig::default(),
            &NucleiConfig::default(),
        );
        assert!(inventory.profiles.contains(&"service_inventory"));

        let dns = DnsConfig {
            enabled: true,
            ..DnsConfig::default()
        };
        let dns_capabilities = ScanCapabilities::from_config(
            &ServiceDetectionConfig::default(),
            &dns,
            &NucleiConfig::default(),
        );
        assert!(dns_capabilities.profiles.contains(&"dns_records"));
        assert!(dns_capabilities.profiles.contains(&"dns_ports"));
        assert!(dns_capabilities.profiles.contains(&"dns_full"));

        let nuclei = NucleiConfig {
            enabled: true,
            ..NucleiConfig::default()
        };
        let vulnerability_capabilities = ScanCapabilities::from_config(
            &ServiceDetectionConfig::default(),
            &DnsConfig::default(),
            &nuclei,
        );
        assert!(
            vulnerability_capabilities
                .profiles
                .contains(&"vulnerability_scan")
        );
        assert!(
            vulnerability_capabilities
                .stages
                .contains(&"vulnerability_detection")
        );
    }
}
