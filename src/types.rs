use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use uuid::Uuid;

// ---- Cache data model ---------------------------------------------------

/// In-memory view of scan results durably stored in SQLite until flushed.
#[derive(Default)]
pub(crate) struct CacheManager {
    pub(crate) store: Option<crate::storage::StateStore>,
    pub(crate) server_origin: String,
    pub(crate) scanner_id: String,
    pub(crate) identities: HashSet<String>,
    pub(crate) task_id: Option<Uuid>,
    pub(crate) upload_id: Option<Uuid>,
    pub(crate) observations: Vec<crate::scan::ScanObservation>,
    pub(crate) next_batch_index: u32,
}

#[derive(serde::Deserialize)]
struct LegacyCacheState {
    task_id: Option<Uuid>,
    upload_id: Option<Uuid>,
    observations: Vec<crate::scan::ScanObservation>,
    next_batch_index: u32,
}

impl CacheManager {
    pub(crate) fn save_runtime_configuration(
        &self,
        configuration: &crate::runtime_config::RuntimeConfigurationEnvelope,
    ) -> Result<(), crate::error::ScannerError> {
        self.store
            .as_ref()
            .ok_or_else(|| crate::error::ScannerError::Config("state store is unavailable".into()))?
            .save_runtime_configuration(&self.server_origin, configuration)
    }

    pub(crate) fn legacy_state_has_pending(
        path: &std::path::Path,
    ) -> Result<bool, crate::error::ScannerError> {
        if !path.exists() {
            return Ok(false);
        }
        let bytes = std::fs::read(path).map_err(crate::error::ScannerError::Io)?;
        let legacy: LegacyCacheState = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::ScannerError::Config(format!(
                "failed to parse legacy scanner state {}: {error}",
                path.display()
            ))
        })?;
        Ok(legacy.task_id.is_some())
    }

    pub(crate) fn load(
        mut store: crate::storage::StateStore,
        server_origin: String,
        scanner_id: String,
        legacy_state_file: PathBuf,
    ) -> Result<Self, crate::error::ScannerError> {
        let mut stored = store.load_upload(&server_origin, &scanner_id)?;
        if stored.is_none() && legacy_state_file.exists() {
            let bytes =
                std::fs::read(&legacy_state_file).map_err(crate::error::ScannerError::Io)?;
            let legacy: LegacyCacheState = serde_json::from_slice(&bytes).map_err(|error| {
                crate::error::ScannerError::Config(format!(
                    "failed to parse legacy scanner state {}: {error}",
                    legacy_state_file.display()
                ))
            })?;
            if let Some(task_id) = legacy.task_id {
                let upload_id = legacy.upload_id.ok_or_else(|| {
                    crate::error::ScannerError::Config(
                        "legacy scanner state has a task_id but no upload_id".into(),
                    )
                })?;
                let upload = crate::storage::StoredUpload {
                    scanner_id: scanner_id.clone(),
                    task_id,
                    upload_id,
                    next_batch_index: legacy.next_batch_index,
                    observations: legacy.observations,
                };
                store.import_upload(&server_origin, &upload)?;
                stored = Some(upload);
            } else if legacy.upload_id.is_some()
                || !legacy.observations.is_empty()
                || legacy.next_batch_index != 0
            {
                return Err(crate::error::ScannerError::Config(
                    "legacy scanner state has upload data but no task_id".into(),
                ));
            }
            archive_legacy_state(&legacy_state_file);
        }

        let (task_id, upload_id, next_batch_index, observations) = stored.map_or_else(
            || (None, None, 0, Vec::new()),
            |upload| {
                (
                    Some(upload.task_id),
                    Some(upload.upload_id),
                    upload.next_batch_index,
                    upload.observations,
                )
            },
        );
        let identities = observations
            .iter()
            .map(crate::scan::ScanObservation::identity)
            .collect();
        Ok(Self {
            store: Some(store),
            server_origin,
            scanner_id,
            identities,
            task_id,
            upload_id,
            observations,
            next_batch_index,
        })
    }

    pub(crate) fn clear(&mut self) -> Result<(), crate::error::ScannerError> {
        if let Some(store) = self.store.as_mut() {
            store.clear_upload(&self.server_origin)?;
        }
        self.task_id = None;
        self.upload_id = None;
        self.identities.clear();
        self.observations.clear();
        self.next_batch_index = 0;
        Ok(())
    }
}

fn archive_legacy_state(path: &std::path::Path) {
    let archive = path.with_extension("json.migrated");
    if archive.exists() {
        tracing::warn!(
            legacy_state_path = %path.display(),
            archive_path = %archive.display(),
            "legacy scanner state was imported but could not be archived because the target exists"
        );
        return;
    }
    match std::fs::rename(path, &archive) {
        Ok(()) => tracing::info!(
            legacy_state_path = %path.display(),
            archive_path = %archive.display(),
            "legacy scanner state imported into SQLite"
        ),
        Err(error) => tracing::warn!(
            %error,
            legacy_state_path = %path.display(),
            "legacy scanner state was imported but could not be archived"
        ),
    }
}

/// Task assigned by the server.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AssignedTask {
    pub(crate) task_id: Uuid,
    pub(crate) task_target: Vec<String>,
    pub(crate) task_port: String,
    #[serde(default = "default_address_family")]
    pub(crate) address_family: String,
    #[serde(default)]
    pub(crate) scan_plan: Option<crate::scan::ScanPlan>,
    #[serde(default)]
    pub(crate) dns_resolvers: Vec<DnsResolver>,
    #[serde(default)]
    pub(crate) lease_expires_at_ms: Option<i64>,
    #[serde(default = "default_task_lease_ttl_ms")]
    pub(crate) lease_ttl_ms: u64,
}

/// A DNS server selected by the user for one task. DNS task configuration is
/// delivered by the control plane instead of being taken from the scanner's
/// host configuration, so a result can always be attributed to its source.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct DnsResolver {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) transport: String,
}

impl DnsResolver {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() || self.id.len() > 64 {
            return Err("DNS resolver id must contain 1 to 64 characters".into());
        }
        if self.label.trim().is_empty() || self.label.len() > 128 {
            return Err("DNS resolver label must contain 1 to 128 characters".into());
        }
        if self.ip.parse::<std::net::IpAddr>().is_err() {
            return Err("DNS resolver ip must be an IP address".into());
        }
        if self.port == 0 {
            return Err("DNS resolver port must be between 1 and 65535".into());
        }
        if !matches!(self.transport.as_str(), "udp" | "tcp") {
            return Err("DNS resolver transport must be udp or tcp".into());
        }
        Ok(())
    }
}

impl AssignedTask {
    pub(crate) fn validate_targets(&self) -> Result<(), String> {
        if self.scan_plan.as_ref().is_some_and(|plan| {
            matches!(
                plan.profile.as_str(),
                "dns_records" | "dns_ports" | "dns_full"
            )
        }) {
            if self.task_target.is_empty()
                || self
                    .task_target
                    .iter()
                    .any(|target| !is_valid_dns_domain(target))
            {
                return Err("DNS task contains an invalid domain target".into());
            }
            if self.dns_resolvers.len() > 8 {
                return Err("DNS task contains more than 8 resolvers".into());
            }
            let mut resolver_ids = std::collections::HashSet::new();
            for resolver in &self.dns_resolvers {
                resolver.validate()?;
                if !resolver_ids.insert(resolver.id.as_str()) {
                    return Err("DNS task contains duplicate resolver ids".into());
                }
            }
            return Ok(());
        }
        for target in &self.task_target {
            let address = target
                .split_once('/')
                .map_or(target.as_str(), |(address, _)| address)
                .trim();
            if address
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| address.octets()[0] == 0)
            {
                return Err(format!(
                    "task target {target} belongs to the non-routable 0.0.0.0/8 network"
                ));
            }
        }
        Ok(())
    }
}

fn is_valid_dns_domain(value: &str) -> bool {
    let value = value.trim();
    let value = value.strip_suffix('.').unwrap_or(value);
    let labels = value.split('.').collect::<Vec<_>>();
    let wire_length = 1 + labels.iter().map(|label| 1 + label.len()).sum::<usize>();
    !value.is_empty()
        && value.len() <= 253
        && labels.len() >= 2
        && wire_length <= 255
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn default_address_family() -> String {
    "ipv4".into()
}

fn default_task_lease_ttl_ms() -> u64 {
    90_000
}

/// Parameters passed to masscan after applying local scanner settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct TargetParams {
    pub(crate) ip: String,
    pub(crate) port: String,
    pub(crate) rate: i32,
    pub(crate) address_family: String,
}

pub(crate) const DNS_RECORD_TYPES: [&str; 12] = [
    "A", "AAAA", "CNAME", "NS", "MX", "PTR", "SRV", "TXT", "CAA", "SOA", "SVCB", "HTTPS",
];

pub(crate) fn is_supported_dns_record_type(value: &str) -> bool {
    DNS_RECORD_TYPES.contains(&value.trim().to_ascii_uppercase().as_str())
}

// ---- Upload payload -----------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannerResultBatchUpload {
    pub(crate) protocol_version: u16,
    pub(crate) scanner_id: Uuid,
    pub(crate) task_id: Uuid,
    pub(crate) upload_id: Uuid,
    pub(crate) batch_index: u32,
    pub(crate) is_final: bool,
    pub(crate) observations: Vec<crate::scan::ScanObservation>,
}

// ---- Configuration structures -------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct AppConfig {
    #[serde(default)]
    pub(crate) modules: crate::modules::ModulesConfig,
    pub(crate) scanner: ScannerConfig,
    pub(crate) upload: UploadConfig,
    #[serde(default)]
    pub(crate) network: NetworkConfig,
    #[serde(default)]
    pub(crate) service_detection: ServiceDetectionConfig,
    #[serde(default)]
    pub(crate) dns: DnsConfig,
    #[serde(default)]
    pub(crate) nuclei: NucleiConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(crate) struct NucleiConfig {
    pub(crate) port_fallback: bool,
    pub(crate) enabled: bool,
    pub(crate) path: String,
    pub(crate) templates_path: String,
    /// Optional immutable seed directory shipped with the Docker image.
    pub(crate) bundled_templates_path: String,
    /// Local startup setting; never enabled by a remote task configuration.
    pub(crate) update_templates: bool,
    pub(crate) template_update_timeout_seconds: u64,
    pub(crate) severities: Vec<String>,
    pub(crate) rate_limit: u32,
    pub(crate) bulk_size: usize,
    pub(crate) concurrency: usize,
    pub(crate) timeout_seconds: u64,
    pub(crate) retries: u8,
    pub(crate) max_runtime_seconds: u64,
    pub(crate) max_findings: usize,
    pub(crate) max_result_bytes: usize,
}

impl Default for NucleiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "nuclei".into(),
            port_fallback: true,
            templates_path: String::new(),
            bundled_templates_path: String::new(),
            update_templates: false,
            template_update_timeout_seconds: 300,
            severities: vec!["medium".into(), "high".into(), "critical".into()],
            rate_limit: 20,
            bulk_size: 5,
            concurrency: 5,
            timeout_seconds: 10,
            retries: 1,
            max_runtime_seconds: 1_800,
            max_findings: 10_000,
            max_result_bytes: 262_144,
        }
    }
}

pub(crate) fn default_batch_endpoints() -> usize {
    512
}
pub(crate) fn default_idle_timeout() -> u64 {
    120
}
pub(crate) fn default_service_runtime() -> u64 {
    1800
}

#[derive(Debug, PartialEq, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ServiceProbeOptions {
    pub(crate) modbus_unit_id: Option<u8>,
    pub(crate) s7_tsap: Option<u16>,
    pub(crate) mqtt_version: Option<u8>,
    pub(crate) server_name: Option<String>,
    pub(crate) doh_path: Option<String>,
    pub(crate) tls_ca_pem: Option<String>,
    pub(crate) passive_bind: Option<String>,
    pub(crate) passive_group: Option<String>,
    pub(crate) passive_interface: Option<String>,
    pub(crate) passive_window_seconds: Option<u16>,
}
impl ServiceProbeOptions {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.mqtt_version.is_some_and(|v| !matches!(v, 4 | 5)) {
            return Err("MQTT protocol version must be 4 (3.1.1) or 5".into());
        }

        if self.server_name.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 253
                || !s.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }) {
            return Err("invalid probe server name".into());
        }
        if self.doh_path.as_ref().is_some_and(|s| {
            s.len() > 256
                || !s.starts_with('/')
                || s.starts_with("//")
                || s.bytes()
                    .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b' '))
        }) {
            return Err("invalid DNS-over-HTTPS path".into());
        }
        if self.tls_ca_pem.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 65536
                || !s.contains("-----BEGIN CERTIFICATE-----")
                || s.contains("PRIVATE KEY")
        }) {
            return Err("invalid probe CA certificate".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(crate) struct ServiceDetectionConfig {
    pub(crate) probe_options: ServiceProbeOptions,
    /// Task-derived native probes, serialized to the versioned worker.
    pub(crate) required_services: Vec<String>,
    #[serde(default = "default_batch_endpoints")]
    pub(crate) batch_endpoints: usize,
    #[serde(default = "default_idle_timeout")]
    pub(crate) idle_timeout_seconds: u64,
    #[serde(default = "default_service_runtime")]
    pub(crate) max_runtime_seconds: u64,
    pub(crate) enabled: bool,
    pub(crate) required: bool,
    pub(crate) strategy: ServiceDetectionStrategy,
    pub(crate) max_probes_per_endpoint: usize,
    pub(crate) confidence_threshold: u8,
    pub(crate) zgrab_path: String,
    pub(crate) senders: u32,
    pub(crate) server_rate_limit: u32,
    pub(crate) connect_timeout_seconds: u64,
    pub(crate) target_timeout_seconds: u64,
    pub(crate) max_result_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceDetectionStrategy {
    Standard,
    #[default]
    Adaptive,
    Exhaustive,
}

impl ServiceDetectionStrategy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Adaptive => "adaptive",
            Self::Exhaustive => "exhaustive",
        }
    }
}

impl Default for ServiceDetectionConfig {
    fn default() -> Self {
        Self {
            probe_options: Default::default(),
            required_services: Vec::new(),
            batch_endpoints: default_batch_endpoints(),
            idle_timeout_seconds: default_idle_timeout(),
            max_runtime_seconds: default_service_runtime(),
            enabled: false,
            required: false,
            strategy: ServiceDetectionStrategy::Adaptive,
            max_probes_per_endpoint: 8,
            confidence_threshold: 80,
            zgrab_path: "zgrab2".into(),
            senders: 200,
            server_rate_limit: 20,
            connect_timeout_seconds: 5,
            target_timeout_seconds: 15,
            max_result_bytes: 65_536,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(crate) struct DnsConfig {
    pub(crate) enabled: bool,
    pub(crate) record_types: Vec<String>,
    pub(crate) query_timeout_seconds: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            record_types: DNS_RECORD_TYPES.iter().map(ToString::to_string).collect(),
            query_timeout_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(crate) struct NetworkConfig {
    pub(crate) ipv4_enabled: bool,
    pub(crate) ipv6_enabled: bool,
    pub(crate) ipv4_probe_url: String,
    pub(crate) ipv6_probe_url: String,
    pub(crate) probe_interval_seconds: u64,
    pub(crate) probe_timeout_seconds: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4_enabled: true,
            ipv6_enabled: true,
            ipv4_probe_url: "https://api.ipify.org?format=json".into(),
            ipv6_probe_url: "https://api6.ipify.org?format=json".into(),
            probe_interval_seconds: 300,
            probe_timeout_seconds: 5,
        }
    }
}

fn default_scanner_path() -> String {
    "./a".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MasscanOutputMode {
    #[default]
    Compatible,
    StandardList,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub(crate) struct MasscanConfig {
    #[serde(rename = "masscan_output_mode")]
    pub(crate) output_mode: MasscanOutputMode,
    #[serde(rename = "masscan_wait_seconds")]
    pub(crate) wait_seconds: u64,
    #[serde(rename = "masscan_max_runtime_seconds")]
    pub(crate) max_runtime_seconds: u64,
}

impl Default for MasscanConfig {
    fn default() -> Self {
        Self {
            output_mode: MasscanOutputMode::Compatible,
            wait_seconds: 10,
            max_runtime_seconds: 86_400,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct ScannerConfig {
    pub(crate) c_server: String,
    pub(crate) c_port: i64,
    pub(crate) rate: i64,
    #[serde(default)]
    pub(crate) verify_tls: bool,
    #[serde(default = "default_scanner_path")]
    pub(crate) scanner_path: String,
    #[serde(flatten)]
    pub(crate) masscan: MasscanConfig,
    /// Legacy TOML identity, imported into SQLite during upgrade.
    #[serde(default, skip_serializing)]
    pub(crate) scanner_id: String,
    /// Legacy TOML runtime token, imported into SQLite during upgrade.
    #[serde(default, skip_serializing)]
    pub(crate) runtime_token: String,
    #[serde(default = "default_heartbeat_interval")]
    pub(crate) heartbeat_interval_seconds: u64,
    #[serde(default = "default_connect_timeout")]
    pub(crate) connect_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub(crate) request_timeout_seconds: u64,
    #[serde(default = "default_reconnect_initial_delay")]
    pub(crate) reconnect_initial_delay_seconds: u64,
    #[serde(default = "default_reconnect_max_delay")]
    pub(crate) reconnect_max_delay_seconds: u64,
    #[serde(default = "default_active_task_reconnect_max_delay")]
    pub(crate) active_task_reconnect_max_delay_seconds: u64,
    #[serde(default = "default_lease_safety_margin")]
    pub(crate) lease_safety_margin_seconds: u64,
}

impl ScannerConfig {
    pub(crate) fn server_origin(&self) -> String {
        format!(
            "https://{}:{}",
            self.c_server
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            self.c_port
        )
    }

    pub(crate) fn task_url(&self, dry_run: bool) -> String {
        let mut url = format!(
            "https://{}:{}/api/task/apply?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        );
        if dry_run {
            url.push_str("&dryrun=true");
        }
        url
    }

    pub(crate) fn current_task_url(&self, task_id: Option<Uuid>) -> String {
        let mut url = format!(
            "https://{}:{}/api/task/current?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        );
        if let Some(task_id) = task_id {
            url.push_str("&taskid=");
            url.push_str(&task_id.to_string());
        }
        url
    }

    pub(crate) fn heartbeat_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/heartbeat",
            self.c_server, self.c_port
        )
    }

    pub(crate) fn runtime_configuration_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/runtime-config?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        )
    }

    pub(crate) fn public_ip_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/network/public-ip?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        )
    }

    pub(crate) fn maintenance_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/maintenance?scannerid={}",
            self.c_server, self.c_port, self.scanner_id
        )
    }

    pub(crate) fn task_failure_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/task/fail",
            self.c_server, self.c_port
        )
    }

    pub(crate) fn task_cancelled_url(&self) -> String {
        format!(
            "https://{}:{}/api/scanner/task/cancelled",
            self.c_server, self.c_port
        )
    }
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_connect_timeout() -> u64 {
    5
}

fn default_request_timeout() -> u64 {
    15
}

fn default_reconnect_initial_delay() -> u64 {
    1
}

fn default_reconnect_max_delay() -> u64 {
    60
}

fn default_active_task_reconnect_max_delay() -> u64 {
    10
}

fn default_lease_safety_margin() -> u64 {
    10
}

#[cfg(test)]
mod tests {
    use super::{
        AssignedTask, CacheManager, DnsResolver, MasscanConfig, ScannerConfig, is_valid_dns_domain,
    };
    use uuid::Uuid;

    #[test]
    fn dns_task_domains_require_dot_separation_and_obey_wire_limits() {
        let label_63 = "a".repeat(63);
        let maximum = format!(
            "{label_63}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let oversized_name = format!(
            "{label_63}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert!(!is_valid_dns_domain("a"));
        assert!(is_valid_dns_domain("a.example"));
        assert!(is_valid_dns_domain(&format!("{label_63}.example")));
        assert!(!is_valid_dns_domain(&format!("{}.example", "a".repeat(64))));
        assert!(!is_valid_dns_domain("a.example.."));
        assert_eq!(maximum.len(), 253);
        assert!(is_valid_dns_domain(&maximum));
        assert!(!is_valid_dns_domain(&oversized_name));
    }

    #[test]
    fn explicit_dns_resolver_requires_a_literal_address_and_supported_transport() {
        let valid = DnsResolver {
            id: "dns-a".into(),
            label: "DNS A".into(),
            ip: "192.0.2.53".into(),
            port: 53,
            transport: "udp".into(),
        };
        assert!(valid.validate().is_ok());
        let invalid = DnsResolver {
            ip: "resolver.example".into(),
            transport: "doh".into(),
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn assigned_task_matches_server_response() {
        let task: AssignedTask = serde_json::from_str(
            r#"{
                "user_id": 7,
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["192.0.2.0/24", "198.51.100.10"],
                "task_port": "80,443"
            }"#,
        )
        .expect("server task response must deserialize");

        assert_eq!(task.task_target.len(), 2);
        assert_eq!(task.task_port, "80,443");
        assert_eq!(task.address_family, "ipv4");
        assert_eq!(task.lease_ttl_ms, 90_000);
        assert_eq!(task.lease_expires_at_ms, None);
    }

    #[test]
    fn assigned_task_accepts_explicit_server_lease() {
        let task: AssignedTask = serde_json::from_str(
            r#"{
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["192.0.2.1"],
                "task_port": "443",
                "lease_expires_at_ms": 1770000000000,
                "lease_ttl_ms": 120000
            }"#,
        )
        .unwrap();

        assert_eq!(task.lease_expires_at_ms, Some(1_770_000_000_000));
        assert_eq!(task.lease_ttl_ms, 120_000);
    }

    #[test]
    fn task_url_contains_scanner_identity_and_dry_run_flag() {
        let config = ScannerConfig {
            c_server: "scanner.example".into(),
            c_port: 443,
            rate: 1_000,
            verify_tls: true,
            scanner_path: "masscan".into(),
            masscan: MasscanConfig::default(),
            scanner_id: "019c0000-0000-7000-8000-000000000001".into(),
            runtime_token: "secret".into(),
            heartbeat_interval_seconds: 30,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 15,
            reconnect_initial_delay_seconds: 1,
            reconnect_max_delay_seconds: 60,
            active_task_reconnect_max_delay_seconds: 10,
            lease_safety_margin_seconds: 10,
        };

        assert_eq!(
            config.task_url(true),
            "https://scanner.example:443/api/task/apply?scannerid=019c0000-0000-7000-8000-000000000001&dryrun=true"
        );
        assert_eq!(
            config.current_task_url(None),
            "https://scanner.example:443/api/task/current?scannerid=019c0000-0000-7000-8000-000000000001"
        );
        let task_id = Uuid::parse_str("019c0000-0000-7000-8000-000000000002").unwrap();
        assert_eq!(
            config.current_task_url(Some(task_id)),
            "https://scanner.example:443/api/task/current?scannerid=019c0000-0000-7000-8000-000000000001&taskid=019c0000-0000-7000-8000-000000000002"
        );
        assert_eq!(
            config.heartbeat_url(),
            "https://scanner.example:443/api/scanner/heartbeat"
        );
        assert_eq!(
            config.public_ip_url(),
            "https://scanner.example:443/api/scanner/network/public-ip?scannerid=019c0000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            config.maintenance_url(),
            "https://scanner.example:443/api/scanner/maintenance?scannerid=019c0000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            config.task_failure_url(),
            "https://scanner.example:443/api/scanner/task/fail"
        );
    }

    #[test]
    fn legacy_registration_token_is_not_used_as_runtime_token() {
        let config: ScannerConfig = serde_json::from_str(
            r#"{
                "c_server": "scanner.example",
                "c_port": 443,
                "rate": 1000,
                "source_port": 61000,
                "scanner_id": "019c0000-0000-7000-8000-000000000001",
                "token": "one-time-secret"
            }"#,
        )
        .expect("legacy scanner config must remain readable");

        assert!(config.runtime_token.is_empty());
        assert_eq!(config.connect_timeout_seconds, 5);
        assert_eq!(config.request_timeout_seconds, 15);
        assert_eq!(config.reconnect_max_delay_seconds, 60);
        assert_eq!(config.scanner_path, "./a");
        assert_eq!(config.masscan, MasscanConfig::default());
    }

    #[test]
    fn assigned_task_rejects_zero_network_targets() {
        let mut task: AssignedTask = serde_json::from_str(
            r#"{
                "task_id": "019c0000-0000-7000-8000-000000000001",
                "task_target": ["0.0.17.0/24"],
                "task_port": "80"
            }"#,
        )
        .unwrap();

        assert!(task.validate_targets().is_err());
        task.task_target = vec!["1.0.0.0/24".into()];
        assert!(task.validate_targets().is_ok());
    }

    #[test]
    fn durable_cache_round_trips_task_identity_and_progress() {
        let database = std::env::temp_dir().join(format!(
            "network-mapping-scanner-state-{}.sqlite3",
            uuid::Uuid::now_v7()
        ));
        let legacy_state = database.with_extension("json");
        let server_origin = "https://scanner.example:443".to_owned();
        let task_id = uuid::Uuid::now_v7();
        let store = crate::storage::StateStore::open(database.clone()).unwrap();
        let scanner_id = uuid::Uuid::now_v7().to_string();
        let mut cache = CacheManager::load(
            store,
            server_origin.clone(),
            scanner_id.clone(),
            legacy_state.clone(),
        )
        .unwrap();
        cache.begin_task(task_id).unwrap();
        cache.mark_batch_uploaded(0).unwrap();
        let upload_id = cache.upload_id;
        drop(cache);

        let store = crate::storage::StateStore::open(database.clone()).unwrap();
        let mut restored =
            CacheManager::load(store, server_origin, scanner_id, legacy_state).unwrap();
        assert_eq!(restored.task_id, Some(task_id));
        assert_eq!(restored.upload_id, upload_id);
        assert_eq!(restored.next_batch_index, 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        restored.clear().unwrap();
        drop(restored);
        std::fs::remove_file(database).unwrap();
    }

    #[test]
    fn legacy_json_state_is_imported_and_archived() {
        let database = std::env::temp_dir().join(format!(
            "network-mapping-scanner-state-{}.sqlite3",
            uuid::Uuid::now_v7()
        ));
        let legacy_state = database.with_extension("json");
        let archive = legacy_state.with_extension("json.migrated");
        let task_id = uuid::Uuid::now_v7();
        let upload_id = uuid::Uuid::now_v7();
        let observation = crate::scan::ScanObservation::Port(crate::scan::PortObservation {
            ip: "192.0.2.1".into(),
            port: 443,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at: 1,
        });
        let legacy = serde_json::json!({
            "task_id": task_id,
            "upload_id": upload_id,
            "observations": [observation],
            "next_batch_index": 0
        });
        std::fs::write(&legacy_state, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(CacheManager::legacy_state_has_pending(&legacy_state).unwrap());

        let store = crate::storage::StateStore::open(database.clone()).unwrap();
        let mut cache = CacheManager::load(
            store,
            "https://scanner.example:443".into(),
            uuid::Uuid::now_v7().to_string(),
            legacy_state.clone(),
        )
        .unwrap();
        assert_eq!(cache.task_id, Some(task_id));
        assert_eq!(cache.upload_id, Some(upload_id));
        assert_eq!(cache.observations.len(), 1);
        assert!(!legacy_state.exists());
        assert!(archive.exists());

        cache.clear().unwrap();
        drop(cache);
        std::fs::remove_file(database).unwrap();
        std::fs::remove_file(archive).unwrap();
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UploadConfig {
    /// Full HTTPS URL where scan results are POSTed as JSON.
    pub(crate) endpoint: String,
}
