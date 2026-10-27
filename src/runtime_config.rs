use crate::error::{ScannerError, ServerError};
use crate::http_client::{ServerHttpClient, response_error, response_json};
use crate::types::{
    AppConfig, DnsConfig, MasscanConfig, NucleiConfig, ServiceDetectionConfig,
    ServiceDetectionStrategy,
};
use crate::types::{default_batch_endpoints, default_idle_timeout, default_service_runtime};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) const SCHEMA_VERSION: i32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RuntimeConfigurationEnvelope {
    pub(crate) revision: i64,
    pub(crate) schema_version: i32,
    pub(crate) document: RemoteRuntimeConfiguration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteRuntimeConfiguration {
    pub(crate) masscan: RemoteMasscanConfig,
    pub(crate) service_detection: RemoteServiceDetectionConfig,
    pub(crate) dns: RemoteDnsConfig,
    pub(crate) nuclei: RemoteNucleiConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteMasscanConfig {
    pub(crate) rate: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteServiceDetectionConfig {
    #[serde(default = "default_batch_endpoints")]
    pub(crate) batch_endpoints: usize,
    #[serde(default = "default_idle_timeout")]
    pub(crate) idle_timeout_seconds: u64,
    #[serde(default = "default_service_runtime")]
    pub(crate) max_runtime_seconds: u64,
    pub(crate) enabled: bool,
    pub(crate) strategy: ServiceDetectionStrategy,
    pub(crate) max_probes_per_endpoint: usize,
    pub(crate) confidence_threshold: u8,
    pub(crate) senders: u32,
    pub(crate) server_rate_limit: u32,
    pub(crate) connect_timeout_seconds: u64,
    pub(crate) target_timeout_seconds: u64,
    pub(crate) max_result_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteDnsConfig {
    pub(crate) enabled: bool,
    pub(crate) record_types: Vec<String>,
    pub(crate) query_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteNucleiConfig {
    pub(crate) enabled: bool,
    pub(crate) port_fallback: bool,
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

fn default_masscan(config: &MasscanConfig) -> bool {
    *config == MasscanConfig::default()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RuntimeSnapshot {
    pub(crate) revision: i64,
    #[serde(default, skip_serializing_if = "default_masscan")]
    pub(crate) masscan: MasscanConfig,
    pub(crate) rate: i32,
    pub(crate) service_detection: ServiceDetectionConfig,
    pub(crate) dns: DnsConfig,
    pub(crate) nuclei: NucleiConfig,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuntimeConfigurationState {
    pub(crate) supported_schema_versions: [i32; 1],
    pub(crate) applied_revision: Option<i64>,
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug)]
struct State {
    current: RuntimeSnapshot,
    pending: Option<RuntimeConfigurationEnvelope>,
    status: &'static str,
    error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct RuntimeConfiguration {
    state: Arc<RwLock<State>>,
    local_masscan: MasscanConfig,
    local_rate_limit: i32,
    local_service_enabled: bool,
    local_dns_enabled: bool,
    local_nuclei_enabled: bool,
    local_service: ServiceDetectionConfig,
    local_dns: DnsConfig,
    local_nuclei: NucleiConfig,
}

impl RuntimeConfiguration {
    pub(crate) fn new(local: &AppConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(State {
                current: RuntimeSnapshot {
                    revision: 0,
                    masscan: local.scanner.masscan.clone(),
                    rate: local.scanner.rate as i32,
                    service_detection: local.service_detection.clone(),
                    dns: local.dns.clone(),
                    nuclei: local.nuclei.clone(),
                },
                pending: None,
                status: "local",
                error: None,
            })),
            local_masscan: local.scanner.masscan.clone(),
            local_rate_limit: local.scanner.rate as i32,
            local_service_enabled: local.service_detection.enabled,
            local_dns_enabled: local.dns.enabled,
            local_nuclei_enabled: local.nuclei.enabled,
            local_service: local.service_detection.clone(),
            local_dns: local.dns.clone(),
            local_nuclei: local.nuclei.clone(),
        }
    }

    pub(crate) async fn snapshot(&self) -> RuntimeSnapshot {
        self.state.read().await.current.clone()
    }

    pub(crate) async fn report(&self) -> RuntimeConfigurationState {
        let state = self.state.read().await;
        RuntimeConfigurationState {
            supported_schema_versions: [SCHEMA_VERSION],
            applied_revision: (state.current.revision > 0).then_some(state.current.revision),
            status: state.status,
            error: state.error.clone(),
        }
    }

    pub(crate) async fn needs_revision(&self, revision: i64) -> bool {
        let state = self.state.read().await;
        state.current.revision != revision
            && state
                .pending
                .as_ref()
                .is_none_or(|value| value.revision != revision)
    }

    pub(crate) async fn stage(&self, envelope: RuntimeConfigurationEnvelope) {
        let mut state = self.state.write().await;
        state.pending = Some(envelope);
        state.status = "staged";
        state.error = None;
    }

    pub(crate) async fn restore(
        &self,
        envelope: RuntimeConfigurationEnvelope,
    ) -> Result<(), String> {
        let snapshot = self.build_snapshot(&envelope)?;
        let mut state = self.state.write().await;
        state.current = snapshot;
        state.status = "applied";
        state.error = None;
        Ok(())
    }

    pub(crate) async fn apply_pending(
        &self,
    ) -> Result<Option<RuntimeConfigurationEnvelope>, String> {
        let pending = self.state.write().await.pending.take();
        let Some(envelope) = pending else {
            return Ok(None);
        };
        match self.build_snapshot(&envelope) {
            Ok(snapshot) => {
                let mut state = self.state.write().await;
                state.current = snapshot;
                state.status = "applied";
                state.error = None;
                Ok(Some(envelope))
            }
            Err(error) => {
                let mut state = self.state.write().await;
                state.status = "rejected";
                state.error = Some(error.clone());
                Err(error)
            }
        }
    }

    fn build_snapshot(
        &self,
        envelope: &RuntimeConfigurationEnvelope,
    ) -> Result<RuntimeSnapshot, String> {
        if envelope.schema_version != SCHEMA_VERSION || envelope.revision <= 0 {
            return Err("unsupported runtime configuration envelope".into());
        }
        envelope.document.validate()?;
        let remote = &envelope.document;
        let mut service = self.local_service.clone();
        service.enabled = self.local_service_enabled && remote.service_detection.enabled;
        service.strategy = remote.service_detection.strategy;
        service.max_probes_per_endpoint = remote.service_detection.max_probes_per_endpoint;
        service.confidence_threshold = remote.service_detection.confidence_threshold;
        service.senders = remote.service_detection.senders;
        service.server_rate_limit = remote.service_detection.server_rate_limit;
        service.connect_timeout_seconds = remote.service_detection.connect_timeout_seconds;
        service.target_timeout_seconds = remote.service_detection.target_timeout_seconds;
        service.max_result_bytes = remote.service_detection.max_result_bytes;
        service.batch_endpoints = remote.service_detection.batch_endpoints;
        service.idle_timeout_seconds = remote.service_detection.idle_timeout_seconds;
        service.max_runtime_seconds = remote.service_detection.max_runtime_seconds;
        let mut dns = self.local_dns.clone();
        dns.enabled = self.local_dns_enabled && remote.dns.enabled;
        dns.record_types = remote.dns.record_types.clone();
        dns.query_timeout_seconds = remote.dns.query_timeout_seconds;
        let mut nuclei = self.local_nuclei.clone();
        nuclei.enabled = self.local_nuclei_enabled && remote.nuclei.enabled;
        nuclei.port_fallback = remote.nuclei.port_fallback;
        nuclei.severities = remote.nuclei.severities.clone();
        nuclei.rate_limit = remote.nuclei.rate_limit;
        nuclei.bulk_size = remote.nuclei.bulk_size;
        nuclei.concurrency = remote.nuclei.concurrency;
        nuclei.timeout_seconds = remote.nuclei.timeout_seconds;
        nuclei.retries = remote.nuclei.retries;
        nuclei.max_runtime_seconds = remote.nuclei.max_runtime_seconds;
        nuclei.max_findings = remote.nuclei.max_findings;
        nuclei.max_result_bytes = remote.nuclei.max_result_bytes;
        Ok(RuntimeSnapshot {
            revision: envelope.revision,
            masscan: self.local_masscan.clone(),
            rate: remote.masscan.rate.min(self.local_rate_limit),
            service_detection: service,
            dns,
            nuclei,
        })
    }
}

impl RemoteRuntimeConfiguration {
    fn validate(&self) -> Result<(), String> {
        if !(1..=4096).contains(&self.service_detection.batch_endpoints)
            || !(1..=3600).contains(&self.service_detection.idle_timeout_seconds)
            || !(1..=86400).contains(&self.service_detection.max_runtime_seconds)
            || self.masscan.rate <= 0
            || !(1..=32).contains(&self.service_detection.max_probes_per_endpoint)
            || !(1..=100).contains(&self.service_detection.confidence_threshold)
            || !(1..=10_000).contains(&self.service_detection.senders)
            || !(1..=10_000).contains(&self.service_detection.server_rate_limit)
            || !(1..=60).contains(&self.service_detection.connect_timeout_seconds)
            || self.service_detection.target_timeout_seconds
                < self.service_detection.connect_timeout_seconds
            || self.service_detection.target_timeout_seconds > 300
            || !(1_024..=1_048_576).contains(&self.service_detection.max_result_bytes)
            || !(1..=60).contains(&self.dns.query_timeout_seconds)
        {
            return Err("runtime scan configuration contains an out-of-range value".into());
        }
        if self.dns.record_types.is_empty()
            || self.dns.record_types.len() > 12
            || self
                .dns
                .record_types
                .iter()
                .any(|value| !crate::types::is_supported_dns_record_type(value))
        {
            return Err("runtime DNS record types are invalid".into());
        }
        if self.nuclei.severities.is_empty()
            || self.nuclei.severities.len() > 5
            || self.nuclei.severities.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "info" | "low" | "medium" | "high" | "critical"
                )
            })
            || !(1..=10_000).contains(&self.nuclei.rate_limit)
            || !(1..=1_000).contains(&self.nuclei.bulk_size)
            || !(1..=1_000).contains(&self.nuclei.concurrency)
            || !(1..=300).contains(&self.nuclei.timeout_seconds)
            || self.nuclei.retries > 10
            || !(10..=86_400).contains(&self.nuclei.max_runtime_seconds)
            || !(1..=100_000).contains(&self.nuclei.max_findings)
            || !(4_096..=1_048_576).contains(&self.nuclei.max_result_bytes)
        {
            return Err("runtime Nuclei configuration contains an invalid value".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RuntimeConfigurationResponse {
    success: bool,
    data: RuntimeConfigurationEnvelope,
}

pub(crate) async fn fetch_configuration(
    client: &ServerHttpClient,
    url: &str,
) -> Result<RuntimeConfigurationEnvelope, ScannerError> {
    let response = client.get(url, "fetch runtime configuration").await?;
    if !response.status().is_success() {
        return Err(response_error(response, "fetch runtime configuration")
            .await
            .into());
    }
    let response: RuntimeConfigurationResponse =
        response_json(response, "fetch runtime configuration").await?;
    if !response.success {
        return Err(ServerError::InvalidResponse {
            operation: "fetch runtime configuration",
            detail: "server returned success=false".into(),
        }
        .into());
    }
    Ok(response.data)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn legacy_task_snapshot_defaults_masscan_without_changing_serialization() {
        let mut local: super::AppConfig =
            toml_edit::de::from_str(include_str!("../config.toml")).unwrap();
        local.scanner.masscan = Default::default();
        let snapshot = super::RuntimeConfiguration::new(&local).snapshot().await;
        let original = serde_json::to_value(snapshot).unwrap();
        assert!(original.get("masscan").is_none());
        let restored: super::RuntimeSnapshot = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(restored.masscan, Default::default());
        assert_eq!(serde_json::to_value(restored).unwrap(), original);
    }

    #[test]
    fn legacy_remote_configuration_uses_bounded_service_defaults() {
        let value = serde_json::json!({"enabled":true,"strategy":"standard","max_probes_per_endpoint":8,
            "confidence_threshold":80,"senders":200,"server_rate_limit":20,"connect_timeout_seconds":5,
            "target_timeout_seconds":15,"max_result_bytes":65536});
        let service: super::RemoteServiceDetectionConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            (
                service.batch_endpoints,
                service.idle_timeout_seconds,
                service.max_runtime_seconds
            ),
            (512, 120, 1800)
        );
    }

    use super::*;

    #[tokio::test]
    async fn remote_enable_cannot_override_local_disable() {
        let local: AppConfig = toml_edit::de::from_str(include_str!("../config.toml")).unwrap();
        let manager = RuntimeConfiguration::new(&local);
        let mut document: RemoteRuntimeConfiguration = serde_json::from_value(serde_json::json!({
            "masscan": {"rate": 1000},
            "service_detection": {"enabled": true, "strategy": "adaptive", "max_probes_per_endpoint": 8, "confidence_threshold": 80, "senders": 20, "server_rate_limit": 10, "connect_timeout_seconds": 5, "target_timeout_seconds": 15, "max_result_bytes": 65536},
            "dns": {"enabled": true, "record_types": ["A", "AAAA"], "query_timeout_seconds": 5},
            "nuclei": {"enabled": true, "port_fallback": true, "severities": ["high"], "rate_limit": 10, "bulk_size": 5, "concurrency": 5, "timeout_seconds": 10, "retries": 1, "max_runtime_seconds": 60, "max_findings": 100, "max_result_bytes": 65536}
        })).unwrap();
        document.masscan.rate = i32::MAX;
        document.nuclei.enabled = true;
        manager
            .restore(RuntimeConfigurationEnvelope {
                revision: 1,
                schema_version: 1,
                document,
            })
            .await
            .unwrap();
        let snapshot = manager.snapshot().await;
        assert!(!snapshot.nuclei.enabled);
        assert_eq!(snapshot.rate, local.scanner.rate as i32);
    }
}
