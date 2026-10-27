use crate::error::{MaintenanceInfo, ScannerError, ServerError};
use crate::http_client::{ServerHttpClient, response_error, response_json};
use crate::network::{NetworkCapabilities, SharedNetworkCapabilities};
use crate::runtime_config::{RuntimeConfiguration, fetch_configuration};
use crate::scan::ScanCapabilities;
use crate::sysinfo::SystemInfo;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use tokio::sync::{Notify, RwLock};
use tokio::time::{Duration, Instant};
use uuid::Uuid;

const MAX_LEASE_TTL_MS: u64 = 86_400_000;
const LATENCY_PROTOCOL_VERSION: u16 = 1;
const MAX_LATENCY_US: i64 = 120_000_000;
const LATENCY_VERSION_HEADER: HeaderName = HeaderName::from_static("nm-latency-version");
const LATENCY_PROBE_HEADER: HeaderName = HeaderName::from_static("nm-latency-probe");
const SERVER_PROCESSING_HEADER: HeaderName = HeaderName::from_static("nm-server-processing-us");
const SERVER_SENT_AT_HEADER: HeaderName = HeaderName::from_static("nm-server-sent-at-ms");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskCancellationReason {
    ServerRequested,
    LeaseLost,
    Shutdown,
}

impl TaskCancellationReason {
    fn code(self) -> u8 {
        match self {
            Self::ServerRequested => 1,
            Self::LeaseLost => 2,
            Self::Shutdown => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ServerRequested),
            2 => Some(Self::LeaseLost),
            3 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct ActiveTask {
    current: Arc<RwLock<Option<Uuid>>>,
    cancel_requested: Arc<AtomicBool>,
    cancellation_reason: Arc<AtomicU8>,
    lease_deadline: Arc<RwLock<Option<Instant>>>,
    lease_ttl_ms: Arc<AtomicU64>,
    lease_changed: Arc<Notify>,
}

impl ActiveTask {
    pub(crate) async fn get(&self) -> Option<Uuid> {
        *self.current.read().await
    }

    pub(crate) async fn set(&self, task_id: Uuid, lease_ttl_ms: u64) {
        self.cancel_requested.store(false, Ordering::Relaxed);
        self.cancellation_reason.store(0, Ordering::Relaxed);
        *self.current.write().await = Some(task_id);
        self.renew_lease(lease_ttl_ms).await;
        tracing::debug!(%task_id, "active task set");
    }

    pub(crate) async fn clear(&self) {
        let previous_task_id = *self.current.read().await;
        *self.current.write().await = None;
        *self.lease_deadline.write().await = None;
        self.lease_ttl_ms.store(0, Ordering::Relaxed);
        self.cancel_requested.store(false, Ordering::Relaxed);
        self.cancellation_reason.store(0, Ordering::Relaxed);
        self.lease_changed.notify_waiters();
        tracing::debug!(?previous_task_id, "active task cleared");
    }

    pub(crate) async fn request_cancel(&self, task_id: Uuid) {
        let active_task_id = self.get().await;
        if active_task_id == Some(task_id) {
            self.request_cancellation(TaskCancellationReason::ServerRequested);
            tracing::debug!(%task_id, "cancellation requested for active task");
        } else {
            tracing::debug!(%task_id, ?active_task_id, "ignored cancellation for inactive task");
        }
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.cancel_requested.clone()
    }

    pub(crate) fn cancellation_reason(&self) -> Option<TaskCancellationReason> {
        TaskCancellationReason::from_code(self.cancellation_reason.load(Ordering::Relaxed))
    }

    pub(crate) async fn renew_lease(&self, lease_ttl_ms: u64) {
        let bounded_ttl_ms = lease_ttl_ms.clamp(1, MAX_LEASE_TTL_MS);
        if bounded_ttl_ms != lease_ttl_ms {
            tracing::warn!(lease_ttl_ms, bounded_ttl_ms, "server lease TTL was clamped");
        }
        let ttl = Duration::from_millis(bounded_ttl_ms);
        self.lease_ttl_ms.store(bounded_ttl_ms, Ordering::Relaxed);
        *self.lease_deadline.write().await = Some(Instant::now() + ttl);
        self.lease_changed.notify_waiters();
        tracing::debug!(
            lease_ttl_ms = bounded_ttl_ms,
            "active task lease deadline updated"
        );
    }

    async fn renew_last_lease(&self) {
        let lease_ttl_ms = self.lease_ttl_ms.load(Ordering::Relaxed);
        if lease_ttl_ms > 0 {
            self.renew_lease(lease_ttl_ms).await;
        }
    }

    pub(crate) async fn lease_safety_expired(&self, safety_margin: Duration) -> bool {
        self.lease_deadline
            .read()
            .await
            .is_some_and(|deadline| Instant::now() + safety_margin >= deadline)
    }

    pub(crate) async fn lease_safety_remaining(&self, safety_margin: Duration) -> Option<Duration> {
        self.lease_deadline
            .read()
            .await
            .map(|deadline| deadline.saturating_duration_since(Instant::now() + safety_margin))
    }

    /// Wait against the current deadline, including renewals during a long upload.
    pub(crate) async fn wait_for_lease_loss(&self, task_id: Uuid, margin: Duration) {
        loop {
            let changed = self.lease_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.get().await != Some(task_id) || self.cancellation_reason().is_some() {
                return;
            }
            let remaining = self
                .lease_safety_remaining(margin)
                .await
                .unwrap_or_default();
            if remaining.is_zero() {
                return;
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep(remaining) => {},
            }
        }
    }

    pub(crate) async fn request_lease_lost(&self, task_id: Uuid) {
        self.request_lease_lost_from(task_id, "local_safety_deadline")
            .await;
    }

    pub(crate) async fn request_lease_lost_from(&self, task_id: Uuid, source: &str) {
        if self.get().await == Some(task_id) {
            self.request_cancellation(TaskCancellationReason::LeaseLost);
            tracing::error!(
                event = "ActiveTaskLeaseLost",
                operation = "renew_task_lease",
                error_kind = "lease",
                error_code = "task_lease_lost",
                error_message = "active task lease is no longer usable",
                lease_loss_source = source,
                lease_ttl_ms = self.lease_ttl_ms.load(Ordering::Relaxed),
                retryable = false,
                outcome = "task_cancellation_requested",
                %task_id,
                "active task lease was lost"
            );
        }
    }

    pub(crate) async fn request_shutdown(&self) {
        if self.get().await.is_some() {
            self.request_cancellation(TaskCancellationReason::Shutdown);
        }
    }

    fn request_cancellation(&self, reason: TaskCancellationReason) {
        self.cancellation_reason
            .store(reason.code(), Ordering::Relaxed);
        self.cancel_requested.store(true, Ordering::Relaxed);
        self.lease_changed.notify_waiters();
    }
}

#[derive(Serialize)]
struct HeartbeatPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    local_config_check: Option<crate::config_check::ConfigCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_state: Option<serde_json::Value>,
    diagnostics: crate::diagnostics::protocol::Capabilities,
    diagnostic_health: serde_json::Value,
    scanner_id: Uuid,
    state: &'static str,
    active_task_id: Option<Uuid>,
    scanner_version: &'static str,
    system: SystemInfo,
    network_capabilities: NetworkCapabilities,
    scan_capabilities: ScanCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_report: Option<LatencyReport>,
    config_state: crate::runtime_config::RuntimeConfigurationState,
}

#[derive(Clone, Debug, Serialize)]
struct LatencyReport {
    version: u16,
    probe_id: Uuid,
    rtt_us: i64,
    server_processing_us: i64,
    network_rtt_us: i64,
    server_sent_at_ms: i64,
}

#[derive(Serialize)]
struct TaskFailurePayload<'a> {
    scanner_id: Uuid,
    task_id: Uuid,
    error: &'a str,
    retryable: bool,
    failure_class: &'a str,
}

#[derive(Serialize)]
struct TaskCancelledPayload {
    scanner_id: Uuid,
    task_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HeartbeatResponse {
    #[serde(default)]
    diagnostics_enabled: bool,
    #[serde(default)]
    diagnostic_requests: Vec<crate::diagnostics::protocol::Job>,
    command: Option<HeartbeatCommand>,
    lease: Option<HeartbeatLease>,
    #[serde(default)]
    maintenance: Option<MaintenanceInfo>,
    #[serde(default)]
    configuration: Option<ConfigurationNotice>,
}

#[derive(Debug, Deserialize)]
struct ConfigurationNotice {
    revision: i64,
    schema_version: i32,
}

#[derive(Debug, Deserialize)]
struct HeartbeatCommand {
    #[serde(rename = "type")]
    command_type: String,
    task_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct HeartbeatLease {
    task_id: Uuid,
    status: String,
    #[allow(dead_code)]
    expires_at_ms: Option<i64>,
    ttl_ms: u64,
}

#[derive(Clone)]
pub(crate) struct HeartbeatClient {
    local_config_check: Option<crate::config_check::ConfigCheck>,
    modules: Option<crate::modules::registry::Registry>,
    diagnostics: Option<crate::diagnostics::DiagnosticsHandle>,
    client: ServerHttpClient,
    heartbeat_url: String,
    failure_url: String,
    cancelled_url: String,
    maintenance_url: String,
    scanner_id: Uuid,
    network_capabilities: SharedNetworkCapabilities,
    scan_capabilities: ScanCapabilities,
    pending_latency: Arc<RwLock<Option<LatencyReport>>>,
    runtime_configuration_url: String,
    runtime_configuration: RuntimeConfiguration,
}

pub(crate) struct HeartbeatEndpoints {
    pub(crate) heartbeat: String,
    pub(crate) failure: String,
    pub(crate) cancelled: String,
    pub(crate) maintenance: String,
}

#[derive(Deserialize)]
struct MaintenanceProbeResponse {
    success: bool,
    maintenance: MaintenanceInfo,
}

impl HeartbeatClient {
    pub(crate) fn with_config_check(mut self, report: crate::config_check::ConfigCheck) -> Self {
        self.local_config_check = Some(report);
        self
    }
    pub(crate) fn with_diagnostics(
        mut self,
        handle: crate::diagnostics::DiagnosticsHandle,
    ) -> Self {
        self.diagnostics = Some(handle);
        self
    }
    pub(crate) async fn can_scan(&self, address_family: &str) -> bool {
        self.network_capabilities
            .get()
            .await
            .is_ready(address_family)
    }

    pub(crate) fn new(
        client: ServerHttpClient,
        endpoints: HeartbeatEndpoints,
        scanner_id: Uuid,
        network_capabilities: SharedNetworkCapabilities,
        scan_capabilities: ScanCapabilities,
        runtime_configuration_url: String,
        runtime_configuration: RuntimeConfiguration,
    ) -> Self {
        Self {
            local_config_check: None,
            modules: None,
            diagnostics: None,
            client,
            heartbeat_url: endpoints.heartbeat,
            failure_url: endpoints.failure,
            cancelled_url: endpoints.cancelled,
            maintenance_url: endpoints.maintenance,
            scanner_id,
            network_capabilities,
            scan_capabilities,
            pending_latency: Arc::new(RwLock::new(None)),
            runtime_configuration_url,
            runtime_configuration,
        }
    }

    pub(crate) fn with_modules(
        mut self,
        registry: Option<crate::modules::registry::Registry>,
    ) -> Self {
        self.modules = registry;
        self
    }

    pub(crate) async fn maintenance_status(&self) -> Result<MaintenanceInfo, ScannerError> {
        let response = self
            .client
            .get(&self.maintenance_url, "check system maintenance")
            .await?;
        if !response.status().is_success() {
            return Err(response_error(response, "check system maintenance")
                .await
                .into());
        }
        let response: MaintenanceProbeResponse =
            response_json(response, "check system maintenance").await?;
        if !response.success {
            return Err(ServerError::InvalidResponse {
                operation: "check system maintenance",
                detail: "maintenance probe returned success=false".into(),
            }
            .into());
        }
        Ok(response.maintenance)
    }

    pub(crate) async fn send(
        &self,
        active_task_id: Option<Uuid>,
        stopping: bool,
    ) -> Result<HeartbeatResponse, ScannerError> {
        let state = if stopping {
            "stopping"
        } else if active_task_id.is_some() {
            "scanning"
        } else {
            "idle"
        };
        let scan_capabilities = if let Some(registry) = &self.modules {
            let mut runtime = self.runtime_configuration.snapshot().await;
            if let Ok(Some(environment)) = registry.active() {
                runtime.service_detection.enabled &=
                    environment.modules.contains_key("service_detection");
                runtime.dns.enabled &= environment.modules.contains_key("dns_lookup");
                runtime.nuclei.enabled &=
                    environment.modules.contains_key("vulnerability_detection");
            }
            ScanCapabilities::from_config(&runtime.service_detection, &runtime.dns, &runtime.nuclei)
        } else {
            self.scan_capabilities.clone()
        };
        let payload = HeartbeatPayload {
            local_config_check: self.local_config_check.clone(),
            module_state: self.modules.as_ref().map(|registry| {
                let mut report = registry.report();
                report["task_generation"] =
                    serde_json::json!(active_task_id.and_then(|id| registry.task_generation(id)));
                report
            }),
            diagnostics: self
                .diagnostics
                .as_ref()
                .map(|d| d.capabilities())
                .unwrap_or_default(),
            diagnostic_health: self
                .diagnostics
                .as_ref()
                .map(|d| d.health())
                .unwrap_or_else(|| serde_json::json!({"accepting_tasks":true,"status":"healthy"})),
            scanner_id: self.scanner_id,
            state,
            active_task_id,
            scanner_version: env!("CARGO_PKG_VERSION"),
            system: SystemInfo::gather()?,
            network_capabilities: self.network_capabilities.get().await,
            scan_capabilities,
            latency_report: self.pending_latency.read().await.clone(),
            config_state: self.runtime_configuration.report().await,
        };
        tracing::debug!(
            scanner_id = %self.scanner_id,
            state,
            ?active_task_id,
            stopping,
            "sending heartbeat"
        );
        let probe_id = Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(LATENCY_VERSION_HEADER, HeaderValue::from_static("1"));
        headers.insert(
            LATENCY_PROBE_HEADER,
            HeaderValue::from_str(&probe_id.to_string()).map_err(|error| {
                ScannerError::Http(format!("failed to build latency probe header: {error}"))
            })?,
        );
        let started = Instant::now();
        let response = self
            .client
            .post_json_with_headers(&self.heartbeat_url, &payload, headers, "send heartbeat")
            .await?;
        let elapsed = started.elapsed();
        let latency = parse_latency_response(response.headers(), probe_id, elapsed);
        tracing::debug!(status = %response.status(), state, "heartbeat endpoint responded");
        if response.status().is_success() {
            let response = response_json(response, "send heartbeat").await?;
            if let Some(latency) = &latency {
                tracing::debug!(
                    rtt_ms = latency.rtt_us as f64 / 1_000.0,
                    network_rtt_ms = latency.network_rtt_us as f64 / 1_000.0,
                    server_processing_ms = latency.server_processing_us as f64 / 1_000.0,
                    "heartbeat latency measured"
                );
            }
            *self.pending_latency.write().await = latency;
            tracing::debug!(response = ?response, "heartbeat response decoded");
            Ok(response)
        } else {
            Err(response_error(response, "send heartbeat").await.into())
        }
    }

    pub(crate) async fn report_failure(
        &self,
        task_id: Uuid,
        error: &str,
    ) -> Result<(), ScannerError> {
        self.report_task_failure(task_id, error, true, "scan_error")
            .await
    }

    pub(crate) async fn report_terminal_failure(
        &self,
        task_id: Uuid,
        error: &str,
    ) -> Result<(), ScannerError> {
        self.report_task_failure(task_id, error, false, "scan_error")
            .await
    }

    pub(crate) async fn report_route_failure(
        &self,
        task_id: Uuid,
        error: &str,
    ) -> Result<(), ScannerError> {
        self.report_task_failure(task_id, error, true, "route_unavailable")
            .await
    }
    pub(crate) async fn report_performance(
        &self,
        task_id: Uuid,
        performance: &crate::performance::Performance,
    ) {
        let Some(base) = self.failure_url.strip_suffix("/api/scanner/task/fail") else {
            return;
        };
        let url = format!("{base}/api/scanner/task/performance");
        let payload = serde_json::json!({"scanner_id":self.scanner_id,"task_id":task_id,"performance":performance});
        match tokio::time::timeout(
            Duration::from_secs(2),
            self.client
                .post_json(&url, &payload, "report task performance"),
        )
        .await
        {
            Ok(Ok(response)) if response.status().is_success() => {}
            _ => tracing::debug!(%task_id,"optional task quality report was not accepted"),
        }
    }
    async fn report_task_failure(
        &self,
        task_id: Uuid,
        error: &str,
        retryable: bool,
        failure_class: &str,
    ) -> Result<(), ScannerError> {
        let payload = TaskFailurePayload {
            scanner_id: self.scanner_id,
            task_id,
            error,
            retryable,
            failure_class,
        };
        tracing::debug!(%task_id, retryable, "reporting scan task failure");
        let response = self
            .client
            .post_json(&self.failure_url, &payload, "report task failure")
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task failure endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_error(response, "report task failure").await.into())
        }
    }

    pub(crate) async fn report_cancelled(&self, task_id: Uuid) -> Result<(), ScannerError> {
        tracing::debug!(%task_id, "acknowledging scan task cancellation");
        let response = self
            .client
            .post_json(
                &self.cancelled_url,
                &TaskCancelledPayload {
                    scanner_id: self.scanner_id,
                    task_id,
                },
                "report task cancellation",
            )
            .await?;
        tracing::debug!(%task_id, status = %response.status(), "task cancellation endpoint responded");
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_error(response, "report task cancellation")
                .await
                .into())
        }
    }

    pub(crate) async fn apply_command(
        &self,
        response: HeartbeatResponse,
        active: &ActiveTask,
    ) -> Option<MaintenanceInfo> {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.dispatch(response.diagnostic_requests, response.diagnostics_enabled);
        }
        if let Some(lease) = response.lease {
            match lease.status.as_str() {
                "renewed" if active.get().await == Some(lease.task_id) => {
                    active.renew_lease(lease.ttl_ms).await;
                }
                "held" if active.get().await == Some(lease.task_id) => {
                    active.renew_lease(lease.ttl_ms).await;
                    tracing::info!(
                        task_id = %lease.task_id,
                        grace_ttl_ms = lease.ttl_ms,
                        "active task lease frozen for maintenance result upload"
                    );
                }
                "lost" => {
                    active
                        .request_lease_lost_from(lease.task_id, "server_reported_lost")
                        .await
                }
                status => tracing::warn!(%status, task_id = %lease.task_id, "unknown lease status"),
            }
        } else if active.get().await.is_some() {
            // Compatibility with servers that renew leases but predate the
            // explicit lease response object.
            active.renew_last_lease().await;
        }
        if let Some(command) = response.command
            && command.command_type == "cancel_task"
        {
            tracing::debug!(task_id = %command.task_id, "applying heartbeat cancellation command");
            active.request_cancel(command.task_id).await;
        } else {
            tracing::debug!("heartbeat contained no actionable command");
        }
        if let Some(configuration) = response.configuration
            && configuration.schema_version == crate::runtime_config::SCHEMA_VERSION
            && self
                .runtime_configuration
                .needs_revision(configuration.revision)
                .await
        {
            match fetch_configuration(&self.client, &self.runtime_configuration_url).await {
                Ok(envelope) if envelope.revision == configuration.revision => {
                    self.runtime_configuration.stage(envelope).await;
                    tracing::info!(
                        revision = configuration.revision,
                        "runtime configuration staged"
                    );
                }
                Ok(envelope) => tracing::warn!(
                    announced_revision = configuration.revision,
                    fetched_revision = envelope.revision,
                    "runtime configuration changed while it was fetched"
                ),
                Err(error) => {
                    tracing::warn!(%error, revision = configuration.revision, "failed to fetch runtime configuration")
                }
            }
        }
        response.maintenance
    }
}

fn parse_latency_response(
    headers: &HeaderMap,
    expected_probe_id: Uuid,
    elapsed: Duration,
) -> Option<LatencyReport> {
    let version = headers
        .get(&LATENCY_VERSION_HEADER)?
        .to_str()
        .ok()?
        .parse::<u16>()
        .ok()?;
    if version != LATENCY_PROTOCOL_VERSION {
        return None;
    }
    let probe_id = headers
        .get(&LATENCY_PROBE_HEADER)?
        .to_str()
        .ok()
        .and_then(|value| Uuid::parse_str(value).ok())?;
    if probe_id != expected_probe_id {
        return None;
    }
    let server_processing_us = parse_non_negative_header(headers, &SERVER_PROCESSING_HEADER)?;
    let server_sent_at_ms = parse_non_negative_header(headers, &SERVER_SENT_AT_HEADER)?;
    let rtt_us = i64::try_from(elapsed.as_micros()).ok()?;
    if rtt_us > MAX_LATENCY_US
        || server_processing_us > MAX_LATENCY_US
        || server_processing_us > rtt_us
    {
        return None;
    }
    Some(LatencyReport {
        version,
        probe_id,
        rtt_us,
        server_processing_us,
        network_rtt_us: rtt_us.saturating_sub(server_processing_us),
        server_sent_at_ms,
    })
}

fn parse_non_negative_header(headers: &HeaderMap, name: &HeaderName) -> Option<i64> {
    let value = headers.get(name)?.to_str().ok()?.parse::<i64>().ok()?;
    (value >= 0).then_some(value)
}

#[cfg(test)]
mod tests {
    #[tokio::test(start_paused = true)]
    async fn upload_monitor_tracks_renewals_beyond_original_deadline() {
        let active = super::ActiveTask::default();
        let task = uuid::Uuid::now_v7();
        active.set(task, 90_000).await;
        let monitor = active.clone();
        let waiter = tokio::spawn(async move {
            monitor
                .wait_for_lease_loss(task, tokio::time::Duration::from_secs(10))
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(tokio::time::Duration::from_secs(40)).await;
        active.renew_lease(90_000).await;
        tokio::task::yield_now().await;
        tokio::time::advance(tokio::time::Duration::from_secs(45)).await;
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "the original deadline must not terminate an upload"
        );
        tokio::time::advance(tokio::time::Duration::from_secs(36)).await;
        waiter.await.unwrap();
        assert!(
            active
                .lease_safety_expired(tokio::time::Duration::from_secs(10))
                .await
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_wakes_upload_monitor_immediately() {
        let active = super::ActiveTask::default();
        let task = uuid::Uuid::now_v7();
        active.set(task, 90_000).await;
        let monitor = active.clone();
        let waiter = tokio::spawn(async move {
            monitor
                .wait_for_lease_loss(task, tokio::time::Duration::from_secs(10))
                .await
        });
        tokio::task::yield_now().await;
        active.request_cancel(task).await;
        waiter.await.unwrap();
        assert!(
            !active
                .lease_safety_expired(tokio::time::Duration::from_secs(10))
                .await
        );
    }

    use super::*;

    #[tokio::test]
    async fn cancellation_command_only_targets_active_task() {
        let active = ActiveTask::default();
        let active_id = Uuid::now_v7();
        active.set(active_id, 90_000).await;
        active.request_cancel(Uuid::now_v7()).await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
        active.request_cancel(active_id).await;
        assert!(active.cancellation_flag().load(Ordering::Relaxed));
        active.clear().await;
        assert!(!active.cancellation_flag().load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn lease_loss_has_a_distinct_cancellation_reason() {
        let active = ActiveTask::default();
        let task_id = Uuid::now_v7();
        active.set(task_id, 90_000).await;
        active.request_lease_lost(task_id).await;
        assert_eq!(
            active.cancellation_reason(),
            Some(TaskCancellationReason::LeaseLost)
        );
    }

    #[test]
    fn parses_matching_latency_headers_and_subtracts_server_time() {
        let probe_id = Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(LATENCY_VERSION_HEADER, HeaderValue::from_static("1"));
        headers.insert(
            LATENCY_PROBE_HEADER,
            HeaderValue::from_str(&probe_id.to_string()).unwrap(),
        );
        headers.insert(SERVER_PROCESSING_HEADER, HeaderValue::from_static("7000"));
        headers.insert(
            SERVER_SENT_AT_HEADER,
            HeaderValue::from_static("1787361234567"),
        );

        let report = parse_latency_response(&headers, probe_id, Duration::from_millis(42)).unwrap();
        assert_eq!(report.rtt_us, 42_000);
        assert_eq!(report.network_rtt_us, 35_000);
        assert_eq!(report.server_processing_us, 7_000);
    }

    #[test]
    fn rejects_mismatched_probe_or_impossible_processing_time() {
        let probe_id = Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(LATENCY_VERSION_HEADER, HeaderValue::from_static("1"));
        headers.insert(
            LATENCY_PROBE_HEADER,
            HeaderValue::from_str(&probe_id.to_string()).unwrap(),
        );
        headers.insert(SERVER_PROCESSING_HEADER, HeaderValue::from_static("50000"));
        headers.insert(SERVER_SENT_AT_HEADER, HeaderValue::from_static("1"));

        assert!(
            parse_latency_response(&headers, Uuid::now_v7(), Duration::from_millis(60)).is_none()
        );
        assert!(parse_latency_response(&headers, probe_id, Duration::from_millis(40)).is_none());
    }
}
