use crate::error::ScannerError;
use crate::types::AppConfig;

/// Parsed config + raw content kept for comment-preserving writes.
pub(crate) struct LoadedConfig {
    pub(crate) app: AppConfig,
    pub(crate) check: crate::config_check::ConfigCheck,
    raw: String,
    path: String,
}

pub(crate) fn load(path: &str) -> Result<LoadedConfig, ScannerError> {
    tracing::debug!(config_path = path, "reading scanner configuration");
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ScannerError::Config(format!("cannot read config file {}: {}", path, e)))?;

    // Parse for type checking, but keep the raw string for later edits.
    let doc: toml_edit::ImDocument<String> = raw
        .parse()
        .map_err(|e| ScannerError::Config(format!("failed to parse config {}: {}", path, e)))?;

    let value: serde_json::Value = toml_edit::de::from_str(&raw)
        .map_err(|_| ScannerError::Config("cannot inspect TOML configuration".into()))?;
    let check = crate::config_check::inspect_scanner(&value)
        .map_err(|_| ScannerError::Config("cannot construct configuration field catalog".into()))?;
    check.emit_startup();
    if check.error_count() > 0 {
        return Err(ScannerError::Config(
            "缺少必需配置，请根据启动提示补齐参数".into(),
        ));
    }

    let app: AppConfig = toml_edit::de::from_document(doc).map_err(|e| {
        ScannerError::Config(format!("failed to deserialize config {}: {}", path, e))
    })?;

    validate(&app)?;
    tracing::debug!(
        config_path = path,
        config_bytes = raw.len(),
        "configuration parsed"
    );
    Ok(LoadedConfig {
        app,
        check,
        raw,
        path: path.to_owned(),
    })
}

pub(crate) fn load_env() -> Result<LoadedConfig, ScannerError> {
    load_env_pairs(std::env::vars().filter(|(key, _)| !key.starts_with("NM__REGISTRATION__")))
}

fn load_env_pairs(
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<LoadedConfig, ScannerError> {
    let mut value: serde_json::Value =
        toml_edit::de::from_str(include_str!("../docker/config.example.toml"))
            .map_err(|_| ScannerError::Config("invalid embedded container defaults".into()))?;
    // A deployment must name its own server instead of using the example host.
    value["scanner"]["c_server"] = serde_json::Value::String(String::new());
    value["upload"]["endpoint"] = serde_json::Value::String(String::new());
    crate::config_env::apply(
        &mut value,
        pairs,
        crate::config_check::environment_field_allowed,
    )?;
    if value["upload"]["endpoint"].as_str() == Some("") {
        let host = value["scanner"]["c_server"].as_str().unwrap_or("");
        let port = value["scanner"]["c_port"].as_i64().unwrap_or(0);
        value["upload"]["endpoint"] =
            serde_json::Value::String(format!("https://{host}:{port}/api/scanner/result"));
    }
    let app: AppConfig = serde_json::from_value(value.clone()).map_err(|_| {
        ScannerError::Config("environment configuration has invalid field types".into())
    })?;
    validate(&app)?;
    let check = crate::config_check::inspect_scanner(&value)
        .map_err(|_| ScannerError::Config("cannot inspect environment configuration".into()))?;
    check.emit_startup();
    Ok(LoadedConfig {
        app,
        check,
        raw: String::new(),
        path: String::new(),
    })
}

impl LoadedConfig {
    pub(crate) fn has_legacy_runtime_token(&self) -> bool {
        !self.app.scanner.runtime_token.is_empty()
    }

    pub(crate) fn has_legacy_secret(&self) -> bool {
        if self.has_legacy_runtime_token() {
            return true;
        }
        self.raw
            .parse::<toml_edit::DocumentMut>()
            .ok()
            .and_then(|doc| {
                doc.get("scanner")
                    .and_then(toml_edit::Item::as_table)
                    .map(|scanner| scanner.contains_key("token"))
            })
            .unwrap_or(false)
    }

    /// Remove runtime identity from the legacy TOML after it has been stored in SQLite.
    pub(crate) fn clear_legacy_identity(&self) -> Result<(), ScannerError> {
        if self.path.is_empty() {
            return Ok(());
        }
        tracing::debug!(config_path = %self.path, "removing legacy scanner identity");
        let mut doc: toml_edit::DocumentMut = self.raw.parse().map_err(|e| {
            ScannerError::Config(format!("failed to re-parse config for saving: {}", e))
        })?;
        let scanner = doc["scanner"].as_table_mut().ok_or_else(|| {
            ScannerError::Config("scanner configuration must be a TOML table".into())
        })?;
        scanner.remove("token");
        scanner["scanner_id"] = toml_edit::value("");
        scanner["runtime_token"] = toml_edit::value("");
        atomic_write(&self.path, doc.to_string().as_bytes())?;
        tracing::debug!(config_path = %self.path, "legacy scanner identity removed");
        Ok(())
    }
}

fn atomic_write(path: &str, contents: &[u8]) -> Result<(), ScannerError> {
    use std::io::Write;

    let path = std::path::Path::new(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| ScannerError::Config("config path has no valid file name".into()))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::now_v7()));
    let original_permissions = std::fs::metadata(path)
        .map_err(ScannerError::Io)?
        .permissions();
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    let write_result = (|| {
        let mut file = options.open(&temporary).map_err(ScannerError::Io)?;
        std::fs::set_permissions(&temporary, original_permissions).map_err(ScannerError::Io)?;
        file.write_all(contents).map_err(ScannerError::Io)?;
        file.sync_all().map_err(ScannerError::Io)
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    std::fs::rename(&temporary, path).map_err(ScannerError::Io)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(ScannerError::Io)
}

fn validate(cfg: &AppConfig) -> Result<(), ScannerError> {
    let rules: &[(&str, bool, &str)] = &[
        (
            "scanner.c_server",
            cfg.scanner.c_server.is_empty(),
            "must not be empty",
        ),
        ("scanner.c_port", cfg.scanner.c_port <= 0, "must be > 0"),
        (
            "scanner.rate",
            cfg.scanner.rate <= 0 || cfg.scanner.rate > i64::from(i32::MAX),
            "must be between 1 and 2147483647",
        ),
        (
            "scanner.masscan_wait_seconds",
            cfg.scanner.masscan.wait_seconds > 300,
            "must be between 0 and 300",
        ),
        (
            "scanner.masscan_max_runtime_seconds",
            !(1..=604_800).contains(&cfg.scanner.masscan.max_runtime_seconds)
                || cfg.scanner.masscan.max_runtime_seconds <= cfg.scanner.masscan.wait_seconds,
            "must be between 1 and 604800 and greater than masscan_wait_seconds",
        ),
        (
            "upload.endpoint",
            cfg.upload.endpoint.is_empty(),
            "must not be empty",
        ),
        (
            "scanner.heartbeat_interval_seconds",
            !(5..=300).contains(&cfg.scanner.heartbeat_interval_seconds),
            "must be between 5 and 300",
        ),
        (
            "scanner.connect_timeout_seconds",
            !(1..=60).contains(&cfg.scanner.connect_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "scanner.request_timeout_seconds",
            cfg.scanner.request_timeout_seconds < cfg.scanner.connect_timeout_seconds
                || cfg.scanner.request_timeout_seconds > 300,
            "must be at least connect_timeout_seconds and at most 300",
        ),
        (
            "scanner.reconnect_initial_delay_seconds",
            !(1..=60).contains(&cfg.scanner.reconnect_initial_delay_seconds),
            "must be between 1 and 60",
        ),
        (
            "scanner.reconnect_max_delay_seconds",
            cfg.scanner.reconnect_max_delay_seconds < cfg.scanner.reconnect_initial_delay_seconds
                || cfg.scanner.reconnect_max_delay_seconds > 600,
            "must be at least reconnect_initial_delay_seconds and at most 600",
        ),
        (
            "scanner.active_task_reconnect_max_delay_seconds",
            cfg.scanner.active_task_reconnect_max_delay_seconds == 0
                || cfg.scanner.active_task_reconnect_max_delay_seconds
                    > cfg.scanner.reconnect_max_delay_seconds,
            "must be between 1 and reconnect_max_delay_seconds",
        ),
        (
            "scanner.lease_safety_margin_seconds",
            !(1..=60).contains(&cfg.scanner.lease_safety_margin_seconds),
            "must be between 1 and 60",
        ),
        (
            "network.probe_interval_seconds",
            !(30..=86400).contains(&cfg.network.probe_interval_seconds),
            "must be between 30 and 86400",
        ),
        (
            "network.probe_timeout_seconds",
            !(1..=60).contains(&cfg.network.probe_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "service_detection.zgrab_path",
            cfg.service_detection.enabled && cfg.service_detection.zgrab_path.trim().is_empty(),
            "must not be empty when service detection is enabled",
        ),
        (
            "service_detection.max_probes_per_endpoint",
            !(1..=32).contains(&cfg.service_detection.max_probes_per_endpoint),
            "must be between 1 and 32",
        ),
        (
            "service_detection.confidence_threshold",
            !(1..=100).contains(&cfg.service_detection.confidence_threshold),
            "must be between 1 and 100",
        ),
        (
            "service_detection.senders",
            !(1..=10_000).contains(&cfg.service_detection.senders),
            "must be between 1 and 10000",
        ),
        (
            "service_detection.server_rate_limit",
            !(1..=10_000).contains(&cfg.service_detection.server_rate_limit),
            "must be between 1 and 10000",
        ),
        (
            "service_detection.connect_timeout_seconds",
            !(1..=60).contains(&cfg.service_detection.connect_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "service_detection.target_timeout_seconds",
            cfg.service_detection.target_timeout_seconds
                < cfg.service_detection.connect_timeout_seconds
                || cfg.service_detection.target_timeout_seconds > 300,
            "must be at least connect_timeout_seconds and at most 300",
        ),
        (
            "service_detection.batch_endpoints",
            !(1..=4096).contains(&cfg.service_detection.batch_endpoints),
            "must be between 1 and 4096",
        ),
        (
            "service_detection.idle_timeout_seconds",
            !(1..=3600).contains(&cfg.service_detection.idle_timeout_seconds),
            "must be between 1 and 3600",
        ),
        (
            "service_detection.max_runtime_seconds",
            !(1..=86400).contains(&cfg.service_detection.max_runtime_seconds),
            "must be between 1 and 86400",
        ),
        (
            "service_detection.max_result_bytes",
            !(1_024..=1_048_576).contains(&cfg.service_detection.max_result_bytes),
            "must be between 1024 and 1048576",
        ),
        (
            "dns.query_timeout_seconds",
            !(1..=60).contains(&cfg.dns.query_timeout_seconds),
            "must be between 1 and 60",
        ),
        (
            "dns.record_types",
            cfg.dns.record_types.is_empty() || cfg.dns.record_types.len() > 12,
            "must contain 1 to 12 entries",
        ),
        (
            "nuclei.path",
            cfg.nuclei.enabled && cfg.nuclei.path.trim().is_empty(),
            "must not be empty when nuclei is enabled",
        ),
        (
            "nuclei.templates_path",
            cfg.nuclei.enabled && cfg.nuclei.templates_path.trim().is_empty(),
            "must not be empty when nuclei is enabled",
        ),
        (
            "nuclei.template_update_timeout_seconds",
            !(1..=3600).contains(&cfg.nuclei.template_update_timeout_seconds),
            "must be between 1 and 3600",
        ),
        (
            "nuclei.update_templates",
            cfg.modules.enabled && cfg.nuclei.update_templates,
            "module mode uses versioned template bundles; update through the module release instead",
        ),
        (
            "nuclei.severities",
            cfg.nuclei.severities.is_empty() || cfg.nuclei.severities.len() > 5,
            "must contain 1 to 5 entries",
        ),
        (
            "nuclei.rate_limit",
            !(1..=10_000).contains(&cfg.nuclei.rate_limit),
            "must be between 1 and 10000",
        ),
        (
            "nuclei.bulk_size",
            !(1..=1_000).contains(&cfg.nuclei.bulk_size),
            "must be between 1 and 1000",
        ),
        (
            "nuclei.concurrency",
            !(1..=1_000).contains(&cfg.nuclei.concurrency),
            "must be between 1 and 1000",
        ),
        (
            "nuclei.timeout_seconds",
            !(1..=300).contains(&cfg.nuclei.timeout_seconds),
            "must be between 1 and 300",
        ),
        (
            "nuclei.retries",
            cfg.nuclei.retries > 10,
            "must be between 0 and 10",
        ),
        (
            "nuclei.max_runtime_seconds",
            !(10..=86_400).contains(&cfg.nuclei.max_runtime_seconds),
            "must be between 10 and 86400",
        ),
        (
            "nuclei.max_findings",
            !(1..=100_000).contains(&cfg.nuclei.max_findings),
            "must be between 1 and 100000",
        ),
        (
            "nuclei.max_result_bytes",
            !(4_096..=1_048_576).contains(&cfg.nuclei.max_result_bytes),
            "must be between 4096 and 1048576",
        ),
    ];

    for &(field, failed, msg) in rules {
        if failed {
            return Err(ScannerError::Config(format!("{}: {}", field, msg)));
        }
    }
    if cfg
        .dns
        .record_types
        .iter()
        .any(|record_type| !crate::types::is_supported_dns_record_type(record_type))
    {
        return Err(ScannerError::Config(
            "dns.record_types contains an unsupported record type".into(),
        ));
    }
    if cfg.nuclei.severities.iter().any(|severity| {
        !matches!(
            severity.trim().to_ascii_lowercase().as_str(),
            "info" | "low" | "medium" | "high" | "critical"
        )
    }) {
        return Err(ScannerError::Config(
            "nuclei.severities contains an unsupported severity".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn environment_loads_without_toml_and_derives_upload_endpoint() {
        let config = super::load_env_pairs([
            (
                "NM__SCANNER__C_SERVER".into(),
                "scanner.example.test".into(),
            ),
            ("NM__NUCLEI__UPDATE_TEMPLATES".into(), "true".into()),
            ("NM__SCANNER__MASSCAN_WAIT_SECONDS".into(), "0".into()),
        ])
        .unwrap();
        assert_eq!(
            config.app.upload.endpoint,
            "https://scanner.example.test:9999/api/scanner/result"
        );
        assert!(config.app.scanner.verify_tls);
        assert_eq!(config.app.scanner.masscan.wait_seconds, 0);
        assert!(config.app.nuclei.update_templates);
        assert_eq!(
            config.app.nuclei.bundled_templates_path,
            "/opt/nuclei-templates/bundled"
        );
        assert!(!config.has_legacy_secret());
        config.clear_legacy_identity().unwrap();
    }
    #[test]
    fn environment_refuses_the_example_server_or_invalid_boolean() {
        assert!(super::load_env_pairs([]).is_err());
        assert!(
            super::load_env_pairs([
                ("NM__SCANNER__C_SERVER".into(), "example.test".into()),
                ("NM__SCANNER__VERIFY_TLS".into(), "not-a-boolean".into())
            ])
            .is_err()
        );
    }
    use super::*;

    #[test]
    fn clearing_legacy_identity_preserves_other_config_content() {
        let path =
            std::env::temp_dir().join(format!("scanner-config-{}.toml", uuid::Uuid::now_v7()));
        let raw = include_str!("../config.toml")
            .replace(
                "scanner_id = \"\"",
                "scanner_id = \"019c0000-0000-7000-8000-000000000001\"",
            )
            .replace("runtime_token = \"\"", "runtime_token = \"runtime-secret\"")
            .replace("[scanner]", "[scanner]\ntoken = \"one-time-secret\"");
        std::fs::write(&path, raw).unwrap();

        let loaded = load(path.to_str().unwrap()).unwrap();
        assert!(loaded.has_legacy_secret());
        loaded.clear_legacy_identity().unwrap();

        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# Target API server hostname"));
        assert!(updated.contains("scanner_id = \"\""));
        assert!(updated.contains("runtime_token = \"\""));
        assert!(!updated.contains("one-time-secret"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn masscan_configuration_validates_limits_and_output_mode() {
        let raw = include_str!("../config.toml");
        let mut cfg: AppConfig = toml_edit::de::from_str(raw).unwrap();
        assert_eq!(cfg.scanner.masscan, crate::types::MasscanConfig::default());
        cfg.scanner.masscan.wait_seconds = 301;
        assert!(
            validate(&cfg)
                .unwrap_err()
                .to_string()
                .contains("masscan_wait_seconds")
        );
        cfg.scanner.masscan.wait_seconds = 10;
        for limit in [0, 10, 604_801] {
            cfg.scanner.masscan.max_runtime_seconds = limit;
            assert!(
                validate(&cfg)
                    .unwrap_err()
                    .to_string()
                    .contains("masscan_max_runtime_seconds")
            );
        }
        let explicit = raw.replace("[scanner]", "[scanner]\nmasscan_output_mode = \"standard_list\"\nmasscan_wait_seconds = 0\nmasscan_max_runtime_seconds = 60");
        let cfg: AppConfig = toml_edit::de::from_str(&explicit).unwrap();
        assert_eq!(
            cfg.scanner.masscan.output_mode,
            crate::types::MasscanOutputMode::StandardList
        );
        assert_eq!(cfg.scanner.masscan.wait_seconds, 0);
        assert_eq!(cfg.scanner.masscan.max_runtime_seconds, 60);
        validate(&cfg).unwrap();
        assert!(
            toml_edit::de::from_str::<AppConfig>(&explicit.replace("standard_list", "invalid"))
                .is_err()
        );
    }
}
