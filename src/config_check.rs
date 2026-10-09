//! Read-only inspection of the original TOML, before Serde fills defaults.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

include!(concat!(env!("OUT_DIR"), "/public_config_fields.rs"));

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssueKind {
    Default,
    Optional,
    Required,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigIssue {
    pub field: String,
    pub kind: ConfigIssueKind,
    pub source: String,
    pub default_value: Option<String>,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigCheck {
    pub component: String,
    pub version: String,
    pub checked_at: DateTime<Utc>,
    pub items: Vec<ConfigIssue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_fields: Vec<String>,
}

impl ConfigCheck {
    pub fn inspect(raw: &Value, defaults: &Value, required: &[&str], component: &str) -> Self {
        let mut report = Self {
            component: component.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            checked_at: Utc::now(),
            items: Vec::new(),
            public_fields: Vec::new(),
        };
        for field in required {
            if lookup(raw, field).is_none() {
                report.items.push(ConfigIssue {
                    field: (*field).into(),
                    kind: ConfigIssueKind::Required,
                    source: "startup".into(),
                    default_value: None,
                    description: "必需的部署参数，请在配置文件中填写。".into(),
                });
            }
        }
        report.collect(raw, defaults, "", defaults);
        report.items.sort_by(|a, b| a.field.cmp(&b.field));
        report
    }

    fn collect(&mut self, raw: &Value, value: &Value, prefix: &str, defaults: &Value) {
        if let Some(object) = value.as_object()
            && !prefix.ends_with("service_defaults")
        {
            for (key, child) in object {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                self.collect(raw, child, &field, defaults);
            }
            return;
        }
        // None describes the unset default; it does not suppress a missing
        // public field. Public-schema and source filters decide eligibility.
        if lookup(raw, prefix).is_some() || sensitive(prefix) {
            return;
        }
        let section = prefix.split('.').next().unwrap_or_default();
        let source = source_for(prefix);
        // Web-managed runtime fields live in the server database and are sent
        // to the scanner. Their omitted TOML fallback values need no notice.
        if source == "remote_override" {
            return;
        }
        let enabled_path = match section {
            "report_mail" => "report_mail.remote_images_enabled".into(),
            _ => format!("{section}.enabled"),
        };
        let inactive = lookup(raw, &enabled_path)
            .or_else(|| lookup(defaults, &enabled_path))
            .and_then(Value::as_bool)
            == Some(false);
        let optional = inactive && prefix != enabled_path;
        let description = if optional {
            "本地功能未启用，此参数无需补齐；启用时请检查相关配置。"
        } else if value.is_null() {
            "此参数未显式配置，当前保持未设置；如需调整，请修改启动配置并重启。"
        } else if source == "local_limit" {
            "采用本地默认值；远程配置仍受本地开关和速率限制约束。"
        } else if prefix.ends_with("directory") || prefix.ends_with("path") {
            "采用内置路径；请按文件或 Docker 部署检查路径及挂载，修改后重启。"
        } else {
            "采用内置默认值；如需调整，请修改启动配置并重启。"
        };
        let default_value = (!value.is_null()).then(|| {
            let rendered = value.to_string();
            if rendered.chars().count() > 480 {
                "内置规则（详情见对应运行时设置）".into()
            } else {
                rendered
            }
        });
        self.items.push(ConfigIssue {
            field: prefix.into(),
            kind: if optional {
                ConfigIssueKind::Optional
            } else {
                ConfigIssueKind::Default
            },
            source: source.into(),
            default_value,
            description: description.into(),
        });
    }

    pub fn error_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.kind == ConfigIssueKind::Required)
            .count()
    }

    pub fn default_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.kind == ConfigIssueKind::Default)
            .count()
    }

    pub fn emit_startup(&self) {
        eprintln!(
            "配置检查：{} 项未显式配置，{} 项为未启用功能的可选参数，{} 项必需参数缺失。",
            self.default_count(),
            self.items.len() - self.default_count() - self.error_count(),
            self.error_count()
        );
        tracing::info!(event = "ConfigCheckSummary", component = %self.component,
            default_count = self.default_count(), missing_required = self.error_count(),
            optional_count = self.items.len() - self.default_count() - self.error_count(), "启动配置检查完成");
        for item in &self.items {
            if item.kind == ConfigIssueKind::Required {
                eprintln!("配置错误：缺少 {}。{}", item.field, item.description);
                tracing::error!(event = "ConfigFieldMissing", field = %item.field, "必需配置缺失");
            } else if item.kind == ConfigIssueKind::Default {
                tracing::info!(event = "ConfigFieldDefaulted", field = %item.field,
                    source = %item.source, default_value = ?item.default_value,
                    description = %item.description, "配置字段未显式填写");
            }
        }
    }
}

fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |value, key| value.get(key))
}

fn sensitive(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        "password",
        "token",
        "secret",
        "encrypt_key",
        "pepper",
        "api_key",
        "private_key",
        "scanner_id",
    ]
    .iter()
    .any(|part| path.contains(part))
}

fn source_for(field: &str) -> &'static str {
    match field {
        "service_detection.enabled" | "dns.enabled" | "nuclei.enabled" | "scanner.rate" => {
            "local_limit"
        }
        "service_detection.zgrab_path"
        | "service_detection.required"
        | "nuclei.path"
        | "nuclei.templates_path" => "startup",
        _ if field.starts_with("service_detection.")
            || field.starts_with("dns.")
            || field.starts_with("nuclei.") =>
        {
            "remote_override"
        }
        _ => "startup",
    }
}

pub(crate) fn inspect_scanner(raw: &Value) -> Result<ConfigCheck, serde_json::Error> {
    use crate::types::*;
    // Deserialize a credential-free prototype to reuse all real scanner defaults,
    // including flattened masscan fields. It is never used to run the scanner.
    let scanner: ScannerConfig =
        serde_json::from_value(json!({"c_server":"", "c_port":0, "rate":0}))?;
    let mut scanner = serde_json::to_value(scanner)?;
    if let Some(fields) = scanner.as_object_mut() {
        for field in ["c_server", "c_port", "rate", "scanner_id", "runtime_token"] {
            fields.remove(field);
        }
    }
    let defaults = json!({
        "scanner": scanner, "network": NetworkConfig::default(),
        "service_detection": ServiceDetectionConfig::default(),
        "dns": DnsConfig::default(), "nuclei": NucleiConfig::default(),
    });
    let mut report = ConfigCheck::inspect(
        raw,
        &defaults,
        &[
            "scanner.c_server",
            "scanner.c_port",
            "scanner.rate",
            "upload.endpoint",
        ],
        "scanner",
    );
    report
        .items
        .retain(|item| PUBLIC_CONFIG_FIELDS.contains(&item.field.as_str()));
    report.public_fields = PUBLIC_CONFIG_FIELDS
        .iter()
        .filter(|field| !sensitive(field))
        .map(|field| (*field).into())
        .collect();
    for issue in &mut report.items {
        if issue.field == "scanner.verify_tls" {
            issue.description = "缺省值关闭 TLS 证书校验；文件及 Docker 部署均建议显式设置 verify_tls = true 并配置可信 CA。".into();
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_local_defaults_are_reported_without_leaking_identity_or_remote_fields() {
        let report = ConfigCheck::inspect(
            &json!({"nuclei": {"enabled": true}}),
            &json!({"nuclei": {"enabled": false, "path": null, "rate_limit": null},
                "scanner": {"runtime_token": null, "scanner_id": null}}),
            &[],
            "scanner",
        );
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].field, "nuclei.path");
        assert_eq!(report.items[0].kind, ConfigIssueKind::Default);
        assert!(report.items[0].default_value.is_none());
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn unpublished_defaults_never_generate_notices() {
        let report = inspect_scanner(&json!({})).unwrap();
        assert!(
            report
                .items
                .iter()
                .all(|item| PUBLIC_CONFIG_FIELDS.contains(&item.field.as_str()))
        );
        for field in [
            "scanner.heartbeat_interval_seconds",
            "scanner.masscan_output_mode",
            "scanner.masscan_wait_seconds",
            "scanner.masscan_max_runtime_seconds",
        ] {
            assert!(!report.items.iter().any(|item| item.field == field));
        }
    }

    #[test]
    fn tracked_public_configuration_has_no_notices() {
        if option_env!("NM_PUBLIC_CONFIG_FIELDS_FILE").is_some() {
            return;
        }
        let content =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.toml")).unwrap();
        let raw: Value = toml_edit::de::from_str(&content).unwrap();
        assert!(inspect_scanner(&raw).unwrap().items.is_empty());
    }

    #[test]
    fn omitted_fields_use_real_defaults_and_do_not_expose_identity() {
        let raw = json!({"scanner":{"c_server":"private.internal", "c_port":9999,
            "rate":1000, "runtime_token":"private-token"}, "upload":{"endpoint":"https://private.internal/result"}});
        let report = inspect_scanner(&raw).unwrap();
        assert_eq!(report.error_count(), 0);
        let field = report
            .items
            .iter()
            .find(|item| item.field == "scanner.connect_timeout_seconds")
            .unwrap();
        assert_eq!(field.default_value.as_deref(), Some("5"));
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("private-token"));
        assert!(!output.contains("private.internal"));
        assert!(!output.contains("scanner.runtime_token"));
    }

    #[test]
    fn inactive_engine_paths_are_optional_but_missing_connection_is_required() {
        let report = inspect_scanner(&json!({"service_detection":{"enabled":false}})).unwrap();
        assert_eq!(report.error_count(), 4);
        assert!(
            report
                .items
                .iter()
                .any(|item| item.field == "service_detection.zgrab_path"
                    && item.kind == ConfigIssueKind::Optional
                    && item.source == "startup")
        );
    }

    #[test]
    fn remote_runtime_fields_are_excluded_but_local_limits_and_paths_remain() {
        let report = inspect_scanner(&json!({})).unwrap();
        assert!(
            !report
                .items
                .iter()
                .any(|item| item.source == "remote_override")
        );
        for field in [
            "service_detection.batch_endpoints",
            "service_detection.strategy",
            "dns.record_types",
            "dns.query_timeout_seconds",
            "nuclei.rate_limit",
            "nuclei.max_findings",
        ] {
            assert!(!report.items.iter().any(|item| item.field == field));
        }
        for field in [
            "service_detection.enabled",
            "service_detection.zgrab_path",
            "dns.enabled",
            "nuclei.enabled",
            "nuclei.path",
            "nuclei.templates_path",
            "scanner.connect_timeout_seconds",
        ] {
            assert!(report.items.iter().any(|item| item.field == field));
        }
    }

    #[test]
    fn explicit_fields_are_not_reported_even_when_extra_fields_keep_the_count_equal() {
        let report = ConfigCheck::inspect(
            &json!({"scanner":{"rate":0,"old":1}}),
            &json!({"scanner":{"rate":1000,"timeout":5}}),
            &[],
            "scanner",
        );
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].field, "scanner.timeout");
    }
}

#[cfg(test)]
mod deployment_tests {
    use super::*;

    #[test]
    fn custom_read_only_config_uses_same_defaults_without_writing() {
        use std::fs;
        let directory =
            std::env::temp_dir().join(format!("nm-scanner-check-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("custom-scanner.toml");
        let content = include_str!("../docker/config.example.toml")
            .lines()
            .filter(|line| {
                !line.starts_with("connect_timeout_seconds =")
                    && !line.starts_with("masscan_wait_seconds =")
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, &content).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let loaded = crate::config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.app.scanner.masscan.wait_seconds, 10);
        assert!(
            !loaded
                .check
                .items
                .iter()
                .any(|item| item.field.starts_with("scanner.masscan_"))
        );
        assert_eq!(loaded.app.scanner.connect_timeout_seconds, 5);
        assert_eq!(loaded.app.service_detection.connect_timeout_seconds, 5);
        assert!(
            loaded
                .check
                .items
                .iter()
                .any(|item| item.field == "scanner.connect_timeout_seconds")
        );
        assert!(
            !loaded
                .check
                .items
                .iter()
                .any(|item| item.field == "service_detection.connect_timeout_seconds")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn tool_paths_are_local_while_engine_switches_are_local_limits() {
        let report = inspect_scanner(&json!({"service_detection":{"enabled":true}})).unwrap();
        let path = report
            .items
            .iter()
            .find(|item| item.field == "service_detection.zgrab_path")
            .unwrap();
        assert_eq!(path.source, "startup");
        let report = inspect_scanner(&json!({})).unwrap();
        let enabled = report
            .items
            .iter()
            .find(|item| item.field == "service_detection.enabled")
            .unwrap();
        assert_eq!(enabled.source, "local_limit");
    }
}
