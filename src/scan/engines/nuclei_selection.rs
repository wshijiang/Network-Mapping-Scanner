//! Select templates per endpoint; never fall back to an unrestricted scan.
use crate::scan::{PortObservation, ServiceObservation};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Selection {
    Web,
    Service(&'static str),
    Tls,
}

impl Selection {
    pub(super) fn args(&self) -> Vec<&str> {
        match self {
            Self::Web => vec!["-as", "-pt", "http"],
            Self::Service(tag) => vec!["-tags", tag, "-pt", "tcp,javascript", "-nh"],
            Self::Tls => vec!["-tags", "ssl,tls", "-pt", "ssl", "-nh"],
        }
    }
}

fn service_selection(service: &str) -> Option<(Selection, Option<&'static str>)> {
    Some(match service {
        "http" | "http-alt" => (Selection::Web, Some("http")),
        "https" | "https-alt" | "doh" => (Selection::Web, Some("https")),
        "tls" | "ssl" | "dot" => (Selection::Tls, None),
        "ssh" => (Selection::Service("ssh"), None),
        "ftp" => (Selection::Service("ftp"), None),
        "smtp" => (Selection::Service("smtp"), None),
        "pop3" => (Selection::Service("pop3"), None),
        "imap" => (Selection::Service("imap"), None),
        "mysql" => (Selection::Service("mysql"), None),
        "postgres" | "postgresql" => (Selection::Service("postgresql"), None),
        "redis" => (Selection::Service("redis"), None),
        "mongodb" | "mongo" => (Selection::Service("mongodb"), None),
        "mssql" => (Selection::Service("mssql"), None),
        "smb" => (Selection::Service("smb"), None),
        "rdp" => (Selection::Service("rdp"), None),
        "vnc" => (Selection::Service("vnc"), None),
        "mqtt" => (Selection::Service("mqtt"), None),
        "telnet" => (Selection::Service("telnet"), None),
        // Do not send plaintext application templates to implicit TLS services.
        "smtps" | "imaps" | "pop3s" | "ftps" | "mqtts" => (Selection::Tls, None),
        _ => return None,
    })
}

fn port_service(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        110 => "pop3",
        143 => "imap",
        445 => "smb",
        1433 => "mssql",
        1883 => "mqtt",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        27017 => "mongodb",
        // HTTP requires positive service evidence; a port number is insufficient.
        _ => return None,
    })
}

pub(super) fn build_batches(
    ports: &[PortObservation],
    services: &[ServiceObservation],
    port_fallback: bool,
) -> BTreeMap<Selection, Vec<String>> {
    let services: HashMap<_, _> = services
        .iter()
        .filter_map(|item| {
            item.service.as_deref().map(|service| {
                (
                    (item.ip.as_str(), item.port, item.protocol.as_str()),
                    service,
                )
            })
        })
        .collect();
    let mut batches: BTreeMap<Selection, BTreeSet<String>> = BTreeMap::new();
    for endpoint in ports.iter().filter(|p| p.state == "open") {
        if endpoint.protocol != "tcp" {
            tracing::info!(ip = %endpoint.ip, port = endpoint.port, reason = "unsupported_transport", "nuclei endpoint skipped");
            continue;
        }
        let detected = services.get(&(
            endpoint.ip.as_str(),
            endpoint.port,
            endpoint.protocol.as_str(),
        ));
        let service = detected
            .copied()
            .or_else(|| port_fallback.then(|| port_service(endpoint.port)).flatten());
        let Some((selection, scheme)) =
            service.and_then(|s| service_selection(&s.to_ascii_lowercase()))
        else {
            tracing::info!(ip = %endpoint.ip, port = endpoint.port, reason = "no_template_selection", "nuclei endpoint skipped (not assessed)");
            continue;
        };
        let host = if endpoint.ip.contains(':') {
            format!("[{}]", endpoint.ip)
        } else {
            endpoint.ip.clone()
        };
        let target = match scheme {
            Some(scheme) => format!("{scheme}://{host}:{}", endpoint.port),
            None => format!("{host}:{}", endpoint.port),
        };
        tracing::debug!(%target, ?selection, basis = if detected.is_some() { "service" } else { "port_fallback" }, "selected nuclei batch");
        batches.entry(selection).or_default().insert(target);
    }
    batches
        .into_iter()
        .map(|(selection, targets)| (selection, targets.into_iter().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn port(port: u16) -> PortObservation {
        PortObservation {
            ip: "2001:db8::1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "test".into(),
            observed_at: 0,
        }
    }
    fn service(port: u16, service: &str) -> ServiceObservation {
        ServiceObservation {
            ip: "2001:db8::1".into(),
            port,
            protocol: "tcp".into(),
            service: Some(service.into()),
            banner: None,
            source: "test".into(),
            data: None,
            observed_at: 0,
        }
    }
    #[test]
    fn detected_services_override_ports_and_are_isolated() {
        let batches = build_batches(
            &[port(8080), port(13306), port(10443), port(636)],
            &[
                service(8080, "redis"),
                service(13306, "mysql"),
                service(10443, "https"),
                service(636, "tls"),
            ],
            true,
        );
        assert_eq!(batches[&Selection::Web], ["https://[2001:db8::1]:10443"]);
        assert_eq!(
            batches[&Selection::Service("redis")],
            ["[2001:db8::1]:8080"]
        );
        assert_eq!(
            batches[&Selection::Service("mysql")],
            ["[2001:db8::1]:13306"]
        );
        assert_eq!(batches[&Selection::Tls], ["[2001:db8::1]:636"]);
    }
    #[test]
    fn unknown_web_ports_and_unsupported_services_never_scan_unrestricted() {
        assert!(
            build_batches(
                &[port(8080), port(9000), port(22)],
                &[service(22, "unknown-app")],
                true
            )
            .is_empty()
        );
        assert!(build_batches(&[port(22)], &[], false).is_empty());
        assert_eq!(
            build_batches(&[port(22), port(22)], &[], true)[&Selection::Service("ssh")].len(),
            1
        );
    }
    #[test]
    fn closed_and_udp_endpoints_are_excluded() {
        let mut closed = port(22);
        closed.state = "closed".into();
        let mut udp = port(6379);
        udp.protocol = "udp".into();
        assert!(build_batches(&[closed, udp], &[], true).is_empty());
    }
    #[test]
    fn every_selection_has_an_explicit_filter() {
        assert_eq!(Selection::Web.args(), ["-as", "-pt", "http"]);
        assert_eq!(
            Selection::Service("redis").args(),
            ["-tags", "redis", "-pt", "tcp,javascript", "-nh"]
        );
        assert_eq!(
            Selection::Tls.args(),
            ["-tags", "ssl,tls", "-pt", "ssl", "-nh"]
        );
    }
}
