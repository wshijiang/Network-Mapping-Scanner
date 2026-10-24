use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{collections::BTreeSet, net::IpAddr};

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
};

use crate::error::ScannerError;
use crate::scan::{DnsAnswer, DnsObservation, DnsQuestion};
use crate::types::{DnsConfig, DnsResolver, TargetParams};

const MAX_CONCURRENT_QUERIES: usize = 16;

pub(crate) struct DnsLookupResult {
    pub(crate) observations: Vec<DnsObservation>,
    pub(crate) resolved_ips: Vec<IpAddr>,
}

pub(crate) async fn run(
    config: &DnsConfig,
    target: &TargetParams,
    resolvers: &[DnsResolver],
    cancel_requested: &AtomicBool,
) -> Result<Option<DnsLookupResult>, ScannerError> {
    let resolver_configs = resolver_configs(resolvers)?;
    let mut queries = tokio::task::JoinSet::new();
    let mut observations = Vec::new();
    for domain in target
        .ip
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        for resolver in &resolver_configs {
            for record_type in &config.record_types {
                if cancel_requested.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                let dns_resolver = resolver.resolver.clone();
                let resolver_metadata = resolver.metadata.clone();
                let domain = domain.to_owned();
                let record_type = parse_record_type(record_type)?;
                let timeout_seconds = config.query_timeout_seconds;
                queries.spawn(async move {
                    query(
                        &dns_resolver,
                        &domain,
                        record_type,
                        timeout_seconds,
                        resolver_metadata.as_ref(),
                    )
                    .await
                });
                if queries.len() >= MAX_CONCURRENT_QUERIES {
                    collect_query(&mut queries, &mut observations).await?;
                }
            }
        }
    }
    while !queries.is_empty() {
        if cancel_requested.load(Ordering::Relaxed) {
            queries.abort_all();
            return Ok(None);
        }
        collect_query(&mut queries, &mut observations).await?;
    }
    observations.sort_by(|left, right| {
        (
            left.question.name.as_str(),
            left.resolver_id.as_deref().unwrap_or("system"),
            left.question.record_type.as_str(),
        )
            .cmp(&(
                right.question.name.as_str(),
                right.resolver_id.as_deref().unwrap_or("system"),
                right.question.record_type.as_str(),
            ))
    });
    let resolved_ips = observations
        .iter()
        .flat_map(|observation| observation.answers.iter())
        .filter_map(|answer| {
            matches!(answer.record_type.as_str(), "A" | "AAAA")
                .then(|| answer.value.parse::<IpAddr>().ok())
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    Ok(Some(DnsLookupResult {
        observations,
        resolved_ips: resolved_ips.into_iter().collect(),
    }))
}

async fn collect_query(
    queries: &mut tokio::task::JoinSet<DnsObservation>,
    observations: &mut Vec<DnsObservation>,
) -> Result<(), ScannerError> {
    let observation = queries
        .join_next()
        .await
        .ok_or_else(|| ScannerError::Scan("DNS query task set ended unexpectedly".into()))?
        .map_err(|error| ScannerError::Scan(format!("DNS query task failed: {error}")))?;
    observations.push(observation);
    Ok(())
}

struct ConfiguredResolver {
    resolver: TokioResolver,
    metadata: Option<DnsResolver>,
}

fn resolver_configs(resolvers: &[DnsResolver]) -> Result<Vec<ConfiguredResolver>, ScannerError> {
    if resolvers.is_empty() {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|builder| builder.build())
            .map_err(|error| {
                ScannerError::Scan(format!("failed to create DNS system resolver: {error}"))
            })?;
        return Ok(vec![ConfiguredResolver {
            resolver,
            metadata: None,
        }]);
    }
    resolvers
        .iter()
        .cloned()
        .map(|metadata| {
            let ip = metadata.ip.parse::<IpAddr>().map_err(|error| {
                ScannerError::Scan(format!("invalid DNS resolver {}: {error}", metadata.ip))
            })?;
            let mut connection = match metadata.transport.as_str() {
                "udp" => ConnectionConfig::udp(),
                "tcp" => ConnectionConfig::tcp(),
                other => {
                    return Err(ScannerError::Scan(format!(
                        "unsupported DNS resolver transport '{other}'"
                    )));
                }
            };
            connection.port = metadata.port;
            let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
                ip,
                true,
                vec![connection],
            )]);
            Ok(ConfiguredResolver {
                resolver: TokioResolver::builder_with_config(config, Default::default())
                    .build()
                    .map_err(|error| {
                        ScannerError::Scan(format!("failed to create DNS resolver: {error}"))
                    })?,
                metadata: Some(metadata),
            })
        })
        .collect()
}

fn parse_record_type(value: &str) -> Result<RecordType, ScannerError> {
    let normalized = value.trim().to_ascii_uppercase();
    if !crate::types::is_supported_dns_record_type(&normalized) {
        return Err(ScannerError::Scan(format!(
            "unsupported configured DNS record type '{normalized}'"
        )));
    }
    normalized.parse::<RecordType>().map_err(|error| {
        ScannerError::Scan(format!(
            "failed to parse configured DNS record type '{normalized}': {error}"
        ))
    })
}

async fn query(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
    timeout_seconds: u64,
    resolver_metadata: Option<&DnsResolver>,
) -> DnsObservation {
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(timeout_seconds),
        resolver.lookup(domain, record_type),
    )
    .await;
    let elapsed = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    let observed_at = chrono::Utc::now().timestamp_millis();
    let (response_code, answers) = match result {
        Ok(Ok(lookup)) => (
            "NOERROR".into(),
            lookup
                .answers()
                .iter()
                .map(|record| answer_from_rdata(record.record_type(), &record.data, record.ttl))
                .collect(),
        ),
        Ok(Err(error)) => (response_code(&error.to_string()), Vec::new()),
        Err(_) => ("TIMEOUT".into(), Vec::new()),
    };
    DnsObservation {
        observed_at,
        question: DnsQuestion {
            name: domain.into(),
            record_type: record_type.to_string(),
            class: "IN".into(),
        },
        response_code,
        authoritative: false,
        truncated: false,
        dnssec_authenticated: false,
        answers,
        authority: Vec::new(),
        additional: Vec::new(),
        resolver_ip: resolver_metadata.map(|item| item.ip.clone()),
        resolver_id: resolver_metadata
            .map(|item| item.id.clone())
            .or_else(|| Some("system".into())),
        resolver_label: resolver_metadata
            .map(|item| item.label.clone())
            .or_else(|| Some("系统 DNS".into())),
        resolver_port: resolver_metadata.map(|item| item.port),
        resolver_transport: Some(
            resolver_metadata.map_or_else(|| "system".into(), |item| item.transport.clone()),
        ),
        latency_ms: Some(elapsed),
    }
}

fn answer_from_rdata(record_type: RecordType, data: &RData, ttl: u32) -> DnsAnswer {
    let mut answer = DnsAnswer {
        record_type: record_type.to_string(),
        value: data.to_string(),
        ttl,
        priority: None,
        weight: None,
        port: None,
    };
    match data {
        RData::A(value) => answer.value = value.0.to_string(),
        RData::AAAA(value) => answer.value = value.0.to_string(),
        RData::CNAME(value) => answer.value = value.0.to_string(),
        RData::NS(value) => answer.value = value.0.to_string(),
        RData::PTR(value) => answer.value = value.0.to_string(),
        RData::MX(value) => {
            answer.value = value.exchange.to_string();
            answer.priority = Some(value.preference);
        }
        RData::SRV(value) => {
            answer.value = value.target.to_string();
            answer.priority = Some(value.priority);
            answer.weight = Some(value.weight);
            answer.port = Some(value.port);
        }
        _ => {}
    }
    answer
}

fn response_code(error: &str) -> String {
    let error = error.to_ascii_uppercase();
    if error.contains("NXDOMAIN") || error.contains("NONEXISTENT") {
        "NXDOMAIN".into()
    } else if error.contains("NO RECORDS") {
        "NOERROR".into()
    } else {
        "SERVFAIL".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{
        Name,
        rdata::{MX, SRV},
    };

    #[test]
    fn accepts_all_supported_record_types() {
        for value in crate::types::DNS_RECORD_TYPES {
            assert_eq!(parse_record_type(value).unwrap().to_string(), value);
        }
        assert!(parse_record_type("ANY").is_err());
    }

    #[test]
    fn error_responses_are_never_reported_as_successful_answers() {
        assert_eq!(response_code("NXDOMAIN"), "NXDOMAIN");
        assert_eq!(response_code("connection failed"), "SERVFAIL");
    }

    #[test]
    fn extracts_structured_mx_and_srv_fields() {
        let mx = answer_from_rdata(
            RecordType::MX,
            &RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
            300,
        );
        assert_eq!(mx.value, "mail.example.com.");
        assert_eq!(mx.priority, Some(10));

        let srv = answer_from_rdata(
            RecordType::SRV,
            &RData::SRV(SRV::new(
                20,
                5,
                443,
                Name::from_ascii("service.example.com.").unwrap(),
            )),
            60,
        );
        assert_eq!(srv.value, "service.example.com.");
        assert_eq!(srv.priority, Some(20));
        assert_eq!(srv.weight, Some(5));
        assert_eq!(srv.port, Some(443));
    }

    #[tokio::test]
    async fn custom_udp_and_tcp_resolvers_preserve_transport_port_metadata_and_ttl() {
        use hickory_resolver::proto::{
            op::{Message, MessageType, OpCode},
            rr::{Record, rdata::A},
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, UdpSocket},
        };
        fn response(bytes: &[u8]) -> Vec<u8> {
            let request = Message::from_vec(bytes).unwrap();
            let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_available = true;
            response.queries = request.queries;
            response.add_answer(Record::from_rdata(
                Name::from_ascii("probe.test.").unwrap(),
                321,
                RData::A(A("192.0.2.20".parse().unwrap())),
            ));
            response.to_vec().unwrap()
        }
        for transport in ["udp", "tcp"] {
            let (port, server) = if transport == "udp" {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = socket.local_addr().unwrap().port();
                let server = tokio::spawn(async move {
                    let mut bytes = [0; 8192];
                    let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
                    socket.send_to(&response(&bytes[..n]), peer).await.unwrap();
                });
                (port, server)
            } else {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let n = stream.read_u16().await.unwrap();
                    let mut bytes = vec![0; n as usize];
                    stream.read_exact(&mut bytes).await.unwrap();
                    let reply = response(&bytes);
                    stream.write_u16(reply.len() as u16).await.unwrap();
                    stream.write_all(&reply).await.unwrap();
                });
                (port, server)
            };
            let metadata = DnsResolver {
                id: "local".into(),
                label: "Local fixture".into(),
                ip: "127.0.0.1".into(),
                port,
                transport: transport.into(),
            };
            let resolvers = resolver_configs(std::slice::from_ref(&metadata)).unwrap();
            let result = query(
                &resolvers[0].resolver,
                "probe.test.",
                RecordType::A,
                2,
                Some(&metadata),
            )
            .await;
            assert_eq!(result.response_code, "NOERROR");
            assert_eq!(result.answers.len(), 1);
            assert_eq!(result.answers[0].value, "192.0.2.20");
            assert_eq!(result.answers[0].ttl, 321);
            assert_eq!(result.resolver_port, Some(port));
            assert_eq!(result.resolver_transport.as_deref(), Some(transport));
            assert_eq!(result.resolver_id.as_deref(), Some("local"));
            server.await.unwrap();
        }
    }
}
