//! Bounded UDP protocol probes for the next task-protocol revision.
//!
//! This library API is deliberately not wired into task execution or capabilities:
//! the server must first distinguish TCP and UDP endpoint identities. Callers must
//! authorize targets and enforce aggregate/per-IP rate and concurrency limits.
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode},
    rr::{DNSClass, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, sync::watch, time::Instant};

const MAX_DATAGRAM: usize = 8192;
const MAX_IGNORED: u32 = 32;
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// Supported wire protocols. These identify protocols, not implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpService {
    Dns,
    Ntp,
    Stun,
}

/// A caller can establish reachability only from a matched protocol response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Identified,
    NoResponse,
    PortUnreachable,
    ResponseLimit,
    Cancelled,
}

/// No raw datagrams, returned addresses, names or IDs are retained.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub status: ProbeStatus,
    pub service: Option<UdpService>,
    pub attempts: u8,
    pub ignored_datagrams: u32,
    pub evidence: Option<Value>,
}

/// Per-endpoint bounds. Closing the cancellation channel cancels the probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeOptions {
    pub timeout: Duration,
    pub attempts: u8,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            attempts: 2,
        }
    }
}

impl ProbeResult {
    fn new(status: ProbeStatus) -> Self {
        Self {
            status,
            service: None,
            attempts: 0,
            ignored_datagrams: 0,
            evidence: None,
        }
    }
}

struct Request {
    service: UdpService,
    bytes: Vec<u8>,
}

impl Request {
    fn new(service: UdpService) -> io::Result<Self> {
        // All 16 bytes come from the platform RNG; protocol IDs are not UUID timestamps.
        let mut nonce = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| io::Error::other("platform random source unavailable"))?;
        Ok(Self::with_nonce(service, nonce))
    }

    fn with_nonce(service: UdpService, nonce: [u8; 16]) -> Self {
        let bytes = match service {
            UdpService::Dns => {
                // Root SOA, RD=0, no EDNS/DNSSEC/ANY request or external query name.
                let mut bytes = vec![0; 12];
                bytes[..2].copy_from_slice(&nonce[..2]);
                bytes[5] = 1;
                bytes.extend_from_slice(&[0, 0, 6, 0, 1]);
                bytes
            }
            UdpService::Ntp => {
                let mut bytes = vec![0; 48];
                bytes[0] = 0x23; // NTPv4 client request, never mode 6/7.
                bytes[40..48].copy_from_slice(&nonce[..8]);
                bytes
            }
            UdpService::Stun => {
                let mut bytes = vec![0; 20];
                bytes[1] = 1; // Binding request, no TURN allocation.
                bytes[4..8].copy_from_slice(&STUN_COOKIE);
                bytes[8..20].copy_from_slice(&nonce[..12]);
                bytes
            }
        };
        Self { service, bytes }
    }

    fn identify(&self, response: &[u8]) -> Option<Value> {
        match self.service {
            UdpService::Dns => {
                // Bound advertised record counts before the DNS decoder allocates.
                if response.len() < 12
                    || response[4..12]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|n| usize::from(u16::from_be_bytes(*n)))
                        .sum::<usize>()
                        > 64
                {
                    return None;
                }
                let mut decoder = BinDecoder::new(response);
                let message = Message::read(&mut decoder).ok()?;
                if !decoder.is_empty()
                    || message.id() != u16::from_be_bytes([self.bytes[0], self.bytes[1]])
                    || message.message_type() != MessageType::Response
                    || message.op_code() != OpCode::Query
                    || message.queries().len() != 1
                {
                    return None;
                }
                let query = &message.queries()[0];
                if !query.name().is_root()
                    || query.query_type() != RecordType::SOA
                    || query.query_class() != DNSClass::IN
                {
                    return None;
                }
                Some(json!({"response_code":u16::from(message.response_code()),
                    "truncated":message.truncated(),"authoritative":message.authoritative()}))
            }
            UdpService::Ntp => {
                if response.len() != 48
                    || !matches!((response[0] >> 3) & 7, 3 | 4)
                    || response[0] & 7 != 4
                    || response[1] > 16
                    || response[24..32] != self.bytes[40..48]
                {
                    return None;
                }
                Some(json!({"version":(response[0] >> 3) & 7,"mode":4,
                    "stratum":response[1],"kiss_of_death":response[1] == 0}))
            }
            UdpService::Stun => {
                if response.len() < 20
                    || !matches!(&response[..2], [0x01, 0x01] | [0x01, 0x11])
                    || response[4..8] != STUN_COOKIE
                    || response[8..20] != self.bytes[8..20]
                {
                    return None;
                }
                let declared = usize::from(u16::from_be_bytes([response[2], response[3]]));
                if declared % 4 != 0 || declared + 20 != response.len() {
                    return None;
                }
                let mut offset = 20;
                let mut error_code = None;
                let mut mapped_address = false;
                while offset < response.len() {
                    let header = response.get(offset..offset + 4)?;
                    let kind = u16::from_be_bytes([header[0], header[1]]);
                    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
                    let value = response.get(offset + 4..offset + 4 + len)?;
                    if matches!(kind, 0x0001 | 0x0020) {
                        if !matches!(
                            value,
                            [0, 1, _, _, _, _, _, _]
                                | [0, 2, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _]
                        ) {
                            return None;
                        }
                        mapped_address = true;
                    }
                    if kind == 0x0009 {
                        if error_code.is_some()
                            || len < 4
                            || value[0] != 0
                            || value[1] != 0
                            || !(3..=6).contains(&value[2])
                            || value[3] > 99
                        {
                            return None;
                        }
                        error_code = Some(u16::from(value[2]) * 100 + u16::from(value[3]));
                    }
                    offset += 4 + len.div_ceil(4) * 4;
                    if offset > response.len() {
                        return None;
                    }
                }
                let error = response[1] == 0x11;
                if (error && error_code.is_none())
                    || (!error && (!mapped_address || error_code.is_some()))
                {
                    return None;
                }
                Some(
                    json!({"method":"binding","class":if error {"error"} else {"success"},
                    "error_code":error_code}),
                )
            }
        }
    }
}

/// Probe one explicitly selected unicast endpoint. A timeout never means closed.
///
/// Connected UDP filters other peers. Unrelated/oversized packets cannot extend
/// the attempt deadline and are bounded by a total response limit. This function
/// does not enumerate networks or ports and is not called by normal scan tasks.
pub async fn probe(
    target: SocketAddr,
    service: UdpService,
    options: ProbeOptions,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<ProbeResult> {
    let address = target.ip().to_canonical();
    if target.port() == 0
        || address.is_unspecified()
        || address.is_multicast()
        || address == std::net::Ipv4Addr::BROADCAST
        || options.attempts == 0
        || options.attempts > 2
        || options.timeout.is_zero()
        || options.timeout > Duration::from_secs(5)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UDP target or probe bounds",
        ));
    }
    let mut result = ProbeResult::new(ProbeStatus::NoResponse);
    if *cancel.borrow() || cancel.has_changed().is_err() {
        result.status = ProbeStatus::Cancelled;
        return Ok(result);
    }
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(target).await?;
    // One extra byte detects truncation instead of parsing a valid-looking prefix.
    let mut buffer = vec![0; MAX_DATAGRAM + 1];
    for attempt in 1..=options.attempts {
        let request = Request::new(service)?;
        let deadline = Instant::now() + options.timeout;
        let exchange = async {
            result.attempts = attempt;
            socket.send(&request.bytes).await?;
            loop {
                let length = socket.recv(&mut buffer).await?;
                if length <= MAX_DATAGRAM
                    && let Some(evidence) = request.identify(&buffer[..length])
                {
                    result.status = ProbeStatus::Identified;
                    result.service = Some(service);
                    result.evidence = Some(evidence);
                    return Ok::<_, io::Error>(true);
                }
                result.ignored_datagrams += 1;
                if result.ignored_datagrams >= MAX_IGNORED {
                    result.status = ProbeStatus::ResponseLimit;
                    return Ok(true);
                }
            }
        };
        let outcome = tokio::select! {
            biased;
            _ = cancel.wait_for(|value| *value) => {
                // A closed control channel also cancels the operation.
                result.status = ProbeStatus::Cancelled;
                return Ok(result);
            }
            outcome = tokio::time::timeout_at(deadline, exchange) => outcome,
        };
        match outcome {
            Ok(Ok(true)) => return Ok(result),
            Ok(Ok(false)) | Err(_) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {
                result.status = ProbeStatus::PortUnreachable;
                return Ok(result);
            }
            Ok(Err(error)) => return Err(error),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
