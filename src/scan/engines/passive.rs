//! Bounded UDP receiver. Never sends packets or opens a CIP/OPC UA session.
use super::zgrab2::EngineOutcome;
use crate::{
    error::ScannerError,
    scan::{PortObservation, ScanObservation, ServiceObservation},
    types::{ServiceDetectionConfig, ServiceProbeOptions},
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{
    net::UdpSocket,
    time::{Duration, Instant, sleep, timeout_at},
};
fn invalid() -> ScannerError {
    ScannerError::Scan("invalid IPv4 passive receiver configuration".into())
}
pub(crate) fn validate_options(o: &ServiceProbeOptions) -> Result<(), ScannerError> {
    let bind: Ipv4Addr = o
        .passive_bind
        .as_ref()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    if bind.is_unspecified()
        || bind.is_multicast()
        || bind.is_broadcast()
        || o.passive_window_seconds
            .is_some_and(|s| !(1..=60).contains(&s))
    {
        return Err(invalid());
    }
    if let Some(group) = &o.passive_group {
        let group: Ipv4Addr = group.parse().map_err(|_| invalid())?;
        let interface: Ipv4Addr = o
            .passive_interface
            .as_ref()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        if !group.is_multicast() || interface != bind {
            return Err(invalid());
        }
    } else if o.passive_interface.is_some() {
        return Err(invalid());
    }
    if o.modbus_unit_id.is_some()
        || o.s7_tsap.is_some()
        || o.mqtt_version.is_some()
        || o.server_name.is_some()
        || o.doh_path.is_some()
        || o.tls_ca_pem.is_some()
    {
        return Err(invalid());
    }
    Ok(())
}
fn enip_io(p: &[u8]) -> Option<Value> {
    // UDP I/O: Common Packet Format, Sequenced Address then Connected Data.
    if p.len() < 20 || p[..6] != [2, 0, 2, 0x80, 8, 0] || p[14..16] != [0xb1, 0] {
        return None;
    }
    let id = u32::from_le_bytes(p[6..10].try_into().ok()?);
    let n = u16::from_le_bytes(p[16..18].try_into().ok()?) as usize;
    if id == 0 || n < 2 || 18 + n != p.len() {
        return None;
    }
    Some(
        json!({"confirmation":"sequenced_address_and_connected_data","connection_id":id,"sequence":u32::from_le_bytes(p[10..14].try_into().ok()?),"payload_retained":false,"reachability_asserted":false}),
    )
}
struct Cursor<'a> {
    p: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.p.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(b)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn word(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<()> {
        let n = i32::from_le_bytes(self.take(4)?.try_into().ok()?);
        if !(-1..=1024).contains(&n) {
            return None;
        }
        if n >= 0 {
            std::str::from_utf8(self.take(n as usize)?).ok()?;
        }
        Some(())
    }
}
fn scalar(c: &mut Cursor<'_>) -> Option<()> {
    // A deliberately bounded subset of UA Binary scalar Variants. Arrays, nested
    // ExtensionObjects and DataValues require metadata and remain unconfirmed.
    let tag = c.byte()?;
    match tag {
        0 => {}
        1 => {
            if c.byte()? > 1 {
                return None;
            }
        }
        2 | 3 => {
            c.take(1)?;
        }
        4 | 5 => {
            c.take(2)?;
        }
        6 | 7 | 10 | 19 => {
            c.take(4)?;
        }
        8 | 9 | 11 | 13 => {
            c.take(8)?;
        }
        12 => c.string()?,
        14 => {
            c.take(16)?;
        }
        15 => {
            let n = i32::from_le_bytes(c.take(4)?.try_into().ok()?);
            if !(-1..=1024).contains(&n) {
                return None;
            }
            if n >= 0 {
                c.take(n as usize)?;
            }
        }
        _ => return None,
    };
    Some(())
}
fn dataset(p: &[u8]) -> Option<()> {
    let mut c = Cursor { p, at: 0 };
    let flags = c.byte()?;
    if flags & 1 == 0 || flags & 6 != 0 {
        return None;
    } // valid, Variant encoding only
    let flags2 = if flags & 128 != 0 { c.byte()? } else { 0 };
    if flags2 & 0xcf != 0 {
        return None;
    } // key frames only; reserved flags zero
    if flags & 8 != 0 {
        c.take(2)?;
    }
    if flags2 & 16 != 0 {
        c.take(8)?;
    }
    if flags2 & 32 != 0 {
        c.take(2)?;
    }
    if flags & 16 != 0 {
        c.take(2)?;
    }
    if flags & 32 != 0 {
        c.take(4)?;
    }
    if flags & 64 != 0 {
        c.take(4)?;
    }
    let count = c.word()?;
    if count == 0 || count > 128 {
        return None;
    }
    for _ in 0..count {
        scalar(&mut c)?;
    }
    (c.at == p.len()).then_some(())
}
fn uadp(p: &[u8]) -> Option<Value> {
    let mut c = Cursor { p, at: 0 };
    let flags = c.byte()?;
    if flags & 15 != 1 || flags & 0x70 != 0x70 {
        return None;
    } // publisher, writer group and payload header required
    let ext = if flags & 128 != 0 { c.byte()? } else { 0 };
    if ext & 0x10 != 0 || ext & 7 > 4 {
        return None;
    } // secured messages require keys; no guessing
    if ext & 128 != 0 && c.byte()? != 0 {
        return None;
    } // no chunking/promoted fields/discovery
    match ext & 7 {
        0 => {
            c.take(1)?;
        }
        1 => {
            c.take(2)?;
        }
        2 => {
            c.take(4)?;
        }
        3 => {
            c.take(8)?;
        }
        4 => c.string()?,
        _ => return None,
    }
    if ext & 8 != 0 {
        c.take(16)?;
    }
    let group_flags = c.byte()?;
    if group_flags & 0xf0 != 0 || group_flags & 1 == 0 {
        return None;
    }
    let writer_group = c.word()?;
    if group_flags & 2 != 0 {
        c.take(4)?;
    }
    if group_flags & 4 != 0 {
        c.take(2)?;
    }
    if group_flags & 8 != 0 {
        c.take(2)?;
    }
    let count = c.byte()? as usize;
    if !(1..=16).contains(&count) {
        return None;
    }
    let mut writers = Vec::new();
    for _ in 0..count {
        writers.push(c.word()?);
    }
    if ext & 32 != 0 {
        c.take(8)?;
    }
    if ext & 64 != 0 {
        c.take(2)?;
    }
    let mut lengths = Vec::new();
    if count > 1 {
        for _ in 0..count {
            lengths.push(c.word()? as usize);
        }
    } else {
        lengths.push(p.len() - c.at);
    }
    for n in lengths {
        dataset(c.take(n)?)?;
    }
    if c.at != p.len() {
        return None;
    }
    Some(
        json!({"confirmation":"uadp_variant_keyframe","version":1,"writer_group_id":writer_group,"dataset_writer_ids":writers,"payload_retained":false,"reachability_asserted":false}),
    )
}
pub(crate) async fn run(
    config: &ServiceDetectionConfig,
    ports: &[PortObservation],
    cancel: &AtomicBool,
    journal: Option<&mut crate::journal::ScanJournal<'_>>,
) -> Result<EngineOutcome, ScannerError> {
    let o = &config.probe_options;
    validate_options(o)?;
    if ports.is_empty()
        || ports.iter().any(|p| {
            p.protocol != "udp" || p.port != ports[0].port || p.ip.parse::<Ipv4Addr>().is_err()
        })
        || config.required_services.is_empty()
        || config.required_services.len() > 2
        || config
            .required_services
            .iter()
            .any(|s| !matches!(s.as_str(), "enip_io" | "opcua_pubsub"))
    {
        return Err(invalid());
    }
    let bind: Ipv4Addr = o
        .passive_bind
        .as_ref()
        .unwrap()
        .parse()
        .map_err(|_| invalid())?;
    let socket = UdpSocket::bind(SocketAddrV4::new(
        if let Some(group) = &o.passive_group {
            group.parse().map_err(|_| invalid())?
        } else {
            bind
        },
        ports[0].port,
    ))
    .await?;
    if let Some(group) = &o.passive_group {
        socket.join_multicast_v4(group.parse().map_err(|_| invalid())?, bind)?;
    }
    receive(config, ports, cancel, journal, socket).await
}

async fn receive(
    config: &ServiceDetectionConfig,
    ports: &[PortObservation],
    cancel: &AtomicBool,
    mut journal: Option<&mut crate::journal::ScanJournal<'_>>,
    socket: UdpSocket,
) -> Result<EngineOutcome, ScannerError> {
    let o = &config.probe_options;
    let allowed: std::collections::HashSet<_> = ports.iter().map(|p| p.ip.as_str()).collect();
    let prior = journal.as_ref().map_or(0, |j| j.state.elapsed_ms);
    let budget = (o.passive_window_seconds.unwrap_or(10) as u64 * 1000)
        .min(config.max_runtime_seconds.saturating_mul(1000));
    let start = Instant::now();
    let deadline = start + Duration::from_millis(budget.saturating_sub(prior));
    if let Some(j) = journal.as_mut() {
        j.start_block()?;
    }
    let mut bytes = [0; 8193];
    let mut results = Vec::new();
    // This receiver uses one cursor: each acknowledged payload must therefore
    // contain the whole snapshot, including evidence recovered after restart.
    let mut snapshot:Vec<ScanObservation>=journal.as_ref().map(|j|j.state.observations.iter().filter(|o|matches!(o,ScanObservation::Service(s) if s.source=="passive_udp" && s.protocol=="udp")).cloned().collect()).unwrap_or_default();
    let mut seen: std::collections::HashSet<_> = snapshot
        .iter()
        .filter_map(|o| {
            if let ScanObservation::Service(s) = o {
                Some((
                    std::net::SocketAddr::new(s.ip.parse().ok()?, s.port),
                    s.service.clone()?,
                ))
            } else {
                None
            }
        })
        .collect();
    let mut datagrams = 0;
    let mut checkpoint_at = Instant::now();
    while datagrams < 1024 {
        if cancel.load(Ordering::Relaxed) {
            return Ok(EngineOutcome::Cancelled);
        }
        if Instant::now() >= deadline {
            break;
        }
        let received = tokio::select! {
            v=timeout_at(deadline,socket.recv_from(&mut bytes))=>v,
            _=sleep(Duration::from_millis(20))=>{
                if checkpoint_at.elapsed()>=Duration::from_millis(250) {
                    if let Some(j)=journal.as_mut(){j.save(j.state.stage,0,prior+start.elapsed().as_millis() as u64,None)?;}
                    checkpoint_at=Instant::now();
                }
                continue;
            }
        };
        let (n, peer) = match received {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        datagrams += 1;
        if n > 8192 || peer.port() == 0 || !allowed.contains(peer.ip().to_string().as_str()) {
            continue;
        }
        for service in &config.required_services {
            let value = match service.as_str() {
                "enip_io" => enip_io(&bytes[..n]),
                "opcua_pubsub" => uadp(&bytes[..n]),
                _ => None,
            };
            if let Some(value) = value {
                if !seen.insert((peer, service.clone())) {
                    continue;
                }
                if seen.len() > 256 {
                    return Ok(EngineOutcome::Partial(
                        results,
                        "passive_endpoint_limit".into(),
                    ));
                }
                let s = ServiceObservation {
                    ip: peer.ip().to_string(),
                    port: peer.port(),
                    protocol: "udp".into(),
                    service: Some(service.clone()),
                    banner: None,
                    source: "passive_udp".into(),
                    observed_at: chrono::Utc::now().timestamp_millis(),
                    data: Some(
                        json!({"schema_version":2,"confidence":80,"selected_probe":service,"evidence":[{"role":"passive_protocol","module":service,"result":value,"truncated":false}]}),
                    ),
                };
                snapshot.push(ScanObservation::Service(s.clone()));
                if let Some(j) = journal.as_mut() {
                    j.save(
                        j.state.stage,
                        0,
                        prior + start.elapsed().as_millis() as u64,
                        Some(&snapshot),
                    )?;
                }
                results.push(s);
            }
        }
    }
    if let Some(j) = journal.as_mut() {
        j.save(
            j.state.stage,
            0,
            prior + start.elapsed().as_millis() as u64,
            None,
        )?;
    }
    if datagrams >= 1024 {
        Ok(EngineOutcome::Partial(
            results,
            "passive_datagram_limit".into(),
        ))
    } else {
        Ok(EngineOutcome::Completed(results))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn receiver_attributes_only_allowed_source_and_never_replies() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = sender.local_addr().unwrap();
        let config = ServiceDetectionConfig {
            required_services: vec!["enip_io".into()],
            probe_options: ServiceProbeOptions {
                passive_bind: Some("127.0.0.1".into()),
                passive_window_seconds: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let ports = vec![PortObservation {
            ip: "127.0.0.1".into(),
            port,
            protocol: "udp".into(),
            state: "unknown".into(),
            source: "udp_target".into(),
            observed_at: 0,
        }];
        let cancel = AtomicBool::new(false);
        let receiver = run(&config, &ports, &cancel, None);
        let send = async {
            sleep(Duration::from_millis(30)).await;
            sender
                .send_to(
                    &[
                        2, 0, 2, 0x80, 8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xb1, 0, 2, 0, 0, 0,
                    ],
                    ("127.0.0.1", port),
                )
                .await
                .unwrap();
        };
        let (received, ()) = tokio::join!(receiver, send);
        let EngineOutcome::Completed(items) = received.unwrap() else {
            panic!("incomplete receiver");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].port, source.port());
        assert_eq!(items[0].source, "passive_udp");
        assert_eq!(
            items[0].data.as_ref().unwrap()["evidence"][0]["result"]["reachability_asserted"],
            false
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), sender.recv(&mut [0; 32]))
                .await
                .is_err()
        );
    }
    #[test]
    fn uadp_requires_valid_keyframe_and_bounded_variants() {
        let mut p = vec![0x71, 1, 1, 1, 0, 1, 2, 0, 1, 1, 0, 7, 42, 0, 0, 0];
        assert_eq!(uadp(&p).unwrap()["writer_group_id"], 1);
        p[11] = 0x87;
        assert!(uadp(&p).is_none());
        p[11] = 7;
        p.push(0);
        assert!(uadp(&p).is_none());
        for n in 0..16 {
            let _ = uadp(&p[..n]);
        }
    }
    #[test]
    fn enip_io_requires_full_cpf() {
        let mut p = vec![
            2, 0, 2, 0x80, 8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xb1, 0, 2, 0, 0, 0,
        ];
        assert!(enip_io(&p).is_some());
        p[6] = 0;
        assert!(enip_io(&p).is_none());
        for n in 0..20 {
            let _ = enip_io(&p[..n]);
        }
    }
    #[test]
    fn receiver_requires_explicit_local_interface_and_window() {
        let mut o = ServiceProbeOptions::default();
        assert!(validate_options(&o).is_err());
        o.passive_bind = Some("127.0.0.1".into());
        assert!(validate_options(&o).is_ok());
        o.passive_group = Some("239.0.0.1".into());
        assert!(validate_options(&o).is_err());
        o.passive_interface = Some("127.0.0.1".into());
        assert!(validate_options(&o).is_ok());
        o.passive_window_seconds = Some(61);
        assert!(validate_options(&o).is_err());
    }
    #[tokio::test]
    async fn checkpoint_preserves_multiple_sources_across_restarts() {
        let senders = [
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        ];
        let config = ServiceDetectionConfig {
            required_services: vec!["enip_io".into()],
            probe_options: ServiceProbeOptions {
                passive_bind: Some("127.0.0.1".into()),
                passive_window_seconds: Some(2),
                ..Default::default()
            },
            ..Default::default()
        };
        let path =
            std::env::temp_dir().join(format!("passive-recovery-{}.sqlite3", uuid::Uuid::new_v4()));
        let key = format!("{}|configuration", uuid::Uuid::new_v4());
        let frame = [
            2, 0, 2, 0x80, 8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xb1, 0, 2, 0, 0, 0,
        ];
        for (iteration, indices) in [vec![0, 1], vec![0, 2]].iter().enumerate() {
            // Keep ownership of the OS-assigned port instead of dropping a
            // reservation and racing other tests (or inherited descriptors).
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let ports = [PortObservation {
                ip: "127.0.0.1".into(),
                port,
                protocol: "udp".into(),
                state: "unknown".into(),
                source: "udp_target".into(),
                observed_at: 0,
            }];
            let store = crate::storage::StateStore::open(path.clone()).unwrap();
            let mut journal =
                crate::journal::ScanJournal::open(&store, "origin", key.clone()).unwrap();
            let cancel = AtomicBool::new(false);
            let receive = receive(&config, &ports, &cancel, Some(&mut journal), socket);
            let send = async {
                sleep(Duration::from_millis(30)).await;
                for &index in indices {
                    senders[index]
                        .send_to(&frame, ("127.0.0.1", port))
                        .await
                        .unwrap();
                }
                sleep(Duration::from_millis(60)).await;
                cancel.store(true, Ordering::Relaxed);
            };
            let (result, ()) = tokio::join!(receive, send);
            assert!(matches!(result.unwrap(), EngineOutcome::Cancelled));
            drop(journal);
            drop(store);
            let reopened = crate::storage::StateStore::open(path.clone()).unwrap();
            let state = reopened.load_checkpoint("origin", &key).unwrap().unwrap();
            assert_eq!(state.observations.len(), iteration + 2);
            let found: std::collections::HashSet<_> = state
                .observations
                .iter()
                .map(|o| {
                    if let ScanObservation::Service(s) = o {
                        s.port
                    } else {
                        panic!("unexpected checkpoint kind")
                    }
                })
                .collect();
            assert_eq!(found.len(), iteration + 2);
        }
        std::fs::remove_file(path).unwrap();
    }
}
