//! Minimal read-only discovery; no control writes or process-data reads.
use crate::{
    scan::detection::{ProbeAttempt, ProbeKind},
    types::ServiceDetectionConfig,
};
use serde_json::{Value, json};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid industrial response")
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
        .map_err(|_| invalid())?;
    Ok(b)
}

pub(super) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    a: &ProbeAttempt,
    c: &ServiceDetectionConfig,
) -> io::Result<Value> {
    match a.probe {
        ProbeKind::Modbus => modbus(s, c.probe_options.modbus_unit_id.unwrap_or(1)).await,
        ProbeKind::Enip => enip(s).await,
        ProbeKind::S7 => s7(s, c.probe_options.s7_tsap.unwrap_or(0x0102)).await,
        ProbeKind::Opcua => opcua(s, a).await,
        ProbeKind::Mqtt => mqtt(s, c.probe_options.mqtt_version.unwrap_or(4)).await,
        _ => Err(invalid()),
    }
}
async fn modbus<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, unit: u8) -> io::Result<Value> {
    let id = random::<2>()?;
    s.write_all(&[id[0], id[1], 0, 0, 0, 5, unit, 0x2b, 0x0e, 1, 0])
        .await?;
    let mut h = [0; 7];
    s.read_exact(&mut h).await?;
    let length = u16::from_be_bytes([h[4], h[5]]) as usize;
    if h[..2] != id || h[2..4] != [0, 0] || h[6] != unit || !(3..=254).contains(&length) {
        return Err(invalid());
    }
    let mut p = vec![0; length - 1];
    s.read_exact(&mut p).await?;
    if p[0] == 0xab && p.len() == 2 && matches!(p[1], 1..=8 | 10 | 11) {
        return Ok(json!({"unit_id":unit,"exception_code":p[1],"device_identity_supported":false}));
    }
    if p.len() < 7
        || p[..3] != [0x2b, 0x0e, 1]
        || !matches!(p[3],1..=3|0x81..=0x83)
        || !matches!(p[4], 0 | 255)
    {
        return Err(invalid());
    }
    let mut at = 7;
    let mut objects = serde_json::Map::new();
    for _ in 0..p[6] {
        let h = p.get(at..at + 2).ok_or_else(invalid)?;
        let n = h[1] as usize;
        let bytes = p.get(at + 2..at + 2 + n).ok_or_else(invalid)?;
        if h[0] <= 2 {
            objects.insert(
                ["vendor", "product", "revision"][h[0] as usize].into(),
                json!(
                    String::from_utf8_lossy(bytes)
                        .chars()
                        .take(128)
                        .collect::<String>()
                ),
            );
        }
        at += 2 + n;
    }
    if at != p.len() {
        return Err(invalid());
    }
    Ok(
        json!({"unit_id":unit,"device_identity_supported":true,"identity":objects,"more_follows":p[4]==255}),
    )
}
pub(crate) fn enip_request() -> io::Result<Vec<u8>> {
    let mut h = vec![0; 24];
    h[0] = 0x63;
    h[12..20].copy_from_slice(&random::<8>()?);
    Ok(h)
}
pub(crate) fn enip_response(request: &[u8], response: &[u8]) -> Option<Value> {
    if request.len() != 24
        || response.len() < 26
        || response[..2] != [0x63, 0]
        || response[4..12] != [0; 8]
        || response[12..20] != request[12..20]
        || response[20..24] != [0; 4]
    {
        return None;
    }
    let length = u16::from_le_bytes([response[2], response[3]]) as usize;
    if length + 24 != response.len() {
        return None;
    }
    let count = u16::from_le_bytes([response[24], response[25]]);
    if count == 0 || count > 16 {
        return None;
    }
    let mut at = 26;
    let mut result = None;
    for _ in 0..count {
        let h = response.get(at..at + 4)?;
        let n = u16::from_le_bytes([h[2], h[3]]) as usize;
        let p = response.get(at + 4..at + 4 + n)?;
        if h[..2] == [0x0c, 0] {
            if p.len() < 34
                || p[..2] != [1, 0]
                || p[2..4] != [0, 2]
                || p.len() != 34 + p[32] as usize
            {
                return None;
            }
            if result.is_some() {
                return None;
            }
            result = Some(
                json!({"vendor_id":u16::from_le_bytes([p[18],p[19]]),"device_type":u16::from_le_bytes([p[20],p[21]]),"product_code":u16::from_le_bytes([p[22],p[23]]),"revision":format!("{}.{}",p[24],p[25]),"product_name":String::from_utf8_lossy(&p[33..33+p[32] as usize]).chars().take(128).collect::<String>()}),
            );
        }
        at += 4 + n;
    }
    (at == response.len()).then_some(result).flatten()
}
async fn enip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> io::Result<Value> {
    let request = enip_request()?;
    s.write_all(&request).await?;
    let mut h = [0; 24];
    s.read_exact(&mut h).await?;
    let n = u16::from_le_bytes([h[2], h[3]]) as usize;
    if !(2..=4096).contains(&n) {
        return Err(invalid());
    }
    let mut response = h.to_vec();
    response.resize(24 + n, 0);
    s.read_exact(&mut response[24..]).await?;
    enip_response(&request, &response).ok_or_else(invalid)
}
async fn tpkt<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = u16::from_be_bytes([h[2], h[3]]) as usize;
    if h[..2] != [3, 0] || !(7..=1024).contains(&n) {
        return Err(invalid());
    }
    let mut b = vec![0; n - 4];
    s.read_exact(&mut b).await?;
    Ok(b)
}
async fn s7<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, tsap: u16) -> io::Result<Value> {
    let t = tsap.to_be_bytes();
    s.write_all(&[
        3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, t[0], t[1], 0xc0, 1, 10,
    ])
    .await?;
    let cc = tpkt(s).await?;
    if cc.len() < 7
        || cc[0] as usize + 1 != cc.len()
        || cc[1] != 0xd0
        || cc[2..4] != [0, 1]
        || cc[6] != 0
    {
        return Err(invalid());
    }
    let mut at = 7;
    while at < cc.len() {
        let n = *cc.get(at + 1).ok_or_else(invalid)? as usize;
        at += 2 + n;
        if at > cc.len() {
            return Err(invalid());
        }
    }
    s.write_all(&[
        3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1, 1, 0xe0,
    ])
    .await?;
    let p = tpkt(s).await?;
    if p.len() != 23
        || p[..3] != [2, 0xf0, 0x80]
        || p[3..5] != [0x32, 3]
        || p[7..9] != [0, 1]
        || p[9..13] != [0, 8, 0, 0]
        || p[13..15] != [0, 0]
        || p[15] != 0xf0
    {
        return Err(invalid());
    }
    let size = u16::from_be_bytes([p[21], p[22]]);
    if size < 24 {
        return Err(invalid());
    }
    Ok(
        json!({"protocol":"s7comm","tsap":tsap,"negotiated_pdu_length":size,"confirmation":"setup_communication"}),
    )
}
async fn opcua<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    a: &ProbeAttempt,
) -> io::Result<Value> {
    let host = if a.ip.contains(':') {
        format!("[{}]", a.ip)
    } else {
        a.ip.clone()
    };
    let url = format!("opc.tcp://{host}:{}", a.port);
    let mut hello = b"HELF".to_vec();
    hello.extend_from_slice(&(32 + url.len() as u32).to_le_bytes());
    for n in [0u32, 8192, 8192, 8192, 1, url.len() as u32] {
        hello.extend_from_slice(&n.to_le_bytes());
    }
    hello.extend_from_slice(url.as_bytes());
    s.write_all(&hello).await?;
    let mut h = [0; 8];
    s.read_exact(&mut h).await?;
    let n = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
    if !(12..=8192).contains(&n) {
        return Err(invalid());
    }
    let mut p = vec![0; n - 8];
    s.read_exact(&mut p).await?;
    if &h[..4] == b"ACKF" && p.len() == 20 {
        let fields: Vec<u32> = p
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        if fields[0] != 0 || fields[1] < 1024 || fields[2] < 1024 {
            return Err(invalid());
        }
        return Ok(
            json!({"transport":"opc.tcp","protocol_version":fields[0],"confirmation":"hello_ack","session_opened":false}),
        );
    }
    if &h[..4] == b"ERRF" && p.len() >= 8 {
        let status = u32::from_le_bytes(p[..4].try_into().unwrap());
        let length = i32::from_le_bytes(p[4..8].try_into().unwrap());
        if status & 0x80000000 == 0
            || length < -1
            || (length == -1 && p.len() != 8)
            || (length >= 0 && (length > 1024 || p.len() != 8 + length as usize))
        {
            return Err(invalid());
        }
        return Ok(
            json!({"transport":"opc.tcp","confirmation":"hello_error","status_code":status,"restricted":true,"session_opened":false}),
        );
    }
    Err(invalid())
}
pub(super) async fn mqtt<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    version: u8,
) -> io::Result<Value> {
    let id = format!("nm-{:x}", u64::from_be_bytes(random::<8>()?));
    let mut p = vec![0, 4, b'M', b'Q', b'T', b'T', version, 2, 0, 10];
    if version == 5 {
        p.push(0);
    }
    p.extend_from_slice(&(id.len() as u16).to_be_bytes());
    p.extend_from_slice(id.as_bytes());
    let mut frame = vec![0x10, p.len() as u8];
    frame.extend(p);
    s.write_all(&frame).await?;
    if s.read_u8().await? != 0x20 {
        return Err(invalid());
    }
    let mut n = 0;
    let mut factor = 1;
    let mut width = 0;
    loop {
        let b = s.read_u8().await?;
        width += 1;
        n += (b as usize & 127) * factor;
        if b & 128 == 0 {
            break;
        }
        if width == 4 {
            return Err(invalid());
        }
        factor *= 128;
    }
    if (width > 1 && n < 128usize.pow(width - 1))
        || !(2..=1024).contains(&n)
        || (version == 4 && n != 2)
    {
        return Err(invalid());
    }
    let mut body = vec![0; n];
    s.read_exact(&mut body).await?;
    if body[0] != 0 || (version == 4 && body[1] > 5) {
        return Err(invalid());
    }
    if version == 5
        && (n < 3
            || !matches!(body[1], 0 | 0x80..=0x8a | 0x8c | 0x90 | 0x95 | 0x97 | 0x99..=0x9d | 0x9f)
            || !connack_properties(&body[2..]))
    {
        return Err(invalid());
    }
    // Clean session, no Will, subscriptions or publications; one bounded CONNECT only.
    if body[1] == 0 {
        let _ = s.write_all(&[0xe0, 0]).await;
    }
    Ok(
        json!({"protocol_version":if version==5 {"5.0"}else{"3.1.1"},"connack_code":body[1],"authentication_required":matches!(body[1],4|5|0x86|0x87),"session_opened":body[1]==0}),
    )
}

// MQTT 5 CONNACK properties: bounded, canonical varints and legal property types.
fn variable(bytes: &[u8], at: &mut usize) -> Option<usize> {
    let mut value = 0;
    for width in 0..4 {
        let b = *bytes.get(*at)?;
        *at += 1;
        value |= (b as usize & 127) << (7 * width);
        if b & 128 == 0 {
            return (width == 0 || value >= 1 << (7 * width)).then_some(value);
        }
    }
    None
}
fn mqtt_string(bytes: &[u8], at: &mut usize) -> Option<()> {
    let n = u16::from_be_bytes(bytes.get(*at..*at + 2)?.try_into().ok()?) as usize;
    *at += 2;
    let value = std::str::from_utf8(bytes.get(*at..*at + n)?).ok()?;
    if value.chars().any(|c| c == '\0' || c.is_control()) {
        return None;
    }
    *at += n;
    Some(())
}
fn connack_properties(bytes: &[u8]) -> bool {
    let mut at = 0;
    let Some(n) = variable(bytes, &mut at) else {
        return false;
    };
    if n != bytes.len() - at {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    while at < bytes.len() {
        let Some(id) = variable(bytes, &mut at) else {
            return false;
        };
        if id != 0x26 && !seen.insert(id) {
            return false;
        }
        let valid = match id {
            0x24 | 0x25 | 0x28 | 0x29 | 0x2a => {
                let b = bytes.get(at).copied();
                at += 1;
                matches!(b, Some(0 | 1))
            }
            0x13 | 0x21 | 0x22 => {
                let v = bytes.get(at..at + 2);
                at += 2;
                v.is_some_and(|v| id != 0x21 || v != [0, 0])
            }
            0x11 | 0x27 => {
                let v = bytes.get(at..at + 4);
                at += 4;
                v.is_some_and(|v| id != 0x27 || v != [0, 0, 0, 0])
            }
            0x12 | 0x15 | 0x1a | 0x1c | 0x1f => mqtt_string(bytes, &mut at).is_some(),
            0x26 => mqtt_string(bytes, &mut at).is_some() && mqtt_string(bytes, &mut at).is_some(),
            0x16 => {
                let Some(v) = bytes.get(at..at + 2) else {
                    return false;
                };
                let n = u16::from_be_bytes([v[0], v[1]]) as usize;
                at += 2;
                let valid = bytes.get(at..at + n).is_some();
                at += n;
                valid
            }
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    !seen.contains(&0x16) || seen.contains(&0x15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    #[tokio::test]
    async fn modbus_correlates_transaction_and_unit_and_accepts_restricted_exception() {
        for wrong in [false, true] {
            let (mut client, mut server) = duplex(1024);
            let peer = tokio::spawn(async move {
                let mut req = [0; 11];
                server.read_exact(&mut req).await.unwrap();
                assert_eq!(&req[7..], &[0x2b, 0x0e, 1, 0]);
                let mut response = req[..7].to_vec();
                response[4..6].copy_from_slice(&3u16.to_be_bytes());
                if wrong {
                    response[0] ^= 1;
                }
                response.extend([0xab, 1]);
                server.write_all(&response).await.unwrap();
            });
            let result = modbus(&mut client, 7).await;
            assert_eq!(result.is_ok(), !wrong);
            if let Ok(v) = result {
                assert_eq!(v["device_identity_supported"], false);
            }
            peer.await.unwrap();
        }
    }
    #[test]
    fn enip_requires_identity_layout_and_sender_context() {
        let req = enip_request().unwrap();
        let mut response = req.clone();
        let mut item = vec![0; 35];
        item[..2].copy_from_slice(&1u16.to_le_bytes());
        item[2..4].copy_from_slice(&[0, 2]);
        item[32] = 1;
        item[33] = b'X';
        response[2..4].copy_from_slice(&41u16.to_le_bytes());
        response.extend([1, 0, 12, 0, 35, 0]);
        response.extend(item);
        assert_eq!(enip_response(&req, &response).unwrap()["product_name"], "X");
        response[12] ^= 1;
        assert!(enip_response(&req, &response).is_none());
        assert!(enip_response(&[], &response).is_none());
    }
    #[tokio::test]
    async fn mqtt_confirms_auth_refusal_but_rejects_bad_codes_and_properties() {
        for (version, bytes, ok) in [
            (4, vec![0x20, 2, 0, 5], true),
            (4, vec![0x20, 2, 0, 6], false),
            (5, vec![0x20, 3, 0, 0x87, 0], true),
            (5, vec![0x20, 3, 0, 0xff, 0], false),
            (5, vec![0x20, 4, 0, 0, 1, 0xff], false),
        ] {
            let (mut client, mut server) = duplex(2048);
            let peer = tokio::spawn(async move {
                let mut h = [0; 2];
                server.read_exact(&mut h).await.unwrap();
                let mut connect = vec![0; h[1] as usize];
                server.read_exact(&mut connect).await.unwrap();
                assert_eq!(connect[7], 2);
                server.write_all(&bytes).await.unwrap();
            });
            assert_eq!(mqtt(&mut client, version).await.is_ok(), ok);
            peer.await.unwrap();
        }
        assert!(connack_properties(&[3, 0x21, 0, 1]));
        assert!(!connack_properties(&[3, 0x21, 0, 0]));
        assert!(!connack_properties(&[4, 0x24, 1, 0x24, 1]));
    }
    #[tokio::test]
    async fn opcua_hello_accepts_ack_and_bounded_error_without_session() {
        for bad in [false, true] {
            let (mut client, mut server) = duplex(2048);
            let peer = tokio::spawn(async move {
                let mut h = [0; 8];
                server.read_exact(&mut h).await.unwrap();
                assert_eq!(&h[..4], b"HELF");
                let mut rest = vec![0; u32::from_le_bytes(h[4..].try_into().unwrap()) as usize - 8];
                server.read_exact(&mut rest).await.unwrap();
                let mut response = b"ACKF".to_vec();
                response.extend(28u32.to_le_bytes());
                for n in [0u32, 8192, if bad { 0 } else { 8192 }, 0, 0] {
                    response.extend(n.to_le_bytes());
                }
                server.write_all(&response).await.unwrap();
            });
            let a = ProbeAttempt {
                ip: "127.0.0.1".into(),
                port: 4840,
                probe: ProbeKind::Opcua,
            };
            assert_eq!(opcua(&mut client, &a).await.is_ok(), !bad);
            peer.await.unwrap();
        }
    }
    #[tokio::test]
    async fn s7_requires_correlated_cotp_and_setup_ack() {
        for bad in [false, true] {
            let (mut client, mut server) = duplex(2048);
            let peer = tokio::spawn(async move {
                let mut cr = [0; 22];
                server.read_exact(&mut cr).await.unwrap();
                assert_eq!(&cr[17..19], &[1, 2]);
                server
                    .write_all(&[3, 0, 0, 11, 6, 0xd0, 0, 1, 0, 2, 0])
                    .await
                    .unwrap();
                let mut setup = [0; 25];
                server.read_exact(&mut setup).await.unwrap();
                let p = [
                    2,
                    0xf0,
                    0x80,
                    0x32,
                    3,
                    0,
                    0,
                    0,
                    if bad { 2 } else { 1 },
                    0,
                    8,
                    0,
                    0,
                    0,
                    0,
                    0xf0,
                    0,
                    0,
                    1,
                    0,
                    1,
                    1,
                    0xe0,
                ];
                let mut frame = vec![3, 0, 0, 27];
                frame.extend(p);
                server.write_all(&frame).await.unwrap();
            });
            assert_eq!(s7(&mut client, 0x0102).await.is_ok(), !bad);
            peer.await.unwrap();
        }
    }
}
