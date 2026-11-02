//! Normalize and validate Modbus evidence returned by the zgrab2 module.
//!
//! zgrab2 performs the network exchange. Its structured result also contains
//! the raw response; validate it before accepting a protocol exception or
//! publishing the scanner's existing, bounded evidence format.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(super) fn normalize(result: &Value, status: &str, request_id: u16, unit: u8) -> Option<Value> {
    if !matches!(status, "success" | "application-error") {
        return None;
    }
    let raw = result.get("raw")?.as_str()?;
    // The accepted MBAP length is at most 254 bytes, plus its six-byte prefix.
    if raw.len() > 348 {
        return None;
    }
    let bytes = STANDARD.decode(raw).ok()?;
    let header = bytes.get(..7)?;
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if header[..2] != request_id.to_be_bytes()
        || header[2..4] != [0, 0]
        || header[6] != unit
        || !(3..=254).contains(&length)
        || bytes.len() != length + 6
    {
        return None;
    }
    let payload = &bytes[7..];
    if payload[0] == 0xab
        && payload.len() == 2
        && matches!(payload[1], 1..=8 | 10 | 11)
        && status == "application-error"
    {
        return Some(json!({"unit_id":unit,"exception_code":payload[1],
            "device_identity_supported":false,"upstream_status":status}));
    }
    if status != "success"
        || payload.len() < 7
        || payload[..3] != [0x2b, 0x0e, 1]
        || !matches!(payload[3], 1..=3 | 0x81..=0x83)
        || !matches!(payload[4], 0 | 255)
    {
        return None;
    }
    let mut at = 7;
    let mut objects = serde_json::Map::new();
    for _ in 0..payload[6] {
        let header = payload.get(at..at + 2)?;
        let n = usize::from(header[1]);
        let value = payload.get(at + 2..at + 2 + n)?;
        if header[0] <= 2 {
            objects.insert(
                ["vendor", "product", "revision"][usize::from(header[0])].into(),
                json!(
                    String::from_utf8_lossy(value)
                        .chars()
                        .take(128)
                        .collect::<String>()
                ),
            );
        }
        at += 2 + n;
    }
    if at != payload.len() {
        return None;
    }
    Some(
        json!({"unit_id":unit,"device_identity_supported":true,"identity":objects,
        "more_follows":payload[4]==255}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(unit: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, 0, 0];
        bytes.extend_from_slice(&((payload.len() + 1) as u16).to_be_bytes());
        bytes.push(unit);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn result(raw: &[u8]) -> Value {
        json!({"raw":STANDARD.encode(raw)})
    }

    #[test]
    fn identity_and_exceptions_keep_existing_evidence() {
        let raw = response(
            7,
            &[0x2b, 0x0e, 1, 1, 0, 0, 2, 0, 2, b'A', b'B', 1, 1, b'X'],
        );
        let value = normalize(&result(&raw), "success", 0x1234, 7).unwrap();
        assert_eq!(value["unit_id"], 7);
        assert_eq!(value["identity"]["vendor"], "AB");
        assert_eq!(value["identity"]["product"], "X");
        assert_eq!(value["device_identity_supported"], true);

        let raw = response(0, &[0xab, 2]);
        let value = normalize(&result(&raw), "application-error", 0x1234, 0).unwrap();
        assert_eq!(value["exception_code"], 2);
        assert_eq!(value["device_identity_supported"], false);
        assert_eq!(value["upstream_status"], "application-error");
        assert!(normalize(&result(&raw), "success", 0x1234, 0).is_none());
    }

    #[test]
    fn rejects_uncorrelated_and_malformed_upstream_results() {
        let good = response(7, &[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 1, b'A']);
        assert!(normalize(&result(&good), "success", 0x1235, 7).is_none());
        assert!(normalize(&result(&good), "success", 0x1234, 0).is_none());
        assert!(normalize(&result(&good), "connection-timeout", 0x1234, 7).is_none());
        for raw in [
            response(7, &[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 2, b'A']),
            response(7, &[0x2b, 0x0e, 1, 1, 0, 0, 0, 99]),
            response(7, &[0xab, 9]),
        ] {
            assert!(normalize(&result(&raw), "success", 0x1234, 7).is_none());
        }
        let mut wrong_length = good;
        wrong_length[5] += 1;
        assert!(normalize(&result(&wrong_length), "success", 0x1234, 7).is_none());
        assert!(normalize(&json!({"raw":"!"}), "success", 0x1234, 7).is_none());
        assert!(normalize(&json!({"raw":"A".repeat(352)}), "success", 0x1234, 7).is_none());
    }
}
