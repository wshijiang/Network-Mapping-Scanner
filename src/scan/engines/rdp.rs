//! RDP negotiation only: no credentials, TLS session or desktop connection.
use serde_json::{Value, json};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// TPKT + X.224 CR + RDP_NEG_REQ: TLS, HYBRID and HYBRID_EX.
const REQUEST: [u8; 19] = [
    3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 11, 0, 0, 0,
];

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid RDP negotiation response",
    )
}

pub(super) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> io::Result<Value> {
    s.write_all(&REQUEST).await?;
    let mut response = [0; 19];
    s.read_exact(&mut response[..4]).await?;
    // A bare X.224 confirm is shared with other protocols and is insufficient.
    if response[..4] != [3, 0, 0, 19] {
        return Err(invalid());
    }
    s.read_exact(&mut response[4..]).await?;
    parse(&response)
}

fn parse(p: &[u8; 19]) -> io::Result<Value> {
    if p[..4] != [3, 0, 0, 19] || p[4..8] != [14, 0xd0, 0, 0] || p[10] != 0 || p[13..15] != [8, 0] {
        return Err(invalid());
    }
    let value = u32::from_le_bytes(p[15..19].try_into().unwrap());
    match p[11] {
        2 if p[12] & !0x1b == 0 && matches!(value, 0 | 1 | 2 | 8) => {
            Ok(json!({"confirmation":"rdp_negotiation","selected_protocol":value,"flags":p[12]}))
        }
        3 if p[12] == 0 && (1..=6).contains(&value) => {
            // A well-formed RDP rejection still identifies the service.
            Ok(json!({"confirmation":"rdp_negotiation_failure","failure_code":value}))
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(kind: u8, value: u8) -> [u8; 19] {
        [
            3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, kind, 0, 8, 0, value, 0, 0, 0,
        ]
    }

    #[tokio::test]
    async fn fragmented_negotiation_and_rejection_identify_without_authentication() {
        for (kind, value) in [(2, 0), (2, 1), (2, 2), (2, 8), (3, 5)] {
            let (mut client, mut server) = tokio::io::duplex(1);
            let fixture = async {
                let mut request = [0; 19];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, REQUEST);
                for byte in response(kind, value) {
                    server.write_all(&[byte]).await.unwrap();
                }
                let mut extra = [0];
                assert_eq!(server.read(&mut extra).await.unwrap(), 0);
            };
            let scan = async {
                let result = handshake(&mut client).await.unwrap();
                drop(client);
                assert!(
                    result["confirmation"]
                        .as_str()
                        .unwrap()
                        .starts_with("rdp_negotiation")
                );
            };
            tokio::join!(fixture, scan);
        }
    }

    #[test]
    fn malformed_or_unrequested_negotiation_is_not_a_match() {
        for (offset, value) in [
            (0, 4),
            (3, 18),
            (4, 13),
            (5, 0xe0),
            (6, 1),
            (10, 1),
            (11, 1),
            (12, 4),
            (13, 7),
            (15, 4),
        ] {
            let mut p = response(2, 1);
            p[offset] = value;
            assert!(parse(&p).is_err(), "offset {offset}");
        }
        assert!(parse(&response(3, 0)).is_err());
        assert!(parse(&response(3, 7)).is_err());
    }

    #[tokio::test]
    async fn short_and_legacy_x224_responses_are_not_confirmed() {
        for bytes in [
            vec![3, 0],
            vec![3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0],
            vec![3, 0, 0, 19, 14],
        ] {
            let (mut client, mut server) = tokio::io::duplex(64);
            server.write_all(&bytes).await.unwrap();
            server.shutdown().await.unwrap();
            assert!(handshake(&mut client).await.is_err());
        }
    }
}
