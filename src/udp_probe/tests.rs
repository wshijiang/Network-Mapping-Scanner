use super::*;

fn response(request: &Request) -> Vec<u8> {
    let mut bytes = request.bytes.clone();
    match request.service {
        UdpService::Dns => bytes[2] = 0x80,
        UdpService::Ntp => {
            bytes[0] = 0x24;
            bytes[1] = 2;
            bytes[24..32].copy_from_slice(&request.bytes[40..48]);
        }
        UdpService::Stun => {
            bytes[0] = 1;
            bytes[3] = 12;
            bytes.extend_from_slice(&[0, 0x20, 0, 8, 0, 1, 0, 1, 127, 0, 0, 1]);
        }
    }
    bytes
}

#[test]
fn parsers_require_matched_responses_and_do_not_identify_echoes() {
    for service in [UdpService::Dns, UdpService::Ntp, UdpService::Stun] {
        let request = Request::with_nonce(service, [1; 16]);
        assert!(request.identify(&request.bytes).is_none());
        let bytes = response(&request);
        assert!(request.identify(&bytes).is_some());
        let other = Request::with_nonce(service, [2; 16]);
        assert!(other.identify(&bytes).is_none());
        for length in 0..bytes.len() {
            assert!(
                request.identify(&bytes[..length]).is_none(),
                "{service:?} {length}"
            );
        }
        let json = request.identify(&bytes).unwrap().to_string();
        assert!(!json.contains("127.0.0.1"));
    }
}

#[test]
fn dns_accepts_refused_but_rejects_other_questions_and_trailing_bytes() {
    let request = Request::with_nonce(UdpService::Dns, [1; 16]);
    let mut bytes = response(&request);
    bytes[3] = 5;
    assert_eq!(request.identify(&bytes).unwrap()["response_code"], 5);
    bytes[14] = 1; // A instead of SOA.
    assert!(request.identify(&bytes).is_none());
    bytes[14] = 6;
    bytes.push(0);
    assert!(request.identify(&bytes).is_none());
    bytes.truncate(12);
    bytes[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert!(request.identify(&bytes).is_none());
    let mut excessive = response(&request);
    excessive[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(request.identify(&excessive).is_none());
}

#[test]
fn ntp_retains_kod_but_rejects_control_modes_and_malformed_lengths() {
    let request = Request::with_nonce(UdpService::Ntp, [1; 16]);
    let mut bytes = response(&request);
    bytes[1] = 0;
    bytes[12..16].copy_from_slice(b"RATE");
    assert_eq!(request.identify(&bytes).unwrap()["kiss_of_death"], true);
    for mode in [3, 5, 6, 7] {
        bytes[0] = 0x20 | mode;
        assert!(request.identify(&bytes).is_none());
    }
    bytes[0] = 0x24;
    bytes[1] = 17;
    assert!(request.identify(&bytes).is_none());
    bytes[1] = 2;
    bytes.push(0);
    assert!(request.identify(&bytes).is_none());
}

#[test]
fn stun_checks_cookie_method_length_attributes_and_error_class() {
    let request = Request::with_nonce(UdpService::Stun, [1; 16]);
    let good = response(&request);
    for index in [0, 1, 2, 3, 4, 8, 22, 23, 24, 25] {
        let mut bytes = good.clone();
        bytes[index] ^= 0xff;
        assert!(request.identify(&bytes).is_none(), "index {index}");
    }
    let mut error = request.bytes.clone();
    error[..4].copy_from_slice(&[1, 0x11, 0, 8]);
    error.extend_from_slice(&[0, 9, 0, 4, 0, 0, 4, 1]);
    assert_eq!(request.identify(&error).unwrap()["error_code"], 401);
    error[1] = 1;
    assert!(request.identify(&error).is_none());
    let mut empty = request.bytes.clone();
    empty[0] = 1;
    assert!(request.identify(&empty).is_none());
}

fn options() -> ProbeOptions {
    ProbeOptions {
        timeout: Duration::from_millis(100),
        attempts: 1,
    }
}

#[tokio::test]
async fn connected_probes_identify_each_protocol_on_nonstandard_ports() {
    for service in [UdpService::Dns, UdpService::Ntp, UdpService::Stun] {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let (_control, cancel) = watch::channel(false);
        let fixture = tokio::spawn(async move {
            let mut buffer = [0; 256];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let request = Request {
                service,
                bytes: buffer[..length].to_vec(),
            };
            let bytes = response(&request);
            // A datagram with the right token from a different peer is ignored by connect().
            let other_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            other_peer.send_to(&bytes, peer).await.unwrap();
            let mut wrong_id = bytes.clone();
            match service {
                UdpService::Dns => wrong_id[0] ^= 1,
                UdpService::Ntp => wrong_id[24] ^= 1,
                UdpService::Stun => wrong_id[8] ^= 1,
            }
            server.send_to(&wrong_id, peer).await.unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });
        let result = probe(
            target,
            service,
            ProbeOptions {
                timeout: Duration::from_secs(1),
                ..options()
            },
            cancel,
        )
        .await
        .unwrap();
        fixture.await.unwrap();
        assert_eq!(result.status, ProbeStatus::Identified);
        assert_eq!(result.service, Some(service));
        assert_eq!(result.attempts, 1);
        assert_eq!(result.ignored_datagrams, 1);
    }
}

#[tokio::test]
async fn silence_and_cancellation_never_become_identified_or_closed() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (control, cancel) = watch::channel(false);
    let result = probe(target, UdpService::Ntp, options(), cancel.clone())
        .await
        .unwrap();
    assert_eq!(result.status, ProbeStatus::NoResponse);
    assert_eq!(result.service, None);
    control.send(true).unwrap();
    let result = probe(target, UdpService::Ntp, options(), cancel)
        .await
        .unwrap();
    assert_eq!(result.status, ProbeStatus::Cancelled);
    assert_eq!(result.attempts, 0);
    let (control, cancel) = watch::channel(false);
    drop(control);
    assert_eq!(
        probe(target, UdpService::Dns, options(), cancel)
            .await
            .unwrap()
            .status,
        ProbeStatus::Cancelled
    );
}

#[tokio::test]
async fn cancellation_interrupts_an_in_flight_receive() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (control, cancel) = watch::channel(false);
    let fixture = tokio::spawn(async move {
        let mut buffer = [0; 64];
        server.recv_from(&mut buffer).await.unwrap();
        control.send(true).unwrap();
    });
    let result = probe(target, UdpService::Stun, options(), cancel)
        .await
        .unwrap();
    fixture.await.unwrap();
    assert_eq!(result.status, ProbeStatus::Cancelled);
    assert_eq!(result.attempts, 1);
}

#[tokio::test]
async fn retries_have_fresh_ids_and_old_responses_do_not_match() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (_control, cancel) = watch::channel(false);
    let fixture = tokio::spawn(async move {
        let mut buffer = [0; 64];
        let (n, _) = server.recv_from(&mut buffer).await.unwrap();
        let first = Request {
            service: UdpService::Stun,
            bytes: buffer[..n].to_vec(),
        };
        let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
        let second = Request {
            service: UdpService::Stun,
            bytes: buffer[..n].to_vec(),
        };
        assert_ne!(first.bytes[8..20], second.bytes[8..20]);
        server.send_to(&response(&first), peer).await.unwrap();
        server.send_to(&response(&second), peer).await.unwrap();
    });
    let result = probe(
        target,
        UdpService::Stun,
        ProbeOptions {
            attempts: 2,
            ..options()
        },
        cancel,
    )
    .await
    .unwrap();
    fixture.await.unwrap();
    assert_eq!(result.status, ProbeStatus::Identified);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.ignored_datagrams, 1);
}

#[tokio::test]
async fn oversized_datagrams_and_invalid_response_floods_are_bounded() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (_control, cancel) = watch::channel(false);
    let fixture = tokio::spawn(async move {
        let mut buffer = [0; 64];
        let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
        let request = Request {
            service: UdpService::Stun,
            bytes: buffer[..n].to_vec(),
        };
        let mut big = response(&request);
        big.resize(MAX_DATAGRAM + 100, 0);
        server.send_to(&big, peer).await.unwrap();
        for _ in 1..MAX_IGNORED {
            server.send_to(&[0], peer).await.unwrap();
        }
    });
    let result = probe(
        target,
        UdpService::Stun,
        ProbeOptions {
            timeout: Duration::from_secs(1),
            ..options()
        },
        cancel,
    )
    .await
    .unwrap();
    fixture.await.unwrap();
    assert_eq!(result.status, ProbeStatus::ResponseLimit);
    assert_eq!(result.ignored_datagrams, MAX_IGNORED);
    assert_eq!(result.service, None);
}

#[tokio::test]
async fn invalid_bounds_and_multicast_are_rejected_before_sending() {
    let (_control, cancel) = watch::channel(false);
    for target in [
        "127.0.0.1:0",
        "0.0.0.0:53",
        "224.0.0.251:5353",
        "255.255.255.255:53",
        "[ff02::fb]:5353",
        "[::ffff:224.0.0.251]:5353",
        "[::ffff:255.255.255.255]:53",
    ] {
        assert_eq!(
            probe(
                target.parse().unwrap(),
                UdpService::Dns,
                options(),
                cancel.clone()
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    for invalid in [
        ProbeOptions {
            attempts: 0,
            ..options()
        },
        ProbeOptions {
            attempts: 3,
            ..options()
        },
        ProbeOptions {
            timeout: Duration::ZERO,
            ..options()
        },
        ProbeOptions {
            timeout: Duration::from_secs(6),
            ..options()
        },
    ] {
        assert_eq!(
            probe(
                "127.0.0.1:53".parse().unwrap(),
                UdpService::Dns,
                invalid,
                cancel.clone()
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn ipv6_loopback_uses_the_same_peer_and_transaction_validation() {
    let server = UdpSocket::bind("[::1]:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (_control, cancel) = watch::channel(false);
    let fixture = tokio::spawn(async move {
        let mut buffer = [0; 64];
        let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
        let request = Request {
            service: UdpService::Dns,
            bytes: buffer[..n].to_vec(),
        };
        server.send_to(&response(&request), peer).await.unwrap();
    });
    let result = probe(
        target,
        UdpService::Dns,
        ProbeOptions {
            timeout: Duration::from_secs(1),
            ..options()
        },
        cancel,
    )
    .await
    .unwrap();
    fixture.await.unwrap();
    assert_eq!(result.status, ProbeStatus::Identified);
}
