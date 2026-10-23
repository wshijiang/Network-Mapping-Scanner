//! Exercise the released worker executable and real framed pipes. Fake engines
//! emit fixed results and never contact a scan target or a control server.
#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Worker {
    child: Child,
    root: PathBuf,
}
impl Worker {
    fn start(stage: &str, engine: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("worker-integration-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("engine"), engine).unwrap();
        fs::set_permissions(root.join("engine"), fs::Permissions::from_mode(0o700)).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_scanner-worker"))
            .args(["--stage", stage])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut worker = Self { child, root };
        let hello = worker.read();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["ipc_version"], 3);
        assert_eq!(hello["stage"], stage);
        worker
    }
    fn send(&mut self, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        let input = self.child.stdin.as_mut().unwrap();
        input
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
    }
    fn read(&mut self) -> Value {
        let mut header = [0; 4];
        let output = self.child.stdout.as_mut().unwrap();
        output.read_exact(&mut header).unwrap();
        let size = u32::from_be_bytes(header) as usize;
        assert!(size <= 8 * 1024 * 1024);
        let mut bytes = vec![0; size];
        output.read_exact(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn request(&self, stage: &str) -> Value {
        let config: Value = toml_edit::de::from_str(include_str!("../config.toml")).unwrap();
        let mut service = config["service_detection"].clone();
        service["zgrab_path"] = json!(self.root.join("engine"));
        service["strategy"] = json!("standard");
        service["batch_endpoints"] = json!(1);
        json!({"id":"019c0000-0000-7000-8000-000000000001","stage":stage,"target":{"ip":"192.0.2.1","port":"22","rate":1,"address_family":"ipv4"},"engine_path":self.root.join("engine"),"service":service,"dns":config["dns"],"nuclei":config["nuclei"],"resolvers":[],"checkpoint":{"stage":1,"chunk":0,"elapsed_ms":0,"observations":[]}})
    }
    fn finish(&mut self) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let event = self.read();
            if matches!(
                event["type"].as_str(),
                Some("checkpoint_save" | "block_started")
            ) {
                self.send(json!({"type":"ack","id":event["id"],"sequence":event["sequence"]}));
            }
            let finished = event["type"] == "finished";
            events.push(event);
            if finished {
                break;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "worker did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        events
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn real_worker_runs_port_engine_and_keeps_protocol_stdout_clean() {
    let mut worker = Worker::start(
        "port_discovery",
        "#!/bin/sh\nprintf 'open tcp 22 192.0.2.1 1\n'\n",
    );
    let request = worker.request("port_discovery");
    let id = request["id"].clone();
    worker.send(json!({"type":"execute","request":request}));
    worker.send(json!({"type":"input_end","id":id}));
    let events = worker.finish();
    assert_eq!(events.last().unwrap()["outcome"], "completed");
    assert!(events.iter().any(|e| e["type"] == "observation"
        && e["observation"]["kind"] == "port"
        && e["observation"]["port"] == 22));
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"], index + 1);
    }
}

#[test]
fn port_worker_applies_nondefault_masscan_settings() {
    let mut worker = Worker::start(
        "port_discovery",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\nprintf 'open tcp 22 192.0.2.1 1\\n'\n",
    );
    let mut request = worker.request("port_discovery");
    request["masscan"] = json!({"masscan_output_mode":"standard_list","masscan_wait_seconds":42,"masscan_max_runtime_seconds":60});
    let id = request["id"].clone();
    worker.send(json!({"type":"execute","request":request}));
    worker.send(json!({"type":"input_end","id":id}));
    assert_eq!(worker.finish().last().unwrap()["outcome"], "completed");
    let args = fs::read_to_string(worker.root.join("engine.args")).unwrap();
    assert!(args.contains("--wait\n42\n"), "{args}");
}

#[test]
fn service_worker_waits_for_checkpoint_ack_before_next_block() {
    let engine = "#!/bin/sh\nwhile IFS=',' read -r ip domain tag port; do\n printf '{\"ip\":\"%s\",\"data\":{\"%s\":{\"status\":\"success\",\"protocol\":\"%s\",\"port\":%s,\"result\":{\"banner\":\"identified\"}}}}\\n' \"$ip\" \"$tag\" \"$tag\" \"$port\"\ndone\n";
    let mut worker = Worker::start("service_detection", engine);
    let request = worker.request("service_detection");
    let id = request["id"].clone();
    worker.send(json!({"type":"execute","request":request}));
    for port in [22, 23] {
        worker.send(json!({"type":"input","id":id,"observation":{"kind":"port","ip":"192.0.2.1","port":port,"protocol":"tcp","state":"open","source":"masscan","observed_at":1}}));
    }
    worker.send(json!({"type":"input_end","id":id}));
    let events = worker.finish();
    assert_eq!(events.last().unwrap()["outcome"], "completed");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["type"] == "block_started")
            .count(),
        2
    );
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "checkpoint_save" && e["chunk"] == 2 && e["has_part"] == true)
    );
    assert_eq!(
        events.iter().filter(|e| e["type"] == "observation").count(),
        2
    );
}

#[test]
fn cancellation_is_read_while_engine_is_running() {
    let mut worker = Worker::start("port_discovery", "#!/bin/sh\nexec sleep 30\n");
    let request = worker.request("port_discovery");
    let id = request["id"].clone();
    worker.send(json!({"type":"execute","request":request}));
    worker.send(json!({"type":"input_end","id":id}));
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    worker.send(json!({"type":"cancel","id":id}));
    let events = worker.finish();
    assert_eq!(events.last().unwrap()["outcome"], "cancelled");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn package_tool_generates_private_keys_and_signs_exact_manifest() {
    let root = std::env::temp_dir().join(format!("package-integration-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let program = env!("CARGO_BIN_EXE_scanner-package");
    assert!(
        Command::new(program)
            .args(["keygen", "--private"])
            .arg(root.join("key.pkcs8"))
            .arg("--public")
            .arg(root.join("keys.json"))
            .args(["--key-id", "test"])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::metadata(root.join("key.pkcs8"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::write(root.join("worker"), "#!/bin/sh\nexit 0\n").unwrap();
    let manifest = json!({"schema":1,"ipc_version":3,"release_id":"test","revision":2,"target":format!("{}-unknown-linux-gnu",std::env::consts::ARCH),"files":[{"path":"worker","sha256":"","size":0,"executable":true}],"modules":{"dns_lookup":{"worker":"worker","engine":null,"templates":null}}});
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(
        Command::new(program)
            .arg("sign")
            .arg("--bundle")
            .arg(&root)
            .arg("--private")
            .arg(root.join("key.pkcs8"))
            .args(["--key-id", "test"])
            .status()
            .unwrap()
            .success()
    );
    let raw = fs::read(root.join("manifest.json")).unwrap();
    let signature: Value =
        serde_json::from_slice(&fs::read(root.join("manifest.sig")).unwrap()).unwrap();
    let keys: Value = serde_json::from_slice(&fs::read(root.join("keys.json")).unwrap()).unwrap();
    let unhex = |s: &str| {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        unhex(keys["test"].as_str().unwrap()),
    )
    .verify(&raw, &unhex(signature["signature"].as_str().unwrap()))
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_udp_worker_confirms_response_and_preserves_transport() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut bytes = [0; 1024];
        let (n, from) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[12..n], &[0, 0, 6, 0, 1]);
        bytes[2] = 0x80;
        bytes[3] = 5;
        socket.send_to(&bytes[..n], from).unwrap();
    });
    let mut worker = Worker::start("service_detection", "#!/bin/sh\nexit 99\n");
    let mut request = worker.request("service_detection");
    request["service"]["required_services"] = json!(["dns_udp"]);
    request["service"]["enabled"] = json!(true);
    worker.send(json!({"type":"execute","request":request}));
    let id = "019c0000-0000-7000-8000-000000000001";
    worker.send(json!({"type":"input","id":id,"observation":{"kind":"port","ip":"127.0.0.1","port":address.port(),"protocol":"udp","state":"unknown","source":"udp_target","observed_at":0}}));
    worker.send(json!({"type":"input_end","id":id}));
    let events = worker.finish();
    let observation = events.iter().find(|e| e["type"] == "observation").unwrap();
    assert_eq!(observation["observation"]["protocol"], "udp");
    assert_eq!(observation["observation"]["service"], "dns");
    assert_eq!(events.last().unwrap()["outcome"], "completed");
    peer.join().unwrap();
}
