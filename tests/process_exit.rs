//! Process-level shutdown tests against a local TLS control-server fixture.
#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const SERVER: &str = r#"
import http.server, json, pathlib, ssl, sys, time
marker, mode, cert, key = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(204); self.end_headers()
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/api/scanner/heartbeat':
            path = pathlib.Path(marker)
            count = int(path.read_text() or '0') + 1 if path.exists() else 1
            path.write_text(str(count))
            if mode == 'storage':
                deadline = time.monotonic() + 12
                while not path.with_name('continue').exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
            if mode == 'truncate' and count == 1:
                self.send_response(200)
                self.send_header('Content-Length', '100')
                self.end_headers()
                self.wfile.write(b'{')
                self.close_connection = True
                return
            status = 401 if mode == 'reject' else 200
            body = json.dumps({'command': None, 'lease': None}).encode()
        else:
            status, body = 200, b'{}'
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
"#;

struct Fixture {
    root: PathBuf,
    server: Child,
    scanner: Child,
}

impl Fixture {
    fn start(mode: &str) -> Self {
        let root = std::env::temp_dir().join(format!("scanner-exit-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/scan/engines/encrypted_dns_fixtures");
        let mut server = Command::new("python3")
            .arg("-u")
            .arg("-c")
            .arg(SERVER)
            .arg(root.join("heartbeat"))
            .arg(mode)
            .arg(fixtures.join("server.pem"))
            .arg(fixtures.join("server.key"))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("python3 is required for the local HTTPS fixture");
        let mut port = String::new();
        BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        let port: u16 = port.trim().parse().expect("fixture did not start");
        // Keep this fixture independent of deployment examples: Docker builds
        // replace config.toml with their own public defaults before testing.
        let config = format!(
            r#"[scanner]
c_server = "127.0.0.1"
c_port = {port}
rate = 1000
verify_tls = false
scanner_path = "/bin/true"
scanner_id = "019c0000-0000-7000-8000-000000000001"
runtime_token = "fixture-token"
reconnect_initial_delay_seconds = 1
reconnect_max_delay_seconds = 1
active_task_reconnect_max_delay_seconds = 1

[network]
ipv4_enabled = false
ipv6_enabled = false

[service_detection]
enabled = false

[dns]
enabled = false

[nuclei]
enabled = false

[upload]
endpoint = "https://127.0.0.1:{port}/api/scanner/result"
"#
        );
        fs::write(root.join("config.toml"), config).unwrap();
        let log = fs::File::create(root.join("process.log")).unwrap();
        let scanner = Command::new(env!("CARGO_BIN_EXE_scanner-rs"))
            .current_dir(&root)
            .arg("--config")
            .arg(root.join("config.toml"))
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self {
            root,
            server,
            scanner,
        }
    }

    fn wait_for_heartbeat(&mut self) {
        self.wait_for_heartbeats(1);
    }

    fn wait_for_heartbeats(&mut self, expected: u32) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while fs::read_to_string(self.root.join("heartbeat"))
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0)
            < expected
        {
            assert!(
                self.scanner.try_wait().unwrap().is_none(),
                "scanner exited before heartbeat: {}",
                self.log()
            );
            assert!(
                Instant::now() < deadline,
                "heartbeat timed out: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.scanner.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "scanner did not exit: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(self.root.join("process.log")).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.scanner.kill();
        let _ = self.scanner.wait();
        let _ = self.server.kill();
        let _ = self.server.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn heartbeat_auth_rejection_exits_with_failure() {
    let mut fixture = Fixture::start("reject");
    fixture.wait_for_heartbeat();
    let status = fixture.wait();
    assert!(
        !status.success(),
        "heartbeat rejection must fail the process: {}",
        fixture.log()
    );
}

#[test]
fn sigint_exits_successfully() {
    let mut fixture = Fixture::start("accept");
    fixture.wait_for_heartbeat();
    // The fixture has observed a real heartbeat, so the signal handler is installed.
    assert_eq!(
        unsafe { libc::kill(fixture.scanner.id() as i32, libc::SIGINT) },
        0
    );
    let status = fixture.wait();
    assert!(
        status.success(),
        "SIGINT should shut down cleanly: {}",
        fixture.log()
    );
}

#[test]
fn truncated_heartbeat_retries_and_scanner_stays_running() {
    let mut fixture = Fixture::start("truncate");
    fixture.wait_for_heartbeats(2);
    assert!(
        fixture.scanner.try_wait().unwrap().is_none(),
        "scanner stopped instead of retrying: {}",
        fixture.log()
    );
    assert_eq!(
        unsafe { libc::kill(fixture.scanner.id() as i32, libc::SIGINT) },
        0
    );
    assert!(
        fixture.wait().success(),
        "scanner did not shut down cleanly after retry: {}",
        fixture.log()
    );
}

#[test]
fn runtime_storage_failure_exits_with_failure() {
    let mut fixture = Fixture::start("storage");
    fixture.wait_for_heartbeat();
    let db = rusqlite::Connection::open(fixture.root.join("scanner-state.sqlite3")).unwrap();
    db.execute("DROP TABLE scan_retry", []).unwrap();
    drop(db);
    fs::write(fixture.root.join("continue"), "").unwrap();
    let status = fixture.wait();
    let log = fixture.log();
    assert!(
        log.contains("failed to load recovery failure report"),
        "unexpected failure path: {log}"
    );
    assert!(
        !status.success(),
        "storage failure must fail the process: {log}"
    );
}
