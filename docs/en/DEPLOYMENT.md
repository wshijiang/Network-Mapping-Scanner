# Scanner deployment

[Documentation](README.md) · [Complete deployment reference (Chinese)](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/DEPLOYMENT.md)

## Prepare the server and engines

Deploy PostgreSQL, Elasticsearch, the Network Mapping server and Web console before installing scanner nodes. Scanners connect to the server over trusted HTTPS; they do not need direct PostgreSQL or Elasticsearch access.

Linux source/release installations require the relevant external engines: masscan for ports, zgrab2 at commit `835aa53808aed88b4c3e017d623b374fb26dca95` for service detection (v1.0.0 lacks RDP), and Nuclei plus reviewed signed templates for vulnerability scans. Release archives contain the Rust programs, not those external engines. The container image includes pinned engines and official templates; see the [Docker guide (Chinese)](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/DOCKER.md).

```sh
git clone https://github.com/wshijiang/Network-Mapping-Scanner.git
cd Network-Mapping-Scanner
cargo build --locked --release --bins
```

Use only explicitly authorized targets. Configure interfaces, routes and raw-packet permissions for the actual node. Host networking does not automatically provide IPv6 routing.

## Configuration and registration

Edit the complete `config.toml`: set `scanner.c_server` (hostname/IP only), `scanner.c_port`, `upload.endpoint`, absolute engine paths and conservative scan rates. Replace sample addresses and paths. Use `scanner.masscan_output_mode = "standard_list"` for official masscan. Keep TLS verification enabled; install only the public private-CA certificate when needed, not the server private key.

Create a scanner in the console and use its ID and one-time registration token:

```sh
./target/release/scanner-rs --config config.toml \
  --id '<scanner-id>' --token '<registration-token>'
```

Successful registration stores the identity in local SQLite and exits. Start the scan loop using the same working directory and database path, without registration parameters:

```sh
./target/release/scanner-rs --config config.toml
```

Each node needs its own identity and state directory. The default database is `./scanner-state.sqlite3`; `--database` selects a different path. It contains a runtime token. Store the complete state directory on restricted persistent local storage, including SQLite auxiliary files and diagnostic state. Do not clone a registered identity across nodes or clear pending uploads during normal upgrades.

## Verify and upgrade

Confirm trusted HTTPS access, successful registration/heartbeats and advertised engine/address-family capabilities. A process or open port alone does not prove operation. Run an authorized representative task and confirm results, cancellation and recovery before rollout.

Interrupted heartbeat or task response bodies are retried with backoff; a complete response that cannot be decoded remains a protocol error. An unrecoverable runtime error exits with a nonzero status, allowing a supervisor configured to restart on failure to restart the scanner. A normal SIGINT shutdown exits successfully. Inspect logs and correct persistent failures, and retain the state directory for recovery.

Agent, Worker and module packages must be compatible. Current native service expansion uses IPC 3; legacy IPC 2 and UDP-library-only notes describe historical stages. Follow [module upgrade instructions (Chinese)](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/MODULE_UPDATES.md) and the [current protocol matrix](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md), including server transport-endpoint migration.

Preserve identity, leases, checkpoints, diagnostics and pending uploads. Stop and replace according to the [recovery guide (Chinese)](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/recovery.md); do not re-register merely to upgrade. Protocol evidence, authentication rejection and passive observations do not imply successful login, ownership or an open source port.

## Documentation languages

The language menu selects English or Chinese. The first English release covers entry, deployment and maintenance pages; advanced references remain explicitly linked in Chinese. CLI output, protocol identifiers and original evidence are unchanged. See [documentation maintenance](LOCALIZATION.md).
