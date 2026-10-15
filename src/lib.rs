mod cache;
mod config;
mod config_check;
mod config_env;
mod diagnostics;
mod error;
mod health;
mod heartbeat;
mod http_client;
mod journal;
mod logging;
mod modules;
mod network;
mod nuclei_templates;
mod performance;
mod reconnect;
mod register;
mod registration_env;
mod runtime_config;
mod scan;
mod storage;
mod sysinfo;
mod types;
mod upload;

use crate::config::load;
use crate::error::{MaintenanceInfo, ScannerError, ServerError, UploadBatchContext};
use crate::health::health_check;
use crate::heartbeat::{ActiveTask, HeartbeatClient, HeartbeatEndpoints, TaskCancellationReason};
use crate::http_client::{FetchTaskOutcome, ServerHttpClient, fetch_task, recover_task};
use crate::logging::{LogLevel, init_logging};
use crate::network::{NetworkDetector, SharedNetworkCapabilities};
use crate::reconnect::{Backoff, ConnectionState, RetryPolicy};
use crate::runtime_config::{RuntimeConfiguration, RuntimeConfigurationEnvelope};
use crate::scan::{
    ScanCapabilities, ScanObservation, ScanOutcome, ScanPlan, ScanRuntimeConfig, run_scan,
    validate_nuclei_binary, validate_nuclei_templates, validate_scanner_binary,
    validate_zgrab_binary,
};
use crate::storage::{StateStore, StoredIdentity};
use crate::sysinfo::SystemInfo;
use crate::types::{CacheManager, TargetParams};
use crate::upload::Uploader;
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;
use tokio::time::{Duration, Instant, sleep};
use tracing::Instrument;
use uuid::Uuid;

// ---- CLI ----------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "scanner-rs",
    version,
    about = "Network port scanner orchestrator"
)]
struct Cli {
    /// 配置来源：文件部署使用 file，Docker 使用 env
    #[arg(long, value_enum, default_value = "file")]
    config_source: ConfigSource,
    /// Run a maintenance command instead of starting the scan loop
    #[command(subcommand)]
    command: Option<ScannerCommand>,

    /// Run health-check only (no scanning)
    #[arg(short = 'c', long)]
    health_check: bool,

    /// Enable debug output
    #[arg(short = 'd', long)]
    debug: bool,

    /// Print system information and exit
    #[arg(short = 'i', long)]
    get_system_info: bool,

    /// Scanner identity (UUIDv7)
    #[arg(long)]
    id: Option<String>,

    /// Registration token from server
    #[arg(long)]
    token: Option<String>,

    /// Path to config file (default: config.toml)
    #[arg(short = 'f', long, default_value = "config.toml")]
    config: String,

    /// Directory for daily JSON log files
    #[arg(long, default_value = "./logs")]
    log_directory: PathBuf,

    /// Durable state file used to resume result uploads after a restart
    /// (legacy JSON input; imported into --database when present)
    #[arg(long, default_value = "./scanner-state.json")]
    state_file: PathBuf,

    /// SQLite database for scanner identity and durable upload state
    #[arg(long, default_value = "./scanner-state.sqlite3")]
    database: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ConfigSource {
    File,
    Env,
}

#[derive(Subcommand, Debug)]
enum ScannerCommand {
    /// Inspect, apply or roll back versioned execution modules
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },
    /// Inspect or clear durable scanner caches
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ModuleCommand {
    Status,
    Apply {
        #[arg(long)]
        bundle: PathBuf,
    },
    Rollback {
        #[arg(long)]
        generation: i64,
    },
    Gc,
}

#[derive(Subcommand, Debug)]
enum CacheCommand {
    /// Clear pending scan results and task/upload progress
    Clear {
        /// Clear cached results for every server origin in the state database
        #[arg(long)]
        all_origins: bool,
        /// Also clear cached runtime configuration (scanner identity is always preserved)
        #[arg(long)]
        include_runtime_config: bool,
        /// Show what would be removed without changing files
        #[arg(long)]
        dry_run: bool,
        /// Skip the interactive confirmation
        #[arg(long)]
        yes: bool,
    },
}

// ---- globals ------------------------------------------------------------

static STOP: AtomicBool = AtomicBool::new(false);
static SHUTDOWN: OnceLock<watch::Sender<bool>> = OnceLock::new();

fn init_shutdown() {
    let (sender, _) = watch::channel(false);
    let _ = SHUTDOWN.set(sender);
}

fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

fn request_stop() {
    STOP.store(true, Ordering::Relaxed);
    if let Some(sender) = SHUTDOWN.get() {
        let _ = sender.send(true);
    }
}

fn shutdown_receiver() -> watch::Receiver<bool> {
    SHUTDOWN
        .get()
        .expect("shutdown channel must be initialized")
        .subscribe()
}

// ---- entry point --------------------------------------------------------

pub async fn agent_main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_shutdown();
    let logging_guard = match init_logging(cli.debug, &cli.log_directory) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("failed to initialize logs: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(event="ScannerPanic",error_kind="process",error_code="scanner_panic",operation="runtime",error_message=%info,"scanner panicked");
        previous_hook(info);
    }));
    let result = run(cli, &logging_guard).await;
    let code = if let Err(e) = result {
        tracing::error!(event="ScannerFatal",error_kind="process",error_code="scanner_fatal",operation="runtime",error_message=%e,"scanner terminated");
        eprintln!("fatal: {e}");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    };
    diagnostics::flush_capture().await;
    code
}

async fn run(cli: Cli, logging_guard: &crate::logging::LoggingGuard) -> Result<(), ScannerError> {
    if cli.command.is_some()
        && (cli.health_check || cli.get_system_info || cli.id.is_some() || cli.token.is_some())
    {
        return Err(ScannerError::Config(
            "cache commands cannot be combined with health, system-info, or registration options"
                .into(),
        ));
    }

    tracing::debug!(
        version = env!("CARGO_PKG_VERSION"),
        process_id = std::process::id(),
        config_source = ?cli.config_source,
        health_check = cli.health_check,
        system_info_only = cli.get_system_info,
        registration_requested = cli.id.is_some() || cli.token.is_some(),
        log_directory = %logging_guard.directory().display(),
        "command-line options parsed"
    );

    log_event!(LogLevel::Info, "SCANNER-START", "scanner started", "main");

    spawn_signal_handler();

    // ---- system info ----
    match SystemInfo::gather() {
        Ok(info) => info.print(),
        Err(e) => tracing::warn!("failed to gather system info: {}", e),
    }

    if cli.get_system_info {
        return Ok(());
    }

    // ---- load config ----
    let mut loaded = match cli.config_source {
        ConfigSource::File => load(&cli.config),
        ConfigSource::Env => config::load_env(),
    }
    .inspect_err(|e| {
        log_event!(
            LogLevel::Error,
            "CONFIG-LOAD",
            "failed to load config",
            "main"
        );
        eprintln!("\x1b[31mconfig error: {}\x1b[0m", e);
    })?;

    tracing::debug!(config_source = ?cli.config_source, "configuration loaded and validated");

    let server_origin = loaded.app.scanner.server_origin();
    if let Some(ScannerCommand::Module { command }) = cli.command.as_ref() {
        return execute_module_command(command, &loaded.app.modules, &server_origin).await;
    }
    let mut state_store = StateStore::open(cli.database.clone())?;
    if let Some(command) = cli.command.as_ref() {
        execute_maintenance_command(command, &mut state_store, &server_origin, &cli.state_file)?;
        return Ok(());
    }
    let legacy_identity_present = loaded.has_legacy_runtime_token();
    let legacy_secret_present = loaded.has_legacy_secret();
    if let Some(identity) = state_store.load_identity(&server_origin)? {
        if legacy_identity_present
            && (loaded.app.scanner.scanner_id != identity.scanner_id
                || loaded.app.scanner.runtime_token != identity.runtime_token)
        {
            tracing::warn!(
                server_origin,
                "SQLite identity overrides a different legacy TOML identity"
            );
        }
        loaded.app.scanner.scanner_id = identity.scanner_id;
        loaded.app.scanner.runtime_token = identity.runtime_token;
    } else if legacy_identity_present {
        Uuid::parse_str(&loaded.app.scanner.scanner_id).map_err(|error| {
            ScannerError::Config(format!("invalid legacy scanner.scanner_id: {error}"))
        })?;
        state_store.save_identity(
            &server_origin,
            &StoredIdentity {
                scanner_id: loaded.app.scanner.scanner_id.clone(),
                runtime_token: loaded.app.scanner.runtime_token.clone(),
            },
        )?;
        tracing::info!(server_origin, "legacy TOML identity imported into SQLite");
    }
    if legacy_secret_present && let Err(error) = loaded.clear_legacy_identity() {
        tracing::warn!(%error, "identity is stored in SQLite but could not be removed from TOML");
    }

    let env_registration = if cli.config_source == ConfigSource::Env
        && !cli.health_check
        && cli.id.is_none()
        && cli.token.is_none()
    {
        registration_env::load()?
    } else {
        registration_env::Registration::default()
    };
    let requested_id = cli.id.as_deref().or(env_registration.scanner_id.as_deref());
    if let Some(requested_scanner_id) = requested_id
        && let Some(pending_scanner_id) = state_store.pending_upload_scanner_id(&server_origin)?
        && pending_scanner_id != requested_scanner_id
    {
        return Err(ScannerError::Config(format!(
            "cannot register scanner {requested_scanner_id} while results for scanner {pending_scanner_id} are pending upload"
        )));
    }
    if let Some(requested_scanner_id) = requested_id
        && requested_scanner_id != loaded.app.scanner.scanner_id
        && CacheManager::legacy_state_has_pending(&cli.state_file)?
    {
        return Err(ScannerError::Config(format!(
            "cannot register scanner {requested_scanner_id} while legacy JSON results for scanner {} are pending migration",
            loaded.app.scanner.scanner_id
        )));
    }

    // ---- handle --id / --token ----
    let automatic_registration = env_registration.needs_registration(
        &loaded.app.scanner.scanner_id,
        !loaded.app.scanner.runtime_token.is_empty(),
        state_store
            .load_registration_fingerprint(&server_origin)?
            .as_deref(),
    )?;
    let explicit_registration = cli.id.is_some() || cli.token.is_some();
    let registration_id = cli.id.as_deref().or(env_registration.scanner_id.as_deref());
    let registration_token = cli.token.as_deref().or(env_registration.token.as_deref());
    let identity_changed = if explicit_registration || automatic_registration {
        handle_identity(registration_id, registration_token, &mut loaded).await?
    } else {
        false
    };

    if identity_changed {
        state_store.save_registered_identity(
            &server_origin,
            &StoredIdentity {
                scanner_id: loaded.app.scanner.scanner_id.clone(),
                runtime_token: loaded.app.scanner.runtime_token.clone(),
            },
            &registration_env::fingerprint(registration_id.unwrap(), registration_token.unwrap()),
        )?;
        println!("\x1b[32mscanner identity stored in SQLite\x1b[0m");
        // When --id/--token are explicitly passed, registration is the goal; exit.
        if cli.id.is_some() || cli.token.is_some() {
            return Ok(());
        }
    }

    let cfg = &loaded.app;
    let task_url = cfg.scanner.task_url(false);
    let current_task_url = cfg.scanner.current_task_url(None);

    tracing::debug!(
        server = %cfg.scanner.c_server,
        server_port = cfg.scanner.c_port,
        scan_rate = cfg.scanner.rate,
        verify_tls = cfg.scanner.verify_tls,
        scanner_path = %cfg.scanner.scanner_path,
        scanner_id = %cfg.scanner.scanner_id,
        runtime_token_configured = !cfg.scanner.runtime_token.is_empty(),
        upload_endpoint = %cfg.upload.endpoint,
        heartbeat_interval_seconds = cfg.scanner.heartbeat_interval_seconds,
        connect_timeout_seconds = cfg.scanner.connect_timeout_seconds,
        request_timeout_seconds = cfg.scanner.request_timeout_seconds,
        reconnect_initial_delay_seconds = cfg.scanner.reconnect_initial_delay_seconds,
        reconnect_max_delay_seconds = cfg.scanner.reconnect_max_delay_seconds,
        active_task_reconnect_max_delay_seconds = cfg.scanner.active_task_reconnect_max_delay_seconds,
        lease_safety_margin_seconds = cfg.scanner.lease_safety_margin_seconds,
        service_detection_enabled = cfg.service_detection.enabled,
        service_detection_strategy = cfg.service_detection.strategy.as_str(),
        service_detection_max_probes = cfg.service_detection.max_probes_per_endpoint,
        zgrab_path = %cfg.service_detection.zgrab_path,
        zgrab_senders = cfg.service_detection.senders,
        "effective scanner configuration"
    );

    println!("scanner.c_server   = {}", cfg.scanner.c_server);
    println!("scanner.c_port     = {}", cfg.scanner.c_port);
    println!("scanner.rate       = {}", cfg.scanner.rate);
    println!("scanner.verify_tls = {}", cfg.scanner.verify_tls);
    println!("scanner.path       = {}", cfg.scanner.scanner_path);
    println!("scanner.id         = {}", cfg.scanner.scanner_id);
    println!(
        "scanner.runtime_token = {}",
        if cfg.scanner.runtime_token.is_empty() {
            "(not set)"
        } else {
            "****"
        }
    );
    println!("upload.endpoint    = {}", cfg.upload.endpoint);
    println!(
        "service detection  = {}",
        if cfg.service_detection.enabled {
            "zgrab2"
        } else {
            "disabled"
        }
    );
    if cfg.service_detection.enabled {
        println!("zgrab.path         = {}", cfg.service_detection.zgrab_path);
        println!("zgrab.senders      = {}", cfg.service_detection.senders);
        println!(
            "zgrab.strategy     = {} (max {} probes/endpoint)",
            cfg.service_detection.strategy.as_str(),
            cfg.service_detection.max_probes_per_endpoint
        );
    }
    println!(
        "heartbeat.interval = {}s",
        cfg.scanner.heartbeat_interval_seconds
    );
    println!("task URL           = {}", task_url);
    println!("\nconfig validated\n");

    log_event!(LogLevel::Info, "CONFIG-OK", "config validated", "main");

    // ---- health-check mode ----
    if cli.health_check {
        if cfg.scanner.runtime_token.is_empty() {
            return Err(ScannerError::Config(
                "scanner.runtime_token is required; register the scanner first".into(),
            ));
        }
        println!("HEALTH CHECKING");
        let client = ServerHttpClient::new(
            cfg.scanner.verify_tls,
            cfg.scanner.runtime_token.clone(),
            Duration::from_secs(cfg.scanner.connect_timeout_seconds),
            Duration::from_secs(cfg.scanner.request_timeout_seconds),
        )?;
        match health_check(&client, &cfg.scanner.task_url(true)).await {
            Ok(()) => {
                log_event!(
                    LogLevel::Info,
                    "HEALTH-CHECK",
                    "health check passed",
                    "main"
                );
                println!("\x1b[32mhealth check passed\x1b[0m");
            }
            Err(e) => {
                log_event!(
                    LogLevel::Warn,
                    "HEALTH-CHECK",
                    "health check failed",
                    "main"
                );
                eprintln!("\x1b[31mhealth check error: {}\x1b[0m", e);
            }
        }
        return Ok(());
    }

    println!("starting...");

    if cfg.scanner.runtime_token.is_empty() {
        return Err(ScannerError::Config(
            "scanner.runtime_token is required; register the scanner first".into(),
        ));
    }
    let scanner_id = Uuid::parse_str(&cfg.scanner.scanner_id)
        .map_err(|error| ScannerError::Config(format!("invalid scanner.scanner_id: {error}")))?;
    let server_client = ServerHttpClient::new(
        cfg.scanner.verify_tls,
        cfg.scanner.runtime_token.clone(),
        Duration::from_secs(cfg.scanner.connect_timeout_seconds),
        Duration::from_secs(cfg.scanner.request_timeout_seconds),
    )?;

    nuclei_templates::prepare(&cfg.nuclei).await?;
    let module_registry = if cfg.modules.enabled {
        Some(
            modules::registry::Registry::open(cfg.modules.clone(), cfg, server_origin.clone())
                .await?,
        )
    } else {
        None
    };
    let module_update_handle = module_registry
        .as_ref()
        .map(|registry| modules::update::start(registry.clone(), shutdown_receiver()));
    let uploader = Uploader::new(cfg.upload.endpoint.clone(), server_client.clone());
    let (connection_tx, connection_rx) = watch::channel(ConnectionState::Connecting);
    let network_detector = NetworkDetector::new(
        cfg.network.clone(),
        cfg.scanner.verify_tls,
        cfg.scanner.public_ip_url(),
        cfg.scanner.runtime_token.clone(),
    )?;
    let network_capabilities = SharedNetworkCapabilities::new(network_detector.detect().await);
    let scan_capabilities =
        ScanCapabilities::from_config(&cfg.service_detection, &cfg.dns, &cfg.nuclei);
    let runtime_configuration = RuntimeConfiguration::new(cfg);
    if let Some(stored) = state_store.load_runtime_configuration(&server_origin)? {
        let envelope = RuntimeConfigurationEnvelope {
            revision: stored.revision,
            schema_version: stored.schema_version,
            document: serde_json::from_slice(&stored.document)?,
        };
        if let Err(error) = runtime_configuration.restore(envelope).await {
            tracing::warn!(%error, "ignored invalid cached runtime configuration");
        }
    }
    let network_probe_handle =
        network_detector.spawn(network_capabilities.clone(), connection_rx.clone());
    let diagnostics_runtime = diagnostics::DiagnosticsRuntime::start(
        logging_guard.directory(),
        &cli.database,
        server_origin.clone(),
        scanner_id,
        server_client.clone(),
        connection_rx.clone(),
        shutdown_receiver(),
    )
    .await
    .map_err(|e| ScannerError::Config(format!("diagnostics initialization failed: {e}")))?;
    let diagnostics_supervisor = diagnostics_runtime.supervisor();
    let startup_validation = (|| -> Result<(), ScannerError> {
        if let Some(registry) = &module_registry {
            let environment = registry
                .active()?
                .ok_or_else(|| ScannerError::Config("module environment unavailable".into()))?;
            for stage in [
                "port_discovery",
                "service_detection",
                "dns_lookup",
                "vulnerability_detection",
            ] {
                let enabled = match stage {
                    "service_detection" => cfg.service_detection.enabled,
                    "dns_lookup" => cfg.dns.enabled,
                    "vulnerability_detection" => cfg.nuclei.enabled,
                    _ => true,
                };
                if enabled && !environment.modules.contains_key(stage) {
                    return Err(ScannerError::Config(format!(
                        "required local module {stage} missing"
                    )));
                }
            }
            return Ok(());
        }
        validate_scanner_binary(&cfg.scanner.scanner_path)?;
        if cfg.service_detection.enabled {
            validate_zgrab_binary(&cfg.service_detection.zgrab_path)?;
        }
        if cfg.nuclei.enabled {
            validate_nuclei_binary(&cfg.nuclei.path)?;
            validate_nuclei_templates(&cfg.nuclei.templates_path)?;
        }
        Ok(())
    })();
    if let Err(error) = &startup_validation {
        diagnostics_runtime.handle.set_accepting_tasks(false);
        tracing::error!(event="ScannerStartupValidationFailed",error_kind="configuration",error_code="scanner_engine_validation_failed",operation="startup",error_message=%error,"scanner engine validation failed; diagnostics remain available");
    }
    if startup_validation.is_ok() {
        tracing::info!(
            event = "ScannerOperationRecovered",
            operation = "startup",
            "scanner startup checks passed"
        );
    }
    let heartbeat_client = HeartbeatClient::new(
        server_client.clone(),
        HeartbeatEndpoints {
            heartbeat: cfg.scanner.heartbeat_url(),
            failure: cfg.scanner.task_failure_url(),
            cancelled: cfg.scanner.task_cancelled_url(),
            maintenance: cfg.scanner.maintenance_url(),
        },
        scanner_id,
        network_capabilities,
        scan_capabilities,
        cfg.scanner.runtime_configuration_url(),
        runtime_configuration.clone(),
    )
    .with_config_check(loaded.check.clone())
    .with_diagnostics(diagnostics_runtime.handle.clone())
    .with_modules(module_registry.clone());
    let active_task = ActiveTask::default();
    let stop_bridge_handle = spawn_active_task_stop_bridge(active_task.clone());
    let heartbeat_handle = spawn_heartbeat(
        heartbeat_client.clone(),
        active_task.clone(),
        connection_tx,
        HeartbeatLoopConfig {
            interval: Duration::from_secs(cfg.scanner.heartbeat_interval_seconds),
            retry_policy: RetryPolicy::new(
                Duration::from_secs(cfg.scanner.reconnect_initial_delay_seconds),
                Duration::from_secs(cfg.scanner.reconnect_max_delay_seconds),
            ),
            active_retry_max: Duration::from_secs(
                cfg.scanner.active_task_reconnect_max_delay_seconds,
            ),
            lease_safety_margin: Duration::from_secs(cfg.scanner.lease_safety_margin_seconds),
        },
    );
    tracing::debug!(
        scanner_id = %scanner_id,
        heartbeat_interval_seconds = cfg.scanner.heartbeat_interval_seconds,
        "runtime clients initialized"
    );
    let mut cache = CacheManager::load(
        state_store,
        server_origin,
        cfg.scanner.scanner_id.clone(),
        cli.state_file.clone(),
    )?;
    if cache.has_pending_task() {
        tracing::warn!(
            task_id = ?cache.task_id,
            upload_id = ?cache.upload_id,
            next_batch_index = cache.next_batch_index,
            observation_count = cache.observations.len(),
            "resuming durable result upload state"
        );
    }

    if startup_validation.is_err() {
        let mut shutdown = shutdown_receiver();
        while !stop_requested() {
            if heartbeat_handle.is_finished() || diagnostics_runtime.is_finished() {
                request_stop();
                break;
            }
            tokio::select! {_ = sleep(Duration::from_secs(1)) => {}, _ = shutdown.changed() => break}
        }
    }
    if !stop_requested() && startup_validation.is_ok() {
        scan_loop(
            ScanLoopConfig {
                module_registry: module_registry.clone(),
                scanner_path: &cfg.scanner.scanner_path,
                task_url: &task_url,
                current_task_url: &current_task_url,
                server_client: &server_client,
                scanner_id,
                runtime_configuration,
                retry_policy: RetryPolicy::new(
                    Duration::from_secs(cfg.scanner.reconnect_initial_delay_seconds),
                    Duration::from_secs(cfg.scanner.reconnect_max_delay_seconds),
                ),
                lease_safety_margin: Duration::from_secs(cfg.scanner.lease_safety_margin_seconds),
            },
            &uploader,
            &heartbeat_client,
            &active_task,
            &mut cache,
            connection_rx,
        )
        .await;
        println!("scan complete");
        log_event!(LogLevel::Info, "SCAN-DONE", "scan loop finished", "main");
    }

    tracing::info!(
        event = "ShutdownUploadRetained",
        pending = cache.has_pending_task(),
        "shutdown preserves durable results for the next lease recovery"
    );
    if let Err(error) = heartbeat_client.send(active_task.get().await, true).await {
        tracing::warn!(
            event = "FinalHeartbeatFailed",
            operation = "send_final_heartbeat",
            reason = %error,
            retryable = false,
            outcome = "shutdown_continued",
            "final heartbeat failed"
        );
    }
    if let Some(handle) = module_update_handle {
        handle.abort();
    }
    heartbeat_handle.abort();
    stop_bridge_handle.abort();
    network_probe_handle.abort();
    request_stop();
    diagnostics_supervisor.abort();
    diagnostics_runtime.stop(true).await;

    log_event!(LogLevel::Info, "CLEANUP", "shutdown complete", "main");
    println!("shutdown complete");
    Ok(())
}

fn execute_maintenance_command(
    command: &ScannerCommand,
    store: &mut StateStore,
    server_origin: &str,
    legacy_state_file: &std::path::Path,
) -> Result<(), ScannerError> {
    match command {
        ScannerCommand::Module { .. } => Err(ScannerError::Config(
            "module command routed to cache maintenance".into(),
        )),
        ScannerCommand::Cache {
            command:
                CacheCommand::Clear {
                    all_origins,
                    include_runtime_config,
                    dry_run,
                    yes,
                },
        } => {
            let origin = (!all_origins).then_some(server_origin);
            let summary = store.cache_summary(origin)?;
            let legacy_present = legacy_state_file.exists();
            println!("Scanner cache clear summary");
            println!(
                "  scope                 : {}",
                origin.unwrap_or("all origins")
            );
            println!("  pending tasks         : {}", summary.pending_tasks);
            println!("  cached observations   : {}", summary.observations);
            println!(
                "  runtime configurations: {} ({})",
                summary.runtime_configurations,
                if *include_runtime_config {
                    "clear"
                } else {
                    "preserve"
                }
            );
            println!(
                "  legacy JSON state     : {}",
                if legacy_present {
                    legacy_state_file.display().to_string()
                } else {
                    "not present".into()
                }
            );
            println!("  scanner identity      : preserved");
            if *dry_run {
                println!("dry-run: no cache was changed");
                return Ok(());
            }
            if !*yes {
                if !io::stdin().is_terminal() {
                    return Err(ScannerError::Config(
                        "non-interactive cache clear requires --yes".into(),
                    ));
                }
                eprint!("Permanently discard these unuploaded results? [y/N] ");
                io::stderr().flush().map_err(ScannerError::Io)?;
                let mut answer = String::new();
                io::stdin()
                    .read_line(&mut answer)
                    .map_err(ScannerError::Io)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    return Err(ScannerError::Config("cache clear cancelled".into()));
                }
            }
            let staged_legacy = if legacy_present {
                let staged = legacy_state_file.with_extension("json.clearing");
                if staged.exists() {
                    return Err(ScannerError::Config(format!(
                        "cannot stage legacy state because {} already exists",
                        staged.display()
                    )));
                }
                std::fs::rename(legacy_state_file, &staged).map_err(ScannerError::Io)?;
                Some(staged)
            } else {
                None
            };
            if let Err(error) = store.clear_cache(origin, *include_runtime_config) {
                if let Some(staged) = staged_legacy.as_ref() {
                    let _ = std::fs::rename(staged, legacy_state_file);
                }
                return Err(error);
            }
            if let Some(staged) = staged_legacy {
                std::fs::remove_file(staged).map_err(ScannerError::Io)?;
            }
            println!("cache cleared; scanner identity was preserved");
            Ok(())
        }
    }
}

// ---- identity management ------------------------------------------------

/// Returns `true` if the runtime identity was changed.
async fn handle_identity(
    id: Option<&str>,
    token: Option<&str>,
    loaded: &mut config::LoadedConfig,
) -> Result<bool, ScannerError> {
    let id_provided = id.is_some();
    let token_provided = token.is_some();

    if !id_provided && !token_provided {
        tracing::debug!("registration options not provided; using stored identity");
        return Ok(false);
    }

    tracing::debug!(
        id_provided,
        token_provided,
        "processing scanner registration options"
    );

    if !id_provided || !token_provided {
        return Err(ScannerError::Config(
            "--id and --token must be provided together for registration".into(),
        ));
    }

    let scanner_id = id.expect("checked above");
    let registration_token = token.expect("checked above");
    match register::register(
        &loaded.app.scanner.c_server,
        loaded.app.scanner.c_port,
        loaded.app.scanner.verify_tls,
        loaded.app.scanner.connect_timeout_seconds,
        loaded.app.scanner.request_timeout_seconds,
        scanner_id,
        registration_token,
    )
    .await?
    {
        register::RegisterOutcome::Registered { runtime_token } => {
            loaded.app.scanner.scanner_id = scanner_id.to_owned();
            loaded.app.scanner.runtime_token = runtime_token;
            println!("\x1b[32mregistration successful\x1b[0m");
            log_event!(LogLevel::Info, "REGISTER", "registration accepted", "main");
            Ok(true)
        }
        register::RegisterOutcome::Unauthorized => Err(ScannerError::Http(
            "registration rejected: invalid or expired credentials".into(),
        )),
    }
}

// ---- signal handler -----------------------------------------------------

fn spawn_signal_handler() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            request_stop();
            eprintln!("\nSIGINT received, shutting down gracefully...");
            log_event!(LogLevel::Info, "SIGNAL", "SIGINT received", "main");
        }
    });
}

fn spawn_active_task_stop_bridge(active_task: ActiveTask) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        wait_for_stop().await;
        active_task.request_shutdown().await;
    })
}

async fn wait_for_stop() {
    if stop_requested() {
        return;
    }
    let mut shutdown = shutdown_receiver();
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

async fn sleep_or_stop(duration: Duration) -> bool {
    if stop_requested() {
        return true;
    }
    let mut shutdown = shutdown_receiver();
    tokio::select! {
        _ = sleep(duration) => false,
        _ = shutdown.changed() => true,
    }
}

#[derive(Clone, Copy)]
struct HeartbeatLoopConfig {
    interval: Duration,
    retry_policy: RetryPolicy,
    active_retry_max: Duration,
    lease_safety_margin: Duration,
}

fn spawn_heartbeat(
    client: HeartbeatClient,
    active_task: ActiveTask,
    connection_tx: watch::Sender<ConnectionState>,
    config: HeartbeatLoopConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut backoff = Backoff::new(config.retry_policy);
        let mut shutdown = shutdown_receiver();
        tracing::debug!(
            interval_seconds = config.interval.as_secs(),
            "heartbeat loop started"
        );
        while !stop_requested() {
            let active_task_id =
                if active_task.cancellation_reason() == Some(TaskCancellationReason::LeaseLost) {
                    None
                } else {
                    active_task.get().await
                };
            tracing::debug!(?active_task_id, "sending periodic heartbeat");
            let send_result = if let Some(task_id) = active_task_id {
                let remaining = active_task
                    .lease_safety_remaining(config.lease_safety_margin)
                    .await
                    .unwrap_or_default();
                if remaining.is_zero() {
                    active_task.request_lease_lost(task_id).await;
                    continue;
                }
                tokio::select! {
                    result = client.send(active_task_id, false) => result,
                    _ = sleep(remaining) => {
                        active_task.request_lease_lost(task_id).await;
                        continue;
                    }
                    _ = shutdown.changed() => break,
                }
            } else {
                tokio::select! {
                    result = client.send(None, false) => result,
                    _ = shutdown.changed() => break,
                }
            };
            match send_result {
                Ok(response) => {
                    backoff.reset();
                    let maintenance = client.apply_command(response, &active_task).await;
                    if let Some(info) = maintenance.filter(|info| info.enabled) {
                        publish_connection_state(&connection_tx, ConnectionState::Maintenance);
                        tracing::warn!(
                            maintenance_id = ?info.id,
                            phase = %info.phase,
                            message = %info.message,
                            task_action = %info.task_action,
                            result_upload_grace_hours = info.result_upload_grace_hours,
                            "maintenance announced by heartbeat; active scan will finish locally"
                        );
                        match wait_for_maintenance_exit(&client, &active_task, info).await {
                            Ok(true) => {
                                publish_connection_state(
                                    &connection_tx,
                                    ConnectionState::Connecting,
                                );
                                tracing::info!(
                                    "system maintenance ended; resuming heartbeat and cached uploads"
                                );
                                continue;
                            }
                            Ok(false) => break,
                            Err(error) => {
                                log_terminal_scanner_error(
                                    "MaintenanceProbeFailed",
                                    "poll_maintenance_status",
                                    &error,
                                    "process_stopping",
                                    active_task_id,
                                );
                                request_stop();
                                break;
                            }
                        }
                    }
                    publish_connection_state(&connection_tx, ConnectionState::Online);
                    let next_interval = if active_task.get().await.is_some() {
                        active_task
                            .lease_safety_remaining(config.lease_safety_margin)
                            .await
                            .map(|remaining| {
                                config
                                    .interval
                                    .min((remaining / 2).max(Duration::from_secs(1)))
                            })
                            .unwrap_or(config.interval)
                    } else {
                        config.interval
                    };
                    if sleep_or_stop(next_interval).await {
                        break;
                    }
                }
                Err(ScannerError::Server(ServerError::Maintenance { info, .. })) => {
                    publish_connection_state(&connection_tx, ConnectionState::Maintenance);
                    tracing::warn!(
                        maintenance_id = ?info.id,
                        phase = %info.phase,
                        message = %info.message,
                        started_at = ?info.started_at,
                        expected_end_at = ?info.expected_end_at,
                        revision = info.revision,
                        task_action = %info.task_action,
                        result_upload_grace_hours = info.result_upload_grace_hours,
                        retry_delay_seconds = info.retry_delay().as_secs(),
                            "system maintenance started; scanner will sleep after its active scan finishes locally"
                    );
                    match wait_for_maintenance_exit(&client, &active_task, *info).await {
                        Ok(true) => {
                            backoff.reset();
                            publish_connection_state(&connection_tx, ConnectionState::Connecting);
                            tracing::info!("system maintenance ended; resuming heartbeat");
                        }
                        Ok(false) => break,
                        Err(ScannerError::Server(ServerError::AuthRejected { .. })) => {
                            publish_connection_state(&connection_tx, ConnectionState::AuthRejected);
                            active_task.request_shutdown().await;
                            request_stop();
                            break;
                        }
                        Err(ScannerError::Server(ServerError::PolicyBlocked { .. })) => {
                            publish_connection_state(
                                &connection_tx,
                                ConnectionState::PolicyBlocked,
                            );
                            active_task.request_shutdown().await;
                            request_stop();
                            break;
                        }
                        Err(error) => {
                            log_terminal_scanner_error(
                                "MaintenanceProbeFailed",
                                "poll_maintenance_status",
                                &error,
                                "process_stopping",
                                active_task_id,
                            );
                            request_stop();
                            break;
                        }
                    }
                }
                Err(ScannerError::Server(error)) if error.is_retryable() => {
                    publish_connection_state(&connection_tx, ConnectionState::Reconnecting);
                    if let Some(task_id) = active_task_id
                        && active_task
                            .lease_safety_expired(config.lease_safety_margin)
                            .await
                    {
                        active_task.request_lease_lost(task_id).await;
                    }
                    let maximum = active_task_id.map(|_| config.active_retry_max);
                    let retry_after = error
                        .retry_after()
                        .map(|delay| maximum.map_or(delay, |maximum| delay.min(maximum)));
                    let mut delay = backoff.next_delay(maximum, retry_after);
                    if active_task_id.is_some()
                        && let Some(remaining) = active_task
                            .lease_safety_remaining(config.lease_safety_margin)
                            .await
                    {
                        delay = delay.min(remaining);
                    }
                    tracing::warn!(
                        event = "HeartbeatRetry",
                        operation = error.operation(),
                        reason = %error,
                        error_kind = error.kind(),
                        error_code = error.code(),
                        retryable = true,
                        outcome = "reconnecting",
                        http_status = ?error.status(),
                        server_request_id = ?error.request_id(),
                        task_id = ?active_task_id,
                        attempt = backoff.failures(),
                        retry_after_ms = delay.as_millis() as u64,
                        "heartbeat failed; reconnecting"
                    );
                    if sleep_or_stop(delay).await {
                        break;
                    }
                }
                Err(ScannerError::Server(error @ ServerError::AuthRejected { .. })) => {
                    publish_connection_state(&connection_tx, ConnectionState::AuthRejected);
                    active_task.request_shutdown().await;
                    log_terminal_scanner_error(
                        "HeartbeatAuthenticationRejected",
                        "send_heartbeat",
                        &ScannerError::Server(error),
                        "process_stopping",
                        active_task_id,
                    );
                    request_stop();
                    break;
                }
                Err(ScannerError::Server(error @ ServerError::PolicyBlocked { .. })) => {
                    publish_connection_state(&connection_tx, ConnectionState::PolicyBlocked);
                    active_task.request_shutdown().await;
                    log_terminal_scanner_error(
                        "HeartbeatPolicyBlocked",
                        "send_heartbeat",
                        &ScannerError::Server(error),
                        "process_stopping",
                        active_task_id,
                    );
                    request_stop();
                    break;
                }
                Err(ScannerError::Server(error)) => {
                    log_terminal_scanner_error(
                        "HeartbeatFailed",
                        "send_heartbeat",
                        &ScannerError::Server(error),
                        "process_stopping",
                        active_task_id,
                    );
                    request_stop();
                    break;
                }
                Err(error) => {
                    publish_connection_state(&connection_tx, ConnectionState::Reconnecting);
                    let delay = backoff.next_delay(None, None);
                    tracing::warn!(
                        event = "HeartbeatRetry",
                        operation = "send_heartbeat",
                        reason = %error,
                        retryable = true,
                        outcome = "reconnecting",
                        task_id = ?active_task_id,
                        attempt = backoff.failures(),
                        retry_after_ms = delay.as_millis() as u64,
                        "heartbeat failed; reconnecting"
                    );
                    if sleep_or_stop(delay).await {
                        break;
                    }
                }
            }
        }
    })
}

async fn wait_for_maintenance_exit(
    client: &HeartbeatClient,
    active_task: &ActiveTask,
    mut info: MaintenanceInfo,
) -> Result<bool, ScannerError> {
    renew_maintenance_hold(active_task, &info).await;
    loop {
        let delay = info.retry_delay();
        if sleep_or_stop(delay).await {
            return Ok(false);
        }
        match client.maintenance_status().await {
            Ok(next) if next.enabled => {
                renew_maintenance_hold(active_task, &next).await;
                tracing::info!(
                    maintenance_id = ?next.id,
                    phase = %next.phase,
                    message = %next.message,
                    started_at = ?next.started_at,
                    expected_end_at = ?next.expected_end_at,
                    revision = next.revision,
                    retry_delay_seconds = next.retry_delay().as_secs(),
                    "system maintenance is still active"
                );
                info = next;
            }
            Ok(next) => {
                renew_maintenance_hold(active_task, &next).await;
                return Ok(true);
            }
            Err(ScannerError::Server(ServerError::Maintenance { info: next, .. })) => {
                renew_maintenance_hold(active_task, &next).await;
                info = *next;
            }
            Err(error @ ScannerError::Server(ServerError::AuthRejected { .. }))
            | Err(error @ ScannerError::Server(ServerError::PolicyBlocked { .. })) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(
                    event = "MaintenanceProbeRetry",
                    operation = "poll_maintenance_status",
                    reason = %error,
                    retryable = true,
                    outcome = "maintenance_sleep_continued",
                    retry_after_ms = delay.as_millis() as u64,
                    "maintenance probe failed; remaining asleep"
                );
            }
        }
    }
}

async fn renew_maintenance_hold(active_task: &ActiveTask, info: &MaintenanceInfo) {
    if active_task.get().await.is_some() {
        let ttl_ms =
            u64::try_from(info.result_upload_grace_ttl().as_millis()).unwrap_or(86_400_000);
        active_task.renew_lease(ttl_ms).await;
    }
}

fn publish_connection_state(sender: &watch::Sender<ConnectionState>, state: ConnectionState) {
    if *sender.borrow() != state {
        tracing::info!(?state, "server connection state changed");
        let _ = sender.send(state);
    }
}

async fn wait_until_online(receiver: &mut watch::Receiver<ConnectionState>) -> bool {
    let mut shutdown = shutdown_receiver();
    loop {
        if stop_requested() {
            return false;
        }
        match *receiver.borrow() {
            ConnectionState::Online => return true,
            ConnectionState::AuthRejected | ConnectionState::PolicyBlocked => return false,
            ConnectionState::Connecting
            | ConnectionState::Reconnecting
            | ConnectionState::Maintenance => {}
        }
        tokio::select! {
            changed = receiver.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
            _ = shutdown.changed() => return false,
        }
    }
}

// ---- pipeline helpers ---------------------------------------------------

fn log_terminal_scanner_error(
    event: &'static str,
    operation: &'static str,
    error: &ScannerError,
    outcome: &'static str,
    task_id: Option<Uuid>,
) {
    match error {
        ScannerError::Server(source) => tracing::error!(
            event,
            operation = source.operation(),
            error_kind = source.kind(),
            error_code = source.code(),
            error_message = %source,
            retryable = false,
            outcome,
            task_id = ?task_id,
            http_status = ?source.status(),
            server_request_id = ?source.request_id(),
            "server operation failed"
        ),
        _ => tracing::error!(
            event,
            operation,
            error_kind = "scanner",
            error_code = "scanner_operation_failed",
            error_message = %error,
            retryable = false,
            outcome,
            task_id = ?task_id,
            "scanner operation failed"
        ),
    }
}

async fn flush(
    uploader: &Uploader,
    scanner_id: Uuid,
    cache: &mut CacheManager,
) -> Result<(), ScannerError> {
    if !cache.has_pending_task() {
        tracing::debug!("result flush skipped; no pending task");
        return Ok(());
    }

    let ranges = cache.upload_ranges(scanner_id)?;
    let first_batch = cache.batch_at(scanner_id, &ranges, cache.next_batch_index)?;
    if let Some(first) = first_batch.as_ref() {
        tracing::debug!(
            task_id = %first.task_id,
            upload_id = %first.upload_id,
            pending_batch_count = ranges.len().saturating_sub(cache.next_batch_index as usize),
            observation_count = cache.observations.len(),
            "flushing cached scan observations"
        );
    }
    let task_id = cache
        .task_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let upload_id = cache
        .upload_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let observation_count = cache.observations.len();
    let batch_count = ranges.len();
    while let Some(batch) = cache.batch_at(scanner_id, &ranges, cache.next_batch_index)? {
        uploader
            .upload(&batch)
            .await
            .map_err(|source| ScannerError::UploadBatch {
                context: UploadBatchContext {
                    scanner_id: batch.scanner_id,
                    task_id: batch.task_id,
                    upload_id: batch.upload_id,
                    batch_index: batch.batch_index,
                    is_final: batch.is_final,
                    protocol_version: batch.protocol_version,
                    observation_count: batch.observations.len(),
                },
                source: Box::new(source),
            })?;
        cache.mark_batch_uploaded(batch.batch_index)?;
    }
    tracing::info!(
        event = "ResultUploadCompleted",
        task_id = %task_id,
        upload_id = %upload_id,
        batch_count,
        observation_count,
        "all cached scan results uploaded"
    );
    if let (Some(store), Some(task_id)) = (&cache.store, cache.task_id) {
        store.clear_scan_failures(&cache.server_origin, task_id)?;
    }
    cache.clear()?;
    Ok(())
}

enum FlushAttempt {
    Completed(Result<(), ScannerError>),
    LeaseExpired(Uuid),
    Stopped,
}

async fn flush_with_guards(
    uploader: &Uploader,
    scanner_id: Uuid,
    cache: &mut CacheManager,
    active_task: &ActiveTask,
    lease_safety_margin: Duration,
) -> FlushAttempt {
    let Some(task_id) = active_task.get().await else {
        return FlushAttempt::Completed(flush(uploader, scanner_id, cache).await);
    };
    let mut shutdown = shutdown_receiver();
    tokio::select! {
        biased;
        _ = active_task.wait_for_lease_loss(task_id, lease_safety_margin) => FlushAttempt::LeaseExpired(task_id),
        _ = shutdown.changed() => FlushAttempt::Stopped,
        result = flush(uploader, scanner_id, cache) => FlushAttempt::Completed(result),
    }
}

// ---- scan loop ----------------------------------------------------------

struct ScanLoopConfig<'a> {
    module_registry: Option<modules::registry::Registry>,
    scanner_path: &'a str,
    task_url: &'a str,
    current_task_url: &'a str,
    server_client: &'a ServerHttpClient,
    scanner_id: Uuid,
    runtime_configuration: RuntimeConfiguration,
    retry_policy: RetryPolicy,
    lease_safety_margin: Duration,
}

async fn scan_loop(
    config: ScanLoopConfig<'_>,
    uploader: &Uploader,
    heartbeat_client: &HeartbeatClient,
    active_task: &ActiveTask,
    cache: &mut CacheManager,
    mut connection: watch::Receiver<ConnectionState>,
) {
    let mut fetch_backoff = Backoff::new(config.retry_policy);
    let mut upload_backoff = Backoff::new(config.retry_policy);
    let mut upload_identity_recoveries = 0u8;
    let mut module_task_id = cache.task_id;

    tracing::debug!(
        scanner_id = %config.scanner_id,
        task_url = %config.task_url,
        "scan loop started"
    );

    while !stop_requested() {
        if !cache.has_pending_task()
            && let Some(task_id) = module_task_id.take()
            && let Some(registry) = &config.module_registry
            && let Err(error) = registry.release(task_id)
        {
            tracing::error!(%error,"module pin release failed");
            request_stop();
            break;
        }
        apply_runtime_configuration(&config.runtime_configuration, cache).await;
        if cache.has_pending_task() {
            if !wait_until_online(&mut connection).await {
                break;
            }
            // A freshly restarted scanner has durable upload state but no
            // in-memory lease. Recover the exact server task before uploading
            // so another scanner cannot reclaim it during the retry window.
            if active_task.get().await.is_none() {
                let Some(cached_task_id) = cache.task_id else {
                    tracing::error!(
                        event = "PendingUploadIdentityMissing",
                        operation = "recover_pending_upload",
                        error_kind = "local_storage",
                        error_code = "pending_upload_task_id_missing",
                        error_message = "durable upload state has no task identity",
                        retryable = false,
                        outcome = "process_stopping",
                        upload_id = ?cache.upload_id,
                        next_batch_index = cache.next_batch_index,
                        observation_count = cache.observations.len(),
                        "pending upload is missing its task identity"
                    );
                    break;
                };
                let recovery_url = pending_upload_recovery_url(
                    config.current_task_url,
                    cached_task_id,
                    cache.upload_id,
                );
                match recover_task(config.server_client, &recovery_url).await {
                    Ok(FetchTaskOutcome::Task(task)) if task.task_id == cached_task_id => {
                        fetch_backoff.reset();
                        active_task.set(task.task_id, task.lease_ttl_ms).await;
                        tracing::info!(
                            event = "PendingUploadRecovered",
                            task_id = %task.task_id,
                            upload_id = ?cache.upload_id,
                            "recovered task lease for durable result upload"
                        );
                    }
                    Ok(FetchTaskOutcome::Task(task)) => {
                        tracing::error!(
                            event = "PendingUploadRecoveryMismatch",
                            operation = "recover_pending_upload",
                            error_kind = "protocol",
                            error_code = "recovered_task_identity_mismatch",
                            error_message = "server returned a different task during upload recovery",
                            retryable = false,
                            outcome = "process_stopping",
                            expected_task_id = %cached_task_id,
                            returned_task_id = %task.task_id,
                            upload_id = ?cache.upload_id,
                            next_batch_index = cache.next_batch_index,
                            "server returned the wrong task during upload recovery"
                        );
                        request_stop();
                        break;
                    }
                    Ok(FetchTaskOutcome::NoTask) => {
                        fetch_backoff.reset();
                        tracing::info!(
                            event = "PendingUploadReconcile",
                            task_id = %cached_task_id,
                            "server has no running lease for cached results; attempting idempotent upload"
                        );
                    }
                    Ok(FetchTaskOutcome::RecoveryRequired) => {
                        tracing::warn!(
                            event = "PendingUploadRecoveryRedirected",
                            operation = "recover_pending_upload",
                            reason = "server_requires_recovery",
                            outcome = "recovery_retried",
                            task_id = %cached_task_id,
                            upload_id = ?cache.upload_id,
                            "upload recovery was redirected; retrying recovery"
                        );
                        continue;
                    }
                    Err(ServerError::Maintenance { info, .. }) => {
                        tracing::warn!(
                            event = "PendingUploadRecoveryPaused",
                            operation = "recover_pending_upload",
                            reason = "system_maintenance",
                            outcome = "recovery_delayed",
                            task_id = %cached_task_id,
                            upload_id = ?cache.upload_id,
                            maintenance_id = ?info.id,
                            retry_after_ms = info.retry_delay().as_millis() as u64,
                            "pending upload recovery paused for maintenance"
                        );
                        if sleep_or_stop(info.retry_delay()).await {
                            break;
                        }
                        continue;
                    }
                    Err(error) if error.is_retryable() => {
                        let delay = fetch_backoff.next_delay(None, error.retry_after());
                        tracing::warn!(
                            event = "PendingUploadRecoveryRetry",
                            operation = error.operation(),
                            reason = %error,
                            error_kind = error.kind(),
                            error_code = error.code(),
                            retryable = true,
                            outcome = "recovery_pending",
                            http_status = ?error.status(),
                            server_request_id = ?error.request_id(),
                            task_id = %cached_task_id,
                            upload_id = ?cache.upload_id,
                            attempt = fetch_backoff.failures(),
                            retry_after_ms = delay.as_millis() as u64,
                            "pending upload recovery failed"
                        );
                        if sleep_or_stop(delay).await {
                            break;
                        }
                        continue;
                    }
                    Err(error) if stop_for_server_error(&error, Some(cached_task_id)) => break,
                    Err(error) => {
                        log_terminal_scanner_error(
                            "PendingUploadRecoveryFailed",
                            "recover_pending_upload",
                            &ScannerError::Server(error),
                            "process_stopping",
                            Some(cached_task_id),
                        );
                        request_stop();
                        break;
                    }
                }
            }
            if active_task.cancellation_reason() == Some(TaskCancellationReason::LeaseLost) {
                tracing::warn!(event = "ResultUploadRecoveryRequired", task_id = ?cache.task_id,
                    upload_id = ?cache.upload_id, next_batch_index = cache.next_batch_index,
                    "upload paused after lease loss; durable results retained");
                active_task.clear().await;
                continue;
            }
            match flush_with_guards(
                uploader,
                config.scanner_id,
                cache,
                active_task,
                config.lease_safety_margin,
            )
            .await
            {
                FlushAttempt::LeaseExpired(task_id) => {
                    if active_task.cancellation_reason() == Some(TaskCancellationReason::Shutdown) {
                        break;
                    }
                    if active_task.cancellation_reason()
                        == Some(TaskCancellationReason::ServerRequested)
                    {
                        let _ = heartbeat_client.report_cancelled(task_id).await;
                        if let Err(error) = cache.archive("server_cancelled_task") {
                            tracing::error!(%error, "failed to archive cancelled upload");
                            break;
                        }
                        active_task.clear().await;
                        continue;
                    }
                    active_task.request_lease_lost(task_id).await;
                    tracing::error!(
                        event = "ResultUploadLeaseDeadlineExceeded",
                        operation = "guard_result_upload_lease",
                        error_kind = "lease",
                        error_code = "upload_lease_safety_deadline_exceeded",
                        retryable = false,
                        outcome = "cached_results_retained",
                        %task_id,
                        upload_id = ?cache.upload_id,
                        next_batch_index = cache.next_batch_index,
                        observation_count = cache.observations.len(),
                        lease_safety_margin_ms = config.lease_safety_margin.as_millis() as u64,
                        "result upload stopped at the lease safety deadline"
                    );
                    active_task.clear().await;
                    continue;
                }
                FlushAttempt::Stopped => break,
                FlushAttempt::Completed(Ok(())) => {
                    upload_backoff.reset();
                    upload_identity_recoveries = 0;
                    active_task.clear().await;
                }
                FlushAttempt::Completed(Err(ScannerError::UploadBatch { context, source }))
                    if matches!(source.as_ref(), ServerError::Maintenance { .. }) =>
                {
                    let ServerError::Maintenance {
                        info, request_id, ..
                    } = source.as_ref()
                    else {
                        unreachable!("maintenance guard guarantees the error variant");
                    };
                    tracing::warn!(
                        event = "ResultBatchUploadPaused",
                        operation = "upload_results",
                        error_kind = "maintenance",
                        error_code = "server_maintenance",
                        retryable = true,
                        outcome = "batch_retained",
                        scanner_id = %context.scanner_id,
                        task_id = %context.task_id,
                        upload_id = %context.upload_id,
                        batch_index = context.batch_index,
                        is_final = context.is_final,
                        protocol_version = context.protocol_version,
                        observation_count = context.observation_count,
                        server_request_id = ?request_id,
                        maintenance_id = ?info.id,
                        phase = %info.phase,
                        reason = %info.message,
                        retry_after_ms = info.retry_delay().as_millis() as u64,
                        "result upload paused for maintenance; cached task retained"
                    );
                    if sleep_or_stop(info.retry_delay()).await {
                        break;
                    }
                    continue;
                }
                FlushAttempt::Completed(Err(ScannerError::UploadBatch { context, source }))
                    if source.is_retryable() =>
                {
                    let mut delay = upload_backoff.next_delay(None, source.retry_after());
                    if let Some(remaining) = active_task
                        .lease_safety_remaining(config.lease_safety_margin)
                        .await
                    {
                        delay = delay.min(remaining);
                    }
                    tracing::warn!(
                        event = "ResultBatchUploadRetry",
                        operation = source.operation(),
                        error_kind = source.kind(),
                        error_code = source.code(),
                        error_message = %source,
                        retryable = true,
                        outcome = "batch_retained",
                        scanner_id = %context.scanner_id,
                        task_id = %context.task_id,
                        upload_id = %context.upload_id,
                        batch_index = context.batch_index,
                        is_final = context.is_final,
                        protocol_version = context.protocol_version,
                        observation_count = context.observation_count,
                        http_status = ?source.status(),
                        server_request_id = ?source.request_id(),
                        attempt = upload_backoff.failures(),
                        retry_after_ms = delay.as_millis() as u64,
                        "upload failed; cached task retained"
                    );
                    if sleep_or_stop(delay).await {
                        break;
                    }
                    continue;
                }
                FlushAttempt::Completed(Err(ScannerError::UploadBatch { context, source }))
                    if matches!(source.as_ref(), ServerError::UploadIdentityConflict { .. })
                        && upload_identity_recoveries < 2 =>
                {
                    upload_identity_recoveries += 1;
                    tracing::warn!(
                        event = "ResultUploadExecutionRecovery",
                        operation = source.operation(),
                        error_kind = source.kind(),
                        error_code = source.code(),
                        error_message = %source,
                        retryable = true,
                        outcome = "execution_recovery_requested",
                        scanner_id = %context.scanner_id,
                        task_id = %context.task_id,
                        upload_id = %context.upload_id,
                        batch_index = context.batch_index,
                        server_request_id = ?source.request_id(),
                        attempt = upload_identity_recoveries,
                        "upload identity conflicted with a previous execution attempt; recovering a clean execution"
                    );
                    active_task.clear().await;
                    continue;
                }
                FlushAttempt::Completed(Err(ScannerError::UploadBatch { context, source }))
                    if is_stale_task_error(&source) =>
                {
                    tracing::error!(
                        event = "ResultBatchUploadRejected",
                        operation = source.operation(),
                        error_kind = source.kind(),
                        error_code = source.code(),
                        error_message = %source,
                        retryable = false,
                        outcome = "batch_archived",
                        scanner_id = %context.scanner_id,
                        task_id = %context.task_id,
                        upload_id = %context.upload_id,
                        batch_index = context.batch_index,
                        is_final = context.is_final,
                        protocol_version = context.protocol_version,
                        observation_count = context.observation_count,
                        http_status = ?source.status(),
                        server_request_id = ?source.request_id(),
                        "server no longer accepts this task; archiving cached results"
                    );
                    if let Err(clear_error) = cache.archive("server_rejected_upload") {
                        tracing::error!(
                            event = "RejectedResultCacheDiscardError",
                            operation = "clear_result_cache",
                            error_kind = "local_storage",
                            error_code = "result_cache_clear_failed",
                            error_message = %clear_error,
                            retryable = false,
                            outcome = "cached_results_retained",
                            scanner_id = %context.scanner_id,
                            task_id = %context.task_id,
                            upload_id = %context.upload_id,
                            batch_index = context.batch_index,
                            "failed to discard rejected cached results"
                        );
                        break;
                    }
                    active_task.clear().await;
                    continue;
                }
                FlushAttempt::Completed(Err(ScannerError::UploadBatch { context, source })) => {
                    tracing::error!(
                        event = "ResultBatchUploadFailed",
                        operation = source.operation(),
                        error_kind = source.kind(),
                        error_code = source.code(),
                        error_message = %source,
                        retryable = false,
                        outcome = "process_stopping",
                        scanner_id = %context.scanner_id,
                        task_id = %context.task_id,
                        upload_id = %context.upload_id,
                        batch_index = context.batch_index,
                        is_final = context.is_final,
                        protocol_version = context.protocol_version,
                        observation_count = context.observation_count,
                        http_status = ?source.status(),
                        server_request_id = ?source.request_id(),
                        "non-retryable upload failure; stopping"
                    );
                    request_stop();
                    break;
                }
                FlushAttempt::Completed(Err(error)) => {
                    tracing::error!(
                        event = "ResultCacheOperationFailed",
                        operation = "prepare_or_commit_result_cache",
                        error_kind = "local_storage",
                        error_code = "result_cache_operation_failed",
                        error_message = %error,
                        retryable = false,
                        outcome = "process_stopping",
                        task_id = ?cache.task_id,
                        upload_id = ?cache.upload_id,
                        next_batch_index = cache.next_batch_index,
                        observation_count = cache.observations.len(),
                        "non-retryable result cache failure; stopping"
                    );
                    request_stop();
                    break;
                }
            }
        }

        if !wait_until_online(&mut connection).await {
            break;
        }
        let recovery_url = match cache
            .store
            .as_ref()
            .map(|store| store.latest_scan_failure(&cache.server_origin))
            .transpose()
        {
            Ok(Some(Some((task_id, count)))) => format!(
                "{}&failure_taskid={task_id}&failure_count={count}",
                config.current_task_url
            ),
            Ok(_) => config.current_task_url.to_owned(),
            Err(error) => {
                tracing::error!(%error,"failed to load recovery failure report");
                break;
            }
        };
        let recovered_task = match recover_task(config.server_client, &recovery_url).await {
            Ok(FetchTaskOutcome::Task(task)) => {
                fetch_backoff.reset();
                tracing::info!(
                    event = "TaskRecovered",
                    task_id = %task.task_id,
                    lease_expires_at_ms = ?task.lease_expires_at_ms,
                    "recovered unfinished task before requesting new work"
                );
                Some(task)
            }
            Ok(FetchTaskOutcome::NoTask) => {
                fetch_backoff.reset();
                tracing::debug!(event = "RecoveryQueueDrained", "no unfinished task remains");
                None
            }
            Ok(FetchTaskOutcome::RecoveryRequired) => {
                tracing::warn!(
                    event = "TaskRecoveryRedirected",
                    operation = "recover_task",
                    reason = "server_requires_recovery",
                    outcome = "recovery_retried",
                    "task recovery requested another recovery pass"
                );
                continue;
            }
            Err(ServerError::Maintenance { info, .. }) => {
                tracing::warn!(
                    event = "TaskRecoveryPaused",
                    operation = "recover_task",
                    reason = "system_maintenance",
                    outcome = "recovery_delayed",
                    maintenance_id = ?info.id,
                    phase = %info.phase,
                    retry_after_ms = info.retry_delay().as_millis() as u64,
                    "task recovery paused for maintenance"
                );
                if sleep_or_stop(info.retry_delay()).await {
                    break;
                }
                continue;
            }
            Err(error) if error.is_retryable() => {
                let delay = fetch_backoff.next_delay(None, error.retry_after());
                tracing::warn!(
                    event = "TaskRecoveryRetry",
                    operation = error.operation(),
                    reason = %error,
                    error_kind = error.kind(),
                    error_code = error.code(),
                    retryable = true,
                    outcome = "recovery_pending",
                    http_status = ?error.status(),
                    server_request_id = ?error.request_id(),
                    attempt = fetch_backoff.failures(),
                    retry_after_ms = delay.as_millis() as u64,
                    "recover task failed"
                );
                if sleep_or_stop(delay).await {
                    break;
                }
                continue;
            }
            Err(error) if stop_for_server_error(&error, None) => break,
            Err(error) => {
                log_terminal_scanner_error(
                    "TaskRecoveryFailed",
                    "recover_task",
                    &ScannerError::Server(error),
                    "process_stopping",
                    None,
                );
                request_stop();
                break;
            }
        };

        let assigned_task = if let Some(task) = recovered_task {
            task
        } else {
            tracing::debug!(event = "NewTaskRequested", "requesting a new scan task");
            match fetch_task(config.server_client, config.task_url).await {
                Ok(FetchTaskOutcome::Task(task)) => {
                    fetch_backoff.reset();
                    tracing::debug!(
                        task_id = %task.task_id,
                        target_count = task.task_target.len(),
                        ports = %task.task_port,
                        lease_expires_at_ms = ?task.lease_expires_at_ms,
                        lease_ttl_ms = task.lease_ttl_ms,
                        "new scan task received"
                    );
                    task
                }
                Ok(FetchTaskOutcome::RecoveryRequired) => {
                    fetch_backoff.reset();
                    tracing::info!(
                        "server reported unfinished work during claim; returning to recovery"
                    );
                    continue;
                }
                Ok(FetchTaskOutcome::NoTask) => {
                    fetch_backoff.reset();
                    tracing::debug!(retry_delay_seconds = 5, "no scan task available");
                    if sleep_or_stop(Duration::from_secs(5)).await {
                        break;
                    }
                    continue;
                }
                Err(ServerError::Maintenance { info, .. }) => {
                    tracing::warn!(
                        event = "TaskAssignmentPaused",
                        operation = "fetch_task",
                        reason = "system_maintenance",
                        outcome = "task_claim_delayed",
                        maintenance_id = ?info.id,
                        phase = %info.phase,
                        retry_after_ms = info.retry_delay().as_millis() as u64,
                        "task assignment paused for maintenance"
                    );
                    if sleep_or_stop(info.retry_delay()).await {
                        break;
                    }
                    continue;
                }
                Err(error) if error.is_retryable() => {
                    let delay = fetch_backoff.next_delay(None, error.retry_after());
                    tracing::warn!(
                        event = "TaskFetchRetry",
                        operation = error.operation(),
                        reason = %error,
                        error_kind = error.kind(),
                        error_code = error.code(),
                        retryable = true,
                        outcome = "task_claim_pending",
                        http_status = ?error.status(),
                        server_request_id = ?error.request_id(),
                        attempt = fetch_backoff.failures(),
                        retry_after_ms = delay.as_millis() as u64,
                        "fetch task failed"
                    );
                    if sleep_or_stop(delay).await {
                        break;
                    }
                    continue;
                }
                Err(error) if stop_for_server_error(&error, None) => break,
                Err(error) => {
                    log_terminal_scanner_error(
                        "TaskRequestFailed",
                        "fetch_task",
                        &ScannerError::Server(error),
                        "process_stopping",
                        None,
                    );
                    request_stop();
                    break;
                }
            }
        };
        // A heartbeat may have staged a revision while this loop was waiting for
        // connectivity or task assignment. Apply it before the new task becomes
        // active so one task always runs against one immutable snapshot.
        apply_runtime_configuration(&config.runtime_configuration, cache).await;
        active_task
            .set(assigned_task.task_id, assigned_task.lease_ttl_ms)
            .await;
        if let Err(message) = assigned_task.validate_targets() {
            tracing::error!(
                event = "UnsafeScanTargetRejected",
                operation = "validate_scan_targets",
                error_kind = "validation",
                error_code = "unsafe_scan_target",
                error_message = %message,
                retryable = false,
                outcome = "task_failed",
                task_id = %assigned_task.task_id,
                "rejecting unsafe scan target"
            );
            if report_task_status_with_retry(
                heartbeat_client,
                active_task,
                assigned_task.task_id,
                TaskReport::TerminalFailure(&message),
                config.retry_policy,
                config.lease_safety_margin,
            )
            .await
            {
                active_task.clear().await;
            } else if stop_requested() {
                break;
            } else {
                active_task.clear().await;
            }
            continue;
        }
        if !heartbeat_client
            .can_scan(&assigned_task.address_family)
            .await
        {
            let message = format!(
                "{} network is no longer available on this scanner",
                assigned_task.address_family
            );
            tracing::warn!(
                event = "ScanTaskRejected",
                operation = "validate_task_network_capability",
                reason = "address_family_unavailable",
                outcome = "task_failure_reported",
                task_id = %assigned_task.task_id,
                address_family = %assigned_task.address_family,
                "rejecting incompatible scan task"
            );
            if report_task_status_with_retry(
                heartbeat_client,
                active_task,
                assigned_task.task_id,
                TaskReport::RouteFailure(&message),
                config.retry_policy,
                config.lease_safety_margin,
            )
            .await
            {
                active_task.clear().await;
            } else if stop_requested() {
                break;
            } else {
                active_task.clear().await;
            }
            continue;
        }
        tracing::debug!(task_id = %assigned_task.task_id, "task marked active");

        let latest_runtime = config.runtime_configuration.snapshot().await;
        let pinned = match config
            .module_registry
            .as_ref()
            .map(|registry| registry.bind(&assigned_task, latest_runtime.clone()))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to pin module task environment");
                request_stop();
                break;
            }
        };
        let runtime = pinned
            .as_ref()
            .map_or(latest_runtime, |value| value.runtime.clone());

        let target = TargetParams {
            ip: assigned_task.task_target.join(","),
            port: assigned_task.task_port.clone(),
            rate: runtime.rate,
            address_family: assigned_task.address_family.clone(),
        };
        let scan_plan = assigned_task
            .scan_plan
            .clone()
            .unwrap_or_else(|| ScanPlan::legacy(&runtime.service_detection));

        let mut scan_key = if let Some(environment) = &pinned {
            let bytes = serde_json::to_vec(&(
                assigned_task.task_id,
                &target,
                &scan_plan,
                &runtime,
                &assigned_task.dns_resolvers,
                environment,
            ))
            .expect("task environment serialization");
            format!(
                "{}|v2|{}",
                assigned_task.task_id,
                modules::package::digest(&bytes)
            )
        } else {
            format!(
                "{}|{}|{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
                assigned_task.task_id,
                target.ip,
                target.port,
                target.address_family,
                target.rate,
                scan_plan,
                runtime.service_detection,
                runtime.dns,
                runtime.nuclei,
                assigned_task.dns_resolvers
            )
        };
        if pinned.is_none() && runtime.masscan != Default::default() {
            scan_key.push_str(&format!("|{:?}", runtime.masscan));
        }
        let journal = match cache
            .store
            .as_ref()
            .map(|store| journal::ScanJournal::open(store, &cache.server_origin, scan_key))
            .transpose()
        {
            Ok(journal) => journal,
            Err(error) => {
                tracing::error!(%error, "failed to load scan checkpoint");
                break;
            }
        };
        let retry_state = cache
            .store
            .as_ref()
            .map(|store| store.scan_failures(&cache.server_origin, assigned_task.task_id))
            .transpose();
        let (failures, retry_at) = match retry_state {
            Ok(state) => state.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "failed to read scan retry state");
                break;
            }
        };
        if failures >= 3 {
            drop(journal);
            let reported = report_task_status_with_retry(
                heartbeat_client,
                active_task,
                assigned_task.task_id,
                TaskReport::TerminalFailure("scan recovery limit exceeded after three failures"),
                config.retry_policy,
                config.lease_safety_margin,
            )
            .await;
            active_task.clear().await;
            if reported {
                if let Some(store) = &cache.store
                    && let Err(error) = store.clear_checkpoint(&cache.server_origin)
                {
                    tracing::error!(%error, "failed to clear terminal checkpoint");
                    break;
                }
            } else if stop_requested() {
                break;
            }
            continue;
        }
        if retry_at > chrono::Utc::now().timestamp_millis()
            && sleep_or_stop(Duration::from_millis(
                (retry_at - chrono::Utc::now().timestamp_millis()).max(0) as u64,
            ))
            .await
        {
            break;
        }
        let scan_started_at = Instant::now();
        tracing::info!(
            event = "ScanTaskStarted",
            task_id = %assigned_task.task_id,
            scan_profile = %scan_plan.profile,
            stage_count = scan_plan.stages.len(),
            address_family = %target.address_family,
            targets = %target.ip,
            ports = %target.port,
            rate = target.rate,
            configuration_revision = runtime.revision,
            service_detection_enabled = runtime.service_detection.enabled,
            "scan task started"
        );

        let cancel_flag = active_task.cancellation_flag();
        let ipv4_ready = heartbeat_client.can_scan("ipv4").await;
        let ipv6_ready = heartbeat_client.can_scan("ipv6").await;
        let scan_span = tracing::info_span!(
            "scan_task",
            task_id = %assigned_task.task_id,
            scan_profile = %scan_plan.profile,
            address_family = %target.address_family,
        );
        let (results, dns_results) = match run_scan(
            ScanRuntimeConfig {
                environment: pinned.as_ref().map(|value| &value.environment),
                modules_config: config
                    .module_registry
                    .as_ref()
                    .map(|registry| &registry.config),
                registry: config.module_registry.as_ref(),
                journal,
                scanner_path: config.scanner_path,
                masscan: &runtime.masscan,
                service_detection: &runtime.service_detection,
                dns: &runtime.dns,
                nuclei: &runtime.nuclei,
                dns_resolvers: &assigned_task.dns_resolvers,
                ipv4_ready,
                ipv6_ready,
            },
            &scan_plan,
            &target,
            &cancel_flag,
        )
        .instrument(scan_span)
        .await
        {
            Ok(ScanOutcome::Completed(results, dns_results)) => (results, dns_results),
            Ok(ScanOutcome::Cancelled) => match active_task.cancellation_reason() {
                Some(TaskCancellationReason::ServerRequested) => {
                    let reported = report_task_status_with_retry(
                        heartbeat_client,
                        active_task,
                        assigned_task.task_id,
                        TaskReport::Cancelled,
                        config.retry_policy,
                        config.lease_safety_margin,
                    )
                    .await;
                    if reported {
                        tracing::info!(
                            event = "ScanTaskCancelled",
                            task_id = %assigned_task.task_id,
                            reason = "server_requested",
                            elapsed_ms = scan_started_at.elapsed().as_millis(),
                            "scan task cancelled"
                        );
                    }
                    active_task.clear().await;
                    if stop_requested() {
                        return;
                    }
                    continue;
                }
                Some(TaskCancellationReason::LeaseLost) => {
                    if let Some(store) = &cache.store
                        && let Err(error) =
                            store.record_scan_failure(&cache.server_origin, assigned_task.task_id)
                    {
                        tracing::error!(%error, "failed to persist scan failure");
                        break;
                    }
                    tracing::error!(
                        event = "ScanTaskLeaseLost",
                        operation = "monitor_task_lease",
                        error_kind = "lease",
                        error_code = "task_lease_lost",
                        error_message = "scan stopped because its lease was lost",
                        retryable = false,
                        outcome = "task_aborted",
                        task_id = %assigned_task.task_id,
                        elapsed_ms = scan_started_at.elapsed().as_millis(),
                        "scan stopped because its lease was lost"
                    );
                    active_task.clear().await;
                    continue;
                }
                Some(TaskCancellationReason::Shutdown) | None => return,
            },
            Err(e) => {
                if let Some(store) = &cache.store
                    && let Err(error) =
                        store.record_scan_failure(&cache.server_origin, assigned_task.task_id)
                {
                    tracing::error!(%error, "failed to persist scan failure");
                    break;
                }
                let diagnostics = e.scan_diagnostics();
                tracing::error!(
                    event = "ScanTaskFailed",
                    operation = "execute_scan_plan",
                    error_kind = diagnostics.error_kind,
                    error_code = diagnostics.error_code,
                    error_message = %e,
                    retryable = false,
                    outcome = "task_failed",
                    engine = ?diagnostics.engine,
                    stage = ?diagnostics.stage,
                    process_id = ?diagnostics.process_id,
                    exit_code = ?diagnostics.exit_code,
                    process_elapsed_ms = ?diagnostics.elapsed_ms,
                    result_count = ?diagnostics.result_count,
                    invalid_line_count = ?diagnostics.invalid_line_count,
                    stderr_bytes = ?diagnostics.stderr_bytes,
                    stderr_truncated = ?diagnostics.stderr_truncated,
                    task_id = %assigned_task.task_id,
                    scan_profile = %scan_plan.profile,
                    address_family = %target.address_family,
                    elapsed_ms = scan_started_at.elapsed().as_millis(),
                    "scan task failed"
                );
                let error_message = e.to_string();
                if report_task_status_with_retry(
                    heartbeat_client,
                    active_task,
                    assigned_task.task_id,
                    if e.is_route_failure() {
                        TaskReport::RouteFailure(&error_message)
                    } else {
                        TaskReport::Failure(&error_message)
                    },
                    config.retry_policy,
                    config.lease_safety_margin,
                )
                .await
                {
                    active_task.clear().await;
                    continue;
                }
                if stop_requested() {
                    break;
                }
                active_task.clear().await;
                continue;
            }
        };

        let port_count = results
            .iter()
            .filter(|item| matches!(item, ScanObservation::Port(_)))
            .count();
        let service_observation_count = results.len().saturating_sub(port_count);
        let service_count = results
            .iter()
            .filter(|item| {
                matches!(item, ScanObservation::Service(service) if service.service.is_some())
            })
            .count();
        tracing::info!(
            event = "ScanTaskCompleted",
            task_id = %assigned_task.task_id,
            scan_profile = %scan_plan.profile,
            elapsed_ms = scan_started_at.elapsed().as_millis(),
            observation_count = results.len(),
            port_count,
            service_observation_count,
            service_count,
            "scan task completed"
        );

        if active_task.cancellation_reason().is_none()
            && !active_task
                .lease_safety_expired(config.lease_safety_margin + Duration::from_secs(3))
                .await
        {
            let performance = performance::collect(
                &results,
                &target,
                scan_started_at.elapsed().as_millis().min(604800000) as u64,
                &dns_results,
            )
            .await;
            if active_task.cancellation_reason().is_none() {
                heartbeat_client
                    .report_performance(assigned_task.task_id, &performance)
                    .await;
            }
        }
        if let Err(error) = cache.begin_task_with_observations(assigned_task.task_id, &results) {
            tracing::error!(
                event = "ResultCacheBindFailed",
                operation = "cache_task_results",
                error_kind = "local_storage",
                error_code = "result_cache_bind_failed",
                error_message = %error,
                retryable = false,
                outcome = "process_stopping",
                task_id = %assigned_task.task_id,
                upload_id = ?cache.upload_id,
                observation_count = results.len(),
                "failed to bind results to task"
            );
            break;
        }
        module_task_id = Some(assigned_task.task_id);
        if let Some(store) = &cache.store
            && let Err(error) = store.clear_checkpoint(&cache.server_origin)
        {
            tracing::error!(%error, "failed to clear completed checkpoint");
            break;
        }
        match active_task.cancellation_reason() {
            Some(TaskCancellationReason::LeaseLost) => {
                tracing::error!(
                    event = "CompletedResultsRetainedAfterLeaseLoss",
                    operation = "validate_task_lease",
                    error_kind = "lease",
                    error_code = "task_lease_lost",
                    error_message = "completed results cannot be uploaded after lease loss",
                    retryable = false,
                    outcome = "results_retained",
                    task_id = %assigned_task.task_id,
                    observation_count = results.len(),
                    "retaining completed results for lease recovery"
                );
                active_task.clear().await;
                continue;
            }
            Some(TaskCancellationReason::Shutdown) => return,
            Some(TaskCancellationReason::ServerRequested) => {
                let _ = report_task_status_with_retry(
                    heartbeat_client,
                    active_task,
                    assigned_task.task_id,
                    TaskReport::Cancelled,
                    config.retry_policy,
                    config.lease_safety_margin,
                )
                .await;
                if let Err(error) = cache.archive("server_cancelled_task") {
                    tracing::error!(%error, "failed to archive cancelled results");
                    break;
                }
                active_task.clear().await;
                continue;
            }
            None => {}
        }

        tracing::debug!(
            task_id = %assigned_task.task_id,
            result_count = results.len(),
            "scan execution completed"
        );

        if stop_requested() {
            return;
        }

        tracing::debug!(
            task_id = %assigned_task.task_id,
            cached_result_count = results.len(),
            "scan results cached"
        );
    }

    tracing::debug!(stop_requested = stop_requested(), "scan loop exiting");

    tracing::info!(
        event = "ScanLoopStopped",
        pending = cache.has_pending_task(),
        "scan loop stopped; durable state retained"
    );
}

fn pending_upload_recovery_url(
    current_task_url: &str,
    task_id: Uuid,
    upload_id: Option<Uuid>,
) -> String {
    match upload_id {
        Some(upload_id) => {
            format!("{current_task_url}&taskid={task_id}&uploadid={upload_id}")
        }
        None => format!("{current_task_url}&taskid={task_id}"),
    }
}

#[cfg(test)]
mod recovery_url_tests {
    use super::pending_upload_recovery_url;
    use uuid::Uuid;

    #[test]
    fn durable_upload_recovery_includes_both_identities() {
        let task_id = Uuid::parse_str("019c0000-0000-7000-8000-000000000001").unwrap();
        let upload_id = Uuid::parse_str("019c0000-0000-7000-8000-000000000002").unwrap();

        assert_eq!(
            pending_upload_recovery_url(
                "https://scanner.example/api/task/current?scannerid=scanner",
                task_id,
                Some(upload_id),
            ),
            "https://scanner.example/api/task/current?scannerid=scanner&taskid=019c0000-0000-7000-8000-000000000001&uploadid=019c0000-0000-7000-8000-000000000002"
        );
    }
}

async fn apply_runtime_configuration(
    runtime_configuration: &RuntimeConfiguration,
    cache: &CacheManager,
) {
    match runtime_configuration.apply_pending().await {
        Ok(Some(configuration)) => {
            if let Err(error) = cache.save_runtime_configuration(&configuration) {
                tracing::warn!(
                    event = "RuntimeConfigurationCacheFailed",
                    operation = "cache_runtime_configuration",
                    reason = %error,
                    outcome = "runtime_configuration_active_memory_only",
                    revision = configuration.revision,
                    "runtime configuration applied but could not be cached"
                );
            }
            tracing::info!(
                revision = configuration.revision,
                "runtime configuration applied at task boundary"
            );
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            event = "RuntimeConfigurationRejected",
            operation = "apply_runtime_configuration",
            reason = %error,
            outcome = "previous_configuration_retained",
            "rejected staged runtime configuration"
        ),
    }
}

#[derive(Clone, Copy)]
enum TaskReport<'a> {
    Failure(&'a str),
    RouteFailure(&'a str),
    TerminalFailure(&'a str),
    Cancelled,
}

async fn report_task_status_with_retry(
    client: &HeartbeatClient,
    active_task: &ActiveTask,
    task_id: Uuid,
    report: TaskReport<'_>,
    retry_policy: RetryPolicy,
    lease_safety_margin: Duration,
) -> bool {
    let mut backoff = Backoff::new(retry_policy);
    loop {
        if stop_requested()
            || active_task.cancellation_reason() == Some(TaskCancellationReason::LeaseLost)
        {
            return false;
        }
        let remaining = active_task
            .lease_safety_remaining(lease_safety_margin)
            .await
            .unwrap_or_default();
        if remaining.is_zero() {
            active_task.request_lease_lost(task_id).await;
            return false;
        }
        let report_future = async {
            match report {
                TaskReport::Failure(message) => client.report_failure(task_id, message).await,
                TaskReport::RouteFailure(message) => {
                    client.report_route_failure(task_id, message).await
                }
                TaskReport::TerminalFailure(message) => {
                    client.report_terminal_failure(task_id, message).await
                }
                TaskReport::Cancelled => client.report_cancelled(task_id).await,
            }
        };
        let mut shutdown = shutdown_receiver();
        let result = tokio::select! {
            result = report_future => result,
            _ = sleep(remaining) => {
                active_task.request_lease_lost(task_id).await;
                return false;
            }
            _ = shutdown.changed() => return false,
        };
        match result {
            Ok(()) => return true,
            Err(ScannerError::Server(ServerError::Maintenance { info, .. })) => {
                renew_maintenance_hold(active_task, &info).await;
                tracing::warn!(
                    event = "TaskStatusReportPaused",
                    operation = "report_task_status",
                    reason = "system_maintenance",
                    outcome = "task_status_pending",
                    task_id = %task_id,
                    maintenance_id = ?info.id,
                    retry_after_ms = info.retry_delay().as_millis() as u64,
                    "task status report paused for maintenance"
                );
                if sleep_or_stop(info.retry_delay()).await {
                    return false;
                }
            }
            Err(ScannerError::Server(error)) if error.is_retryable() => {
                if active_task.lease_safety_expired(lease_safety_margin).await {
                    active_task.request_lease_lost(task_id).await;
                    return false;
                }
                let mut delay = backoff.next_delay(None, error.retry_after());
                if let Some(remaining) = active_task
                    .lease_safety_remaining(lease_safety_margin)
                    .await
                {
                    delay = delay.min(remaining);
                }
                tracing::warn!(
                    event = "TaskStatusReportRetry",
                    operation = error.operation(),
                    reason = %error,
                    error_kind = error.kind(),
                    error_code = error.code(),
                    retryable = true,
                    outcome = "task_status_pending",
                    http_status = ?error.status(),
                    server_request_id = ?error.request_id(),
                    task_id = %task_id,
                    attempt = backoff.failures(),
                    retry_after_ms = delay.as_millis() as u64,
                    "task status report failed; retrying"
                );
                if sleep_or_stop(delay).await {
                    return false;
                }
            }
            Err(ScannerError::Server(error)) if is_stale_task_error(&error) => {
                active_task.request_lease_lost(task_id).await;
                return false;
            }
            Err(ScannerError::Server(error)) if stop_for_server_error(&error, Some(task_id)) => {
                return false;
            }
            Err(error) => {
                log_terminal_scanner_error(
                    "TaskStatusReportFailed",
                    "report_task_status",
                    &error,
                    "process_stopping",
                    Some(task_id),
                );
                request_stop();
                return false;
            }
        }
    }
}

fn is_stale_task_error(error: &ServerError) -> bool {
    matches!(
        error.status(),
        Some(reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::CONFLICT)
    )
}

fn stop_for_server_error(error: &ServerError, task_id: Option<Uuid>) -> bool {
    match error {
        ServerError::AuthRejected { .. } => {
            tracing::error!(
                event = "ServerAuthenticationRejected",
                operation = error.operation(),
                error_kind = error.kind(),
                error_code = error.code(),
                error_message = %error,
                retryable = false,
                outcome = "process_stopping",
                task_id = ?task_id,
                http_status = ?error.status(),
                server_request_id = ?error.request_id(),
                "runtime token rejected; register the scanner again"
            );
            request_stop();
            true
        }
        ServerError::PolicyBlocked { .. } => {
            tracing::error!(
                event = "ServerPolicyBlocked",
                operation = error.operation(),
                error_kind = error.kind(),
                error_code = error.code(),
                error_message = %error,
                retryable = false,
                outcome = "process_stopping",
                task_id = ?task_id,
                http_status = ?error.status(),
                server_request_id = ?error.request_id(),
                "request blocked by server policy"
            );
            request_stop();
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod cli_command_tests {
    use clap::Parser;

    use super::{CacheCommand, Cli, ScannerCommand};

    #[test]
    fn no_subcommand_keeps_scan_loop_mode() {
        assert!(
            Cli::try_parse_from(["scanner-rs"])
                .unwrap()
                .command
                .is_none()
        );
    }

    #[test]
    fn parses_cache_clear_safety_options() {
        let cli = Cli::try_parse_from([
            "scanner-rs",
            "cache",
            "clear",
            "--all-origins",
            "--include-runtime-config",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(ScannerCommand::Cache {
                command: CacheCommand::Clear {
                    all_origins: true,
                    include_runtime_config: true,
                    yes: true,
                    ..
                }
            })
        ));
    }
}

#[cfg(test)]
mod upload_recovery_tests {
    use super::*;
    use std::io::{Read, Write};

    fn fixture(
        delays: Vec<Option<std::time::Duration>>,
    ) -> (String, std::thread::JoinHandle<Vec<serde_json::Value>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let mut payloads = Vec::new();
            for delay in delays {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                let mut buffer = [0; 8192];
                let (start, length) = loop {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                    if let Some(pos) = data.windows(4).position(|b| b == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&data[..pos]);
                        let length = header
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")?
                                    .trim()
                                    .parse::<usize>()
                                    .ok()
                            })
                            .unwrap();
                        break (pos + 4, length);
                    }
                };
                while data.len() < start + length {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                }
                payloads.push(serde_json::from_slice(&data[start..start + length]).unwrap());
                if let Some(delay) = delay {
                    std::thread::sleep(delay);
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                }
            }
            payloads
        });
        (url, thread)
    }

    fn uploader(url: String) -> Uploader {
        Uploader::new(
            url,
            ServerHttpClient::new(
                true,
                "fixture-token".into(),
                Duration::from_secs(1),
                Duration::from_secs(5),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn missing_ack_retries_identical_final_batch_without_clearing_cache() {
        let (url, thread) = fixture(vec![None, Some(std::time::Duration::ZERO)]);
        let uploader = uploader(url);
        let scanner = Uuid::now_v7();
        let mut cache = CacheManager::default();
        cache
            .begin_task_with_observations(Uuid::now_v7(), &[])
            .unwrap();
        let upload = cache.upload_id;
        assert!(flush(&uploader, scanner, &mut cache).await.is_err());
        assert_eq!(cache.next_batch_index, 0);
        assert_eq!(cache.upload_id, upload);
        flush(&uploader, scanner, &mut cache).await.unwrap();
        assert!(!cache.has_pending_task());
        let payloads = thread.join().unwrap();
        assert_eq!(payloads[0], payloads[1]);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_lease_never_starts_upload_or_discards_cache() {
        SHUTDOWN.get_or_init(|| watch::channel(false).0);
        let uploader = uploader("http://127.0.0.1:1".into());
        let scanner = Uuid::now_v7();
        let task = Uuid::now_v7();
        let mut cache = CacheManager::default();
        cache.begin_task_with_observations(task, &[]).unwrap();
        let upload = cache.upload_id;
        let active = ActiveTask::default();
        active.set(task, 90_000).await;
        tokio::time::advance(Duration::from_secs(81)).await;
        assert!(
            matches!(flush_with_guards(&uploader,scanner,&mut cache,&active,Duration::from_secs(10)).await,FlushAttempt::LeaseExpired(id) if id==task)
        );
        assert_eq!(cache.task_id, Some(task));
        assert_eq!(cache.upload_id, upload);
        assert_eq!(cache.next_batch_index, 0);
    }

    #[tokio::test]
    async fn slow_upload_completes_after_lease_renewal() {
        SHUTDOWN.get_or_init(|| watch::channel(false).0);
        let (url, thread) = fixture(vec![Some(std::time::Duration::from_millis(250))]);
        let uploader = uploader(url);
        let scanner = Uuid::now_v7();
        let task = Uuid::now_v7();
        let mut cache = CacheManager::default();
        cache.begin_task_with_observations(task, &[]).unwrap();
        let active = ActiveTask::default();
        active.set(task, 150).await;
        let renewer = active.clone();
        let renew = tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            renewer.renew_lease(1000).await;
        });
        assert!(matches!(
            flush_with_guards(
                &uploader,
                scanner,
                &mut cache,
                &active,
                Duration::from_millis(10)
            )
            .await,
            FlushAttempt::Completed(Ok(()))
        ));
        assert!(!cache.has_pending_task());
        renew.await.unwrap();
        thread.join().unwrap();
    }
}

pub use modules::package::package_main;
pub use modules::worker::worker_main;

async fn execute_module_command(
    command: &ModuleCommand,
    config: &modules::ModulesConfig,
    origin: &str,
) -> Result<(), ScannerError> {
    if !config.enabled {
        return Err(ScannerError::Config("modules.enabled must be true".into()));
    }
    if matches!(command, ModuleCommand::Status) {
        let path = config.directory.join("status.json");
        if path.exists() {
            println!(
                "{}",
                String::from_utf8_lossy(&modules::package::read_limited(&path, 2 * 1024 * 1024)?)
            );
        } else {
            let registry = modules::registry::Registry::open_store(config.clone(), origin.into())?;
            println!("{}", serde_json::to_string_pretty(&registry.report())?);
        }
        return Ok(());
    }
    let request = match command {
        ModuleCommand::Apply { bundle } => modules::registry::UpdateCommand::Apply {
            bundle: modules::update::bundle_path(bundle.clone())?,
        },
        ModuleCommand::Rollback { generation } => modules::registry::UpdateCommand::Rollback {
            generation: *generation,
        },
        ModuleCommand::Gc => modules::registry::UpdateCommand::Gc,
        ModuleCommand::Status => unreachable!(),
    };
    // The same command is always submitted to the agent-owned inbox; maintenance
    // clients never modify its live database or acquire a competing lease.
    let id = modules::update::submit(&config.directory, request)?;
    println!(
        "module update queued: {id}; inspect {}/requests/{id}.result",
        config.directory.display()
    );
    Ok(())
}
