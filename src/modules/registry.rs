use super::{
    ModulesConfig, host,
    package::{self, BundleFile, BundleModule, Manifest, Signature},
};
use crate::{
    error::ScannerError,
    file_lock::ExclusiveFileLock,
    runtime_config::RuntimeSnapshot,
    scan::plan::ScanStageKind,
    types::{AppConfig, AssignedTask},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ModuleSpec {
    pub(crate) worker_path: PathBuf,
    pub(crate) engine_path: Option<PathBuf>,
    pub(crate) templates_path: Option<PathBuf>,
    pub(crate) artifact: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Environment {
    pub(crate) generation: i64,
    pub(crate) revision: i64,
    pub(crate) release_id: String,
    pub(crate) modules: BTreeMap<String, ModuleSpec>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TaskEnvironment {
    pub(crate) environment: Environment,
    pub(crate) runtime: RuntimeSnapshot,
    pub(crate) task_digest: String,
}
#[derive(Clone)]
pub(crate) struct Registry {
    state: Arc<Mutex<Store>>,
    pub(crate) config: ModulesConfig,
    scope: String,
}
struct Store {
    // Fields drop in declaration order: close SQLite before releasing ownership.
    db: Connection,
    _lock: ExclusiveFileLock,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum UpdateCommand {
    Apply { bundle: PathBuf },
    Rollback { generation: i64 },
    Gc,
}

impl Registry {
    pub(crate) async fn open(
        config: ModulesConfig,
        local: &AppConfig,
        scope: String,
    ) -> Result<Self, ScannerError> {
        let registry = Self::open_store(config, scope)?;
        if registry.active()?.is_none() {
            let manifest = bootstrap_manifest(local, &registry.config)?;
            let temporary = registry
                .config
                .directory
                .join(format!("bootstrap-{}", Uuid::now_v7()));
            fs::create_dir_all(&temporary)?;
            let result = (|| {
                let sources = bootstrap_sources(local, &registry.config)?;
                for file in &manifest.files {
                    package::copy_regular(
                        sources.get(&file.path).unwrap(),
                        &temporary.join(&file.path),
                        file,
                    )?;
                }
                fs::write(
                    temporary.join("manifest.json"),
                    serde_json::to_vec(&manifest)?,
                )?;
                Ok::<_, ScannerError>(())
            })();
            if let Err(e) = result {
                let _ = fs::remove_dir_all(&temporary);
                return Err(e);
            }
            let prepared = registry.prepare(&temporary, false).await;
            let _ = fs::remove_dir_all(&temporary);
            registry.commit(prepared?, None)?;
        }
        Ok(registry)
    }

    pub(crate) fn open_store(config: ModulesConfig, scope: String) -> Result<Self, ScannerError> {
        if config.cancel_grace_seconds == 0
            || config.cancel_grace_seconds > 60
            || config.stage_timeout_seconds == 0
            || config.stage_timeout_seconds > 86400
        {
            return Err(ScannerError::Config(
                "invalid module execution timeouts".into(),
            ));
        }
        fs::create_dir_all(&config.directory)?;
        if let Some(parent) = config
            .state_database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let lock_path = config.state_database.with_extension("sqlite3.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        let lock = ExclusiveFileLock::acquire(lock).map_err(|_| {
            ScannerError::Config("module store is in use by the running agent".into())
        })?;
        let db = Connection::open(&config.state_database)?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.busy_timeout(Duration::from_secs(5))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > 1 {
            return Err(ScannerError::Config(
                "unsupported module database schema".into(),
            ));
        }
        db.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS environment(scope TEXT NOT NULL,generation INTEGER NOT NULL,revision INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(scope,generation));
            CREATE TABLE IF NOT EXISTS active_environment(scope TEXT PRIMARY KEY,generation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS task_environment(scope TEXT NOT NULL,task_id TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(scope,task_id));
            CREATE TABLE IF NOT EXISTS deployment(scope TEXT NOT NULL,id TEXT NOT NULL,state TEXT NOT NULL,error TEXT,created_at INTEGER NOT NULL,PRIMARY KEY(scope,id));
            CREATE TABLE IF NOT EXISTS worker_health(scope TEXT NOT NULL,generation INTEGER NOT NULL,stage TEXT NOT NULL,consecutive_failures INTEGER NOT NULL,PRIMARY KEY(scope,generation,stage));
            PRAGMA user_version=1;COMMIT;")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&config.state_database, &lock_path] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut config = config;
        config.directory = config.directory.canonicalize()?;
        Ok(Self {
            state: Arc::new(Mutex::new(Store { db, _lock: lock })),
            config,
            scope,
        })
    }

    pub(crate) fn active(&self) -> Result<Option<Environment>, ScannerError> {
        let store = self.state.lock().unwrap();
        let data:Option<Vec<u8>>=store.db.query_row("SELECT e.payload FROM environment e JOIN active_environment a ON a.scope=e.scope AND a.generation=e.generation WHERE e.scope=?1",[&self.scope],|row|row.get(0)).optional()?;
        data.map(|v| serde_json::from_slice(&v).map_err(Into::into))
            .transpose()
    }

    async fn prepare(
        &self,
        bundle: &Path,
        signed: bool,
    ) -> Result<(Manifest, BTreeMap<String, ModuleSpec>), ScannerError> {
        let registry = self.clone();
        let bundle = bundle.to_path_buf();
        let (manifest, specs) =
            tokio::task::spawn_blocking(move || registry.prepare_files(&bundle, signed))
                .await
                .map_err(|e| ScannerError::Scan(format!("module preparation failed: {e}")))??;
        for (stage, spec) in &specs {
            let stage: ScanStageKind =
                serde_json::from_value(serde_json::Value::String(stage.clone()))?;
            host::preflight(&spec.worker_path, stage).await?;
        }
        Ok((manifest, specs))
    }

    fn prepare_files(
        &self,
        bundle: &Path,
        signed: bool,
    ) -> Result<(Manifest, BTreeMap<String, ModuleSpec>), ScannerError> {
        let bundle = bundle.canonicalize()?;
        let raw =
            package::read_limited(&bundle.join("manifest.json"), package::MAX_MANIFEST as u64)?;
        let manifest = if signed {
            let signature: Signature = serde_json::from_slice(&package::read_limited(
                &bundle.join("manifest.sig"),
                4096,
            )?)?;
            package::verify(&raw, &signature, &self.config.trusted_keys)?
        } else {
            let m = serde_json::from_slice(&raw)?;
            package::validate(&m)?;
            m
        };
        let artifact = package::digest(&raw);
        let destination = self.config.directory.join(&artifact);
        let staging = self
            .config
            .directory
            .join(format!("staging-{}", Uuid::now_v7()));
        fs::create_dir(&staging)?;
        let result = (|| {
            for file in &manifest.files {
                let relative = package::relative(&file.path)?;
                let mut current = bundle.clone();
                for component in relative.components() {
                    current.push(component);
                    if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                        return Err(ScannerError::Config("bundle contains symlink".into()));
                    }
                }
                package::copy_regular(&current, &staging.join(relative), file)?;
            }
            let mut manifest_file = File::create(staging.join("manifest.json"))?;
            use std::io::Write;
            manifest_file.write_all(&raw)?;
            manifest_file.sync_all()?;
            if signed {
                let signature = package::read_limited(&bundle.join("manifest.sig"), 4096)?;
                let mut file = File::create(staging.join("manifest.sig"))?;
                file.write_all(&signature)?;
                file.sync_all()?;
            }
            sync_tree(&staging)?;
            if destination.exists() {
                self.verify_artifact(&destination, &artifact)?;
                fs::remove_dir_all(&staging)?;
            } else {
                fs::rename(&staging, &destination)?;
                File::open(&self.config.directory)?.sync_all()?;
            }
            Ok::<_, ScannerError>(())
        })();
        if let Err(e) = result {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        let specs = package::specs(&manifest, &destination, &artifact);
        for (stage, spec) in &specs {
            let stage: ScanStageKind =
                serde_json::from_value(serde_json::Value::String(stage.clone()))?;
            if let Some(path) = &spec.engine_path {
                match stage {
                    ScanStageKind::PortDiscovery => {
                        crate::scan::validate_scanner_binary(path.to_str().unwrap())?
                    }
                    ScanStageKind::ServiceDetection => {
                        crate::scan::validate_zgrab_binary(path.to_str().unwrap())?
                    }
                    ScanStageKind::VulnerabilityDetection => {
                        crate::scan::validate_nuclei_binary(path.to_str().unwrap())?
                    }
                    ScanStageKind::DnsLookup => {}
                }
            }
        }
        Ok((manifest, specs))
    }

    fn verify_artifact(&self, path: &Path, artifact: &str) -> Result<(), ScannerError> {
        let raw = package::read_limited(&path.join("manifest.json"), package::MAX_MANIFEST as u64)?;
        if package::digest(&raw) != artifact {
            return Err(ScannerError::Config("artifact manifest changed".into()));
        }
        let manifest: Manifest = serde_json::from_slice(&raw)?;
        package::validate(&manifest)?;
        if path.join("manifest.sig").exists() {
            let signature: Signature =
                serde_json::from_slice(&package::read_limited(&path.join("manifest.sig"), 4096)?)?;
            package::verify(&raw, &signature, &self.config.trusted_keys)?;
        }
        for file in &manifest.files {
            let item = path.join(package::relative(&file.path)?);
            if !fs::symlink_metadata(&item)?.file_type().is_file()
                || fs::metadata(&item)?.len() != file.size
                || package::hash_file(&item)? != file.sha256
            {
                return Err(ScannerError::Config("installed artifact changed".into()));
            }
        }
        Ok(())
    }

    fn commit(
        &self,
        prepared: (Manifest, BTreeMap<String, ModuleSpec>),
        expected: Option<i64>,
    ) -> Result<Environment, ScannerError> {
        let (manifest, specs) = prepared;
        let mut store = self.state.lock().unwrap();
        let tx = store.db.transaction()?;
        let current:Option<(i64,Vec<u8>)>=tx.query_row("SELECT e.generation,e.payload FROM environment e JOIN active_environment a ON a.scope=e.scope AND a.generation=e.generation WHERE e.scope=?1",[&self.scope],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if current.as_ref().map(|v| v.0) != expected {
            return Err(ScannerError::Config(
                "environment changed during preflight".into(),
            ));
        }
        let previous = current
            .as_ref()
            .map(|(_, v)| serde_json::from_slice::<Environment>(v))
            .transpose()?;
        if let Some(previous) = &previous
            && previous.revision == manifest.revision
            && previous.release_id == manifest.release_id
            && specs
                .iter()
                .all(|(stage, spec)| previous.modules.get(stage) == Some(spec))
        {
            return Ok(previous.clone());
        }
        if previous
            .as_ref()
            .is_some_and(|e| manifest.revision <= e.revision)
        {
            return Err(ScannerError::Config(
                "release revision must increase (use rollback for historical versions)".into(),
            ));
        }
        let mut modules = previous.map_or_else(BTreeMap::new, |e| e.modules);
        modules.extend(specs);
        let generation: i64 = tx.query_row(
            "SELECT COALESCE(MAX(generation),0)+1 FROM environment WHERE scope=?1",
            [&self.scope],
            |r| r.get(0),
        )?;
        let environment = Environment {
            generation,
            revision: manifest.revision,
            release_id: manifest.release_id,
            modules,
        };
        tx.execute(
            "INSERT INTO environment VALUES(?1,?2,?3,?4)",
            params![
                self.scope,
                generation,
                environment.revision,
                serde_json::to_vec(&environment)?
            ],
        )?;
        tx.execute("INSERT INTO active_environment VALUES(?1,?2) ON CONFLICT(scope) DO UPDATE SET generation=excluded.generation",params![self.scope,generation])?;
        tx.commit()?;
        tracing::info!(event="EnvironmentCommitted",generation,release_id=%environment.release_id,"module environment activated for new tasks");
        Ok(environment)
    }

    pub(crate) async fn apply(&self, bundle: &Path) -> Result<Environment, ScannerError> {
        let expected = self.active()?.map(|e| e.generation);
        let prepared = self.prepare(bundle, true).await?;
        self.commit(prepared, expected)
    }

    pub(crate) async fn rollback(&self, generation: i64) -> Result<Environment, ScannerError> {
        let current = self
            .active()?
            .ok_or_else(|| ScannerError::Config("no active environment".into()))?;
        let old: Environment = {
            let store = self.state.lock().unwrap();
            let payload: Vec<u8> = store.db.query_row(
                "SELECT payload FROM environment WHERE scope=?1 AND generation=?2",
                params![self.scope, generation],
                |r| r.get(0),
            )?;
            serde_json::from_slice(&payload)?
        };
        if current.release_id == format!("rollback-to-{generation}")
            && current.modules == old.modules
        {
            return Ok(current);
        }
        for (stage, spec) in &old.modules {
            self.verify_artifact(&self.config.directory.join(&spec.artifact), &spec.artifact)?;
            host::preflight(
                &spec.worker_path,
                serde_json::from_value(serde_json::Value::String(stage.clone()))?,
            )
            .await?;
        }
        let manifest = Manifest {
            schema: 1,
            ipc_version: crate::modules::protocol::IPC_VERSION,
            release_id: format!("rollback-to-{generation}"),
            revision: current.revision + 1,
            target: format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
            files: Vec::new(),
            modules: BTreeMap::new(),
        };
        // A complete replacement is required for rollback (ordinary deploys may
        // replace only selected stages).
        let mut store = self.state.lock().unwrap();
        let tx = store.db.transaction()?;
        let actual: i64 = tx.query_row(
            "SELECT generation FROM active_environment WHERE scope=?1",
            [&self.scope],
            |r| r.get(0),
        )?;
        if actual != current.generation {
            return Err(ScannerError::Config(
                "environment changed during rollback".into(),
            ));
        }
        let next: i64 = tx.query_row(
            "SELECT MAX(generation)+1 FROM environment WHERE scope=?1",
            [&self.scope],
            |r| r.get(0),
        )?;
        let restored = Environment {
            generation: next,
            revision: manifest.revision,
            release_id: manifest.release_id,
            modules: old.modules,
        };
        tx.execute(
            "INSERT INTO environment VALUES(?1,?2,?3,?4)",
            params![
                self.scope,
                next,
                restored.revision,
                serde_json::to_vec(&restored)?
            ],
        )?;
        tx.execute(
            "UPDATE active_environment SET generation=?2 WHERE scope=?1",
            params![self.scope, next],
        )?;
        tx.commit()?;
        Ok(restored)
    }

    pub(crate) fn bind(
        &self,
        task: &AssignedTask,
        mut runtime: RuntimeSnapshot,
    ) -> Result<TaskEnvironment, ScannerError> {
        let task_digest = package::digest(&serde_json::to_vec(&(
            task.task_id,
            &task.task_target,
            &task.task_port,
            &task.address_family,
            &task.scan_plan,
            &task.dns_resolvers,
        ))?);
        let mut store = self.state.lock().unwrap();
        let tx = store.db.transaction()?;
        let stored: Option<Vec<u8>> = tx
            .query_row(
                "SELECT payload FROM task_environment WHERE scope=?1 AND task_id=?2",
                params![self.scope, task.task_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(payload) = stored {
            let environment: TaskEnvironment = serde_json::from_slice(&payload)?;
            if environment.task_digest != task_digest {
                return Err(ScannerError::Config(
                    "recovered task parameters changed; refusing mixed-version checkpoint".into(),
                ));
            }
            return Ok(environment);
        }
        let payload:Vec<u8>=tx.query_row("SELECT e.payload FROM environment e JOIN active_environment a ON a.scope=e.scope AND a.generation=e.generation WHERE e.scope=?1",[&self.scope],|r|r.get(0))?;
        let environment: Environment = serde_json::from_slice(&payload)?;
        if let Some(module) = environment.modules.get("service_detection") {
            runtime.service_detection.zgrab_path = module
                .engine_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned();
        }
        if let Some(module) = environment.modules.get("vulnerability_detection") {
            runtime.nuclei.path = module
                .engine_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            runtime.nuclei.templates_path = module
                .templates_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned();
        }
        let pinned = TaskEnvironment {
            environment,
            runtime,
            task_digest,
        };
        tx.execute(
            "INSERT INTO task_environment VALUES(?1,?2,?3)",
            params![
                self.scope,
                task.task_id.to_string(),
                serde_json::to_vec(&pinned)?
            ],
        )?;
        tx.commit()?;
        Ok(pinned)
    }

    pub(crate) fn release(&self, task_id: Uuid) -> Result<(), ScannerError> {
        self.state.lock().unwrap().db.execute(
            "DELETE FROM task_environment WHERE scope=?1 AND task_id=?2",
            params![self.scope, task_id.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn observe_worker(
        &self,
        generation: i64,
        stage: &str,
        failed: bool,
    ) -> Result<(), ScannerError> {
        self.state.lock().unwrap().db.execute("INSERT INTO worker_health VALUES(?1,?2,?3,?4) ON CONFLICT(scope,generation,stage) DO UPDATE SET consecutive_failures=CASE WHEN ?4=0 THEN 0 ELSE consecutive_failures+1 END",params![self.scope,generation,stage,i64::from(failed)])?;
        Ok(())
    }
    pub(crate) fn automatic_rollback_target(&self) -> Result<Option<i64>, ScannerError> {
        if !self.config.auto_rollback {
            return Ok(None);
        }
        let store = self.state.lock().unwrap();
        Ok(store.db.query_row("SELECT e.generation FROM environment e JOIN active_environment a ON a.scope=e.scope JOIN worker_health h ON h.scope=a.scope AND h.generation=a.generation WHERE e.scope=?1 AND e.generation<a.generation AND h.consecutive_failures>=3 ORDER BY e.generation DESC LIMIT 1",[&self.scope],|r|r.get(0)).optional()?)
    }
    pub(crate) fn task_generation(&self, task: Uuid) -> Option<i64> {
        let store = self.state.lock().ok()?;
        let payload: Vec<u8> = store
            .db
            .query_row(
                "SELECT payload FROM task_environment WHERE scope=?1 AND task_id=?2",
                params![self.scope, task.to_string()],
                |r| r.get(0),
            )
            .ok()?;
        serde_json::from_slice::<TaskEnvironment>(&payload)
            .ok()
            .map(|p| p.environment.generation)
    }

    pub(crate) fn gc(&self) -> Result<Vec<String>, ScannerError> {
        let store = self.state.lock().unwrap();
        let mut keep = BTreeSet::new();
        // Protect pins from every origin sharing this module store, and retain
        // two latest generations per origin. Activation and pinning use this lock.
        let mut stmt=store.db.prepare("SELECT payload FROM environment e WHERE generation IN (SELECT generation FROM environment x WHERE x.scope=e.scope ORDER BY generation DESC LIMIT 2) UNION ALL SELECT e.payload FROM environment e JOIN active_environment a ON a.scope=e.scope AND a.generation=e.generation")?;
        for payload in stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            for spec in serde_json::from_slice::<Environment>(&payload?)?
                .modules
                .values()
            {
                keep.insert(spec.artifact.clone());
            }
        }
        let mut stmt = store.db.prepare("SELECT payload FROM task_environment")?;
        for payload in stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            for spec in serde_json::from_slice::<TaskEnvironment>(&payload?)?
                .environment
                .modules
                .values()
            {
                keep.insert(spec.artifact.clone());
            }
        }
        let mut removed = Vec::new();
        for entry in fs::read_dir(&self.config.directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 64
                && package::unhex(&name).is_ok()
                && !keep.contains(&name)
                && entry.file_type()?.is_dir()
            {
                fs::remove_dir_all(entry.path())?;
                removed.push(name);
            }
        }
        Ok(removed)
    }

    pub(crate) fn report(&self) -> serde_json::Value {
        match self.active() {
            Ok(Some(e)) => {
                serde_json::json!({"protocol_versions":[crate::modules::protocol::IPC_VERSION],"active_generation":e.generation,"release_id":e.release_id,"revision":e.revision,"modules":e.modules})
            }
            Ok(None) => {
                serde_json::json!({"protocol_versions":[crate::modules::protocol::IPC_VERSION],"status":"uninitialized"})
            }
            Err(e) => serde_json::json!({"status":"error","error":e.to_string()}),
        }
    }

    pub(crate) fn record_deployment(
        &self,
        id: &str,
        result: &Result<(), ScannerError>,
    ) -> Result<(), ScannerError> {
        let error = result.as_ref().err().map(ToString::to_string);
        self.state.lock().unwrap().db.execute("INSERT INTO deployment VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope,id) DO UPDATE SET state=excluded.state,error=excluded.error",params![self.scope,id,if result.is_ok(){"committed"}else{"rejected"},error,chrono::Utc::now().timestamp_millis()])?;
        Ok(())
    }
}

fn executable(path: &Path) -> Result<PathBuf, ScannerError> {
    if path.components().count() > 1 || path.is_absolute() {
        return Ok(path.canonicalize()?);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(path))
        .find(|p| p.is_file())
        .ok_or_else(|| ScannerError::Config(format!("executable {} not found", path.display())))?
        .canonicalize()
        .map_err(Into::into)
}
fn bootstrap_sources(
    local: &AppConfig,
    config: &ModulesConfig,
) -> Result<BTreeMap<String, PathBuf>, ScannerError> {
    let worker = if config.worker_path.exists() {
        config.worker_path.canonicalize()?
    } else if config.worker_path == Path::new("./scanner-worker") {
        std::env::current_exe()?
            .parent()
            .unwrap()
            .join("scanner-worker")
            .canonicalize()?
    } else {
        return Err(ScannerError::Config("worker binary not found".into()));
    };
    let mut files = BTreeMap::from([
        ("bin/worker".into(), worker),
        (
            "bin/masscan".into(),
            executable(Path::new(&local.scanner.scanner_path))?,
        ),
    ]);
    if local.service_detection.enabled {
        files.insert(
            "bin/zgrab2".into(),
            executable(Path::new(&local.service_detection.zgrab_path))?,
        );
    }
    if local.nuclei.enabled {
        files.insert(
            "bin/nuclei".into(),
            executable(Path::new(&local.nuclei.path))?,
        );
        collect_templates(
            Path::new(&local.nuclei.templates_path),
            "templates",
            &mut files,
        )?;
    }
    Ok(files)
}
fn collect_templates(
    path: &Path,
    prefix: &str,
    files: &mut BTreeMap<String, PathBuf>,
) -> Result<(), ScannerError> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(ScannerError::Config(
            "template root must be a regular directory".into(),
        ));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ScannerError::Config("template filename must be UTF-8".into()))?;
        let relative = format!("{prefix}/{name}");
        package::relative(&relative)?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_templates(&entry.path(), &relative, files)?;
        } else if kind.is_file() {
            files.insert(relative, entry.path());
        } else {
            return Err(ScannerError::Config(
                "template links/special files are unsupported".into(),
            ));
        }
        if files.len() > 10000 {
            return Err(ScannerError::Config("too many templates".into()));
        }
    }
    Ok(())
}
fn bootstrap_manifest(local: &AppConfig, config: &ModulesConfig) -> Result<Manifest, ScannerError> {
    let sources = bootstrap_sources(local, config)?;
    let files = sources
        .iter()
        .map(|(name, path)| {
            Ok(BundleFile {
                path: name.clone(),
                sha256: package::hash_file(path)?,
                size: fs::metadata(path)?.len(),
                executable: name.starts_with("bin/"),
            })
        })
        .collect::<Result<Vec<_>, ScannerError>>()?;
    let module = |engine: Option<&str>, templates: Option<&str>| BundleModule {
        worker: "bin/worker".into(),
        engine: engine.map(Into::into),
        templates: templates.map(Into::into),
    };
    let mut modules =
        BTreeMap::from([("port_discovery".into(), module(Some("bin/masscan"), None))]);
    if local.service_detection.enabled {
        modules.insert("service_detection".into(), module(Some("bin/zgrab2"), None));
    }
    if local.dns.enabled {
        modules.insert("dns_lookup".into(), module(None, None));
    }
    if local.nuclei.enabled {
        modules.insert(
            "vulnerability_detection".into(),
            module(Some("bin/nuclei"), Some("templates")),
        );
    }
    Ok(Manifest {
        schema: 1,
        ipc_version: crate::modules::protocol::IPC_VERSION,
        release_id: "local-bootstrap".into(),
        revision: 1,
        target: format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
        files,
        modules,
    })
}
fn sync_tree(path: &Path) -> Result<(), ScannerError> {
    for item in fs::read_dir(path)? {
        let item = item?;
        if item.file_type()?.is_dir() {
            sync_tree(&item.path())?;
        }
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        root: PathBuf,
        local: AppConfig,
        key: Ed25519KeyPair,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("module-registry-test-{}", Uuid::now_v7()));
            fs::create_dir(&root).unwrap();
            let mut worker = String::from("#!/bin/sh\ncase \"$2\" in\n");
            for stage in [
                ScanStageKind::PortDiscovery,
                ScanStageKind::ServiceDetection,
                ScanStageKind::DnsLookup,
                ScanStageKind::VulnerabilityDetection,
            ] {
                let event = super::super::protocol::Event {
                    id: Uuid::nil(),
                    sequence: 0,
                    body: super::super::protocol::EventBody::Hello {
                        ipc_version: crate::modules::protocol::IPC_VERSION,
                        stage,
                        version: "test".into(),
                    },
                };
                let body = serde_json::to_string(&event).unwrap();
                let length = (body.len() as u32)
                    .to_be_bytes()
                    .iter()
                    .map(|b| format!("\\{b:03o}"))
                    .collect::<String>();
                worker.push_str(&format!(
                    "{}) printf '{length}'; printf '%s' '{body}' ;;\n",
                    stage.name()
                ));
            }
            worker.push_str("esac\n");
            fs::write(root.join("worker"), worker).unwrap();
            fs::set_permissions(root.join("worker"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(root.join("masscan"), "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(root.join("masscan"), fs::Permissions::from_mode(0o700)).unwrap();
            let mut local: AppConfig =
                toml_edit::de::from_str(include_str!("../../config.toml")).unwrap();
            local.scanner.scanner_path = root.join("masscan").to_string_lossy().into_owned();
            local.service_detection.enabled = false;
            local.dns.enabled = false;
            local.nuclei.enabled = false;
            local.modules = ModulesConfig {
                enabled: true,
                directory: root.join("modules"),
                state_database: root.join("modules.sqlite3"),
                worker_path: root.join("worker"),
                trusted_keys: root.join("keys.json"),
                ..Default::default()
            };
            let random = SystemRandom::new();
            let key = Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&random).unwrap().as_ref(),
            )
            .unwrap();
            fs::write(
                &local.modules.trusted_keys,
                serde_json::to_vec(&BTreeMap::from([(
                    "test",
                    package::hex(key.public_key().as_ref()),
                )]))
                .unwrap(),
            )
            .unwrap();
            Self { root, local, key }
        }
        fn bundle(&self, revision: i64) -> PathBuf {
            let path = self.root.join(format!("release-{revision}"));
            fs::create_dir_all(&path).unwrap();
            let manifest = bootstrap_manifest(&self.local, &self.local.modules).unwrap();
            for file in &manifest.files {
                let target = path.join(&file.path);
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::copy(
                    bootstrap_sources(&self.local, &self.local.modules)
                        .unwrap()
                        .get(&file.path)
                        .unwrap(),
                    target,
                )
                .unwrap();
            }
            let mut manifest = manifest;
            manifest.revision = revision;
            manifest.release_id = format!("test-release-{revision}");
            let raw = serde_json::to_vec(&manifest).unwrap();
            fs::write(path.join("manifest.json"), &raw).unwrap();
            let signature = Signature {
                key_id: "test".into(),
                signature: package::hex(self.key.sign(&raw).as_ref()),
            };
            fs::write(
                path.join("manifest.sig"),
                serde_json::to_vec(&signature).unwrap(),
            )
            .unwrap();
            path
        }
        fn task(&self) -> AssignedTask {
            serde_json::from_value(serde_json::json!({"task_id":Uuid::now_v7(),"task_target":["192.0.2.1"],"task_port":"22","address_family":"ipv4"})).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn final_owner_releases_lock_even_with_a_duplicated_descriptor() {
        let f = Fixture::new();
        let registry = Registry::open_store(f.local.modules.clone(), "origin".into()).unwrap();
        // dup and fork share the same open-file description on Unix.
        let inherited = registry
            .state
            .lock()
            .unwrap()
            ._lock
            .try_clone_file()
            .unwrap();
        let owner = registry.clone();
        drop(registry);
        assert!(Registry::open_store(f.local.modules.clone(), "origin".into()).is_err());
        drop(owner);
        let reopened = Registry::open_store(f.local.modules.clone(), "origin".into()).unwrap();
        // Closing an old inherited descriptor must not release the new owner's lock.
        drop(inherited);
        assert!(Registry::open_store(f.local.modules.clone(), "origin".into()).is_err());
        drop(reopened);
    }

    #[tokio::test]
    async fn task_pins_survive_update_restart_and_configuration_changes() {
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        let task = f.task();
        let runtime = crate::runtime_config::RuntimeConfiguration::new(&f.local)
            .snapshot()
            .await;
        let pinned = registry.bind(&task, runtime.clone()).unwrap();
        assert_eq!(pinned.environment.generation, 1);
        let second = registry.apply(&f.bundle(2)).await.unwrap();
        assert_eq!(second.generation, 2);
        let mut changed = runtime.clone();
        changed.rate = 1;
        changed.masscan.wait_seconds = 42;
        assert_eq!(
            registry.bind(&task, changed.clone()).unwrap().runtime.rate,
            runtime.rate
        );
        let fresh = registry.bind(&f.task(), changed.clone()).unwrap();
        assert_eq!(fresh.environment.generation, 2);
        assert_eq!(fresh.runtime.rate, 1);
        assert_eq!(fresh.runtime.masscan.wait_seconds, 42);
        assert_eq!(
            registry
                .bind(&task, changed.clone())
                .unwrap()
                .runtime
                .masscan,
            runtime.masscan
        );
        drop(registry);
        let reopened = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        assert_eq!(
            reopened
                .bind(&task, changed)
                .unwrap()
                .environment
                .generation,
            1
        );
        assert_eq!(
            reopened
                .bind(&task, runtime.clone())
                .unwrap()
                .runtime
                .masscan,
            runtime.masscan
        );
        let mut changed_task = task;
        changed_task.task_port = "443".into();
        assert!(reopened.bind(&changed_task, runtime).is_err());
    }
    #[tokio::test]
    async fn rejected_signature_and_bad_worker_leave_active_environment_untouched() {
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        let bundle = f.bundle(2);
        fs::write(bundle.join("manifest.sig"), b"{}").unwrap();
        assert!(registry.apply(&bundle).await.is_err());
        assert_eq!(registry.active().unwrap().unwrap().generation, 1);
        let bundle = f.bundle(3);
        fs::write(bundle.join("bin/worker"), b"corrupt worker").unwrap();
        assert!(registry.apply(&bundle).await.is_err());
        assert_eq!(registry.active().unwrap().unwrap().generation, 1);
    }
    #[tokio::test]
    async fn gc_preserves_task_versions_and_rollback_uses_a_new_generation() {
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        let task = f.task();
        let runtime = crate::runtime_config::RuntimeConfiguration::new(&f.local)
            .snapshot()
            .await;
        let pin = registry.bind(&task, runtime).unwrap();
        let artifact = pin.environment.modules["port_discovery"].artifact.clone();
        registry.apply(&f.bundle(2)).await.unwrap();
        registry.apply(&f.bundle(3)).await.unwrap();
        registry.apply(&f.bundle(4)).await.unwrap();
        registry.gc().unwrap();
        assert!(registry.config.directory.join(&artifact).exists());
        let rollback = registry.rollback(1).await.unwrap();
        assert_eq!(rollback.generation, 5);
        assert_eq!(rollback.revision, 5);
        assert_eq!(rollback.modules, pin.environment.modules);
        registry.apply(&f.bundle(6)).await.unwrap();
        registry.apply(&f.bundle(7)).await.unwrap();
        registry.release(task.task_id).unwrap();
        assert!(registry.gc().unwrap().contains(&artifact));
    }
    #[tokio::test]
    async fn duplicate_release_is_idempotent_and_store_is_exclusive() {
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        let bundle = f.bundle(2);
        assert_eq!(registry.apply(&bundle).await.unwrap().generation, 2);
        assert_eq!(registry.apply(&bundle).await.unwrap().generation, 2);
        assert!(Registry::open_store(f.local.modules.clone(), "origin".into()).is_err());
    }
    #[tokio::test]
    async fn automatic_rollback_counts_protocol_failures_per_stage() {
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        registry.apply(&f.bundle(2)).await.unwrap();
        for _ in 0..2 {
            registry
                .observe_worker(2, "service_detection", true)
                .unwrap();
            registry.observe_worker(2, "port_discovery", false).unwrap();
        }
        assert_eq!(registry.automatic_rollback_target().unwrap(), None);
        registry
            .observe_worker(2, "service_detection", true)
            .unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), Some(1));
        registry.rollback(1).await.unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), None);
        // An older pinned task cannot roll back a different active generation.
        registry
            .observe_worker(2, "service_detection", true)
            .unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), None);
    }

    #[tokio::test]
    async fn completed_wrong_stage_results_trigger_rollback_instead_of_resetting_health() {
        use crate::modules::{host::StageResult, protocol::Outcome};
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        let previous = registry.active().unwrap().unwrap();
        registry.apply(&f.bundle(2)).await.unwrap();
        let wrong: crate::scan::ScanObservation = serde_json::from_value(serde_json::json!({"kind":"service","ip":"192.0.2.1","port":22,"protocol":"tcp","service":"ssh","source":"test","observed_at":1})).unwrap();
        for attempt in 1..=3 {
            let result = crate::scan::process_worker_result(
                ScanStageKind::PortDiscovery,
                Ok(StageResult {
                    outcome: Outcome::Completed,
                    observations: vec![wrong.clone()],
                    error: None,
                }),
                Some(&registry),
                2,
                false,
            );
            assert!(
                matches!(result, Err(ScannerError::Scan(ref message)) if message.contains("observation kind rejected"))
            );
            assert_eq!(
                registry.automatic_rollback_target().unwrap(),
                if attempt == 3 { Some(1) } else { None }
            );
        }
        let restored = registry
            .rollback(registry.automatic_rollback_target().unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(restored.generation, 3);
        assert_eq!(restored.modules, previous.modules);
    }

    #[tokio::test]
    async fn valid_success_resets_health_but_partial_and_cancelled_work_do_not() {
        use crate::modules::{host::StageResult, protocol::Outcome};
        let f = Fixture::new();
        let registry = Registry::open(f.local.modules.clone(), &f.local, "origin".into())
            .await
            .unwrap();
        registry.apply(&f.bundle(2)).await.unwrap();
        for _ in 0..2 {
            registry.observe_worker(2, "port_discovery", true).unwrap();
        }
        let port: crate::scan::ScanObservation = serde_json::from_value(serde_json::json!({"kind":"port","ip":"192.0.2.1","port":22,"protocol":"tcp","state":"open","source":"test","observed_at":1})).unwrap();
        crate::scan::process_worker_result(
            ScanStageKind::PortDiscovery,
            Ok(StageResult {
                outcome: Outcome::Completed,
                observations: vec![port],
                error: None,
            }),
            Some(&registry),
            2,
            false,
        )
        .unwrap();
        registry.observe_worker(2, "port_discovery", true).unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), None);
        // Structurally valid partial and business failures must preserve counts.
        for outcome in [Outcome::Partial, Outcome::Failed, Outcome::Cancelled] {
            crate::scan::process_worker_result(
                ScanStageKind::PortDiscovery,
                Ok(StageResult {
                    outcome,
                    observations: Vec::new(),
                    error: None,
                }),
                Some(&registry),
                2,
                false,
            )
            .unwrap();
        }
        crate::scan::process_worker_result(
            ScanStageKind::PortDiscovery,
            Err(ScannerError::Scan("worker frame rejected".into())),
            Some(&registry),
            2,
            true,
        )
        .err()
        .unwrap();
        registry.observe_worker(2, "port_discovery", true).unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), None);
        registry.observe_worker(2, "port_discovery", true).unwrap();
        assert_eq!(registry.automatic_rollback_target().unwrap(), Some(1));
    }
}
