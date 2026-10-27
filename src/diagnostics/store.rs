use super::{Result, protocol::*};
use crate::file_lock::ExclusiveFileLock;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

struct Inner {
    db: Connection,
    _lock: ExclusiveFileLock,
}
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Inner>>,
    scope: String,
}

impl Store {
    pub fn open(path: PathBuf, origin: &str, scanner: Uuid) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        let lock = ExclusiveFileLock::acquire(lock)?;
        let db = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS outbox(scope TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,level TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT(unixepoch()),PRIMARY KEY(scope,id));
            CREATE TABLE IF NOT EXISTS jobs(scope TEXT NOT NULL,id TEXT NOT NULL,job TEXT NOT NULL,manifest TEXT,done INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL DEFAULT(unixepoch()),PRIMARY KEY(scope,id));
            CREATE TABLE IF NOT EXISTS sources(scope TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(scope,id));
            CREATE TABLE IF NOT EXISTS session(scope TEXT PRIMARY KEY,clean INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(scope,created_at);
            CREATE INDEX IF NOT EXISTS jobs_pending ON jobs(scope,done,created_at);")?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { db, _lock: lock })),
            scope: format!("{origin}|{scanner}"),
        })
    }

    pub fn session_start(&self) -> Result<bool> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "diagnostics_database_poisoned")?;
        let previous: Option<i32> = inner
            .db
            .query_row(
                "SELECT clean FROM session WHERE scope=?1",
                [&self.scope],
                |r| r.get(0),
            )
            .optional()?;
        inner.db.execute("INSERT INTO session(scope,clean) VALUES(?1,0) ON CONFLICT(scope) DO UPDATE SET clean=0",[&self.scope])?;
        Ok(previous == Some(0))
    }

    pub fn insert_event(&self, value: &Value) -> Result<bool> {
        let Some(id) = value.pointer("/fields/event_id").and_then(Value::as_str) else {
            return Ok(false);
        };
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "diagnostics_database_poisoned")?;
        let tx = inner.db.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
        if count >= 4096 {
            let changed=tx.execute("DELETE FROM outbox WHERE rowid IN (SELECT rowid FROM outbox WHERE level='WARN' ORDER BY created_at LIMIT 1)",[])?;
            if changed > 0 {
                super::DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            if changed == 0 {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO outbox(scope,id,payload,level) VALUES(?1,?2,?3,?4)",
            params![
                self.scope,
                id,
                value.to_string(),
                value["level"].as_str().unwrap_or("INFO")
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection, &str) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let result = {
                let mut inner = this
                    .inner
                    .lock()
                    .map_err(|_| "diagnostics_database_poisoned")?;
                f(&mut inner.db, &this.scope)
            };
            // Drop the captured Store before Tokio publishes task completion.
            // Otherwise a caller may reopen while this task still owns the lock.
            drop(this);
            result
        })
        .await?
    }

    pub async fn pending_events(&self) -> Result<Vec<Value>> {
        self.call(|db, scope| {
            let mut stmt = db.prepare(
                "SELECT payload FROM outbox WHERE scope=?1 ORDER BY created_at,rowid LIMIT 50",
            )?;
            stmt.query_map([scope], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect()
        })
        .await
    }

    pub async fn confirm(&self, ids: Vec<String>) -> Result<()> {
        self.call(move |db, scope| {
            let tx = db.transaction()?;
            for id in ids {
                tx.execute(
                    "DELETE FROM outbox WHERE scope=?1 AND id=?2",
                    params![scope, id],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn enqueue(&self, job: Job) -> Result<()> {
        self.call(move |db, scope| {
            db.execute(
                "INSERT OR IGNORE INTO jobs(scope,id,job) VALUES(?1,?2,?3)",
                params![scope, job.job_id.to_string(), serde_json::to_string(&job)?],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn next_job(&self) -> Result<Option<(Job, Option<Manifest>)>> {
        self.call(|db,scope| {
            let record:Option<(String,Option<String>)>=db.query_row("SELECT job,manifest FROM jobs WHERE scope=?1 AND done=0 ORDER BY created_at,rowid LIMIT 1",[scope],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            record.map(|(job,manifest)|Ok((serde_json::from_str(&job)?,manifest.map(|s|serde_json::from_str(&s)).transpose()?))).transpose()
        }).await
    }

    pub async fn save_manifest(&self, id: Uuid, manifest: &Manifest) -> Result<()> {
        let payload = serde_json::to_string(manifest)?;
        self.call(move |db, scope| {
            db.execute(
                "UPDATE jobs SET manifest=?3 WHERE scope=?1 AND id=?2",
                params![scope, id.to_string(), payload],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn done(&self, id: Uuid) -> Result<()> {
        self.call(move |db, scope| {
            db.execute(
                "UPDATE jobs SET done=1 WHERE scope=?1 AND id=?2",
                params![scope, id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn save_sources(&self, sources: Vec<SourceFile>) -> Result<()> {
        self.call(move |db, scope| {
            let tx = db.transaction()?;
            tx.execute("DELETE FROM sources WHERE scope=?1", [scope])?;
            for source in sources {
                tx.execute(
                    "INSERT INTO sources(scope,id,payload) VALUES(?1,?2,?3)",
                    params![
                        scope,
                        source.source_file_id,
                        serde_json::to_string(&source)?
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn source(&self, id: String) -> Result<SourceFile> {
        self.call(move |db, scope| {
            let source: Option<String> = db
                .query_row(
                    "SELECT payload FROM sources WHERE scope=?1 AND id=?2",
                    params![scope, id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(serde_json::from_str(&source.ok_or("log_catalog_stale")?)?)
        })
        .await
    }

    pub async fn clean_shutdown(&self) -> Result<()> {
        self.call(|db, scope| {
            db.execute("UPDATE session SET clean=1 WHERE scope=?1", [scope])?;
            Ok(())
        })
        .await
    }

    pub async fn pending_file_ids(&self) -> Result<std::collections::HashSet<Uuid>> {
        self.call(|db, _| {
            let mut statement =
                db.prepare("SELECT manifest FROM jobs WHERE done=0 AND manifest IS NOT NULL")?;
            let mut ids = std::collections::HashSet::new();
            for row in statement.query_map([], |row| row.get::<_, String>(0))? {
                let manifest: Manifest = serde_json::from_str(&row?)?;
                ids.extend(manifest.files.into_iter().map(|file| file.file_id));
            }
            Ok(ids)
        })
        .await
    }

    pub async fn prune(&self) -> Result<()> {
        self.call(|db, _| {
            db.execute("UPDATE jobs SET done=1 WHERE done=0 AND unixepoch(json_extract(job,'$.expires_at'))<unixepoch()",[])?;
            db.execute(
                "DELETE FROM jobs WHERE done=1 AND created_at<unixepoch()-86400",
                [],
            )?;
            db.execute(
                "DELETE FROM outbox WHERE created_at<unixepoch()-7776000",
                [],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn outbox_survives_restart_and_isolates_identity() {
        let path = std::env::temp_dir().join(format!("diagnostics-{}.sqlite3", Uuid::now_v7()));
        let scanner = Uuid::now_v7();
        let store = Store::open(path.clone(), "https://example.test", scanner).unwrap();
        assert!(!store.session_start().unwrap());
        let event =
            serde_json::json!({"level":"ERROR","fields":{"event_id":Uuid::now_v7().to_string()}});
        assert!(store.insert_event(&event).unwrap());
        drop(store);
        let store = Store::open(path.clone(), "https://example.test", scanner).unwrap();
        assert!(store.session_start().unwrap());
        let events = store.pending_events().await.unwrap();
        assert_eq!(events.len(), 1);
        store
            .confirm(vec![
                event["fields"]["event_id"].as_str().unwrap().to_owned(),
            ])
            .await
            .unwrap();
        assert!(store.pending_events().await.unwrap().is_empty());
        store.clean_shutdown().await.unwrap();
        drop(store);
        let store = Store::open(path.clone(), "https://another.test", scanner).unwrap();
        assert!(!store.session_start().unwrap());
        drop(store);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lock")).unwrap();
    }
    #[tokio::test]
    async fn diagnostic_manifest_survives_restart_and_expires() {
        let path = std::env::temp_dir().join(format!("diagnostic-job-{}.sqlite3", Uuid::now_v7()));
        let scanner = Uuid::now_v7();
        let job = Job {
            job_id: Uuid::now_v7(),
            kind: JobKind::CollectLogs,
            protocol_version: VERSION,
            source_file_ids: vec!["a".repeat(64)],
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
        };
        let file = Snapshot {
            file_id: Uuid::now_v7(),
            source: SourceFile {
                source_file_id: "a".repeat(64),
                name: "scanner.log.2026-10-01".into(),
                size_bytes: 3,
                modified_at: chrono::Utc::now(),
                active: true,
            },
            captured_at: chrono::Utc::now(),
            size_bytes: 3,
            excluded_tail_bytes: 0,
            sha256: "b".repeat(64),
        };
        let manifest = Manifest {
            scanner_id: scanner,
            job_id: job.job_id,
            sources: vec![],
            files: vec![file.clone()],
        };
        let store = Store::open(path.clone(), "https://example.test", scanner).unwrap();
        store.enqueue(job.clone()).await.unwrap();
        store.enqueue(job.clone()).await.unwrap();
        store.save_manifest(job.job_id, &manifest).await.unwrap();
        drop(store);
        let store = Store::open(path.clone(), "https://example.test", scanner).unwrap();
        let (resumed, saved) = store.next_job().await.unwrap().unwrap();
        assert_eq!(resumed.job_id, job.job_id);
        assert_eq!(saved.unwrap().files[0].file_id, file.file_id);
        assert!(
            store
                .pending_file_ids()
                .await
                .unwrap()
                .contains(&file.file_id)
        );
        let id = job.job_id.to_string();
        store.call(move |db,scope| { db.execute("UPDATE jobs SET job=json_set(job,'$.expires_at','2000-01-01T00:00:00Z') WHERE scope=?1 AND id=?2",params![scope,id])?;Ok(()) }).await.unwrap();
        store.prune().await.unwrap();
        assert!(store.next_job().await.unwrap().is_none());
        assert!(store.pending_file_ids().await.unwrap().is_empty());
        drop(store);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lock")).unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn completed_blocking_call_releases_its_store_before_immediate_reopen() {
        let path =
            std::env::temp_dir().join(format!("diagnostic-release-{}.sqlite3", Uuid::now_v7()));
        let scanner = Uuid::now_v7();
        for _ in 0..128 {
            let store = Store::open(path.clone(), "https://example.test", scanner).unwrap();
            store.call(|_, _| Ok(())).await.unwrap();
            assert_eq!(Arc::strong_count(&store.inner), 1);
            drop(store);
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lock")).unwrap();
    }
}
