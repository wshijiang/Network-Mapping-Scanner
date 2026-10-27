use crate::error::ScannerError;
use crate::file_lock::ExclusiveFileLock;
use crate::scan::ScanObservation;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredIdentity {
    pub(crate) scanner_id: String,
    pub(crate) runtime_token: String,
}

#[derive(Debug)]
pub(crate) struct StoredUpload {
    pub(crate) scanner_id: String,
    pub(crate) task_id: Uuid,
    pub(crate) upload_id: Uuid,
    pub(crate) next_batch_index: u32,
    pub(crate) observations: Vec<ScanObservation>,
}

#[derive(Debug)]
pub(crate) struct StoredRuntimeConfiguration {
    pub(crate) revision: i64,
    pub(crate) schema_version: i32,
    pub(crate) document: Vec<u8>,
}

pub(crate) struct StateStore {
    connection: Connection,
    _lock: ExclusiveFileLock,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CacheSummary {
    pub(crate) pending_tasks: u64,
    pub(crate) observations: u64,
    pub(crate) runtime_configurations: u64,
}

impl StateStore {
    pub(crate) fn open(path: PathBuf) -> Result<Self, ScannerError> {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(ScannerError::Io)?;
        }

        let lock_path = path.with_extension("sqlite3.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(ScannerError::Io)?;
        let lock = ExclusiveFileLock::acquire(lock).map_err(|error| {
            ScannerError::Config(format!(
                "scanner state is already in use ({}): {error}",
                lock_path.display()
            ))
        })?;
        set_private_permissions(&lock_path)?;

        let mut connection = Connection::open(&path)?;
        set_private_permissions(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.set_transaction_behavior(TransactionBehavior::Immediate);
        migrate(&mut connection)?;

        tracing::debug!(database_path = %path.display(), "SQLite state database opened");
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    pub(crate) fn cache_summary(
        &self,
        server_origin: Option<&str>,
    ) -> Result<CacheSummary, ScannerError> {
        let (pending_tasks, observations, runtime_configurations): (i64, i64, i64) =
            match server_origin {
                Some(origin) => self.connection.query_row(
                    "SELECT (SELECT COUNT(*) FROM pending_upload WHERE server_origin=?1), \
                            (SELECT COUNT(*) FROM observation WHERE server_origin=?1), \
                            (SELECT COUNT(*) FROM runtime_configuration WHERE server_origin=?1)",
                    [origin],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?,
                None => self.connection.query_row(
                    "SELECT (SELECT COUNT(*) FROM pending_upload), \
                            (SELECT COUNT(*) FROM observation), \
                            (SELECT COUNT(*) FROM runtime_configuration)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?,
            };
        Ok(CacheSummary {
            pending_tasks: pending_tasks.try_into().unwrap_or_default(),
            observations: observations.try_into().unwrap_or_default(),
            runtime_configurations: runtime_configurations.try_into().unwrap_or_default(),
        })
    }

    pub(crate) fn clear_cache(
        &mut self,
        server_origin: Option<&str>,
        include_runtime_configuration: bool,
    ) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        match server_origin {
            Some(origin) => {
                transaction.execute(
                    "DELETE FROM pending_upload WHERE server_origin=?1",
                    [origin],
                )?;
                transaction.execute(
                    "DELETE FROM scan_checkpoint WHERE server_origin=?1",
                    [origin],
                )?;
                transaction.execute("DELETE FROM scan_retry WHERE server_origin=?1", [origin])?;
                if include_runtime_configuration {
                    transaction.execute(
                        "DELETE FROM runtime_configuration WHERE server_origin=?1",
                        [origin],
                    )?;
                }
            }
            None => {
                transaction.execute("DELETE FROM pending_upload", [])?;
                transaction.execute("DELETE FROM scan_checkpoint", [])?;
                transaction.execute("DELETE FROM scan_retry", [])?;
                if include_runtime_configuration {
                    transaction.execute("DELETE FROM runtime_configuration", [])?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn archive_upload(
        &mut self,
        origin: &str,
        reason: &str,
    ) -> Result<(), ScannerError> {
        let scanner_id: Option<String> = self
            .connection
            .query_row(
                "SELECT scanner_id FROM pending_upload WHERE server_origin=?1",
                [origin],
                |row| row.get(0),
            )
            .optional()?;
        let Some(scanner_id) = scanner_id else {
            return Ok(());
        };
        let Some(upload) = self.load_upload(origin, &scanner_id)? else {
            return Ok(());
        };
        let payload = serde_json::to_vec(&serde_json::json!({
            "scanner_id": upload.scanner_id, "task_id": upload.task_id,
            "upload_id": upload.upload_id, "next_batch_index": upload.next_batch_index,
            "observations": upload.observations,
        }))?;
        if payload.len() > 64 * 1024 * 1024 {
            return Err(ScannerError::Upload(
                "upload archive exceeds 64 MiB; pending results retained".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO upload_archive(server_origin, reason, payload, created_at) VALUES (?1, ?2, ?3, unixepoch())",
            params![origin, reason, payload])?;
        transaction.execute(
            "DELETE FROM pending_upload WHERE server_origin=?1",
            [origin],
        )?;
        transaction.execute("DELETE FROM upload_archive WHERE created_at < unixepoch()-604800 OR id NOT IN (SELECT id FROM upload_archive ORDER BY id DESC LIMIT 10)", [])?;
        // Retain the newest archive even when a single large upload exceeds the quota.
        loop {
            let bytes: i64 = transaction.query_row(
                "SELECT COALESCE(SUM(length(payload)),0) FROM upload_archive",
                [],
                |r| r.get(0),
            )?;
            if bytes <= 64 * 1024 * 1024 {
                break;
            }
            if transaction.execute("DELETE FROM upload_archive WHERE id=(SELECT MIN(id) FROM upload_archive) AND id<>(SELECT MAX(id) FROM upload_archive)", [])? == 0 { break; }
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn load_checkpoint(
        &self,
        origin: &str,
        key: &str,
    ) -> Result<Option<crate::journal::Checkpoint>, ScannerError> {
        let header: Option<(String, usize, usize, u64, Option<i64>)> = self.connection.query_row(
            "SELECT scan_key, stage, chunk, elapsed_ms, running_since_ms FROM scan_checkpoint WHERE server_origin=?1",
            [origin], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()?;
        let Some((stored_key, stage, chunk, mut elapsed_ms, running_since)) = header else {
            return Ok(None);
        };
        if stored_key != key {
            return Ok(None);
        }
        if let Some(since) = running_since {
            // Account for an interrupted block before clearing its marker. This is
            // conservative across downtime and prevents restarts resetting budgets.
            elapsed_ms = elapsed_ms.saturating_add(
                chrono::Utc::now()
                    .timestamp_millis()
                    .saturating_sub(since)
                    .max(0) as u64,
            );
            let transaction = self.connection.unchecked_transaction()?;
            transaction.execute("UPDATE scan_checkpoint SET elapsed_ms=?2,running_since_ms=NULL WHERE server_origin=?1", params![origin,elapsed_ms])?;
            transaction.execute("INSERT INTO scan_retry(server_origin,task_id,failures,retry_at_ms) VALUES (?1,?2,1,0) ON CONFLICT(server_origin,task_id) DO UPDATE SET failures=failures+1",
                params![origin,key.split('|').next().unwrap_or_default()])?;
            transaction.commit()?;
        }
        let mut statement = self.connection.prepare(
            "SELECT payload FROM scan_checkpoint_part WHERE server_origin=?1 ORDER BY stage, chunk",
        )?;
        let parts = statement.query_map([origin], |r| r.get::<_, Vec<u8>>(0))?;
        let mut observations = Vec::new();
        for part in parts {
            observations.extend(serde_json::from_slice::<Vec<ScanObservation>>(&part?)?);
        }
        Ok(Some(crate::journal::Checkpoint {
            stage,
            chunk,
            elapsed_ms,
            observations,
        }))
    }

    pub(crate) fn save_checkpoint(
        &self,
        origin: &str,
        key: &str,
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        part: Option<&[ScanObservation]>,
    ) -> Result<(), ScannerError> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM scan_checkpoint WHERE server_origin=?1 AND scan_key<>?2",
            params![origin, key],
        )?;
        transaction.execute("INSERT INTO scan_checkpoint(server_origin, scan_key, stage, chunk, elapsed_ms) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(server_origin) DO UPDATE SET stage=excluded.stage,chunk=excluded.chunk,elapsed_ms=excluded.elapsed_ms,running_since_ms=NULL",
            params![origin,key,stage,chunk,elapsed_ms])?;
        if let Some(part) = part {
            if chunk == 0 && stage > 0 {
                // Completing a stage replaces its incremental blocks with one
                // snapshot in the same transaction, without duplicate evidence.
                transaction.execute("DELETE FROM scan_checkpoint_part WHERE server_origin=?1 AND stage=?2 AND chunk>0", params![origin,stage-1])?;
            }
            transaction.execute("INSERT OR REPLACE INTO scan_checkpoint_part(server_origin,stage,chunk,payload) VALUES (?1,?2,?3,?4)", params![origin,stage,chunk,serde_json::to_vec(part)?])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn start_checkpoint_block(&self, origin: &str) -> Result<(), ScannerError> {
        self.connection.execute(
            "UPDATE scan_checkpoint SET running_since_ms=?2 WHERE server_origin=?1",
            params![origin, chrono::Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub(crate) fn clear_checkpoint(&self, origin: &str) -> Result<(), ScannerError> {
        self.connection.execute(
            "DELETE FROM scan_checkpoint WHERE server_origin=?1",
            [origin],
        )?;
        Ok(())
    }

    pub(crate) fn latest_scan_failure(
        &self,
        origin: &str,
    ) -> Result<Option<(Uuid, u32)>, ScannerError> {
        let record: Option<(String,u32)> = self.connection.query_row(
            "SELECT task_id,failures FROM scan_retry WHERE server_origin=?1 ORDER BY retry_at_ms DESC LIMIT 1",
            [origin], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        record
            .map(|(task, count)| Ok((parse_uuid(&task, "scan retry task_id")?, count.min(3))))
            .transpose()
    }

    pub(crate) fn scan_failures(
        &self,
        origin: &str,
        task_id: Uuid,
    ) -> Result<(u32, i64), ScannerError> {
        Ok(self
            .connection
            .query_row(
                "SELECT failures,retry_at_ms FROM scan_retry WHERE server_origin=?1 AND task_id=?2",
                params![origin, task_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or_default())
    }

    pub(crate) fn record_scan_failure(
        &self,
        origin: &str,
        task_id: Uuid,
    ) -> Result<(), ScannerError> {
        let (failures, _) = self.scan_failures(origin, task_id)?;
        let retry_at = chrono::Utc::now().timestamp_millis()
            + i64::from((5u32.saturating_mul(2u32.pow(failures.min(6)))).min(300)) * 1000;
        self.connection.execute("INSERT INTO scan_retry(server_origin,task_id,failures,retry_at_ms) VALUES (?1,?2,1,?3) ON CONFLICT(server_origin,task_id) DO UPDATE SET failures=failures+1,retry_at_ms=excluded.retry_at_ms",
            params![origin,task_id.to_string(),retry_at])?;
        Ok(())
    }

    pub(crate) fn clear_scan_failures(
        &self,
        origin: &str,
        task_id: Uuid,
    ) -> Result<(), ScannerError> {
        self.connection.execute(
            "DELETE FROM scan_retry WHERE server_origin=?1 AND task_id=?2",
            params![origin, task_id.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn load_identity(
        &self,
        server_origin: &str,
    ) -> Result<Option<StoredIdentity>, ScannerError> {
        self.connection
            .query_row(
                "SELECT scanner_id, runtime_token
                 FROM scanner_identity
                 WHERE server_origin = ?1",
                [server_origin],
                |row| {
                    Ok(StoredIdentity {
                        scanner_id: row.get(0)?,
                        runtime_token: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn save_identity(
        &self,
        server_origin: &str,
        identity: &StoredIdentity,
    ) -> Result<(), ScannerError> {
        self.connection.execute(
            "INSERT INTO scanner_identity (
                 server_origin, scanner_id, runtime_token, updated_at
             ) VALUES (?1, ?2, ?3, unixepoch())
             ON CONFLICT(server_origin) DO UPDATE SET
                 scanner_id = excluded.scanner_id,
                 runtime_token = excluded.runtime_token,
                 updated_at = excluded.updated_at",
            params![server_origin, identity.scanner_id, identity.runtime_token],
        )?;
        Ok(())
    }

    pub(crate) fn load_registration_fingerprint(
        &self,
        origin: &str,
    ) -> Result<Option<String>, ScannerError> {
        Ok(self
            .connection
            .query_row(
                "SELECT fingerprint FROM scanner_registration WHERE server_origin=?1",
                [origin],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn save_registered_identity(
        &mut self,
        origin: &str,
        identity: &StoredIdentity,
        fingerprint: &str,
    ) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO scanner_identity(server_origin,scanner_id,runtime_token,updated_at) VALUES(?1,?2,?3,unixepoch())
            ON CONFLICT(server_origin) DO UPDATE SET scanner_id=excluded.scanner_id,runtime_token=excluded.runtime_token,updated_at=excluded.updated_at",
            params![origin, identity.scanner_id, identity.runtime_token])?;
        transaction.execute(
            "INSERT INTO scanner_registration(server_origin,fingerprint) VALUES(?1,?2)
            ON CONFLICT(server_origin) DO UPDATE SET fingerprint=excluded.fingerprint",
            params![origin, fingerprint],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn load_runtime_configuration(
        &self,
        server_origin: &str,
    ) -> Result<Option<StoredRuntimeConfiguration>, ScannerError> {
        self.connection
            .query_row(
                "SELECT revision, schema_version, document_json FROM runtime_configuration WHERE server_origin = ?1",
                [server_origin],
                |row| Ok(StoredRuntimeConfiguration {
                    revision: row.get(0)?,
                    schema_version: row.get(1)?,
                    document: row.get(2)?,
                }),
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn save_runtime_configuration(
        &self,
        server_origin: &str,
        configuration: &crate::runtime_config::RuntimeConfigurationEnvelope,
    ) -> Result<(), ScannerError> {
        let document = serde_json::to_vec(&configuration.document)?;
        self.connection.execute(
            "INSERT INTO runtime_configuration (server_origin, revision, schema_version, document_json, updated_at) \
             VALUES (?1, ?2, ?3, ?4, unixepoch()) ON CONFLICT(server_origin) DO UPDATE SET \
             revision = excluded.revision, schema_version = excluded.schema_version, \
             document_json = excluded.document_json, updated_at = excluded.updated_at",
            params![server_origin, configuration.revision, configuration.schema_version, document],
        )?;
        Ok(())
    }

    pub(crate) fn load_upload(
        &self,
        server_origin: &str,
        scanner_id: &str,
    ) -> Result<Option<StoredUpload>, ScannerError> {
        let header: Option<(String, String, String, i64)> = self
            .connection
            .query_row(
                "SELECT scanner_id, task_id, upload_id, next_batch_index
                 FROM pending_upload
                 WHERE server_origin = ?1",
                [server_origin],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((stored_scanner_id, task_id, upload_id, next_batch_index)) = header else {
            return Ok(None);
        };
        if stored_scanner_id != scanner_id {
            return Err(ScannerError::Config(format!(
                "pending upload for {server_origin} belongs to scanner {stored_scanner_id}, not current scanner {scanner_id}"
            )));
        }

        let task_id = parse_uuid(&task_id, "stored task_id")?;
        let upload_id = parse_uuid(&upload_id, "stored upload_id")?;
        let next_batch_index = u32::try_from(next_batch_index).map_err(|_| {
            ScannerError::Config("stored next_batch_index is outside the u32 range".into())
        })?;
        let mut statement = self.connection.prepare(
            "SELECT payload_json
             FROM observation
             WHERE server_origin = ?1
             ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([server_origin], |row| row.get::<_, Vec<u8>>(0))?;
        let mut observations = Vec::new();
        for row in rows {
            observations.push(serde_json::from_slice(&row?)?);
        }

        Ok(Some(StoredUpload {
            scanner_id: stored_scanner_id,
            task_id,
            upload_id,
            next_batch_index,
            observations,
        }))
    }

    pub(crate) fn pending_upload_scanner_id(
        &self,
        server_origin: &str,
    ) -> Result<Option<String>, ScannerError> {
        self.connection
            .query_row(
                "SELECT scanner_id
                 FROM pending_upload
                 WHERE server_origin = ?1",
                [server_origin],
                |row| row.get(0),
            )
            .optional()
            .map_err(ScannerError::from)
    }

    pub(crate) fn begin_upload(
        &mut self,
        server_origin: &str,
        scanner_id: &str,
        task_id: Uuid,
        upload_id: Uuid,
        observations: &[ScanObservation],
    ) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO pending_upload (
                 server_origin, scanner_id, task_id, upload_id, next_batch_index, created_at
             ) VALUES (?1, ?2, ?3, ?4, 0, unixepoch())",
            params![
                server_origin,
                scanner_id,
                task_id.to_string(),
                upload_id.to_string()
            ],
        )?;

        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO observation (
                     server_origin, sequence, identity, payload_json
                 ) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut sequence = 0i64;
            for observation in observations {
                let payload = serde_json::to_vec(observation)?;
                let inserted = statement.execute(params![
                    server_origin,
                    sequence,
                    observation.identity(),
                    payload
                ])?;
                sequence = sequence
                    .checked_add(i64::try_from(inserted).map_err(|_| {
                        ScannerError::Upload("observation sequence exceeded i64".into())
                    })?)
                    .ok_or_else(|| {
                        ScannerError::Upload("observation sequence exceeded i64".into())
                    })?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_observation(
        &self,
        server_origin: &str,
        sequence: usize,
        observation: &ScanObservation,
    ) -> Result<bool, ScannerError> {
        let sequence = i64::try_from(sequence)
            .map_err(|_| ScannerError::Upload("observation sequence exceeded i64".into()))?;
        let payload = serde_json::to_vec(observation)?;
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO observation (
                 server_origin, sequence, identity, payload_json
             ) VALUES (?1, ?2, ?3, ?4)",
            params![server_origin, sequence, observation.identity(), payload],
        )?;
        Ok(inserted == 1)
    }

    pub(crate) fn import_upload(
        &mut self,
        server_origin: &str,
        upload: &StoredUpload,
    ) -> Result<(), ScannerError> {
        self.begin_upload(
            server_origin,
            &upload.scanner_id,
            upload.task_id,
            upload.upload_id,
            &upload.observations,
        )?;
        if upload.next_batch_index > 0 {
            self.set_next_batch_index(server_origin, upload.next_batch_index)?;
        }
        Ok(())
    }

    pub(crate) fn set_next_batch_index(
        &self,
        server_origin: &str,
        next_batch_index: u32,
    ) -> Result<(), ScannerError> {
        let updated = self.connection.execute(
            "UPDATE pending_upload
             SET next_batch_index = ?2
             WHERE server_origin = ?1",
            params![server_origin, i64::from(next_batch_index)],
        )?;
        if updated != 1 {
            return Err(ScannerError::Upload(
                "cannot update upload progress without a pending task".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn clear_upload(&mut self, server_origin: &str) -> Result<(), ScannerError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM pending_upload WHERE server_origin = ?1",
            [server_origin],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn migrate(connection: &mut Connection) -> Result<(), ScannerError> {
    let current_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current_version > SCHEMA_VERSION {
        return Err(ScannerError::Config(format!(
            "state database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
        )));
    }
    if current_version < 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE scanner_identity (
             server_origin TEXT PRIMARY KEY NOT NULL,
             scanner_id TEXT NOT NULL,
             runtime_token TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE pending_upload (
             server_origin TEXT PRIMARY KEY NOT NULL,
             scanner_id TEXT NOT NULL,
             task_id TEXT NOT NULL,
             upload_id TEXT NOT NULL,
             next_batch_index INTEGER NOT NULL CHECK(next_batch_index >= 0),
             created_at INTEGER NOT NULL
         );

         CREATE TABLE observation (
             server_origin TEXT NOT NULL,
             sequence INTEGER NOT NULL CHECK(sequence >= 0),
             identity TEXT NOT NULL,
             payload_json BLOB NOT NULL,
             PRIMARY KEY (server_origin, sequence),
             UNIQUE (server_origin, identity),
             FOREIGN KEY (server_origin) REFERENCES pending_upload(server_origin)
                 ON DELETE CASCADE
         );

             PRAGMA user_version = 1;",
        )?;
        transaction.commit()?;
    }
    if current_version < 2 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE runtime_configuration (
                 server_origin TEXT PRIMARY KEY NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision > 0),
                 schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                 document_json BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             PRAGMA user_version = 2;",
        )?;
        transaction.commit()?;
    }
    if current_version < 3 {
        let transaction = connection.transaction()?;
        transaction.execute_batch("CREATE TABLE upload_archive(id INTEGER PRIMARY KEY,server_origin TEXT NOT NULL,reason TEXT NOT NULL,payload BLOB NOT NULL,created_at INTEGER NOT NULL);
            CREATE TABLE scan_checkpoint(server_origin TEXT PRIMARY KEY,scan_key TEXT NOT NULL,stage INTEGER NOT NULL,chunk INTEGER NOT NULL,elapsed_ms INTEGER NOT NULL,running_since_ms INTEGER);
            CREATE TABLE scan_checkpoint_part(server_origin TEXT NOT NULL,stage INTEGER NOT NULL,chunk INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(server_origin,stage,chunk),FOREIGN KEY(server_origin) REFERENCES scan_checkpoint(server_origin) ON DELETE CASCADE);
            CREATE TABLE scan_retry(server_origin TEXT NOT NULL,task_id TEXT NOT NULL,failures INTEGER NOT NULL,retry_at_ms INTEGER NOT NULL,PRIMARY KEY(server_origin,task_id));
            PRAGMA user_version=3;")?;
        transaction.commit()?;
    }
    if current_version < 4 {
        let transaction = connection.transaction()?;
        transaction.execute_batch("CREATE TABLE scanner_registration(server_origin TEXT PRIMARY KEY REFERENCES scanner_identity(server_origin) ON DELETE CASCADE,fingerprint TEXT NOT NULL); PRAGMA user_version=4;")?;
        transaction.commit()?;
    }
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ScannerError> {
    Uuid::parse_str(value).map_err(|error| {
        ScannerError::Config(format!("invalid {field} in state database: {error}"))
    })
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), ScannerError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(ScannerError::Io)?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(ScannerError::Io)
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), ScannerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn registration_identity_and_fingerprint_survive_reopen_and_are_scoped_to_server() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let identity = StoredIdentity {
            scanner_id: "id".into(),
            runtime_token: "runtime-secret".into(),
        };
        store
            .save_registered_identity("https://server-a", &identity, "fingerprint")
            .unwrap();
        drop(store);
        let store = StateStore::open(path.clone()).unwrap();
        assert_eq!(
            store.load_identity("https://server-a").unwrap(),
            Some(identity)
        );
        assert_eq!(
            store
                .load_registration_fingerprint("https://server-a")
                .unwrap()
                .as_deref(),
            Some("fingerprint")
        );
        assert!(
            store
                .load_registration_fingerprint("https://server-b")
                .unwrap()
                .is_none()
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn failed_registration_persistence_does_not_replace_the_old_identity() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let old = StoredIdentity {
            scanner_id: "id".into(),
            runtime_token: "old".into(),
        };
        store.save_identity("origin", &old).unwrap();
        store.connection.execute_batch("CREATE TRIGGER reject_registration BEFORE INSERT ON scanner_registration BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        let new = StoredIdentity {
            scanner_id: "id".into(),
            runtime_token: "new".into(),
        };
        assert!(
            store
                .save_registered_identity("origin", &new, "new-fingerprint")
                .is_err()
        );
        assert_eq!(store.load_identity("origin").unwrap(), Some(old));
        assert!(
            store
                .load_registration_fingerprint("origin")
                .unwrap()
                .is_none()
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn schema_two_upgrade_preserves_pending_upload_and_identity() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let task = Uuid::now_v7();
        let upload = Uuid::now_v7();
        store
            .save_identity(
                "origin",
                &StoredIdentity {
                    scanner_id: "scanner".into(),
                    runtime_token: "fixture-token".into(),
                },
            )
            .unwrap();
        store
            .begin_upload("origin", "scanner", task, upload, &[])
            .unwrap();
        store.connection.execute_batch("DROP TABLE scanner_registration; DROP TABLE scan_checkpoint_part; DROP TABLE scan_checkpoint; DROP TABLE scan_retry; DROP TABLE upload_archive; PRAGMA user_version=2;").unwrap();
        drop(store);
        let store = StateStore::open(path.clone()).unwrap();
        let state = store.load_upload("origin", "scanner").unwrap().unwrap();
        assert_eq!(state.task_id, task);
        assert_eq!(state.upload_id, upload);
        assert_eq!(
            store
                .load_identity("origin")
                .unwrap()
                .unwrap()
                .runtime_token,
            "fixture-token"
        );
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn checkpoint_blocks_and_retry_counts_survive_reopen() {
        let path = database_path();
        let task = Uuid::now_v7();
        let key = format!("{task}|configuration-1");
        let store = StateStore::open(path.clone()).unwrap();
        store
            .save_checkpoint("origin", &key, 1, 2, 350, Some(&[]))
            .unwrap();
        store.record_scan_failure("origin", task).unwrap();
        drop(store);
        let store = StateStore::open(path.clone()).unwrap();
        let state = store.load_checkpoint("origin", &key).unwrap().unwrap();
        assert_eq!((state.stage, state.chunk, state.elapsed_ms), (1, 2, 350));
        assert_eq!(store.scan_failures("origin", task).unwrap().0, 1);
        assert!(
            store
                .load_checkpoint("origin", "changed-configuration")
                .unwrap()
                .is_none()
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unclean_restart_consumes_budget_and_counts_failure_only_once() {
        let path = database_path();
        let task = Uuid::now_v7();
        let key = format!("{task}|config");
        let store = StateStore::open(path.clone()).unwrap();
        store
            .save_checkpoint("origin", &key, 1, 0, 100, None)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE scan_checkpoint SET running_since_ms=?1",
                [chrono::Utc::now().timestamp_millis() - 5000],
            )
            .unwrap();
        drop(store);
        let store = StateStore::open(path.clone()).unwrap();
        assert!(
            store
                .load_checkpoint("origin", &key)
                .unwrap()
                .unwrap()
                .elapsed_ms
                >= 5100
        );
        store.load_checkpoint("origin", &key).unwrap();
        assert_eq!(store.scan_failures("origin", task).unwrap().0, 1);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn archiving_preserves_upload_identity_and_observations() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let task = Uuid::now_v7();
        let upload = Uuid::now_v7();
        store
            .begin_upload("origin", "scanner", task, upload, &[])
            .unwrap();
        store.archive_upload("origin", "server_cancelled").unwrap();
        assert!(store.load_upload("origin", "scanner").unwrap().is_none());
        let bytes: Vec<u8> = store
            .connection
            .query_row("SELECT payload FROM upload_archive", [], |r| r.get(0))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["task_id"], task.to_string());
        assert_eq!(value["upload_id"], upload.to_string());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    use super::*;
    use crate::scan::{PortObservation, ScanObservation};

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!("scanner-state-{}.sqlite3", Uuid::now_v7()))
    }

    fn observation(port: u16) -> ScanObservation {
        ScanObservation::Port(PortObservation {
            ip: "192.0.2.1".into(),
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            source: "masscan".into(),
            observed_at: 1,
        })
    }

    #[test]
    fn identity_is_scoped_to_server_origin() {
        let path = database_path();
        let store = StateStore::open(path.clone()).unwrap();
        let identity = StoredIdentity {
            scanner_id: Uuid::now_v7().to_string(),
            runtime_token: "secret".into(),
        };
        store
            .save_identity("https://scanner.example:443", &identity)
            .unwrap();

        assert_eq!(
            store.load_identity("https://scanner.example:443").unwrap(),
            Some(identity)
        );
        assert_eq!(
            store.load_identity("https://other.example:443").unwrap(),
            None
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn upload_state_round_trips_in_stable_order() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let task_id = Uuid::now_v7();
        let upload_id = Uuid::now_v7();
        store
            .begin_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
                task_id,
                upload_id,
                &[observation(443), observation(80), observation(443)],
            )
            .unwrap();
        store
            .set_next_batch_index("https://scanner.example:443", 1)
            .unwrap();

        let restored = store
            .load_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
            )
            .unwrap()
            .unwrap();
        assert_eq!(restored.task_id, task_id);
        assert_eq!(restored.upload_id, upload_id);
        assert_eq!(restored.next_batch_index, 1);
        assert_eq!(restored.observations.len(), 2);
        assert_eq!(
            restored.observations[0].identity(),
            observation(443).identity()
        );
        assert_eq!(
            restored.observations[1].identity(),
            observation(80).identity()
        );

        store.clear_upload("https://scanner.example:443").unwrap();
        assert!(
            store
                .load_upload(
                    "https://scanner.example:443",
                    "019c0000-0000-7000-8000-000000000001",
                )
                .unwrap()
                .is_none()
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pending_upload_cannot_move_to_a_different_scanner_identity() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        store
            .begin_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000001",
                Uuid::now_v7(),
                Uuid::now_v7(),
                &[observation(443)],
            )
            .unwrap();
        assert_eq!(
            store
                .pending_upload_scanner_id("https://scanner.example:443")
                .unwrap()
                .as_deref(),
            Some("019c0000-0000-7000-8000-000000000001")
        );

        let error = store
            .load_upload(
                "https://scanner.example:443",
                "019c0000-0000-7000-8000-000000000002",
            )
            .unwrap_err();
        assert!(error.to_string().contains("belongs to scanner"));
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cache_clear_preserves_identity_and_optionally_runtime_configuration() {
        let path = database_path();
        let mut store = StateStore::open(path.clone()).unwrap();
        let origin = "https://scanner.example:443";
        let identity = StoredIdentity {
            scanner_id: Uuid::now_v7().to_string(),
            runtime_token: "secret".into(),
        };
        store.save_identity(origin, &identity).unwrap();
        store
            .begin_upload(
                origin,
                &identity.scanner_id,
                Uuid::now_v7(),
                Uuid::now_v7(),
                &[observation(443)],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO runtime_configuration(server_origin,revision,schema_version,document_json,updated_at) VALUES(?1,1,1,'{}',unixepoch())",
                [origin],
            )
            .unwrap();

        assert_eq!(
            store.cache_summary(Some(origin)).unwrap(),
            CacheSummary {
                pending_tasks: 1,
                observations: 1,
                runtime_configurations: 1,
            }
        );
        store.clear_cache(Some(origin), false).unwrap();
        assert_eq!(store.load_identity(origin).unwrap(), Some(identity.clone()));
        assert_eq!(
            store.cache_summary(Some(origin)).unwrap(),
            CacheSummary {
                pending_tasks: 0,
                observations: 0,
                runtime_configurations: 1,
            }
        );
        store.clear_cache(Some(origin), true).unwrap();
        assert_eq!(store.load_identity(origin).unwrap(), Some(identity));
        assert_eq!(
            store
                .cache_summary(Some(origin))
                .unwrap()
                .runtime_configurations,
            0
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
