//! Versioned execution modules. The agent owns credentials, leases and durable state.
pub(crate) mod host;
pub(crate) mod package;
pub(crate) mod protocol;
pub(crate) mod registry;
pub(crate) mod update;
pub(crate) mod worker;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ModulesConfig {
    pub(crate) enabled: bool,
    pub(crate) directory: PathBuf,
    pub(crate) state_database: PathBuf,
    pub(crate) worker_path: PathBuf,
    pub(crate) trusted_keys: PathBuf,
    pub(crate) cancel_grace_seconds: u64,
    pub(crate) stage_timeout_seconds: u64,
    pub(crate) desired_url: Option<String>,
    pub(crate) auto_rollback: bool,
}

impl Default for ModulesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: "./scanner-modules".into(),
            state_database: "./scanner-modules.sqlite3".into(),
            worker_path: "./scanner-worker".into(),
            trusted_keys: "./trusted-update-keys.json".into(),
            cancel_grace_seconds: 5,
            stage_timeout_seconds: 86400,
            desired_url: None,
            auto_rollback: true,
        }
    }
}
