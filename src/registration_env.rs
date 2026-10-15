//! One-time env registration inputs are separate from persisted runtime credentials.
use crate::error::ScannerError;
use sha2::{Digest, Sha256};

#[derive(Default)]
pub(crate) struct Registration {
    pub(crate) scanner_id: Option<String>,
    pub(crate) token: Option<String>,
}

pub(crate) fn fingerprint(id: &str, token: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(id.as_bytes());
    hash.update([0]);
    hash.update(token.as_bytes());
    format!("{:x}", hash.finalize())
}

pub(crate) fn load() -> Result<Registration, ScannerError> {
    let mut raw = serde_json::json!({"registration":{"scanner_id":"", "token":""}});
    crate::config_env::apply(
        &mut raw,
        std::env::vars().filter(|(k, _)| k.starts_with("NM__REGISTRATION__")),
        |f| matches!(f, "registration.scanner_id" | "registration.token"),
    )?;
    let nonempty = |key: &str| {
        raw["registration"][key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let scanner_id = nonempty("scanner_id");
    let token = nonempty("token");
    if token.is_some() && scanner_id.is_none() {
        return Err(ScannerError::Config(
            "NM__REGISTRATION__SCANNER_ID is required with a registration token".into(),
        ));
    }
    if let Some(id) = &scanner_id {
        uuid::Uuid::parse_str(id)
            .map_err(|_| ScannerError::Config("registration scanner ID must be a UUID".into()))?;
    }
    Ok(Registration { scanner_id, token })
}

impl Registration {
    pub(crate) fn needs_registration(
        &self,
        stored_id: &str,
        has_identity: bool,
        previous: Option<&str>,
    ) -> Result<bool, ScannerError> {
        match (&self.scanner_id, &self.token) {
            (None, None) => Ok(false),
            (Some(id), None) if has_identity && id == stored_id => Ok(false),
            (Some(_), None) => Err(ScannerError::Config(
                "registration token is required for a new or different scanner identity".into(),
            )),
            (Some(id), Some(token)) => {
                let same_credentials = previous == Some(fingerprint(id, token).as_str());
                if same_credentials && has_identity && id == stored_id {
                    return Ok(false);
                }
                if same_credentials {
                    return Err(ScannerError::Config("registration credentials were already consumed for a different stored identity; issue a new token".into()));
                }
                Ok(true)
            }
            _ => Err(ScannerError::Config(
                "scanner ID is required for registration".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_registration_and_changed_token_register_but_restart_does_not() {
        let input = Registration {
            scanner_id: Some("id".into()),
            token: Some("one-time".into()),
        };
        assert!(input.needs_registration("", false, None).unwrap());
        let used = fingerprint("id", "one-time");
        assert!(!input.needs_registration("id", true, Some(&used)).unwrap());
        let changed = Registration {
            scanner_id: Some("id".into()),
            token: Some("new-one-time".into()),
        };
        assert!(changed.needs_registration("id", true, Some(&used)).unwrap());
    }
    #[test]
    fn removing_bootstrap_token_preserves_identity_but_does_not_switch_ids() {
        let input = Registration {
            scanner_id: Some("id".into()),
            token: None,
        };
        assert!(!input.needs_registration("id", true, None).unwrap());
        assert!(input.needs_registration("other", true, None).is_err());
        assert!(input.needs_registration("", false, None).is_err());
    }
    #[test]
    fn fingerprints_are_scoped_to_both_id_and_token() {
        assert_ne!(fingerprint("a", "bc"), fingerprint("ab", "c"));
        assert_ne!(fingerprint("a", "token"), fingerprint("b", "token"));
        assert_eq!(fingerprint("id", "secret").len(), 64);
    }
}
