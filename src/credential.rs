//! Credential encryption via the OS keychain (feature `keychain`).
//!
//! Secret fields in `cfg.toml` (`password`, `ttshitu.password`, `bark.token`) are
//! stored EITHER as a literal plaintext value OR as a sentinel of the form
//! `keyring:<key>` whose real value lives in the OS keychain. [`crate::config::read_cfg`]
//! resolves sentinels to real secrets and transparently migrates plaintext →
//! keychain on first read when the keychain is available; [`crate::config::write_cfg`]
//! seals real values into the keychain and writes the sentinel. When the keychain
//! is unavailable, both paths degrade to plaintext with a `log::warn!` — logins
//! never block.
//!
//! Behaviour matrix:
//! - Never migrated (plaintext cfg) → always readable, no encryption.
//! - Migrated (sentinel cfg), keychain up → readable, encrypted at rest.
//! - Migrated (sentinel cfg), keychain down → read fails with a clear error
//!   (encryption's inherent cost; not a bug).
//!
//! The OS-keychain backend is pulled in only under `feature = "keychain"`; otherwise
//! [`default_store`] returns an [`Unavailable`] store and every operation degrades
//! to plaintext identity. This module itself compiles unconditionally.

/// Sentinel prefix marking a field whose real value is in the OS keychain.
pub const SENTINEL_PREFIX: &str = "keyring:";

/// The keychain key each secret field maps to.
pub const PASSWORD_KEY: &str = "portal.password";
pub const TTSHITU_PASSWORD_KEY: &str = "ttshitu.password";
pub const BARK_TOKEN_KEY: &str = "bark.token";

/// Injectable secret-store backend. Production uses the OS keychain (feature
/// `keychain`); tests inject an in-memory implementation.
pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> anyhow::Result<String>;
    fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;
}

/// A store whose every operation fails — used when the keychain is unavailable
/// (feature off, or the backend could not be constructed). resolve/seal then
/// degrade to plaintext uniformly.
pub struct Unavailable;
impl SecretStore for Unavailable {
    fn get(&self, _key: &str) -> anyhow::Result<String> {
        Err(anyhow::anyhow!("keychain unavailable"))
    }
    fn set(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("keychain unavailable"))
    }
}

#[cfg(feature = "keychain")]
mod imp {
    use super::SecretStore;

    /// The production backend: the OS keychain via the `keyring` crate. Uses the
    /// **sync** secret-service backend on Linux (no tokio/async dependency), so it
    /// is safe to call from compio's polling runtime for these rare, brief lookups.
    struct KeyringStore;

    impl SecretStore for KeyringStore {
        fn get(&self, key: &str) -> anyhow::Result<String> {
            let entry = keyring::Entry::new("pku3b", key)
                .map_err(|e| anyhow::anyhow!("keyring entry: {e}"))?;
            entry
                .get_password()
                .map_err(|e| anyhow::anyhow!("keyring get: {e}"))
        }
        fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
            let entry = keyring::Entry::new("pku3b", key)
                .map_err(|e| anyhow::anyhow!("keyring entry: {e}"))?;
            entry
                .set_password(value)
                .map_err(|e| anyhow::anyhow!("keyring set: {e}"))
        }
    }

    pub fn default_store() -> &'static dyn SecretStore {
        static KEYRING: KeyringStore = KeyringStore;
        &KEYRING
    }
}

#[cfg(not(feature = "keychain"))]
mod imp {
    use super::{SecretStore, Unavailable};
    pub fn default_store() -> &'static dyn SecretStore {
        static UNAVAILABLE: Unavailable = Unavailable;
        &UNAVAILABLE
    }
}

/// The active secret-store backend (OS keychain under `keychain`, else
/// [`Unavailable`]).
pub fn default_store() -> &'static dyn SecretStore {
    imp::default_store()
}

/// True if `raw` is a `keyring:<key>` sentinel.
pub fn is_sentinel(raw: &str) -> bool {
    raw.starts_with(SENTINEL_PREFIX)
}

/// Build a sentinel string for a key.
pub fn sentinel(key: &str) -> String {
    format!("{SENTINEL_PREFIX}{key}")
}

/// Resolve a raw cfg field value to the real secret.
///
/// - Plaintext passes through unchanged.
/// - Sentinel `keyring:<key>` is fetched from the store; on failure the field
///   becomes empty (the real value exists only in the keychain — unrecoverable
///   without it) and an `error!` is logged.
pub fn resolve_value(store: &dyn SecretStore, key: &str, raw: &str) -> String {
    if let Some(k) = raw.strip_prefix(SENTINEL_PREFIX) {
        match store.get(k) {
            Ok(v) => v,
            Err(e) => {
                log::error!(
                    "无法从系统钥匙串读取 {key}（sentinel）：{e}；请启动 keyring 守护进程或重新 `pku3b init`"
                );
                String::new()
            }
        }
    } else {
        raw.to_string()
    }
}

/// Seal a real value into the keychain, returning the sentinel.
///
/// On success returns `keyring:<key>`. If the value is already a sentinel it is
/// returned unchanged. On store failure the plaintext is returned unchanged and a
/// `warn!` is logged (the caller keeps working with plaintext).
pub fn seal_value(store: &dyn SecretStore, key: &str, value: &str) -> String {
    if value.starts_with(SENTINEL_PREFIX) {
        return value.to_string();
    }
    match store.set(key, value) {
        Ok(()) => sentinel(key),
        Err(e) => {
            log::warn!("系统钥匙串不可用，{key} 以明文存储：{e}");
            value.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory store for pure unit tests (no OS keychain / D-Bus).
    struct MemStore {
        map: Mutex<std::collections::HashMap<String, String>>,
        fail: bool,
    }
    impl MemStore {
        fn new() -> Self {
            Self {
                map: Mutex::new(std::collections::HashMap::new()),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                map: Mutex::new(std::collections::HashMap::new()),
                fail: true,
            }
        }
    }
    impl SecretStore for MemStore {
        fn get(&self, key: &str) -> anyhow::Result<String> {
            if self.fail {
                return Err(anyhow::anyhow!("simulated unavailable"));
            }
            self.map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not found"))
        }
        fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
            if self.fail {
                return Err(anyhow::anyhow!("simulated unavailable"));
            }
            self.map
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    #[test]
    fn sentinel_detection_and_builder() {
        assert!(is_sentinel("keyring:portal.password"));
        assert!(!is_sentinel("hunter2"));
        assert_eq!(sentinel("portal.password"), "keyring:portal.password");
    }

    #[test]
    fn resolve_plaintext_passes_through() {
        let store = MemStore::new();
        assert_eq!(resolve_value(&store, PASSWORD_KEY, "hunter2"), "hunter2");
    }

    #[test]
    fn seal_then_resolve_round_trips_through_keychain() {
        let store = MemStore::new();
        let sealed = seal_value(&store, PASSWORD_KEY, "hunter2");
        assert_eq!(sealed, "keyring:portal.password");
        // The real value now lives in the store, not the string.
        assert_eq!(resolve_value(&store, PASSWORD_KEY, &sealed), "hunter2");
    }

    #[test]
    fn seal_on_unavailable_store_keeps_plaintext() {
        let store = MemStore::failing();
        let sealed = seal_value(&store, PASSWORD_KEY, "hunter2");
        assert_eq!(sealed, "hunter2"); // degraded, not lost
    }

    #[test]
    fn resolve_sentinel_on_unavailable_store_yields_empty() {
        // Once migrated, the value is ONLY in the keychain — without it the
        // field is unrecoverable (encryption's inherent cost).
        let store = MemStore::failing();
        assert_eq!(resolve_value(&store, PASSWORD_KEY, "keyring:portal.password"), "");
    }

    #[test]
    fn seal_is_idempotent_on_already_sentinel() {
        let store = MemStore::new();
        let s = "keyring:portal.password";
        assert_eq!(seal_value(&store, PASSWORD_KEY, s), s);
    }

    #[test]
    fn unavailable_store_always_errors() {
        let u = Unavailable;
        assert!(u.get(PASSWORD_KEY).is_err());
        assert!(u.set(PASSWORD_KEY, "x").is_err());
    }
}
