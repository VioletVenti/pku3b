use compio::fs;

use crate::credential;

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub ttshitu: Option<TTShiTuConfig>,
    pub bark: Option<BarkConfig>,

    pub auto_supplement: Option<Vec<SupplementCourseConfig>>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct SupplementCourseConfig {
    pub page_id: usize,
    pub name: String,
    pub teacher: String,
    pub class_id: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct TTShiTuConfig {
    pub username: String,
    pub password: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct BarkConfig {
    pub token: String,
}

impl Config {
    pub fn display(&self, attr: ConfigAttrs, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        use std::io::Write as _;
        match attr {
            ConfigAttrs::Username => writeln!(buf, "{}", self.username)?,
            ConfigAttrs::Password => writeln!(buf, "{}", self.password)?,
            ConfigAttrs::TTShiTuUsername => {
                if let Some(tt) = &self.ttshitu {
                    writeln!(buf, "{}", tt.username)?
                } else {
                    writeln!(buf, "<not set>")?
                }
            }
            ConfigAttrs::TTShiTuPassword => {
                if let Some(tt) = &self.ttshitu {
                    writeln!(buf, "{}", tt.password)?
                } else {
                    writeln!(buf, "<not set>")?
                }
            }
            ConfigAttrs::BarkToken => {
                if let Some(bark) = &self.bark {
                    writeln!(buf, "{}", bark.token)?
                } else {
                    writeln!(buf, "<not set>")?
                }
            }
        };
        Ok(())
    }

    pub fn update(&mut self, attr: ConfigAttrs, value: String) -> anyhow::Result<()> {
        match attr {
            ConfigAttrs::Username => self.username = value,
            ConfigAttrs::Password => self.password = value,
            ConfigAttrs::TTShiTuUsername => {
                if let Some(tt) = &mut self.ttshitu {
                    tt.username = value
                } else {
                    self.ttshitu = Some(TTShiTuConfig {
                        username: value,
                        password: String::new(),
                    })
                }
            }
            ConfigAttrs::TTShiTuPassword => {
                if let Some(tt) = &mut self.ttshitu {
                    tt.password = value
                } else {
                    self.ttshitu = Some(TTShiTuConfig {
                        username: String::new(),
                        password: value,
                    })
                }
            }
            ConfigAttrs::BarkToken => self.bark = Some(BarkConfig { token: value }),
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ConfigAttrs {
    Username,
    Password,
    TTShiTuUsername,
    TTShiTuPassword,
    BarkToken,
}

impl clap::ValueEnum for ConfigAttrs {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Username,
            Self::Password,
            Self::TTShiTuUsername,
            Self::TTShiTuPassword,
            Self::BarkToken,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Self::Username => Some(clap::builder::PossibleValue::new("username")),
            Self::Password => Some(clap::builder::PossibleValue::new("password")),
            Self::TTShiTuUsername => Some(clap::builder::PossibleValue::new("ttshitu.username")),
            Self::TTShiTuPassword => Some(clap::builder::PossibleValue::new("ttshitu.password")),
            Self::BarkToken => Some(clap::builder::PossibleValue::new("bark.token")),
        }
    }
}

/// Reads the configuration from the specified file path asynchronously.
///
/// # Errors
///
/// This function will return an error if:
/// - The file does not exist.
/// - The file cannot be opened.
/// - The file contents cannot be read.
/// - The file contents cannot be parsed as TOML.
///
/// Reads the configuration from the specified file path asynchronously.
///
/// Secret fields (`password`, `ttshitu.password`, `bark.token`) are resolved:
/// a `keyring:<key>` sentinel is fetched from the OS keychain and a literal
/// plaintext value passes through. When a plaintext field is found AND the
/// keychain is available, it is **transparently migrated** — stored to the
/// keychain and the field on disk rewritten as a sentinel (one-time, logged).
/// If the keychain is unavailable, plaintext is retained with a `warn!`.
///
/// Note: this "read" may therefore perform a one-time migration write-back.
///
/// # Errors
///
/// This function will return an error if:
/// - The file does not exist.
/// - The file cannot be opened.
/// - The file contents cannot be read.
/// - The file contents cannot be parsed as TOML.
///
pub async fn read_cfg(path: impl AsRef<std::path::Path>) -> anyhow::Result<Config> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("file not found");
    }

    let buffer = fs::read(path).await?;
    let content = String::from_utf8(buffer)?; //.context("invalid UTF-8")?;
    let parsed: Config = toml::from_str(&content)?;

    let store = credential::default_store();
    let (cfg, rewrite, dirty) = resolve_and_migrate(store, parsed);
    if dirty {
        write_cfg_raw(path, &rewrite).await?;
    }

    Ok(cfg)
}

/// Resolve sentinels → real secrets and detect plaintext fields eligible for
/// migration, given a secret store. Returns:
/// - `use_cfg`: the config with real secrets populated (sentinels fetched;
///   plaintext kept) — what callers consume.
/// - `rewrite_cfg`: the config to persist on disk (sentinels for migrated
///   fields) — only meaningful when `dirty` is true.
/// - `dirty`: whether any plaintext field was migrated to the keychain.
///
/// Extracted from [`read_cfg`] so the migration behaviour is unit-testable with
/// an injected store (no OS keychain / D-Bus needed).
fn resolve_and_migrate(
    store: &dyn credential::SecretStore,
    parsed: Config,
) -> (Config, Config, bool) {
    let mut cfg = parsed.clone(); // callers get real secrets
    let mut rewrite = parsed; // persisted form (sentinels for migrated fields)
    let mut dirty = false;

    // portal password
    if credential::is_sentinel(&cfg.password) {
        cfg.password = credential::resolve_value(store, credential::PASSWORD_KEY, &cfg.password);
    } else {
        let sealed = credential::seal_value(store, credential::PASSWORD_KEY, &cfg.password);
        if credential::is_sentinel(&sealed) {
            rewrite.password = sealed;
            dirty = true;
            log::info!("已将 password 迁移至系统钥匙串");
        }
    }

    // ttshitu password (username stays plaintext — not a secret)
    if let Some(tt) = cfg.ttshitu.as_mut()
        && let Some(rt) = rewrite.ttshitu.as_mut()
    {
        if credential::is_sentinel(&tt.password) {
            tt.password =
                credential::resolve_value(store, credential::TTSHITU_PASSWORD_KEY, &tt.password);
        } else {
            let sealed =
                credential::seal_value(store, credential::TTSHITU_PASSWORD_KEY, &tt.password);
            if credential::is_sentinel(&sealed) {
                rt.password = sealed;
                dirty = true;
                log::info!("已将 ttshitu.password 迁移至系统钥匙串");
            }
        }
    }

    // bark token
    if let Some(b) = cfg.bark.as_mut()
        && let Some(rb) = rewrite.bark.as_mut()
    {
        if credential::is_sentinel(&b.token) {
            b.token = credential::resolve_value(store, credential::BARK_TOKEN_KEY, &b.token);
        } else {
            let sealed = credential::seal_value(store, credential::BARK_TOKEN_KEY, &b.token);
            if credential::is_sentinel(&sealed) {
                rb.token = sealed;
                dirty = true;
                log::info!("已将 bark.token 迁移至系统钥匙串");
            }
        }
    }

    (cfg, rewrite, dirty)
}

/// Writes the configuration, sealing any plaintext secret fields into the OS
/// keychain first (the file then holds sentinels). Fields already sealed, and
/// non-secret fields, pass through. If the keychain is unavailable, secrets are
/// written as plaintext with a `warn!` (degrade, never block).
pub async fn write_cfg(path: impl AsRef<std::path::Path>, cfg: &Config) -> anyhow::Result<()> {
    let store = credential::default_store();
    let mut sealed = cfg.clone();

    sealed.password = credential::seal_value(store, credential::PASSWORD_KEY, &sealed.password);
    if let Some(tt) = &sealed.ttshitu {
        let sealed_pw =
            credential::seal_value(store, credential::TTSHITU_PASSWORD_KEY, &tt.password);
        if let Some(t) = sealed.ttshitu.as_mut() {
            t.password = sealed_pw;
        }
    }
    if let Some(b) = &sealed.bark {
        let sealed_tok = credential::seal_value(store, credential::BARK_TOKEN_KEY, &b.token);
        if let Some(bb) = sealed.bark.as_mut() {
            bb.token = sealed_tok;
        }
    }

    write_cfg_raw(path, &sealed).await
}

/// Serialize-and-write without any credential handling — used internally by the
/// migration rewrite (the fields are already sentinels) and available for tests.
pub async fn write_cfg_raw(path: impl AsRef<std::path::Path>, cfg: &Config) -> anyhow::Result<()> {
    let path = path.as_ref();
    // Create the parent directory if it does not exist
    if let Some(par) = path.parent()
        && !par.exists()
    {
        fs::create_dir_all(par).await?;
    }

    let content = toml::to_string(cfg)?;
    fs::write(path, content).await.0?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::SecretStore;
    use std::sync::Mutex;

    /// In-memory store for migration tests (no OS keychain / D-Bus).
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
        fn stored(&self, key: &str) -> Option<String> {
            self.map.lock().unwrap().get(key).cloned()
        }
    }
    impl SecretStore for MemStore {
        fn get(&self, key: &str) -> anyhow::Result<String> {
            if self.fail {
                return Err(anyhow::anyhow!("unavailable"));
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
                return Err(anyhow::anyhow!("unavailable"));
            }
            self.map
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    fn plaintext_cfg() -> Config {
        Config {
            username: "2024000000".into(),
            password: "hunter2".into(),
            ttshitu: Some(TTShiTuConfig {
                username: "ocruser".into(),
                password: "ocrpass".into(),
            }),
            bark: Some(BarkConfig {
                token: "barktoken123".into(),
            }),
            auto_supplement: None,
        }
    }

    #[test]
    fn migrate_plaintext_seals_and_returns_real_value() {
        let store = MemStore::new();
        let (cfg, rewrite, dirty) = resolve_and_migrate(&store, plaintext_cfg());

        // The caller still gets the real secrets.
        assert_eq!(cfg.password, "hunter2");
        assert_eq!(cfg.ttshitu.as_ref().unwrap().password, "ocrpass");
        assert_eq!(cfg.bark.as_ref().unwrap().token, "barktoken123");
        // Non-secret username untouched.
        assert_eq!(cfg.username, "2024000000");
        assert_eq!(cfg.ttshitu.as_ref().unwrap().username, "ocruser");

        // The on-disk rewrite holds sentinels, and the keychain holds the values.
        assert!(dirty);
        assert_eq!(rewrite.password, "keyring:portal.password");
        assert_eq!(
            rewrite.ttshitu.as_ref().unwrap().password,
            "keyring:ttshitu.password"
        );
        assert_eq!(rewrite.bark.as_ref().unwrap().token, "keyring:bark.token");
        assert_eq!(store.stored("portal.password").as_deref(), Some("hunter2"));
        assert_eq!(store.stored("ttshitu.password").as_deref(), Some("ocrpass"));
        assert_eq!(store.stored("bark.token").as_deref(), Some("barktoken123"));
    }

    #[test]
    fn migrate_is_idempotent_after_seal() {
        let store = MemStore::new();
        // First read migrates.
        let (_, rewrite, _) = resolve_and_migrate(&store, plaintext_cfg());
        // A second read of the rewritten (sentinel) form resolves + is NOT dirty.
        let (cfg, rewrite2, dirty2) = resolve_and_migrate(&store, rewrite);
        assert!(!dirty2);
        assert_eq!(cfg.password, "hunter2"); // resolved back from the keychain
        assert_eq!(
            rewrite2.password,
            "keyring:portal.password" // stays sentinel
        );
    }

    #[test]
    fn unavailable_keychain_keeps_plaintext_no_dirty() {
        let store = MemStore::failing();
        let (cfg, _rewrite, dirty) = resolve_and_migrate(&store, plaintext_cfg());
        assert!(!dirty); // nothing to rewrite — plaintext retained as-is
        assert_eq!(cfg.password, "hunter2"); // still usable
    }

    #[test]
    fn unavailable_keychain_cannot_resolve_sentinel() {
        // A migrated (sentinel) cfg is unrecoverable without the keychain.
        let store = MemStore::failing();
        let mut parsed = plaintext_cfg();
        parsed.password = "keyring:portal.password".into();
        let (cfg, _rewrite, dirty) = resolve_and_migrate(&store, parsed);
        assert!(!dirty);
        assert_eq!(cfg.password, ""); // encryption's inherent cost
    }
}
