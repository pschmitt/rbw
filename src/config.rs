use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// Whether `list`/`search`/`get` should proactively unlock this account
// (prompting as needed) when merging entries across every configured
// account. Independent of `Account::exclude_from_list`, which controls
// whether the account's entries show up in the merge at all.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockPolicy {
    // Always unlock this account (prompting as needed) for a multi-account
    // merge, even on a plain `rbw list` with no `--all`.
    Always,
    // Never proactively unlock this account for a merge, not even with
    // `--all`; only included if it happens to already be unlocked.
    Never,
    // Default: included in a merge only if already unlocked; `--all` (or
    // another account's `Always`, which has no bearing on this one) unlocks
    // it too.
    #[default]
    OnDemand,
}

// Default password-generation policy: the fallback used by `rbw gen` and
// `rbw create --generate` whenever a given flag isn't passed explicitly on
// the command line (see `rbw::pwgen::resolve`). Mirrors `rbw gen`'s flag set
// field-for-field; `length` is `None` (rather than 0) so "unset" is
// distinguishable from "explicitly zero" for future flags that might want
// that. Kept `Copy`/`Eq` so `Config` can cheaply skip serializing it when
// it's still the all-defaults value a freshly-written config.json shouldn't
// be cluttered with.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
)]
pub struct PasswordGenPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(default)]
    pub no_symbols: bool,
    #[serde(default)]
    pub only_numbers: bool,
    #[serde(default)]
    pub nonconfusables: bool,
    #[serde(default)]
    pub diceware: bool,
}

impl PasswordGenPolicy {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

// Points at a Login entry, in another configured account's vault, that holds
// this account's master password. Used by the agent's unlock flow to skip
// the pinentry prompt: the source account is unlocked (recursively, if it
// itself has a `credential_source`), the named entry is looked up in its
// vault, and the entry's `password` field is used as this account's master
// password. Only that field is used -- TOTP-protected accounts and non-Login
// entry types aren't handled specially. If resolution fails for any reason
// (source account can't unlock, entry not found, wrong entry type), the
// normal pinentry prompt is used instead.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct CredentialSource {
    // Name of the *other* configured account whose vault holds this
    // account's credentials. Must not be this account's own name, and must
    // not form a cycle with other accounts' `credential_source`s.
    pub account: String,
    // Which entry in that account's vault holds the credentials, matched the
    // same way as an `rbw get NAME` name lookup.
    pub entry: String,
}

// A single Bitwarden/Vaultwarden account. The per-server connection details
// live here so that several accounts (with different servers) can coexist in
// one config; global preferences (lock timeout, pinentry, …) stay on `Config`.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct Account {
    // Stable local identifier used by `--account` and the agent; unrelated to
    // the email/server.
    pub name: String,
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    pub client_cert_path: Option<std::path::PathBuf>,
    // See `UnlockPolicy`.
    #[serde(default)]
    pub unlock: UnlockPolicy,
    // Hard opt-out: never include this account's entries in a `list`/
    // `search`/`get` merge across accounts (even if unlocked, even with
    // `--all`). Still reachable via `--account <name>` directly.
    #[serde(default)]
    pub exclude_from_list: bool,
    // See `CredentialSource`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_source: Option<CredentialSource>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    // ---- legacy single-account fields --------------------------------------
    // Retained for backward compatibility: an older config with these set (and
    // no `accounts`) is treated as a single implicit account named "default".
    // New configs write `accounts` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifications_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<std::path::PathBuf>,

    // ---- accounts ----------------------------------------------------------
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<Account>,
    // Name of the primary account; defaults to the first account when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_account: Option<String>,

    // ---- global preferences ------------------------------------------------
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    // TUI keybinding overrides: action name (e.g. "copy_password",
    // "move_down") to a list of key chord strings (e.g. "ctrl-y", "alt-p",
    // "g", "pagedown") that fully replace that action's built-in default
    // chords. Actions not listed here keep their defaults. See
    // `src/bin/rbw/tui/keymap.rs` for the full action list and defaults.
    #[serde(
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub tui_keybindings: std::collections::HashMap<String, Vec<String>>,
    // Default password-generation policy for `rbw gen` and `rbw create
    // --generate`; see `PasswordGenPolicy`. Editable from the TUI's settings
    // view.
    #[serde(default, skip_serializing_if = "PasswordGenPolicy::is_default")]
    pub password_gen: PasswordGenPolicy,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            client_cert_path: None,
            accounts: Vec::new(),
            primary_account: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            tui_keybindings: std::collections::HashMap::new(),
            password_gen: PasswordGenPolicy::default(),
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut fh = std::fs::File::create(&file).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.clone(),
            }
        })?;
        fh.write_all(
            serde_json::to_string_pretty(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig {
            source,
            file: file.clone(),
        })?;
        fh.write_all(b"\n")
            .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.primary().email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    // ---- account resolution ------------------------------------------------

    // The effective account list: the configured `accounts`, or a single
    // implicit "default" synthesized from the legacy top-level fields.
    pub fn accounts(&self) -> Vec<Account> {
        if !self.accounts.is_empty() {
            return self.accounts.clone();
        }
        if self.email.is_some()
            || self.base_url.is_some()
            || self.sso_id.is_some()
        {
            return vec![Account {
                name: "default".to_string(),
                email: self.email.clone(),
                sso_id: self.sso_id.clone(),
                base_url: self.base_url.clone(),
                identity_url: self.identity_url.clone(),
                ui_url: self.ui_url.clone(),
                notifications_url: self.notifications_url.clone(),
                client_cert_path: self.client_cert_path.clone(),
                unlock: UnlockPolicy::default(),
                exclude_from_list: false,
                credential_source: None,
            }];
        }
        Vec::new()
    }

    // Name of the primary account: the configured `primary_account`, else the
    // first account, else "default".
    pub fn primary_account_name(&self) -> String {
        if let Some(name) = &self.primary_account {
            return name.clone();
        }
        self.accounts()
            .first()
            .map_or_else(|| "default".to_string(), |a| a.name.clone())
    }

    // The primary account. Never fails: falls back to an empty "default" so the
    // URL helpers still yield the public Bitwarden endpoints on a fresh config.
    pub fn primary(&self) -> Account {
        let accounts = self.accounts();
        let name = self.primary_account_name();
        accounts
            .iter()
            .find(|a| a.name == name)
            .or_else(|| accounts.first())
            .cloned()
            .unwrap_or_else(|| Account {
                name: "default".to_string(),
                ..Account::default()
            })
    }

    // Fold the legacy top-level fields into an explicit account entry, clearing
    // them so the config is fully account-based going forward. Idempotent and a
    // no-op once `accounts` is populated. Call before mutating `accounts` so the
    // pre-existing (legacy) account is never lost.
    pub fn migrate_legacy(&mut self) {
        if !self.accounts.is_empty() {
            return;
        }
        if self.email.is_none()
            && self.base_url.is_none()
            && self.sso_id.is_none()
        {
            return;
        }
        let name = self
            .primary_account
            .clone()
            .unwrap_or_else(|| "default".to_string());
        self.accounts.push(Account {
            name: name.clone(),
            email: self.email.take(),
            sso_id: self.sso_id.take(),
            base_url: self.base_url.take(),
            identity_url: self.identity_url.take(),
            ui_url: self.ui_url.take(),
            notifications_url: self.notifications_url.take(),
            client_cert_path: self.client_cert_path.take(),
            unlock: UnlockPolicy::default(),
            exclude_from_list: false,
            credential_source: None,
        });
        if self.primary_account.is_none() {
            self.primary_account = Some(name);
        }
    }

    // Resolve an account by name, or the primary account when `name` is None.
    pub fn account(&self, name: Option<&str>) -> Result<Account> {
        match name {
            Some(name) => self
                .accounts()
                .into_iter()
                .find(|a| a.name == name)
                .ok_or_else(|| Error::UnknownAccount {
                    name: name.to_string(),
                }),
            None => Ok(self.primary()),
        }
    }

    // ---- credential_source resolution ---------------------------------------

    // Walk the `credential_source` chain starting at account `start`,
    // returning the ordered list of account names visited (starting with
    // `start` itself) up to the first account that has no `credential_source`
    // (the one that must ultimately be unlocked via pinentry). Pure account-
    // graph validation only -- no vault access.
    //
    // Fails clearly, rather than looping forever or overflowing the stack, on
    // a self-reference (an account's `credential_source` naming itself), a
    // cycle (A depends on B depends on ... depends on A), or a
    // `credential_source` naming an account that doesn't exist. A chain can
    // never legitimately be longer than the number of configured accounts, so
    // that doubles as a max-depth guard even if the explicit checks below
    // somehow miss a malformed config.
    pub fn credential_source_chain(
        &self,
        start: &str,
    ) -> Result<Vec<String>> {
        let accounts = self.accounts();
        let max_depth = accounts.len().max(1);
        let mut chain = vec![start.to_string()];
        let mut current = start.to_string();

        loop {
            let account = accounts
                .iter()
                .find(|a| a.name == current)
                .ok_or_else(|| Error::UnknownAccount {
                    name: current.clone(),
                })?;
            let Some(source) = &account.credential_source else {
                break;
            };
            if source.account == account.name {
                return Err(Error::CredentialSourceSelfReference {
                    name: account.name.clone(),
                });
            }
            if chain.contains(&source.account) || chain.len() > max_depth {
                return Err(Error::CredentialSourceCycle {
                    name: start.to_string(),
                });
            }
            chain.push(source.account.clone());
            current = source.account.clone();
        }

        Ok(chain)
    }

    // ---- URL helpers (delegate to the primary account) ---------------------

    pub fn base_url(&self) -> String {
        self.primary().base_url()
    }

    pub fn identity_url(&self) -> String {
        self.primary().identity_url()
    }

    pub fn ui_url(&self) -> String {
        self.primary().ui_url()
    }

    pub fn notifications_url(&self) -> String {
        self.primary().notifications_url()
    }

    pub fn client_cert_path(&self) -> Option<std::path::PathBuf> {
        self.primary().client_cert_path
    }

    pub fn server_name(&self) -> String {
        self.primary().server_name()
    }
}

impl Account {
    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}

#[cfg(test)]
mod test {
    use super::{Account, Config, CredentialSource, Error};

    fn named(name: &str, email: &str) -> Account {
        Account {
            name: name.to_string(),
            email: Some(email.to_string()),
            ..Account::default()
        }
    }

    // A legacy config (top-level fields, no `accounts`) is seen as a single
    // implicit "default" account, and the URL helpers still resolve.
    #[test]
    fn legacy_config_synthesizes_default_account() {
        let mut c = Config::new();
        c.email = Some("me@x.com".to_string());
        c.base_url = Some("https://vault.example.com".to_string());

        let accounts = c.accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "default");
        assert_eq!(c.primary_account_name(), "default");
        assert_eq!(c.primary().email.as_deref(), Some("me@x.com"));
        assert_eq!(c.base_url(), "https://vault.example.com/api");
    }

    // With no `primary_account` set, the first account is primary.
    #[test]
    fn primary_defaults_to_first_account() {
        let mut c = Config::new();
        c.accounts =
            vec![named("personal", "a@x.com"), named("work", "b@co.com")];

        assert_eq!(c.primary_account_name(), "personal");
        assert_eq!(
            c.account(Some("work")).unwrap().email.as_deref(),
            Some("b@co.com")
        );
        assert!(c.account(None).unwrap().name == "personal");
        assert!(c.account(Some("nope")).is_err());
    }

    // An explicit `primary_account` overrides the first-account default.
    #[test]
    fn explicit_primary_account_wins() {
        let mut c = Config::new();
        c.accounts =
            vec![named("personal", "a@x.com"), named("work", "b@co.com")];
        c.primary_account = Some("work".to_string());
        assert_eq!(c.primary().name, "work");
    }

    // migrate_legacy folds top-level fields into a "default" account and clears
    // them, and is a no-op once accounts exist.
    #[test]
    fn migrate_legacy_moves_fields_into_default_account() {
        let mut c = Config::new();
        c.email = Some("me@x.com".to_string());
        c.base_url = Some("https://vault.example.com".to_string());
        c.migrate_legacy();

        assert_eq!(c.accounts.len(), 1);
        assert_eq!(c.accounts[0].name, "default");
        assert_eq!(c.accounts[0].email.as_deref(), Some("me@x.com"));
        assert_eq!(c.primary_account.as_deref(), Some("default"));
        // Legacy fields are cleared so we don't shadow the account.
        assert!(c.email.is_none());
        assert!(c.base_url.is_none());

        // Idempotent: a second call adds nothing.
        c.migrate_legacy();
        assert_eq!(c.accounts.len(), 1);
    }

    // A chain with no `credential_source` at all is just the start account.
    #[test]
    fn credential_source_chain_trivial_with_no_source() {
        let mut c = Config::new();
        c.accounts = vec![named("personal", "a@x.com")];
        assert_eq!(
            c.credential_source_chain("personal").unwrap(),
            vec!["personal".to_string()]
        );
    }

    // A valid chain (work's password lives in personal's vault, and personal
    // has no further source) resolves to the full ordered chain.
    #[test]
    fn credential_source_chain_resolves_valid_chain() {
        let mut c = Config::new();
        let mut work = named("work", "b@co.com");
        work.credential_source = Some(CredentialSource {
            account: "personal".to_string(),
            entry: "work login".to_string(),
        });
        c.accounts = vec![named("personal", "a@x.com"), work];

        assert_eq!(
            c.credential_source_chain("work").unwrap(),
            vec!["work".to_string(), "personal".to_string()]
        );
    }

    // An account whose `credential_source` names itself is rejected rather
    // than looping forever.
    #[test]
    fn credential_source_chain_rejects_self_reference() {
        let mut c = Config::new();
        let mut work = named("work", "b@co.com");
        work.credential_source = Some(CredentialSource {
            account: "work".to_string(),
            entry: "whoops".to_string(),
        });
        c.accounts = vec![work];

        assert!(matches!(
            c.credential_source_chain("work"),
            Err(Error::CredentialSourceSelfReference { name }) if name == "work"
        ));
    }

    // A cycle across several accounts (a -> b -> c -> a) is detected rather
    // than recursing forever or overflowing the stack.
    #[test]
    fn credential_source_chain_rejects_cycle() {
        let mut c = Config::new();
        let mut a = named("a", "a@x.com");
        a.credential_source = Some(CredentialSource {
            account: "b".to_string(),
            entry: "e".to_string(),
        });
        let mut b = named("b", "b@x.com");
        b.credential_source = Some(CredentialSource {
            account: "c".to_string(),
            entry: "e".to_string(),
        });
        let mut cc = named("c", "c@x.com");
        cc.credential_source = Some(CredentialSource {
            account: "a".to_string(),
            entry: "e".to_string(),
        });
        c.accounts = vec![a, b, cc];

        assert!(matches!(
            c.credential_source_chain("a"),
            Err(Error::CredentialSourceCycle { name }) if name == "a"
        ));
    }

    // A `credential_source` naming an account that doesn't exist fails
    // clearly instead of panicking.
    #[test]
    fn credential_source_chain_rejects_unknown_account() {
        let mut c = Config::new();
        let mut work = named("work", "b@co.com");
        work.credential_source = Some(CredentialSource {
            account: "nonexistent".to_string(),
            entry: "e".to_string(),
        });
        c.accounts = vec![work];

        assert!(matches!(
            c.credential_source_chain("work"),
            Err(Error::UnknownAccount { name }) if name == "nonexistent"
        ));
    }
}
