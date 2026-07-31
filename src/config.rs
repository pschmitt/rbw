use crate::prelude::*;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// Whether entry lookups should proactively unlock this account (prompting as
// needed) when merging entries across every configured account. Independent
// of `Account::exclude_from` (see `ExcludeContext`), which controls whether
// the account's entries show up in the merge at all.
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

// An account's `unlock` policy plus (optionally) where its master password
// comes from. Grouped together because both are about *how* an account gets
// unlocked, unlike `exclude_from`, which is about whether it participates in
// a merge at all once unlocked.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct UnlockConfig {
    #[serde(default)]
    pub policy: UnlockPolicy,
    // See `CredentialSource`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialSource>,
    // See `TermuxKeystoreUnlock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termux: Option<TermuxKeystoreUnlock>,
}

// Unlock an account with a master-password bundle protected by an
// authentication-gated Android Keystore signing key. The bundle path and key
// alias are deliberately configured separately: the alias is part of the
// trusted local configuration, not attacker-controlled bundle data.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct TermuxKeystoreUnlock {
    pub file: std::path::PathBuf,
    pub key_alias: String,
    #[serde(default = "default_termux_algorithm")]
    pub algorithm: String,
}

fn default_termux_algorithm() -> String {
    "SHA256withRSA".to_string()
}

// Which commands should skip this account when merging entries across every
// configured account. `All` is a magic catch-all equivalent to listing every
// other variant. An account not excluded from a given context is still only
// actually queried there subject to its own `unlock.policy` (see
// `UnlockPolicy`) and that context's own `--all`-style flag, where it has
// one; `exclude_from` is a hard opt-out layered on top of that, not an
// alternative to it. Still reachable via `--account <name>` directly (or,
// for `tui`, via `rbw tui --account <name>`) regardless of what it's
// excluded from.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
#[serde(rename_all = "kebab-case")]
pub enum ExcludeContext {
    List,
    Search,
    Get,
    Show,
    Code,
    Sync,
    Unlock,
    Tui,
    All,
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

// Which mechanism(s) `-c`/`--clipboard` and the TUI's copy actions use to
// set the clipboard. The system clipboard (`arboard`, via the agent, in
// `rbw-agent`'s `state::clipboard`) needs direct X11/Wayland/pasteboard
// access and doesn't work over a plain SSH session. OSC 52 instead writes a
// terminal escape sequence to the *client's* own stdout, asking whatever
// terminal emulator is on the other end to set its clipboard -- which works
// over SSH, in containers, and anywhere else there's no display server, as
// long as that terminal emulator supports OSC 52 (most modern ones do; see
// `src/bin/rbw/osc52.rs`). Unsupported terminals just ignore the escape
// sequence, so it's harmless to attempt even when support is unknown.
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
pub enum ClipboardMechanism {
    // Best-effort: try both. OSC 52 is skipped silently whenever it
    // wouldn't make sense (stdout isn't a terminal or SSH session); only
    // the system clipboard's result is reported back to the caller,
    // matching the behavior from before this option existed.
    #[default]
    Auto,
    // Only the system clipboard (`arboard`, via the agent) -- disables OSC
    // 52 entirely.
    System,
    // Only the OSC 52 escape sequence -- never touches the system
    // clipboard, and fails outright if stdout isn't a terminal or SSH
    // session.
    Osc52,
}

// Points at a Login item, in another configured account's vault, that holds
// this account's master password. Used by the agent's unlock flow to skip
// the pinentry prompt: the source account is unlocked (recursively, if it
// itself has a `credential_source`), the named item is looked up in its
// vault, and the item's `password` field is used as this account's master
// password. If `item` is unset, rbw instead tries to find a unique Login
// item in the source account whose URI matches this account's server URL.
// Only the password/TOTP fields are used; if resolution fails for any
// reason, the normal pinentry prompt is used instead.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct CredentialSource {
    // Name of the *other* configured account whose vault holds this
    // account's credentials. Must not be this account's own name, and must
    // not form a cycle with other accounts' `credential_source`s.
    pub account: String,
    // Which item in that account's vault holds the credentials, matched the
    // same way as an `rbw get NAME` name lookup. If unset, rbw falls back to
    // finding a unique URI match for the child account's UI URL.
    #[serde(
        alias = "entry",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub item: Option<String>,
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
    // See `UnlockConfig`.
    #[serde(default)]
    pub unlock: UnlockConfig,
    // See `ExcludeContext`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_from: Vec<ExcludeContext>,
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
    // Default Android Keystore alias for native Termux unlocks. An explicit
    // RBW_TERMUX_KEY_ALIAS environment variable takes precedence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termux_key_alias: Option<String>,
    // Seconds pinentry waits at the terminal for input before giving up and
    // exiting on its own; passed straight through to pinentry's own
    // `--timeout` flag, so `0` means never (the old, unconditional
    // behavior). Without this, a pinentry left unanswered -- its terminal
    // closed, its process orphaned, whatever -- hangs around forever and
    // wedges every subsequent unlock attempt behind it, since only one
    // pinentry can hold the terminal at a time.
    #[serde(default = "default_pinentry_timeout")]
    pub pinentry_timeout: u64,
    // Seconds of TUI inactivity before the interactive screen locks. Zero
    // disables the inactivity lock; the `rbw tui` flag can override this.
    #[serde(default = "default_tui_lock_timeout")]
    pub tui_lock_timeout: u64,
    // Whether archived entries are hidden from `rbw list`/`rbw search` (and
    // the TUI) by default. Overridable per-invocation with `--archived`
    // (show only archived) / `--include-archived` (disable hiding).
    #[serde(default = "default_hide_archived")]
    pub hide_archived: bool,
    // Whether trashed entries (removed via `rbw remove`/`rbw delete`) are
    // hidden from `rbw list`/`rbw search` (and the TUI) by default.
    // Overridable per-invocation with `--trashed`/`--deleted` (show only
    // trashed) / `--include-trashed`/`--include-deleted` (disable hiding).
    #[serde(default = "default_hide_trashed")]
    pub hide_trashed: bool,
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
    // Which mechanism(s) `-c`/`--clipboard` and the TUI's copy actions use
    // to set the clipboard; see `ClipboardMechanism`.
    #[serde(default)]
    pub clipboard: ClipboardMechanism,
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
            termux_key_alias: None,
            pinentry_timeout: default_pinentry_timeout(),
            tui_lock_timeout: default_tui_lock_timeout(),
            hide_archived: default_hide_archived(),
            hide_trashed: default_hide_trashed(),
            tui_keybindings: std::collections::HashMap::new(),
            password_gen: PasswordGenPolicy::default(),
            clipboard: ClipboardMechanism::default(),
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

pub fn default_pinentry_timeout() -> u64 {
    300
}

pub fn default_tui_lock_timeout() -> u64 {
    0
}

pub fn default_hide_archived() -> bool {
    true
}

pub fn default_hide_trashed() -> bool {
    true
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
        let mut contents = String::new();
        fh.read_to_string(&mut contents).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf = parse_config(&contents, &file)?;
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
        let mut contents = String::new();
        fh.read_to_string(&mut contents).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf = parse_config(&contents, &file)?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_yaml_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        // 0600: the config can hold client secrets (defense in depth on
        // top of the 0700 config dir).
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.clone(),
            })?;
        let mut yaml = serde_yaml::to_string(self).map_err(|source| {
            Error::SaveConfigYaml {
                source,
                file: file.clone(),
            }
        })?;
        if !yaml.ends_with('\n') {
            yaml.push('\n');
        }
        fh.write_all(yaml.as_bytes()).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.clone(),
            }
        })?;
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
                unlock: UnlockConfig::default(),
                exclude_from: Vec::new(),
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
            unlock: UnlockConfig::default(),
            exclude_from: Vec::new(),
        });
        if self.primary_account.is_none() {
            self.primary_account = Some(name);
        }
    }

    // Resolve an account by name, or the primary account when `name` is None.
    pub fn account(&self, name: Option<&str>) -> Result<Account> {
        name.map_or_else(
            || Ok(self.primary()),
            |name| {
                self.accounts()
                    .into_iter()
                    .find(|a| a.name == name)
                    .ok_or_else(|| Error::UnknownAccount {
                        name: name.to_string(),
                    })
            },
        )
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
            let Some(source) = &account.unlock.credentials else {
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

fn parse_config(contents: &str, file: &std::path::Path) -> Result<Config> {
    if file.extension().and_then(std::ffi::OsStr::to_str) == Some("yaml") {
        serde_yaml::from_str(contents).map_err(|source| {
            Error::LoadConfigYaml {
                source,
                file: file.to_path_buf(),
            }
        })
    } else {
        serde_json::from_str(contents).map_err(|source| {
            Error::LoadConfigJson {
                source,
                file: file.to_path_buf(),
            }
        })
    }
}

impl Account {
    // Whether this account should be skipped for `ctx`: either `ctx` itself
    // or the magic `ExcludeContext::All` is in `exclude_from`.
    pub fn excluded_from(&self, ctx: ExcludeContext) -> bool {
        self.exclude_from.contains(&ctx)
            || self.exclude_from.contains(&ExcludeContext::All)
    }

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
        // 0600: the device id is used in login requests; keep it private.
        let mut fh = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
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
    use super::{
        parse_config, Account, ClipboardMechanism, Config, CredentialSource,
        Error, ExcludeContext,
    };

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
        assert_eq!(c.account(None).unwrap().name, "personal");
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
        work.unlock.credentials = Some(CredentialSource {
            account: "personal".to_string(),
            item: Some("work login".to_string()),
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
        work.unlock.credentials = Some(CredentialSource {
            account: "work".to_string(),
            item: Some("whoops".to_string()),
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
        a.unlock.credentials = Some(CredentialSource {
            account: "b".to_string(),
            item: Some("e".to_string()),
        });
        let mut b = named("b", "b@x.com");
        b.unlock.credentials = Some(CredentialSource {
            account: "c".to_string(),
            item: Some("e".to_string()),
        });
        let mut cc = named("c", "c@x.com");
        cc.unlock.credentials = Some(CredentialSource {
            account: "a".to_string(),
            item: Some("e".to_string()),
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
        work.unlock.credentials = Some(CredentialSource {
            account: "nonexistent".to_string(),
            item: Some("e".to_string()),
        });
        c.accounts = vec![work];

        assert!(matches!(
            c.credential_source_chain("work"),
            Err(Error::UnknownAccount { name }) if name == "nonexistent"
        ));
    }

    #[test]
    fn credential_source_deserializes_legacy_entry_key_as_item() {
        let source: CredentialSource = serde_json::from_str(
            r#"{"account":"personal","entry":"work login"}"#,
        )
        .unwrap();
        assert_eq!(source.account, "personal");
        assert_eq!(source.item.as_deref(), Some("work login"));
    }

    // An account with an empty `exclude_from` isn't excluded from anything.
    #[test]
    fn excluded_from_is_false_by_default() {
        let a = named("work", "b@co.com");
        assert!(!a.excluded_from(ExcludeContext::List));
        assert!(!a.excluded_from(ExcludeContext::Tui));
    }

    // `exclude_from` only excludes the specific contexts it names.
    #[test]
    fn excluded_from_checks_only_the_listed_contexts() {
        let mut a = named("work", "b@co.com");
        a.exclude_from = vec![ExcludeContext::List, ExcludeContext::Search];
        assert!(a.excluded_from(ExcludeContext::List));
        assert!(a.excluded_from(ExcludeContext::Search));
        assert!(!a.excluded_from(ExcludeContext::Tui));
        assert!(!a.excluded_from(ExcludeContext::Get));
    }

    // The magic `all` value excludes from every context, not just the ones
    // spelled out alongside it.
    #[test]
    fn excluded_from_all_covers_every_context() {
        let mut a = named("work", "b@co.com");
        a.exclude_from = vec![ExcludeContext::All];
        for ctx in [
            ExcludeContext::List,
            ExcludeContext::Search,
            ExcludeContext::Get,
            ExcludeContext::Show,
            ExcludeContext::Code,
            ExcludeContext::Sync,
            ExcludeContext::Unlock,
            ExcludeContext::Tui,
        ] {
            assert!(a.excluded_from(ctx));
        }
    }

    // A config with no `clipboard` key at all (e.g. one written before this
    // option existed) still deserializes, defaulting to `Auto`.
    #[test]
    fn clipboard_mechanism_defaults_to_auto_when_absent() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(c.clipboard, ClipboardMechanism::Auto);
    }

    // Each variant round-trips through its documented kebab-case JSON
    // spelling (what `config.json` actually contains, and what `rbw config
    // edit` shows/accepts).
    #[test]
    fn clipboard_mechanism_json_round_trips() {
        for (mechanism, json) in [
            (ClipboardMechanism::Auto, "\"auto\""),
            (ClipboardMechanism::System, "\"system\""),
            (ClipboardMechanism::Osc52, "\"osc52\""),
        ] {
            assert_eq!(serde_json::to_string(&mechanism).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<ClipboardMechanism>(json).unwrap(),
                mechanism
            );
        }
    }

    #[test]
    fn config_yaml_deserializes() {
        let config = parse_config(
            "clipboard: osc52\nlock_timeout: 120\n",
            std::path::Path::new("config.yaml"),
        )
        .unwrap();
        assert_eq!(config.clipboard, ClipboardMechanism::Osc52);
        assert_eq!(config.lock_timeout, 120);
    }
}
