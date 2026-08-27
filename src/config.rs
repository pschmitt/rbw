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
#[serde(rename_all = "camelCase")]
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
// it's still the all-defaults value a freshly-written config.yaml shouldn't
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
#[serde(rename_all = "camelCase")]
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

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            sync_interval: default_sync_interval(),
            lock_timeout: default_lock_timeout(),
        }
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct PinentryConfig {
    #[serde(default = "default_pinentry")]
    pub command: String,
    #[serde(default = "default_pinentry_timeout")]
    pub timeout: u64,
}

impl Default for PinentryConfig {
    fn default() -> Self {
        Self {
            command: default_pinentry(),
            timeout: default_pinentry_timeout(),
        }
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct TuiConfig {
    #[serde(
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub keys: std::collections::HashMap<String, Vec<String>>,
    #[serde(default = "default_tui_lock_timeout")]
    pub lock_timeout: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            lock_timeout: default_tui_lock_timeout(),
        }
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct HideConfig {
    #[serde(default = "default_hide_archived")]
    pub archived: bool,
    #[serde(default = "default_hide_trashed")]
    pub trashed: bool,
}

impl Default for HideConfig {
    fn default() -> Self {
        Self {
            archived: default_hide_archived(),
            trashed: default_hide_trashed(),
        }
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, Default,
)]
#[serde(rename_all = "camelCase")]
pub struct TermuxConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_alias: Option<String>,
}

impl TermuxConfig {
    fn is_default(&self) -> bool {
        self.key_alias.is_none()
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

// One or more shortcut names, so a single entry can be written as a bare
// string (`alias: gpg`) or a list (`alias: [gpg, gpg-key]`) without forcing
// callers with only one name to wrap it.
fn deserialize_one_or_many<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match serde::Deserialize::deserialize(deserializer)? {
        OneOrMany::One(name) => vec![name],
        OneOrMany::Many(names) => names,
    })
}

// A shortcut name (or several names sharing the same target) that resolves
// to a specific item (optionally a specific field on it) in a specific
// account, so a memorable name like `gpg` can stand in for a real item's
// name/UUID. E.g. `aliases: [{alias: gpg, item: "GPG key", field:
// "passphrase"}]` makes `rbw get gpg` behave like `rbw get --field
// passphrase "GPG key"`. Only applies to a bare `rbw get NAME` with none of
// --user/--folder/--collection/--org set (see `commands::resolve_get_alias`),
// and only when `--no-alias` isn't given.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct ItemAlias {
    // The shortcut name(s) that resolve to `item`. Accepts either a single
    // string or a list, so several names sharing the same target (e.g.
    // `gpg`/`gnupg`) don't need repeated entries.
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub alias: Vec<String>,
    // Which configured account the item lives in. `None`, `"primary"`, and
    // `"default"` all mean the primary account (see `primary_account_name`);
    // any other value must name a configured account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    // Item name or UUID, matched the same way as an `rbw get NAME` needle.
    pub item: String,
    // Field to fetch instead of the item's default/primary value. A `--field`
    // given on the command line overrides this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    // Only match `item` within this collection (name or ID), same as
    // `rbw get --collection`. Useful to disambiguate an item name that
    // exists in more than one collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    // Only match `item` within this organization (name or ID), same as
    // `rbw get --org`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl ItemAlias {
    // The account name this alias resolves to: the primary account for
    // `None`/`"primary"`/`"default"`, else the literal configured account
    // name. Note that this makes `"default"` always mean "primary", even if
    // an account happens to be literally named "default" without being the
    // primary one.
    pub fn account_name(&self, config: &Config) -> String {
        match self.account.as_deref() {
            None | Some("primary" | "default") => {
                config.primary_account_name()
            }
            Some(name) => name.to_string(),
        }
    }
}

// A string config value that can be given literally, or read from a file at
// the point of use (e.g. a sops-nix secret's decrypted path) instead of
// being embedded directly in config.yaml. Serializes back to whichever shape
// it was read as -- a bare string stays a bare string, `{file: ...}` stays
// `{file: ...}` -- so `rbw config edit`/`save()` never silently bakes a file
// reference's resolved value into the file on an unrelated settings change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretString {
    Literal(String),
    File(std::path::PathBuf),
}

impl SecretString {
    // The effective value: the literal string, or the referenced file's
    // contents with a single trailing newline stripped (matching how most
    // secret-management tools, including sops-nix, write secret files).
    pub fn resolve(&self) -> Result<String> {
        match self {
            Self::Literal(s) => Ok(s.clone()),
            Self::File(file) => {
                let contents =
                    std::fs::read_to_string(file).map_err(|source| {
                        Error::LoadSecretFile {
                            source,
                            file: file.clone(),
                        }
                    })?;
                Ok(contents
                    .strip_suffix('\n')
                    .unwrap_or(&contents)
                    .to_string())
            }
        }
    }

    // Resolves an `Option<SecretString>` field to an `Option<String>`,
    // leaving `None` as `None`. Used by the account URL/email helpers below.
    fn resolve_opt(v: Option<&Self>) -> Result<Option<String>> {
        v.map(Self::resolve).transpose()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::Literal(s)
    }
}

impl serde::Serialize for SecretString {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Literal(s) => serializer.serialize_str(s),
            Self::File(file) => {
                use serde::ser::SerializeStruct as _;
                let mut state =
                    serializer.serialize_struct("SecretString", 1)?;
                state.serialize_field("file", file)?;
                state.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Literal(String),
            File { file: std::path::PathBuf },
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Literal(s) => Self::Literal(s),
            Repr::File { file } => Self::File(file),
        })
    }
}

// A single Bitwarden/Vaultwarden account. The per-server connection details
// live here so that several accounts (with different servers) can coexist in
// one config; global preferences (lock timeout, pinentry, …) stay on `Config`.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    // Stable local identifier used by `--account` and the agent; unrelated to
    // the email/server.
    pub name: String,
    pub email: Option<SecretString>,
    pub sso_id: Option<SecretString>,
    pub base_url: Option<SecretString>,
    pub identity_url: Option<SecretString>,
    pub ui_url: Option<SecretString>,
    pub notifications_url: Option<SecretString>,
    pub client_cert_path: Option<std::path::PathBuf>,
    // See `UnlockConfig`.
    #[serde(default)]
    pub unlock: UnlockConfig,
    // See `ExcludeContext`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_from: Vec<ExcludeContext>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    // ---- legacy single-account fields --------------------------------------
    // Deserialization-only fields for an older single-account shape. New
    // configs always write `accounts` instead.
    #[serde(skip_serializing, default)]
    pub email: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub sso_id: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub base_url: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub identity_url: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub ui_url: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub notifications_url: Option<SecretString>,
    #[serde(skip_serializing, default)]
    pub client_cert_path: Option<std::path::PathBuf>,

    // ---- accounts ----------------------------------------------------------
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<Account>,
    // Name of the primary account; defaults to the first account when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_account: Option<String>,

    // ---- grouped global preferences ---------------------------------------
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub pinentry: PinentryConfig,
    #[serde(default)]
    pub tui: TuiConfig,
    #[serde(default)]
    pub hide: HideConfig,
    // Default Android Keystore alias for native Termux unlocks. An explicit
    // RBW_TERMUX_KEY_ALIAS environment variable takes precedence.
    #[serde(default, skip_serializing_if = "TermuxConfig::is_default")]
    pub termux: TermuxConfig,
    // Default password-generation policy for `rbw gen` and `rbw create
    // --generate`; see `PasswordGenPolicy`. Editable from the TUI's settings
    // view.
    #[serde(default, skip_serializing_if = "PasswordGenPolicy::is_default")]
    pub password_gen: PasswordGenPolicy,
    // Which mechanism(s) `-c`/`--clipboard` and the TUI's copy actions use
    // to set the clipboard; see `ClipboardMechanism`.
    #[serde(default)]
    pub clipboard: ClipboardMechanism,
    // Shortcut names for `rbw get`; see `ItemAlias`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<ItemAlias>,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
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
        slf.migrate_legacy();
        if slf.agent.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.agent.lock_timeout = default_lock_timeout();
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
        slf.migrate_legacy();
        if slf.agent.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.agent.lock_timeout = default_lock_timeout();
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

    // The configured `ItemAlias` whose `alias` list contains `name`, if any.
    pub fn find_alias(&self, name: &str) -> Option<&ItemAlias> {
        self.aliases
            .iter()
            .find(|a| a.alias.iter().any(|n| n == name))
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

    // Return the primary account for configuration updates, creating the
    // default account on a fresh configuration when necessary.
    pub fn primary_mut(&mut self) -> &mut Account {
        self.migrate_legacy();
        if self.accounts.is_empty() {
            let name = self
                .primary_account
                .clone()
                .unwrap_or_else(|| "default".to_string());
            self.accounts.push(Account {
                name: name.clone(),
                ..Account::default()
            });
            self.primary_account = Some(name);
        }
        let name = self.primary_account_name();
        let index = self
            .accounts
            .iter()
            .position(|account| account.name == name)
            .unwrap_or(0);
        &mut self.accounts[index]
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

    pub fn base_url(&self) -> Result<String> {
        self.primary().base_url()
    }

    pub fn identity_url(&self) -> Result<String> {
        self.primary().identity_url()
    }

    pub fn ui_url(&self) -> Result<String> {
        self.primary().ui_url()
    }

    pub fn notifications_url(&self) -> Result<String> {
        self.primary().notifications_url()
    }

    pub fn client_cert_path(&self) -> Option<std::path::PathBuf> {
        self.primary().client_cert_path
    }

    pub fn server_name(&self) -> Result<String> {
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

    pub fn base_url(&self) -> Result<String> {
        Ok(
            SecretString::resolve_opt(self.base_url.as_ref())?.map_or_else(
                || "https://api.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://api.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/api")
                    }
                },
            ),
        )
    }

    pub fn identity_url(&self) -> Result<String> {
        if let Some(url) = &self.identity_url {
            return url.resolve();
        }
        Ok(
            SecretString::resolve_opt(self.base_url.as_ref())?.map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            ),
        )
    }

    pub fn ui_url(&self) -> Result<String> {
        if let Some(url) = &self.ui_url {
            return url.resolve();
        }
        Ok(
            SecretString::resolve_opt(self.base_url.as_ref())?.map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            ),
        )
    }

    pub fn notifications_url(&self) -> Result<String> {
        if let Some(url) = &self.notifications_url {
            return url.resolve();
        }
        Ok(
            SecretString::resolve_opt(self.base_url.as_ref())?.map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            ),
        )
    }

    // A stable identifier for this account's server, used to key the local
    // db file. Resolves a file-based `base_url` so the db path is keyed by
    // the real server URL rather than a secret file's path.
    pub fn server_name(&self) -> Result<String> {
        Ok(SecretString::resolve_opt(self.base_url.as_ref())?
            .unwrap_or_else(|| "default".to_string()))
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
        Error, ExcludeContext, ItemAlias, SecretString,
    };

    fn named(name: &str, email: &str) -> Account {
        Account {
            name: name.to_string(),
            email: Some(SecretString::Literal(email.to_string())),
            ..Account::default()
        }
    }

    // A legacy config (top-level fields, no `accounts`) is seen as a single
    // implicit "default" account, and the URL helpers still resolve.
    #[test]
    fn legacy_config_synthesizes_default_account() {
        let mut c = Config::new();
        c.email = Some(SecretString::Literal("me@x.com".to_string()));
        c.base_url = Some(SecretString::Literal(
            "https://vault.example.com".to_string(),
        ));

        let accounts = c.accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "default");
        assert_eq!(c.primary_account_name(), "default");
        assert_eq!(
            c.primary()
                .email
                .as_ref()
                .map(|s| s.resolve().unwrap())
                .as_deref(),
            Some("me@x.com")
        );
        assert_eq!(c.base_url().unwrap(), "https://vault.example.com/api");
    }

    // With no `primary_account` set, the first account is primary.
    #[test]
    fn primary_defaults_to_first_account() {
        let mut c = Config::new();
        c.accounts =
            vec![named("personal", "a@x.com"), named("work", "b@co.com")];

        assert_eq!(c.primary_account_name(), "personal");
        assert_eq!(
            c.account(Some("work"))
                .unwrap()
                .email
                .as_ref()
                .map(|s| s.resolve().unwrap())
                .as_deref(),
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
        c.email = Some(SecretString::Literal("me@x.com".to_string()));
        c.base_url = Some(SecretString::Literal(
            "https://vault.example.com".to_string(),
        ));
        c.migrate_legacy();

        assert_eq!(c.accounts.len(), 1);
        assert_eq!(c.accounts[0].name, "default");
        assert_eq!(
            c.accounts[0]
                .email
                .as_ref()
                .map(|s| s.resolve().unwrap())
                .as_deref(),
            Some("me@x.com")
        );
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

    // `None`, `"primary"`, and `"default"` all resolve an alias to the
    // primary account; any other string names an account directly.
    #[test]
    fn item_alias_account_name_resolves_sentinels_to_primary() {
        let mut c = Config::new();
        c.accounts =
            vec![named("personal", "a@x.com"), named("work", "b@co.com")];
        c.primary_account = Some("work".to_string());

        let unset = ItemAlias {
            alias: vec!["a".to_string()],
            item: "x".to_string(),
            ..ItemAlias::default()
        };
        let primary = ItemAlias {
            alias: vec!["a".to_string()],
            account: Some("primary".to_string()),
            item: "x".to_string(),
            ..ItemAlias::default()
        };
        let default = ItemAlias {
            alias: vec!["a".to_string()],
            account: Some("default".to_string()),
            item: "x".to_string(),
            ..ItemAlias::default()
        };
        let explicit = ItemAlias {
            alias: vec!["a".to_string()],
            account: Some("personal".to_string()),
            item: "x".to_string(),
            ..ItemAlias::default()
        };

        assert_eq!(unset.account_name(&c), "work");
        assert_eq!(primary.account_name(&c), "work");
        assert_eq!(default.account_name(&c), "work");
        assert_eq!(explicit.account_name(&c), "personal");
    }

    #[test]
    fn aliases_deserialize_from_yaml() {
        let config = parse_config(
            "aliases:\n  - alias: gpg\n    account: work\n    item: GPG key\n    field: passphrase\n    collection: Personal\n    org: Acme\n",
            std::path::Path::new("config.yaml"),
        )
        .unwrap();
        let alias = config.find_alias("gpg").unwrap();
        assert_eq!(alias.account.as_deref(), Some("work"));
        assert_eq!(alias.item, "GPG key");
        assert_eq!(alias.field.as_deref(), Some("passphrase"));
        assert_eq!(alias.collection.as_deref(), Some("Personal"));
        assert_eq!(alias.org.as_deref(), Some("Acme"));
    }

    // `collection`/`org` are optional and omitted entirely from a minimal
    // alias.
    #[test]
    fn aliases_collection_and_org_are_optional() {
        let config = parse_config(
            "aliases:\n  - alias: gpg\n    item: GPG key\n",
            std::path::Path::new("config.yaml"),
        )
        .unwrap();
        let alias = config.find_alias("gpg").unwrap();
        assert!(alias.collection.is_none());
        assert!(alias.org.is_none());
    }

    // `alias` can be a list of names sharing the same target item, each of
    // which resolves independently.
    #[test]
    fn aliases_alias_field_accepts_list_of_names() {
        let config = parse_config(
            "aliases:\n  - alias: [gpg, gnupg]\n    item: GPG key\n",
            std::path::Path::new("config.yaml"),
        )
        .unwrap();
        assert_eq!(config.find_alias("gpg").unwrap().item, "GPG key");
        assert_eq!(config.find_alias("gnupg").unwrap().item, "GPG key");
        assert!(config.find_alias("unknown").is_none());
    }

    // A config with no `aliases` key at all still deserializes, defaulting
    // to an empty list, and an empty list is skipped on serialization.
    #[test]
    fn aliases_default_to_empty_and_are_skipped_when_empty() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert!(c.aliases.is_empty());
        let yaml = serde_yaml::to_string(&c).unwrap();
        assert!(!yaml.contains("aliases"));
    }

    #[test]
    fn config_yaml_deserializes() {
        let config = parse_config(
            "clipboard: osc52\nagent:\n  syncInterval: 42\n  lockTimeout: 120\n\npinentry:\n  command: pinentry\n  timeout: 300\ntui:\n  lockTimeout: 10\nhide:\n  archived: false\n  trashed: true\n",
            std::path::Path::new("config.yaml"),
        )
        .unwrap();
        assert_eq!(config.clipboard, ClipboardMechanism::Osc52);
        assert_eq!(config.agent.sync_interval, 42);
        assert_eq!(config.agent.lock_timeout, 120);
        assert_eq!(config.pinentry.command, "pinentry");
        assert_eq!(config.pinentry.timeout, 300);
        assert_eq!(config.tui.lock_timeout, 10);
        assert!(!config.hide.archived);
        assert!(config.hide.trashed);
    }

    #[test]
    fn config_yaml_serializes_grouped_camel_case() {
        let mut config = Config::new();
        config.agent.sync_interval = 42;
        config.pinentry.command = "pinentry-curses".to_string();
        config.tui.lock_timeout = 10;
        config
            .tui
            .keys
            .insert("forceQuit".to_string(), vec!["alt-Q".to_string()]);
        config.hide.archived = false;
        config.termux.key_alias = Some("rbw-personal".to_string());
        config.password_gen.no_symbols = true;

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("syncInterval: 42"));
        assert!(yaml.contains("command: pinentry-curses"));
        assert!(yaml.contains("lockTimeout: 10"));
        assert!(yaml.contains("forceQuit:"));
        assert!(yaml.contains("keyAlias: rbw-personal"));
        assert!(yaml.contains("noSymbols: true"));
        assert!(yaml.contains("archived: false"));
        assert!(!yaml.contains("sync_interval"));
        assert!(!yaml.contains("tui_keybindings"));
        assert!(!yaml.contains("hide_archived"));
    }

    // A bare string deserializes to `Literal` and resolves to itself,
    // unchanged.
    #[test]
    fn secret_string_literal_resolves_to_itself() {
        let s: SecretString = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(s, SecretString::Literal("hunter2".to_string()));
        assert_eq!(s.resolve().unwrap(), "hunter2");
    }

    // `{file: ...}` deserializes to `File` and resolves to the referenced
    // file's contents, with exactly one trailing newline stripped (matching
    // how sops-nix and most other secret-management tools write files).
    #[test]
    fn secret_string_file_resolves_and_trims_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "hunter2\n\n").unwrap();

        let json = format!("{{\"file\": {:?}}}", path.to_str().unwrap());
        let s: SecretString = serde_json::from_str(&json).unwrap();
        assert_eq!(s, SecretString::File(path));
        // Only the final newline is stripped, not every trailing newline.
        assert_eq!(s.resolve().unwrap(), "hunter2\n");
    }

    // Resolving a `File` variant whose path doesn't exist fails clearly
    // instead of panicking, so a config referencing a not-yet-decrypted
    // secret produces a normal `Result::Err` at the point of use.
    #[test]
    fn secret_string_file_missing_fails_clearly() {
        let s = SecretString::File(std::path::PathBuf::from(
            "/nonexistent/path/to/secret",
        ));
        assert!(matches!(s.resolve(), Err(Error::LoadSecretFile { .. })));
    }

    // `SecretString` serializes back to the same shape it was deserialized
    // from -- a `Literal` as a bare string, a `File` as a `{file: ...}`
    // mapping -- so a config referencing a secret file never gets its
    // reference silently replaced by the resolved value on save.
    #[test]
    fn secret_string_round_trips_through_yaml() {
        let literal = SecretString::Literal("hunter2".to_string());
        let literal_yaml = serde_yaml::to_string(&literal).unwrap();
        assert_eq!(literal_yaml.trim(), "hunter2");
        assert_eq!(
            serde_yaml::from_str::<SecretString>(&literal_yaml).unwrap(),
            literal
        );

        let file =
            SecretString::File(std::path::PathBuf::from("/run/secret"));
        let file_yaml = serde_yaml::to_string(&file).unwrap();
        assert!(file_yaml.contains("file: /run/secret"));
        assert_eq!(
            serde_yaml::from_str::<SecretString>(&file_yaml).unwrap(),
            file
        );
    }

    // An account's `base_url` (and, by extension, `identity_url`/`ui_url`/
    // `notifications_url`/`server_name`, which all fall back to it) can be
    // sourced from a file instead of a literal value.
    #[test]
    fn account_base_url_resolves_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base_url");
        std::fs::write(&path, "https://vault.example.com\n").unwrap();

        let account = Account {
            name: "work".to_string(),
            base_url: Some(SecretString::File(path)),
            ..Account::default()
        };
        assert_eq!(
            account.base_url().unwrap(),
            "https://vault.example.com/api"
        );
        assert_eq!(
            account.server_name().unwrap(),
            "https://vault.example.com"
        );
    }
}
