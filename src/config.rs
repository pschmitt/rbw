use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
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
    use super::{Account, Config};

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
        c.accounts = vec![named("personal", "a@x.com"), named("work", "b@co.com")];

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
        c.accounts = vec![named("personal", "a@x.com"), named("work", "b@co.com")];
        c.primary_account = Some("work".to_string());
        assert_eq!(c.primary().name, "work");
    }
}
