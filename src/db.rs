use crate::prelude::*;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Collection {
    pub id: String,
    pub org_id: String,
    pub name: String,
}

// Unlike collection names, an organization's own name is plaintext in the
// sync response (needed to show org pickers before anything is
// decrypted), so there's no decrypt step for `rbw org list` at all.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Attachment {
    pub id: String,
    pub url: Option<String>,
    pub file_name: Option<String>,
    pub key: Option<String>,
    pub size: Option<String>,
    pub size_name: Option<String>,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub organizations: Vec<Organization>,
}

// A unique sibling path (same directory, so `rename` stays atomic) for staging
// an atomic db write. Uniqueness across concurrent writers (e.g. agent + a CLI
// invocation) comes from the pid plus a nanosecond timestamp.
fn tmp_path(file: &std::path::Path) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut name = file
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    name.push(format!(".tmp.{}.{nanos}", std::process::id()));
    file.with_file_name(name)
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    // XXX need to make this atomic
    // Write atomically: serialize to a sibling temp file, then rename over the
    // target. rename(2) is atomic on POSIX, so a concurrent reader always sees
    // either the old or the new complete db, never a truncated one.
    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveDb {
                source,
                file: file.clone(),
            },
        )?;
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        let tmp = tmp_path(&file);
        let write = || -> std::io::Result<()> {
            // 0600: the db holds access/refresh tokens and protected keys
            // (defense in depth on top of the 0700 data dir).
            let mut fh = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            fh.write_all(json.as_bytes())?;
            fh.sync_all()?;
            drop(fh);
            std::fs::rename(&tmp, &file)
        };
        write().map_err(|source| {
            let _ = std::fs::remove_file(&tmp);
            Error::SaveDb {
                source,
                file: file.clone(),
            }
        })
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        // See `save`: write to a sibling temp file, then atomically rename.
        let tmp = tmp_path(&file);
        let write = || async {
            // 0600: see `save`.
            let mut fh = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .await?;
            fh.write_all(json.as_bytes()).await?;
            fh.sync_all().await?;
            drop(fh);
            tokio::fs::rename(&tmp, &file).await
        };
        match write().await {
            Ok(()) => Ok(()),
            Err(source) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(Error::SaveDbAsync {
                    source,
                    file: file.clone(),
                })
            }
        }
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}
