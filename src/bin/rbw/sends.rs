//! Bitwarden-compatible Sends. Account keys never leave the shared agent.
use anyhow::{ensure, Context as _};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{actions, commands};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SendType {
    Text = 0,
    File = 1,
}

impl std::fmt::Display for SendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "Text"),
            Self::File => write!(f, "File"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendInfo {
    pub id: String,
    pub access_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub send_type: SendType,
    pub disabled: bool,
    pub has_password: bool,
    pub hide_email: bool,
    pub deletion_date: String,
    pub expiration_date: Option<String>,
    pub access_count: u64,
    pub max_access_count: Option<u64>,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub notes: Option<String>,
    pub text: Option<String>,
    pub hidden: bool,
    pub url: String,
}

impl SendInfo {
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = &self.expiration_date {
            if let Ok(t) = humantime::parse_rfc3339(exp) {
                if t < std::time::SystemTime::now() {
                    return true;
                }
            }
        }
        if let Some(max) = self.max_access_count {
            if self.access_count >= max {
                return true;
            }
        }
        false
    }

    pub fn status_label(&self) -> &'static str {
        if self.disabled {
            "Disabled"
        } else if self.is_expired() {
            "Expired"
        } else {
            "Active"
        }
    }
}

pub enum SendContent {
    Text(String),
    File { bytes: Vec<u8>, file_name: String },
}

pub struct CreateParams {
    pub name: String,
    pub content: SendContent,
    pub notes: Option<String>,
    pub password: Option<String>,
    pub hidden: bool,
    pub days: u64,
    pub deletion_date: Option<String>,
    pub expiration_date: Option<String>,
    pub max_access_count: Option<u64>,
    pub hide_email: bool,
}

#[derive(Default)]
#[allow(clippy::option_option)]
pub struct UpdateParams {
    pub name: Option<String>,
    pub notes: Option<String>,
    pub text: Option<String>,
    pub hidden: Option<bool>,
    pub password: Option<String>,
    pub remove_password: bool,
    pub days: Option<u64>,
    pub deletion_date: Option<String>,
    pub expiration_date: Option<Option<String>>,
    pub max_access_count: Option<Option<u64>>,
    pub disabled: Option<bool>,
    pub hide_email: Option<bool>,
}

fn request(
    db: &mut rbw::db::Db,
    method: &str,
    path: &str,
    body: Option<&Value>,
    file: Option<(&[u8], &str)>,
) -> anyhow::Result<Value> {
    let (tokens, result) = rbw::actions::send_request(
        db.access_token.as_deref().context("not logged in")?,
        db.refresh_token.as_deref().context("not logged in")?,
        method,
        path,
        body,
        file,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh) = tokens.refresh_token {
            db.refresh_token = Some(refresh);
        }
        commands::save_db(db)?;
    }
    Ok(result)
}

fn derive(seed: &[u8]) -> anyhow::Result<rbw::locked::Keys> {
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(std::iter::repeat_n(0, 64));
    hkdf::Hkdf::<sha2::Sha256>::new(Some(b"bitwarden-send"), seed)
        .expand(b"send", bytes.data_mut())
        .map_err(|_| anyhow::anyhow!("invalid Send key"))?;
    Ok(rbw::locked::Keys::new(bytes))
}

fn encrypt(keys: &rbw::locked::Keys, value: &str) -> anyhow::Result<String> {
    Ok(rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        value.as_bytes(),
    )?
    .to_string())
}

fn decrypt(
    keys: &rbw::locked::Keys,
    value: &Value,
) -> anyhow::Result<Option<String>> {
    value
        .as_str()
        .map(|v| {
            Ok(String::from_utf8(
                rbw::cipherstring::CipherString::new(v)?
                    .decrypt_symmetric(keys, None)?,
            )?)
        })
        .transpose()
}

fn seed(value: &Value) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(actions::crypt_bytes(
        value["key"]
            .as_str()
            .context("missing Send key")?
            .as_bytes()
            .to_vec(),
        true,
    )?))
}

fn id(data: &Value) -> anyhow::Result<String> {
    Ok(uuid::Uuid::parse_str(
        data["id"].as_str().context("missing Send ID")?,
    )?
    .to_string())
}

pub fn send_url(value: &Value, seed: &[u8]) -> anyhow::Result<String> {
    let config = rbw::config::Config::load()?;
    let account = config.account(actions::current_account().as_deref())?;
    let access = value["accessId"].as_str().context("missing access ID")?;
    ensure!(
        access
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "invalid access ID"
    );
    Ok(format!(
        "{}/#/send/{access}/{}",
        account.ui_url()?.trim_end_matches('/'),
        B64.encode(seed)
    ))
}

pub fn describe_info(value: &Value) -> anyhow::Result<SendInfo> {
    let seed = seed(value)?;
    let keys = derive(&seed)?;
    let url = send_url(value, &seed).unwrap_or_default();
    let name = decrypt(&keys, &value["name"])?.unwrap_or_default();
    let notes = decrypt(&keys, &value["notes"])?;
    let send_type = if value["type"].as_u64().unwrap_or(0) == 1 {
        SendType::File
    } else {
        SendType::Text
    };
    let disabled = value["disabled"].as_bool().unwrap_or(false);
    let has_password = !value["password"].is_null();
    let hide_email = value["hideEmail"].as_bool().unwrap_or(true);
    let deletion_date = value["deletionDate"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let expiration_date =
        value["expirationDate"].as_str().map(str::to_string);
    let access_count = value["accessCount"].as_u64().unwrap_or(0);
    let max_access_count = value["maxAccessCount"].as_u64();
    let file_name = decrypt(&keys, &value["file"]["fileName"])?;
    let file_size = value["file"]["size"].as_u64();
    let text = decrypt(&keys, &value["text"]["text"])?;
    let hidden = value["text"]["hidden"].as_bool().unwrap_or(false);

    Ok(SendInfo {
        id: value["id"].as_str().unwrap_or_default().to_string(),
        access_id: value["accessId"].as_str().unwrap_or_default().to_string(),
        name,
        send_type,
        disabled,
        has_password,
        hide_email,
        deletion_date,
        expiration_date,
        access_count,
        max_access_count,
        file_name,
        file_size,
        notes,
        text,
        hidden,
        url,
    })
}

fn describe(value: &Value, include_text: bool) -> anyhow::Result<Value> {
    let seed = seed(value)?;
    let keys = derive(&seed)?;
    Ok(
        json!({"id": value["id"], "name": decrypt(&keys, &value["name"])?, "type": value["type"], "disabled": value["disabled"], "deletionDate": value["deletionDate"], "expirationDate": value["expirationDate"], "accessCount": value["accessCount"], "maxAccessCount": value["maxAccessCount"], "hasPassword": !value["password"].is_null(), "hideEmail": value["hideEmail"], "fileName": decrypt(&keys, &value["file"]["fileName"])?, "text": if include_text { decrypt(&keys, &value["text"]["text"])? } else { None }, "notes": if include_text { decrypt(&keys, &value["notes"])? } else { None }, "hidden": value["text"]["hidden"]}),
    )
}

pub fn list_sends(db: &mut rbw::db::Db) -> anyhow::Result<Vec<SendInfo>> {
    let list = request(db, "GET", "/sends", None, None)?;
    let items = list["data"]
        .as_array()
        .context("missing Sends list")?
        .iter()
        .map(describe_info)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(items)
}

pub fn find_send(
    db: &mut rbw::db::Db,
    needle: &str,
) -> anyhow::Result<(Value, SendInfo)> {
    if let Ok(id) = uuid::Uuid::parse_str(needle) {
        if let Ok(value) =
            request(db, "GET", &format!("/sends/{id}"), None, None)
        {
            let info = describe_info(&value)?;
            return Ok((value, info));
        }
    }
    let list = request(db, "GET", "/sends", None, None)?;
    let array = list["data"].as_array().context("missing Sends list")?;
    let mut exact_matches = Vec::new();
    let mut sub_matches = Vec::new();
    let needle_lower = needle.to_lowercase();

    for item in array {
        let Ok(seed_bytes) = seed(item) else { continue };
        let Ok(keys) = derive(&seed_bytes) else {
            continue;
        };
        let Ok(Some(name)) = decrypt(&keys, &item["name"]) else {
            continue;
        };
        let id_str = item["id"].as_str().unwrap_or_default();

        if id_str == needle
            || name == needle
            || name.to_lowercase() == needle_lower
        {
            exact_matches.push((name, item.clone()));
        } else if name.to_lowercase().contains(&needle_lower) {
            sub_matches.push((name, item.clone()));
        }
    }

    let target_item = if exact_matches.len() == 1 {
        exact_matches.pop().unwrap().1
    } else if exact_matches.len() > 1 {
        let names: Vec<String> = exact_matches
            .iter()
            .map(|(n, i)| {
                format!("{} ({})", n, i["id"].as_str().unwrap_or_default())
            })
            .collect();
        anyhow::bail!(
            "multiple Sends matched '{}': {}",
            needle,
            names.join(", ")
        );
    } else if sub_matches.len() == 1 {
        sub_matches.pop().unwrap().1
    } else if sub_matches.len() > 1 {
        let names: Vec<String> = sub_matches
            .iter()
            .map(|(n, i)| {
                format!("{} ({})", n, i["id"].as_str().unwrap_or_default())
            })
            .collect();
        anyhow::bail!(
            "multiple Sends matched '{}': {}",
            needle,
            names.join(", ")
        );
    } else {
        anyhow::bail!("no Send found matching '{needle}'");
    };

    let send_id = id(&target_item)?;
    let full = request(db, "GET", &format!("/sends/{send_id}"), None, None)?;
    let info = describe_info(&full)?;
    Ok((full, info))
}

pub fn create_send(
    db: &mut rbw::db::Db,
    params: CreateParams,
) -> anyhow::Result<SendInfo> {
    use rand::Rng as _;

    ensure!(
        !params.name.trim().is_empty() && params.name.len() <= 1024,
        "invalid Send name"
    );
    ensure!(
        (1..=30).contains(&params.days),
        "invalid deletion period (must be 1-30 days)"
    );

    let mut material = Zeroizing::new(vec![0u8; 16]);
    rand::rng().fill_bytes(&mut material);
    let keys = derive(&material)?;

    let deletion = params.deletion_date.unwrap_or_else(|| {
        humantime::format_rfc3339(
            std::time::SystemTime::now()
                + std::time::Duration::from_secs(params.days * 86400),
        )
        .to_string()
    });

    let password = params
        .password
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|pwd| -> anyhow::Result<String> {
            ensure!(pwd.len() <= 4096, "password too long");
            let mut hash = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                pwd.as_bytes(),
                &material,
                100_000,
                hash.as_mut(),
            )
            .map_err(|_| {
                anyhow::anyhow!("Send password derivation failed")
            })?;
            Ok(rbw::base64::encode(hash.as_ref()))
        })
        .transpose()?;

    let wrapped = json!(String::from_utf8(actions::crypt_bytes(
        material.to_vec(),
        false,
    )?)?);

    let send_type = match &params.content {
        SendContent::Text(_) => 0,
        SendContent::File { .. } => 1,
    };

    let mut body = json!({
        "type": send_type,
        "key": wrapped,
        "name": encrypt(&keys, &params.name)?,
        "notes": encrypt(&keys, params.notes.as_deref().unwrap_or_default())?,
        "password": password,
        "maxAccessCount": params.max_access_count,
        "expirationDate": params.expiration_date,
        "deletionDate": deletion,
        "disabled": false,
        "hideEmail": params.hide_email,
    });

    match params.content {
        SendContent::Text(text) => {
            ensure!(
                text.len() <= 100_000,
                "Send text too long (max 100,000 chars)"
            );
            body["text"] = json!({
                "text": encrypt(&keys, &text)?,
                "hidden": params.hidden,
            });
            let response = request(db, "POST", "/sends", Some(&body), None)?;
            describe_info(&response)
        }
        SendContent::File { bytes, file_name } => {
            ensure!(
                bytes.len() <= 100 * 1024 * 1024,
                "Send file too large (max 100 MB)"
            );
            let encrypted =
                rbw::cipherstring::encrypt_file_data(&bytes, &keys)?;
            let enc_file_name = encrypt(&keys, &file_name)?;
            body["file"] = json!({ "fileName": enc_file_name });
            body["fileLength"] = json!(encrypted.len());

            let upload =
                request(db, "POST", "/sends/file/v2", Some(&body), None)?;
            let send = &upload["sendResponse"];
            let send_id = id(send)?;
            let result = (|| -> anyhow::Result<()> {
                ensure!(
                    upload["fileUploadType"] == 0,
                    "server requires unsupported file upload type"
                );
                let file_id =
                    send["file"]["id"].as_str().context("missing file ID")?;
                ensure!(
                    file_id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "invalid file ID"
                );
                request(
                    db,
                    "POST",
                    &format!("/sends/{send_id}/file/{file_id}"),
                    None,
                    Some((&encrypted, &enc_file_name)),
                )?;
                Ok(())
            })();
            if result.is_err() {
                let _ = request(
                    db,
                    "DELETE",
                    &format!("/sends/{send_id}"),
                    None,
                    None,
                );
            }
            result?;
            describe_info(send)
        }
    }
}

pub fn update_send(
    db: &mut rbw::db::Db,
    mut existing: Value,
    params: UpdateParams,
) -> anyhow::Result<SendInfo> {
    let send_id = id(&existing)?;
    let material = seed(&existing)?;
    let keys = derive(&material)?;

    if params.remove_password {
        let _ = request(
            db,
            "PUT",
            &format!("/sends/{send_id}/remove-password"),
            None,
            None,
        );
        existing["password"] = Value::Null;
    }

    let name = if let Some(n) = params.name {
        ensure!(!n.trim().is_empty() && n.len() <= 1024, "invalid Send name");
        encrypt(&keys, &n)?
    } else {
        existing["name"].as_str().unwrap_or_default().to_string()
    };

    let notes = if let Some(n) = params.notes {
        encrypt(&keys, &n)?
    } else {
        existing["notes"].as_str().unwrap_or_default().to_string()
    };

    let password = if let Some(pwd) =
        params.password.as_deref().filter(|v| !v.is_empty())
    {
        ensure!(pwd.len() <= 4096, "password too long");
        let mut hash = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            pwd.as_bytes(),
            &material,
            100_000,
            hash.as_mut(),
        )
        .map_err(|_| anyhow::anyhow!("Send password derivation failed"))?;
        Some(rbw::base64::encode(hash.as_ref()))
    } else if params.remove_password {
        None
    } else {
        existing["password"].as_str().map(str::to_string)
    };

    let deletion = if let Some(d) = params.deletion_date {
        d
    } else if let Some(days) = params.days {
        ensure!(
            (1..=30).contains(&days),
            "invalid deletion period (1-30 days)"
        );
        humantime::format_rfc3339(
            std::time::SystemTime::now()
                + std::time::Duration::from_secs(days * 86400),
        )
        .to_string()
    } else {
        existing["deletionDate"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };

    let expiration = params.expiration_date.unwrap_or_else(|| {
        existing["expirationDate"].as_str().map(str::to_string)
    });

    let max_access = params
        .max_access_count
        .unwrap_or_else(|| existing["maxAccessCount"].as_u64());

    let disabled = params
        .disabled
        .unwrap_or_else(|| existing["disabled"].as_bool().unwrap_or(false));
    let hide_email = params
        .hide_email
        .unwrap_or_else(|| existing["hideEmail"].as_bool().unwrap_or(true));
    let send_type = existing["type"].as_u64().unwrap_or(0);

    let mut body = json!({
        "type": send_type,
        "key": existing["key"],
        "name": name,
        "notes": notes,
        "password": password,
        "maxAccessCount": max_access,
        "expirationDate": expiration,
        "deletionDate": deletion,
        "disabled": disabled,
        "hideEmail": hide_email,
    });

    if send_type == 1 {
        body["file"] = existing["file"].clone();
        body["text"] = Value::Null;
    } else {
        let text = if let Some(t) = params.text {
            ensure!(t.len() <= 100_000, "Send text too long");
            encrypt(&keys, &t)?
        } else {
            existing["text"]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        let hidden = params.hidden.unwrap_or_else(|| {
            existing["text"]["hidden"].as_bool().unwrap_or(false)
        });
        body["text"] = json!({
            "text": text,
            "hidden": hidden,
        });
    }

    let updated =
        request(db, "PUT", &format!("/sends/{send_id}"), Some(&body), None)?;
    describe_info(&updated)
}

pub fn delete_send(
    db: &mut rbw::db::Db,
    send_id: &str,
) -> anyhow::Result<()> {
    let _ = uuid::Uuid::parse_str(send_id).context("invalid Send ID")?;
    request(db, "DELETE", &format!("/sends/{send_id}"), None, None)?;
    Ok(())
}

pub fn dispatch(
    db: &mut rbw::db::Db,
    transfers: &mut crate::browser::attachments::Transfers,
    method: &str,
    data: &Value,
) -> anyhow::Result<Value> {
    match method {
        "list" => {
            let list = request(db, "GET", "/sends", None, None)?;
            let items = list["data"]
                .as_array()
                .context("missing Sends")?
                .iter()
                .map(|v| describe(v, false))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(json!(items))
        }
        "detail" => describe(
            &request(
                db,
                "GET",
                &format!("/sends/{}", id(data)?),
                None,
                None,
            )?,
            true,
        ),
        "copy" => {
            let value = request(
                db,
                "GET",
                &format!("/sends/{}", id(data)?),
                None,
                None,
            )?;
            let material = seed(&value)?;
            let link = send_url(&value, &material)?;
            actions::system_clipboard_store(&link)?;
            Ok(json!(true))
        }
        "delete" => {
            delete_send(db, &id(data)?)?;
            Ok(json!(true))
        }
        "remove_password" => {
            request(
                db,
                "PUT",
                &format!("/sends/{}/remove-password", id(data)?),
                None,
                None,
            )?;
            Ok(json!(true))
        }
        "save" => save(db, transfers, data),
        _ => anyhow::bail!("unknown Send operation"),
    }
}

fn save(
    db: &mut rbw::db::Db,
    transfers: &mut crate::browser::attachments::Transfers,
    data: &Value,
) -> anyhow::Result<Value> {
    use rand::Rng as _;
    let existing = if data["id"].is_null() {
        None
    } else {
        Some(request(
            db,
            "GET",
            &format!("/sends/{}", id(data)?),
            None,
            None,
        )?)
    };
    let material = if let Some(value) = &existing {
        seed(value)?
    } else {
        let mut bytes = Zeroizing::new(vec![0; 16]);
        rand::rng().fill_bytes(&mut bytes);
        bytes
    };
    let keys = derive(&material)?;
    let name = data["name"].as_str().context("name required")?;
    ensure!(
        !name.trim().is_empty() && name.len() <= 1024,
        "invalid Send name"
    );
    let days = data["days"].as_u64().unwrap_or(7);
    ensure!((1..=30).contains(&days), "invalid deletion period");
    let deletion = existing.as_ref().map_or_else(
        || {
            json!(humantime::format_rfc3339(
                std::time::SystemTime::now()
                    + std::time::Duration::from_secs(days * 86400)
            )
            .to_string())
        },
        |value| value["deletionDate"].clone(),
    );
    let password = data["password"]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(|password| -> anyhow::Result<String> {
            ensure!(password.len() <= 4096, "password too long");
            let mut hash = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                password.as_bytes(),
                &material,
                100_000,
                hash.as_mut(),
            )
            .map_err(|_| {
                anyhow::anyhow!("Send password derivation failed")
            })?;
            Ok(rbw::base64::encode(hash.as_ref()))
        })
        .transpose()?;
    let wrapped = if let Some(value) = &existing {
        value["key"].clone()
    } else {
        json!(String::from_utf8(actions::crypt_bytes(
            material.to_vec(),
            false
        )?)?)
    };
    let file = data["file_token"]
        .as_str()
        .map(|t| transfers.take(t))
        .transpose()?;
    let send_type = if file.is_some() {
        1
    } else {
        existing
            .as_ref()
            .and_then(|v| v["type"].as_u64())
            .unwrap_or(0)
    };
    let text = data["text"].as_str().unwrap_or_default();
    ensure!(text.len() <= 100_000, "Send text too long");
    let mut body = json!({"type": send_type, "key": wrapped, "name": encrypt(&keys, name)?, "notes": encrypt(&keys, data["notes"].as_str().unwrap_or_default())?, "password": password, "maxAccessCount": data["maxAccessCount"], "expirationDate": data["expirationDate"], "deletionDate": deletion, "disabled": data["disabled"].as_bool().unwrap_or(false), "hideEmail": data["hideEmail"].as_bool().unwrap_or(true), "text": {"text": encrypt(&keys, text)?, "hidden": data["hidden"].as_bool().unwrap_or(false)}});
    if let Some((bytes, name)) = file {
        let encrypted = rbw::cipherstring::encrypt_file_data(&bytes, &keys)?;
        let file_name = encrypt(&keys, &name)?;
        body["file"] = json!({"fileName": file_name});
        body["text"] = Value::Null;
        body["fileLength"] = json!(encrypted.len());
        let upload =
            request(db, "POST", "/sends/file/v2", Some(&body), None)?;
        let send = &upload["sendResponse"];
        let send_id = id(send)?;
        let result = (|| -> anyhow::Result<()> {
            ensure!(
                upload["fileUploadType"] == 0,
                "this server requires Azure file upload"
            );
            let file_id =
                send["file"]["id"].as_str().context("missing file ID")?;
            ensure!(
                file_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "invalid file ID"
            );
            request(
                db,
                "POST",
                &format!("/sends/{send_id}/file/{file_id}"),
                None,
                Some((&encrypted, &file_name)),
            )?;
            Ok(())
        })();
        if result.is_err() {
            let _ = request(
                db,
                "DELETE",
                &format!("/sends/{send_id}"),
                None,
                None,
            );
        }
        result?;
    } else if let Some(value) = existing {
        if send_type == 1 {
            body["file"] = value["file"].clone();
            body["text"] = Value::Null;
        }
        request(
            db,
            "PUT",
            &format!("/sends/{}", id(&value)?),
            Some(&body),
            None,
        )?;
    } else {
        request(db, "POST", "/sends", Some(&body), None)?;
    }
    Ok(json!(true))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_send_type_display() {
        assert_eq!(SendType::Text.to_string(), "Text");
        assert_eq!(SendType::File.to_string(), "File");
    }

    #[test]
    fn test_derive_and_encrypt_decrypt_round_trip() {
        let seed = [42u8; 64];
        let keys = derive(&seed).expect("failed to derive keys");
        let plaintext = "secret send contents with unicode: 🦀螃蟹";
        let encrypted = encrypt(&keys, plaintext).expect("encryption failed");
        let json_val = json!(encrypted);
        let decrypted = decrypt(&keys, &json_val)
            .expect("decryption failed")
            .expect("expected decrypted string");
        assert_eq!(decrypted, plaintext);

        assert!(decrypt(&keys, &Value::Null).unwrap().is_none());
    }

    #[test]
    fn test_send_info_status_labels() {
        let mut info = SendInfo {
            id: "test-id".to_string(),
            access_id: "test-access".to_string(),
            name: "Test Send".to_string(),
            send_type: SendType::Text,
            disabled: false,
            has_password: false,
            hide_email: true,
            deletion_date: "2099-01-01T00:00:00Z".to_string(),
            expiration_date: None,
            access_count: 0,
            max_access_count: None,
            file_name: None,
            file_size: None,
            notes: None,
            text: Some("hello".to_string()),
            hidden: false,
            url: "https://vault.bitwarden.com/#/send/test/seed".to_string(),
        };

        assert_eq!(info.status_label(), "Active");
        assert!(!info.is_expired());

        info.disabled = true;
        assert_eq!(info.status_label(), "Disabled");
        info.disabled = false;

        info.max_access_count = Some(5);
        info.access_count = 5;
        assert!(info.is_expired());
        assert_eq!(info.status_label(), "Expired");

        info.access_count = 4;
        assert!(!info.is_expired());
        assert_eq!(info.status_label(), "Active");

        info.expiration_date = Some("2020-01-01T00:00:00Z".to_string());
        assert!(info.is_expired());
        assert_eq!(info.status_label(), "Expired");

        info.expiration_date = Some("2099-01-01T00:00:00Z".to_string());
        assert!(!info.is_expired());
        assert_eq!(info.status_label(), "Active");
    }
}
