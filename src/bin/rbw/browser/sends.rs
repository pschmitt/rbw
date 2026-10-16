//! Bitwarden-compatible Sends. Account keys never leave the shared agent.
use anyhow::{ensure, Context as _};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{actions, commands};

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
fn describe(value: &Value, include_text: bool) -> anyhow::Result<Value> {
    let seed = seed(value)?;
    let keys = derive(&seed)?;
    Ok(
        json!({"id": value["id"], "name": decrypt(&keys, &value["name"])?, "type": value["type"], "disabled": value["disabled"], "deletionDate": value["deletionDate"], "expirationDate": value["expirationDate"], "accessCount": value["accessCount"], "maxAccessCount": value["maxAccessCount"], "hasPassword": !value["password"].is_null(), "hideEmail": value["hideEmail"], "fileName": decrypt(&keys, &value["file"]["fileName"])?, "text": if include_text { decrypt(&keys, &value["text"]["text"])? } else { None }, "notes": if include_text { decrypt(&keys, &value["notes"])? } else { None }, "hidden": value["text"]["hidden"]}),
    )
}

pub fn dispatch(
    db: &mut rbw::db::Db,
    transfers: &mut super::attachments::Transfers,
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
            let config = rbw::config::Config::load()?;
            let account =
                config.account(actions::current_account().as_deref())?;
            let access =
                value["accessId"].as_str().context("missing access ID")?;
            ensure!(
                access.chars().all(|c| c.is_ascii_alphanumeric()
                    || c == '-'
                    || c == '_'),
                "invalid access ID"
            );
            let link = format!(
                "{}/#/send/{access}/{}",
                account.ui_url()?.trim_end_matches('/'),
                B64.encode(&material)
            );
            actions::system_clipboard_store(&link)?;
            Ok(json!(true))
        }
        "delete" => {
            request(
                db,
                "DELETE",
                &format!("/sends/{}", id(data)?),
                None,
                None,
            )?;
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
    transfers: &mut super::attachments::Transfers,
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
