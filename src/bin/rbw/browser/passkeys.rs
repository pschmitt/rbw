//! `WebAuthn` responses contain public data and signatures only. Keys stay native.
use anyhow::{ensure, Context as _};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use p256::elliptic_curve::Generate as _;
use serde_cbor::Value as Cbor;
use serde_json::{json, Value};
use sha2::Digest as _;

use crate::{actions, commands, passkey, FindArgs};

pub fn relying_party(
    origin: &str,
    options: &Value,
    create: bool,
) -> anyhow::Result<String> {
    let url = url::Url::parse(origin)?;
    let host = url.host_str().context("missing host")?;
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http" && host == "localhost"),
        "insecure origin"
    );
    let rp = if create {
        options["rp"]["id"].as_str()
    } else {
        options["rpId"].as_str()
    }
    .unwrap_or(host);
    ensure!(
        host == rp || host.ends_with(&format!(".{rp}")),
        "RP mismatch"
    );
    ensure!(
        rp == "localhost" || psl::domain_str(rp).is_some(),
        "public suffix is not a relying party"
    );
    ensure!(
        options["extensions"].get("appid").is_none()
            && options["extensions"].get("appidExclude").is_none(),
        "legacy AppID unsupported"
    );
    ensure!(
        options["extensions"]["enforceCredentialProtectionPolicy"] != true,
        "credential protection policy unsupported"
    );
    ensure!(
        rp.parse::<std::net::IpAddr>().is_err(),
        "IP relying parties unsupported"
    );
    let challenge =
        options["challenge"].as_str().context("missing challenge")?;
    let bytes = decode(challenge)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4096,
        "invalid challenge"
    );
    Ok(rp.to_owned())
}

fn decode(value: &str) -> anyhow::Result<Vec<u8>> {
    let value = value
        .strip_prefix("b64.")
        .unwrap_or(value)
        .replace('-', "+")
        .replace('_', "/");
    let padded = format!("{value}{}", "=".repeat((4 - value.len() % 4) % 4));
    Ok(rbw::base64::decode(padded)?)
}

fn id_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    uuid::Uuid::parse_str(value)
        .map_or_else(|_| decode(value), |id| Ok(id.as_bytes().to_vec()))
}

pub fn candidates(origin: &str, options: &Value) -> anyhow::Result<Value> {
    let rp = relying_party(origin, options, false)?;
    let db = commands::load_db()?;
    let allow = options["allowCredentials"].as_array();
    let mut found = Vec::new();
    for entry in db.entries.iter().filter(|e| !e.deleted && !e.archived) {
        let rbw::db::EntryData::Login {
            fido2_credentials, ..
        } = &entry.data
        else {
            continue;
        };
        for credential in fido2_credentials {
            let decrypt = |value: &Option<String>| {
                value
                    .as_deref()
                    .map(|v| super::decrypt(entry, v))
                    .transpose()
            };
            if decrypt(&credential.rp_id)?.as_deref() != Some(&rp) {
                continue;
            }
            let id = B64.encode(id_bytes(
                &decrypt(&credential.credential_id)?
                    .context("missing credential ID")?,
            )?);
            if allow.is_some_and(|a| {
                !a.is_empty()
                    && !a.iter().any(|v| {
                        v["type"] == "public-key"
                            && v["id"].as_str().is_some_and(|v| {
                                v.trim_end_matches('=') == id
                            })
                    })
            }) {
                continue;
            }
            let icon_origin = match &entry.data {
                rbw::db::EntryData::Login { uris, .. } => uris
                    .iter()
                    .filter_map(|uri| super::decrypt(entry, &uri.uri).ok())
                    .filter_map(|uri| url::Url::parse(&uri).ok())
                    .find(|uri| {
                        uri.scheme() == "https"
                            || (uri.scheme() == "http"
                                && uri.host_str() == Some("localhost"))
                    })
                    .map(|uri| uri.origin().ascii_serialization()),
                _ => None,
            };
            found.push(json!({"id": entry.id, "credential_id": id, "name": super::decrypt(entry, &entry.name)?, "username": decrypt(&credential.user_name)?, "iconOrigin": icon_origin}));
        }
    }
    Ok(json!({"rp": rp, "items": found}))
}

pub fn authenticate(
    item: &str,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    let rp = relying_party(origin, options, false)?;
    let verified = verification(options, false, password)?;
    let found = candidates(origin, options)?;
    ensure!(
        found["items"]
            .as_array()
            .context("missing items")?
            .iter()
            .any(|v| v["id"] == item),
        "credential not allowed"
    );
    let allow = options["allowCredentials"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["id"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let args = FindArgs {
        needles: vec![commands::parse_needle(item)?],
        user: None,
        folder: None,
        collection: None,
        org: None,
        ignorecase: false,
        exact: false,
    };
    passkey::browser_assert(
        &args,
        Some(&rp),
        origin,
        options["challenge"].as_str().context("missing challenge")?,
        &allow,
        verified,
    )
}

pub fn confirm_counter(
    item: &str,
    origin: &str,
    options: &Value,
    counter: u32,
) -> anyhow::Result<Value> {
    let rp = relying_party(origin, options, false)?;
    passkey::browser_confirm_counter(item, &rp, counter)?;
    Ok(json!(true))
}

pub fn register(
    item: Option<&str>,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    let rp = relying_party(origin, options, true)?;
    let verified = verification(options, true, password)?;
    ensure!(
        options["pubKeyCredParams"].as_array().is_some_and(|a| a
            .iter()
            .any(|p| p["type"] == "public-key" && p["alg"] == -7)),
        "ES256 required"
    );
    ensure!(
        options["authenticatorSelection"]["authenticatorAttachment"].as_str()
            != Some("cross-platform"),
        "platform authenticator required"
    );
    // Verify the entire exclude list before generating or persisting a key.
    let exclusion = json!({"challenge": options["challenge"], "rpId": rp, "allowCredentials": options["excludeCredentials"]});
    if options["excludeCredentials"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        ensure!(
            candidates(origin, &exclusion)?["items"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "credential already registered"
        );
    }
    let user = &options["user"];
    let handle = decode(user["id"].as_str().context("missing user handle")?)?;
    ensure!(
        !handle.is_empty() && handle.len() <= 64,
        "invalid user handle"
    );
    let username = user["name"].as_str().context("missing username")?;
    let display = user["displayName"].as_str().unwrap_or(username);
    ensure!(
        username.len() <= 1024 && display.len() <= 1024,
        "user name too long"
    );
    let mut db = commands::load_db()?;
    let existing =
        item.map(|id| super::entry(&db, id).cloned()).transpose()?;
    let mut editable = existing
        .as_ref()
        .map(|e| {
            commands::decrypt_cipher(e)
                .map(|d| commands::decrypted_to_editable(&d))
        })
        .transpose()?
        .unwrap_or_else(|| commands::EditableCipher {
            name: rp.clone(),
            folder: None,
            notes: None,
            fields: vec![],
            data: commands::EditableData::Login {
                username: Some(username.to_owned()),
                password: None,
                uris: vec![commands::EditableUri {
                    uri: origin.to_owned(),
                    match_type: None,
                }],
                totp: None,
                fido2_credentials: vec![],
            },
        });
    let commands::EditableData::Login {
        fido2_credentials, ..
    } = &mut editable.data
    else {
        anyhow::bail!("not a login");
    };
    ensure!(
        !fido2_credentials
            .iter()
            .any(|c| c.rp_id.as_deref() == Some(&rp)),
        "entry already contains a passkey for this relying party"
    );
    let key = p256::ecdsa::SigningKey::generate();
    let id = uuid::Uuid::new_v4();
    let point = key.verifying_key().to_sec1_point(false);
    let x = point.x().context("missing public x")?;
    let y = point.y().context("missing public y")?;
    let cose = Cbor::Map(std::collections::BTreeMap::from([
        (Cbor::Integer(1), Cbor::Integer(2)),
        (Cbor::Integer(3), Cbor::Integer(-7)),
        (Cbor::Integer(-1), Cbor::Integer(1)),
        (Cbor::Integer(-2), Cbor::Bytes(x.to_vec())),
        (Cbor::Integer(-3), Cbor::Bytes(y.to_vec())),
    ]));
    let mut auth = sha2::Sha256::digest(rp.as_bytes()).to_vec();
    // UP, UV, backup eligible, backed up, attested credential data.
    auth.push(if verified { 0x5d } else { 0x59 });
    auth.extend_from_slice(&0u32.to_be_bytes());
    auth.extend_from_slice(&[0; 16]); // Anonymous authenticator AAGUID.
    auth.extend_from_slice(&16u16.to_be_bytes());
    auth.extend_from_slice(id.as_bytes());
    auth.extend(serde_cbor::to_vec(&cose)?);
    let attestation = Cbor::Map(std::collections::BTreeMap::from([
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth.clone())),
        (
            Cbor::Text("attStmt".into()),
            Cbor::Map(std::collections::BTreeMap::new()),
        ),
    ]));
    fido2_credentials.push(commands::EditableFido2Credential {
        credential_id: Some(id.to_string()),
        key_type: Some("public-key".into()),
        key_algorithm: Some("ECDSA".into()),
        key_curve: Some("P-256".into()),
        key_value: Some(rbw::base64::encode(key.to_pkcs8_der()?.as_bytes())),
        rp_id: Some(rp.clone()),
        user_handle: Some(B64.encode(handle)),
        user_name: Some(username.to_owned()),
        counter: Some("0".into()),
        rp_name: Some(
            options["rp"]["name"].as_str().unwrap_or(&rp).to_owned(),
        ),
        user_display_name: Some(display.to_owned()),
        discoverable: Some("true".into()),
        creation_date: Some(
            humantime::format_rfc3339(std::time::SystemTime::now())
                .to_string(),
        ),
    });
    if let Some(entry) = existing {
        commands::tui_save_edit(&mut db, &entry, &editable)?;
    } else {
        commands::tui_save_add(&mut db, &editable)?;
    }
    // Persist and synchronize before returning a successful registration.
    actions::sync()?;
    let fresh = candidates(
        origin,
        &json!({"challenge": options["challenge"], "rpId": rp, "allowCredentials": [{"type": "public-key", "id": B64.encode(id.as_bytes())}]}),
    )?;
    ensure!(
        fresh["items"].as_array().is_some_and(|a| a.len() == 1),
        "registration was not persisted"
    );
    let client = serde_json::to_vec(
        &json!({"type": "webauthn.create", "challenge": B64.encode(decode(options["challenge"].as_str().context("missing challenge")?)?), "origin": url::Url::parse(origin)?.origin().ascii_serialization(), "crossOrigin": false}),
    )?;
    Ok(
        json!({"id": B64.encode(id.as_bytes()), "rawId": B64.encode(id.as_bytes()), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": {"credProps": {"rk": true}}, "response": {"clientDataJSON": B64.encode(client), "attestationObject": B64.encode(serde_cbor::to_vec(&attestation)?), "authenticatorData": B64.encode(auth), "publicKey": B64.encode(key.verifying_key().to_public_key_der()?.as_bytes()), "publicKeyAlgorithm": -7, "transports": ["internal"]}}),
    )
}

fn verification(
    options: &Value,
    create: bool,
    password: Option<&str>,
) -> anyhow::Result<bool> {
    let requirement = if create {
        options["authenticatorSelection"]["userVerification"].as_str()
    } else {
        options["userVerification"].as_str()
    }
    .unwrap_or("preferred");
    ensure!(
        ["preferred", "discouraged", "required"].contains(&requirement),
        "invalid verification requirement"
    );
    if let Some(password) = password {
        ensure!(
            !password.is_empty() && password.len() <= 4096,
            "invalid master password length"
        );
        actions::verify_master_password(password)?;
        Ok(true)
    } else {
        ensure!(
            requirement != "required",
            "master password verification required"
        );
        Ok(false)
    }
}
