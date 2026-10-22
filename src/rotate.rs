// Account key rotation (`rbw security rotate-key`): re-encrypts everything
// in a personal vault that is encrypted directly with the user key, so the
// key can be replaced. Works on the raw `/sync` JSON rather than on rbw's
// own parsed entries, so fields rbw doesn't model survive untouched: every
// symmetric cipherstring under the old key is decrypted and re-encrypted
// under the new one, everything else is copied as is. Anything that can't
// be re-keyed this way is an error, raised before any request is sent.

use crate::prelude::*;

use zeroize::Zeroize as _;

pub struct RotatedVault {
    pub ciphers: Vec<serde_json::Value>,
    pub folders: Vec<serde_json::Value>,
    pub sends: Vec<serde_json::Value>,
    pub private_key: String,
}

fn rotation_error(reason: impl Into<String>) -> Error {
    Error::KeyRotation {
        reason: reason.into(),
    }
}

// Every value encrypted with the user key is re-encrypted with `new`.
// Personal ciphers that carry their own item key only get that key
// re-wrapped, since the rest of their data is encrypted with it. Org
// ciphers are left out: they're encrypted with the org key, which the
// account's (unchanged) RSA key pair protects.
pub fn rotate_vault(
    sync: &serde_json::Value,
    old: &crate::locked::Keys,
    new: &crate::locked::Keys,
) -> Result<RotatedVault> {
    let user_id = sync["profile"]["id"]
        .as_str()
        .ok_or_else(|| rotation_error("sync response has no profile id"))?;
    let private_key = sync["profile"]["privateKey"]
        .as_str()
        .ok_or_else(|| rotation_error("account has no private key"))?;

    let mut ciphers = vec![];
    for cipher in array(sync, "ciphers")? {
        if !cipher["organizationId"].is_null() {
            continue;
        }
        ciphers.push(rotate_cipher(cipher, user_id, old, new)?);
    }

    let mut folders = vec![];
    for folder in array(sync, "folders")? {
        folders.push(serde_json::json!({
            "id": folder["id"],
            "name": reencrypt_str(str_field(folder, "name")?, old, new)?,
        }));
    }

    let mut sends = vec![];
    for send in array(sync, "sends")? {
        // A send's contents are encrypted with a key derived from its own
        // key, which is the only part wrapped with the user key.
        let mut send = send.clone();
        send["key"] =
            reencrypt_str(str_field(&send, "key")?, old, new)?.into();
        sends.push(send);
    }

    Ok(RotatedVault {
        ciphers,
        folders,
        sends,
        private_key: reencrypt_str(private_key, old, new)?,
    })
}

fn array<'a>(
    sync: &'a serde_json::Value,
    field: &str,
) -> Result<&'a Vec<serde_json::Value>> {
    match &sync[field] {
        serde_json::Value::Null => {
            static EMPTY: Vec<serde_json::Value> = vec![];
            Ok(&EMPTY)
        }
        serde_json::Value::Array(values) => Ok(values),
        _ => Err(rotation_error(format!(
            "sync response field {field} is not a list"
        ))),
    }
}

fn str_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str> {
    value[field].as_str().ok_or_else(|| {
        rotation_error(format!(
            "{} {} has no {field}",
            value["object"].as_str().unwrap_or("item"),
            value["id"].as_str().unwrap_or("?"),
        ))
    })
}

fn rotate_cipher(
    cipher: &serde_json::Value,
    user_id: &str,
    old: &crate::locked::Keys,
    new: &crate::locked::Keys,
) -> Result<serde_json::Value> {
    let id = str_field(cipher, "id")?;
    let mut cipher = cipher.clone();

    if let Some(key) = cipher["key"].as_str() {
        cipher["key"] = reencrypt_str(key, old, new)?.into();
    } else {
        for attachment in
            cipher["attachments"].as_array().into_iter().flatten()
        {
            // Without an attachment key the file itself is encrypted with
            // the user key and would have to be re-uploaded.
            if attachment["key"].as_str().is_none() {
                return Err(rotation_error(format!(
                    "attachment {} of item {id} has no key of its own; \
                     re-upload it before rotating",
                    attachment["id"].as_str().unwrap_or("?"),
                )));
            }
        }
        reencrypt_value(&mut cipher, old, new)
            .map_err(|e| rotation_error(format!("item {id}: {e}")))?;
    }

    let attachments: serde_json::Map<_, _> = cipher["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|attachment| {
            Some((
                attachment["id"].as_str()?.to_string(),
                serde_json::json!({
                    "fileName": attachment["fileName"],
                    "key": attachment["key"],
                }),
            ))
        })
        .collect();
    cipher["attachments2"] = attachments.into();
    cipher["encryptedFor"] = user_id.into();
    cipher["lastKnownRevisionDate"] = cipher["revisionDate"].clone();
    Ok(cipher)
}

// Re-encrypts every cipherstring anywhere inside `value`. Bitwarden's JSON
// has no plaintext values that look like `<digits>.<base64>|...`, so any
// string of that shape is treated as encrypted; one that isn't a type 2
// (AES-CBC + HMAC) cipherstring can't be re-encrypted and is an error
// rather than being silently left behind under the old key.
fn reencrypt_value(
    value: &mut serde_json::Value,
    old: &crate::locked::Keys,
    new: &crate::locked::Keys,
) -> Result<()> {
    match value {
        serde_json::Value::String(s) if looks_encrypted(s) => {
            *s = reencrypt_str(s, old, new)?;
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reencrypt_value(value, old, new)?;
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                reencrypt_value(value, old, new)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn looks_encrypted(s: &str) -> bool {
    s.split_once('.').is_some_and(|(ty, rest)| {
        !ty.is_empty()
            && ty.bytes().all(|b| b.is_ascii_digit())
            && rest.contains('|')
    })
}

pub fn reencrypt_str(
    s: &str,
    old: &crate::locked::Keys,
    new: &crate::locked::Keys,
) -> Result<String> {
    if !s.starts_with("2.") {
        return Err(rotation_error(format!(
            "unsupported cipherstring type {}",
            s.split('.').next().unwrap_or_default()
        )));
    }
    let mut plaintext = crate::cipherstring::CipherString::new(s)?
        .decrypt_symmetric(old, None)?;
    let res =
        crate::cipherstring::CipherString::encrypt_symmetric(new, &plaintext);
    plaintext.zeroize();
    Ok(res?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> crate::locked::Keys {
        crate::cipherstring::generate_attachment_keys()
    }

    fn enc(keys: &crate::locked::Keys, s: &str) -> String {
        crate::cipherstring::CipherString::encrypt_symmetric(
            keys,
            s.as_bytes(),
        )
        .unwrap()
        .to_string()
    }

    fn dec(keys: &crate::locked::Keys, s: &serde_json::Value) -> String {
        let bytes =
            crate::cipherstring::CipherString::new(s.as_str().unwrap())
                .unwrap()
                .decrypt_symmetric(keys, None)
                .unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn sync(
        old: &crate::locked::Keys,
        ciphers: &[serde_json::Value],
    ) -> serde_json::Value {
        serde_json::json!({
            "profile": {"id": "user-1", "privateKey": enc(old, "private")},
            "ciphers": ciphers,
            "folders": [{"id": "f1", "name": enc(old, "folder")}],
            "sends": [{"id": "s1", "key": enc(old, "sendkey"), "name": "2.x|y|z"}],
        })
    }

    #[test]
    fn rotates_everything_under_the_user_key() {
        let (old, new) = (keys(), keys());
        let item_key = keys();
        let sync = sync(
            &old,
            &[
                serde_json::json!({
                    "id": "c1",
                    "type": 1,
                    "organizationId": null,
                    "key": null,
                    "revisionDate": "2026-10-22T10:00:00.000000Z",
                    "name": enc(&old, "name"),
                    "login": {
                        "username": enc(&old, "user"),
                        "uris": [{"uri": enc(&old, "https://x"), "match": null}],
                        "fido2Credentials": [{"counter": enc(&old, "0"), "creationDate": "2026-01-01T00:00:00Z"}],
                    },
                    "attachments": [{"id": "a1", "fileName": enc(&old, "f.txt"), "key": enc(&old, "akey")}],
                }),
                serde_json::json!({
                    "id": "c2",
                    "organizationId": null,
                    "key": enc(&old, "itemkey"),
                    "name": enc(&item_key, "keyed"),
                }),
                serde_json::json!({"id": "c3", "organizationId": "o1", "name": "2.a|b|c"}),
            ],
        );

        let rotated = rotate_vault(&sync, &old, &new).unwrap();
        assert_eq!(rotated.ciphers.len(), 2);

        let c1 = &rotated.ciphers[0];
        assert_eq!(dec(&new, &c1["name"]), "name");
        assert_eq!(dec(&new, &c1["login"]["username"]), "user");
        assert_eq!(dec(&new, &c1["login"]["uris"][0]["uri"]), "https://x");
        assert_eq!(
            dec(&new, &c1["login"]["fido2Credentials"][0]["counter"]),
            "0"
        );
        assert_eq!(
            c1["login"]["fido2Credentials"][0]["creationDate"],
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(dec(&new, &c1["attachments2"]["a1"]["key"]), "akey");
        assert_eq!(dec(&new, &c1["attachments2"]["a1"]["fileName"]), "f.txt");
        assert_eq!(c1["encryptedFor"], "user-1");
        assert_eq!(
            c1["lastKnownRevisionDate"],
            "2026-10-22T10:00:00.000000Z"
        );

        let c2 = &rotated.ciphers[1];
        assert_eq!(dec(&new, &c2["key"]), "itemkey");
        // Encrypted with the item key, so left alone.
        assert_eq!(c2["name"], sync["ciphers"][1]["name"]);

        assert_eq!(dec(&new, &rotated.folders[0]["name"]), "folder");
        assert_eq!(dec(&new, &rotated.sends[0]["key"]), "sendkey");
        assert_eq!(rotated.sends[0]["name"], "2.x|y|z");
        assert_eq!(
            dec(&new, &serde_json::Value::String(rotated.private_key)),
            "private"
        );
    }

    #[test]
    fn refuses_what_it_cannot_rotate() {
        let (old, new) = (keys(), keys());
        let keyless_attachment = serde_json::json!({
            "id": "c1", "organizationId": null, "key": null,
            "name": enc(&old, "n"),
            "attachments": [{"id": "a1", "fileName": enc(&old, "f"), "key": null}],
        });
        assert!(rotate_vault(&sync(&old, &[keyless_attachment]), &old, &new)
            .is_err());

        let legacy = serde_json::json!({
            "id": "c1", "organizationId": null, "key": null,
            "name": "0.aaaa|bbbb",
        });
        assert!(rotate_vault(&sync(&old, &[legacy]), &old, &new).is_err());

        // Encrypted with some other key: the MAC check fails.
        let foreign = serde_json::json!({
            "id": "c1", "organizationId": null, "key": null,
            "name": enc(&keys(), "n"),
        });
        assert!(rotate_vault(&sync(&old, &[foreign]), &old, &new).is_err());
    }
}
