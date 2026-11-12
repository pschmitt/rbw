//! `WebAuthn` responses contain public data and signatures only. Keys stay native.
use anyhow::{ensure, Context as _};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use p256::elliptic_curve::Generate as _;
use serde_cbor::Value as Cbor;
use serde_json::{json, Value};
use sha2::Digest as _;

use crate::{actions, commands, passkey, FindArgs};

/// Why a passkey request was refused. The text is shown to the user, so it
/// says what to do and never includes vault data.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("Passkeys need a secure page (HTTPS). This page is not one, so rbw refused the request.")]
    InsecureOrigin,
    #[error("This site asked for a passkey for a domain ({0}) that does not match the page, so rbw refused the request.")]
    RpMismatch(String),
    #[error("This site asked for a passkey for a public suffix, which is not a valid relying party.")]
    PublicSuffix,
    #[error("This site uses the legacy WebAuthn AppID extension, which rbw does not support.")]
    LegacyAppId,
    #[error("This site enforces a credential protection policy that rbw does not support.")]
    CredentialProtection,
    #[error("Passkeys cannot be saved for an IP address.")]
    IpRelyingParty,
    #[error("The site sent an invalid passkey challenge ({0}).")]
    InvalidChallenge(String),
    #[error("This site does not accept ES256 passkeys, the only kind rbw can create.")]
    Es256Required,
    #[error("This site requires a security key (cross-platform authenticator); rbw is a platform authenticator and cannot create one.")]
    PlatformRequired,
    #[error("The site says a passkey for this account is already registered and found it in your vault. Sign in with it, or delete the old passkey first.")]
    AlreadyRegistered,
    #[error("The site sent an invalid user handle for the passkey.")]
    InvalidUserHandle,
    #[error(
        "The site sent a missing or oversized user name for the passkey."
    )]
    InvalidUserName,
    #[error("This item already contains a passkey for this site. Pick another item or choose \"Create a new login\".")]
    AlreadyHasPasskey,
    #[error("Only login items can hold a passkey. Pick a login or create a new one.")]
    NotALogin,
    #[error("That item is not available in the selected vault account. It may have been deleted, belong to another account, or not be synchronized yet. Sync and try again, or pick \"All accounts\".")]
    ItemUnavailable,
    #[error("rbw could not decrypt that item. Unlock the account that holds it, sync, and try again.")]
    ItemUndecryptable,
    #[error("This site requires user verification. Enter your master password to continue.")]
    PasswordRequired,
    #[error("The master password has an invalid length.")]
    PasswordLength,
    #[error("The master password is incorrect.")]
    PasswordRejected,
    #[error("The passkey was saved but did not show up after synchronizing. Sync your vault and check the item before trying again, so you do not end up with duplicates.")]
    NotPersisted,
}

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
        PasskeyError::InsecureOrigin
    );
    let rp = if create {
        options["rp"]["id"].as_str()
    } else {
        options["rpId"].as_str()
    }
    .unwrap_or(host);
    ensure!(
        host == rp || host.ends_with(&format!(".{rp}")),
        PasskeyError::RpMismatch(rp.to_owned())
    );
    ensure!(
        rp == "localhost" || psl::domain_str(rp).is_some(),
        PasskeyError::PublicSuffix
    );
    ensure!(
        options["extensions"].get("appid").is_none()
            && options["extensions"].get("appidExclude").is_none(),
        PasskeyError::LegacyAppId
    );
    ensure!(
        options["extensions"]["enforceCredentialProtectionPolicy"] != true,
        PasskeyError::CredentialProtection
    );
    ensure!(
        rp.parse::<std::net::IpAddr>().is_err(),
        PasskeyError::IpRelyingParty
    );
    let challenge = options["challenge"].as_str().ok_or_else(|| {
        PasskeyError::InvalidChallenge("it is missing".into())
    })?;
    let bytes = decode(challenge).map_err(|_| {
        PasskeyError::InvalidChallenge("it is not valid base64".into())
    })?;
    // WebAuthn sets no maximum; some relying parties (Google) send large
    // challenges. The native message limit bounds it anyway.
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64 * 1024,
        PasskeyError::InvalidChallenge(format!("{} bytes", bytes.len()))
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

/// A passkey sign-in with everything the vault needs around it, so the
/// client just asks for the signature:
///
/// * It signs straight away. The new counter is written to the server first
///   and guarded by the entry's revision, so a stale local vault is refused
///   instead of signing with an old counter; only then is the vault synced
///   and the sign-in tried once more.
/// * Afterwards (once the response is out) it syncs and checks the new
///   counter is in the synchronized vault. A failure is reported through the
///   status until a sync succeeds.
pub fn authenticate_synced(
    item: &str,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    let mut result = match authenticate(item, origin, options, password) {
        Ok(result) => result,
        Err(first) => {
            log::debug!(
                "passkey sign-in failed, syncing and retrying: {first:#}"
            );
            actions::sync().context("could not synchronize the vault")?;
            authenticate(item, origin, options, password)?
        }
    };
    let counter = result["counter"]
        .as_u64()
        .and_then(|counter| u32::try_from(counter).ok())
        .context("the passkey counter could not be confirmed")?;
    if let Some(object) = result.as_object_mut() {
        object.remove("counter");
    }
    let (item, origin, options) =
        (item.to_owned(), origin.to_owned(), options.clone());
    let account = actions::current_account();
    crate::browser::after_response(move || {
        let confirmed = actions::set_active_account(account)
            .and_then(|()| actions::sync())
            .and_then(|()| confirm_counter(&item, &origin, &options, counter))
            .is_ok();
        crate::browser::set_passkey_sync_failure(
            (!confirmed).then_some(origin.as_str()),
        );
    });
    Ok(result)
}

pub fn authenticate(
    item: &str,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    let rp = relying_party(origin, options, false)?;
    let verified =
        verification(&mut LiveVault::default(), options, false, password)?;
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
        fzf: false,
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

/// The vault side of a registration, so the steps around it can be tested
/// without an agent or a server.
pub(super) trait Vault {
    fn verify_master_password(
        &mut self,
        password: &str,
    ) -> anyhow::Result<()>;
    /// Whether the vault already holds one of the credentials in `exclusion`.
    fn holds_excluded(
        &mut self,
        origin: &str,
        exclusion: &Value,
    ) -> anyhow::Result<bool>;
    /// The editable form of an existing item.
    fn load(
        &mut self,
        item: &str,
    ) -> anyhow::Result<commands::EditableCipher>;
    /// Writes the item (a new login when `item` is `None`) and synchronizes.
    fn save(
        &mut self,
        item: Option<&str>,
        editable: &commands::EditableCipher,
    ) -> anyhow::Result<()>;
    /// Whether the credential `id` is in the synchronized vault.
    fn persisted(
        &mut self,
        origin: &str,
        rp: &str,
        challenge: &Value,
        id: &uuid::Uuid,
    ) -> anyhow::Result<bool>;
    fn aaguid(&mut self) -> anyhow::Result<[u8; 16]>;
}

#[derive(Default)]
struct LiveVault {
    db: Option<rbw::db::Db>,
    entry: Option<rbw::db::Entry>,
}

impl Vault for LiveVault {
    fn verify_master_password(
        &mut self,
        password: &str,
    ) -> anyhow::Result<()> {
        actions::verify_master_password(password).map_err(|error| {
            // The agent reports a wrong password as text; other failures
            // (locked, unreachable) keep their own wording.
            if format!("{error:#}").contains("Password is incorrect") {
                error.context(PasskeyError::PasswordRejected)
            } else {
                error.context("could not verify the master password")
            }
        })
    }

    fn holds_excluded(
        &mut self,
        origin: &str,
        exclusion: &Value,
    ) -> anyhow::Result<bool> {
        Ok(!candidates(origin, exclusion)?["items"]
            .as_array()
            .is_none_or(Vec::is_empty))
    }

    fn load(
        &mut self,
        item: &str,
    ) -> anyhow::Result<commands::EditableCipher> {
        let db = commands::load_db()?;
        let entry = super::entry(&db, item)
            .context(PasskeyError::ItemUnavailable)?
            .clone();
        let decrypted = commands::decrypt_cipher(&entry)
            .context(PasskeyError::ItemUndecryptable)?;
        self.db = Some(db);
        self.entry = Some(entry);
        Ok(commands::decrypted_to_editable(&decrypted))
    }

    fn save(
        &mut self,
        _item: Option<&str>,
        editable: &commands::EditableCipher,
    ) -> anyhow::Result<()> {
        let mut db = match self.db.take() {
            Some(db) => db,
            None => commands::load_db()?,
        };
        if let Some(entry) = &self.entry {
            commands::tui_save_edit(&mut db, entry, editable)
                .context("saving the passkey to the existing item")
        } else {
            commands::tui_save_add(&mut db, editable)
                .context("saving the passkey as a new login")
        }
    }

    fn persisted(
        &mut self,
        origin: &str,
        rp: &str,
        challenge: &Value,
        id: &uuid::Uuid,
    ) -> anyhow::Result<bool> {
        actions::sync().context("synchronizing after saving the passkey")?;
        let fresh = candidates(
            origin,
            &json!({"challenge": challenge, "rpId": rp, "allowCredentials": [{"type": "public-key", "id": B64.encode(id.as_bytes())}]}),
        )?;
        Ok(fresh["items"].as_array().is_some_and(|a| a.len() == 1))
    }

    fn aaguid(&mut self) -> anyhow::Result<[u8; 16]> {
        Ok(rbw::config::Config::load()?.browser.passkey_aaguid()?)
    }
}

pub fn register(
    item: Option<&str>,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    register_with(&mut LiveVault::default(), item, origin, options, password)
}

pub(super) fn register_with(
    vault: &mut impl Vault,
    item: Option<&str>,
    origin: &str,
    options: &Value,
    password: Option<&str>,
) -> anyhow::Result<Value> {
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    rbw::audit::note_origin(origin);
    rbw::audit::note_field("passkey");
    let rp = relying_party(origin, options, true)?;
    let verified = verification(vault, options, true, password)?;
    ensure!(
        options["pubKeyCredParams"].as_array().is_some_and(|a| a
            .iter()
            .any(|p| p["type"] == "public-key" && p["alg"] == -7)),
        PasskeyError::Es256Required
    );
    ensure!(
        options["authenticatorSelection"]["authenticatorAttachment"].as_str()
            != Some("cross-platform"),
        PasskeyError::PlatformRequired
    );
    // Verify the entire exclude list before generating or persisting a key.
    let exclusion = json!({"challenge": options["challenge"], "rpId": rp, "allowCredentials": options["excludeCredentials"]});
    if options["excludeCredentials"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        ensure!(
            !vault.holds_excluded(origin, &exclusion)?,
            PasskeyError::AlreadyRegistered
        );
    }
    let user = &options["user"];
    let handle = user["id"]
        .as_str()
        .and_then(|id| decode(id).ok())
        .ok_or(PasskeyError::InvalidUserHandle)?;
    ensure!(
        !handle.is_empty() && handle.len() <= 64,
        PasskeyError::InvalidUserHandle
    );
    let username =
        user["name"].as_str().ok_or(PasskeyError::InvalidUserName)?;
    let display = user["displayName"].as_str().unwrap_or(username);
    ensure!(
        username.len() <= 1024 && display.len() <= 1024,
        PasskeyError::InvalidUserName
    );
    let mut editable = match item {
        Some(id) => vault.load(id)?,
        None => commands::EditableCipher {
            name: rp.strip_prefix("www.").unwrap_or(&rp).to_owned(),
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
        },
    };
    let commands::EditableData::Login {
        fido2_credentials, ..
    } = &mut editable.data
    else {
        return Err(PasskeyError::NotALogin.into());
    };
    rbw::audit::note_item(None, item.unwrap_or(""), Some(&editable.name));
    ensure!(
        !fido2_credentials
            .iter()
            .any(|c| c.rp_id.as_deref() == Some(&rp)),
        PasskeyError::AlreadyHasPasskey
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
    // Sites label the passkey by AAGUID; the default is Bitwarden's, as
    // the credential lives in the Bitwarden vault (browser.passkeyAaguid).
    auth.extend_from_slice(&vault.aaguid()?);
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
    // Persist and synchronize before returning a successful registration.
    vault.save(item, &editable)?;
    ensure!(
        vault.persisted(origin, &rp, &options["challenge"], &id)?,
        PasskeyError::NotPersisted
    );
    let client = serde_json::to_vec(
        &json!({"type": "webauthn.create", "challenge": B64.encode(decode(options["challenge"].as_str().context("missing challenge")?)?), "origin": url::Url::parse(origin)?.origin().ascii_serialization(), "crossOrigin": false}),
    )?;
    Ok(
        json!({"id": B64.encode(id.as_bytes()), "rawId": B64.encode(id.as_bytes()), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": {"credProps": {"rk": true}}, "response": {"clientDataJSON": B64.encode(client), "attestationObject": B64.encode(serde_cbor::to_vec(&attestation)?), "authenticatorData": B64.encode(auth), "publicKey": B64.encode(key.verifying_key().to_public_key_der()?.as_bytes()), "publicKeyAlgorithm": -7, "transports": ["internal"]}}),
    )
}

fn verification(
    vault: &mut impl Vault,
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
            PasskeyError::PasswordLength
        );
        vault.verify_master_password(password)?;
        Ok(true)
    } else {
        ensure!(requirement != "required", PasskeyError::PasswordRequired);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::failure::{describe, Context as FailureContext};

    const ORIGIN: &str = "https://wolle.anika.blue";

    // What a webauthn-rs relying party (Stricknani) sends: ES256 only, user
    // verification required, resident key preferred, no attestation, a
    // 16-byte user handle.
    fn stricknani() -> Value {
        json!({
            "rp": {"name": "Stricknani", "id": "wolle.anika.blue"},
            "user": {
                "id": B64.encode([7u8; 16]),
                "name": "anika",
                "displayName": "Anika"
            },
            "challenge": B64.encode([9u8; 32]),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "attestation": "none",
            "extensions": {
                "credentialProtectionPolicy": "userVerificationRequired",
                "enforceCredentialProtectionPolicy": false,
                "uvm": true,
                "credProps": true
            },
            "authenticatorSelection": {
                "residentKey": "preferred",
                "requireResidentKey": false,
                "userVerification": "required"
            }
        })
    }

    #[derive(Default)]
    struct Fake {
        password_error: Option<PasskeyError>,
        excluded: bool,
        existing: Option<anyhow::Result<commands::EditableCipher>>,
        save_error: Option<rbw::error::Error>,
        persisted: bool,
        saved: Vec<(Option<String>, serde_json::Value)>,
    }

    impl Vault for Fake {
        fn verify_master_password(&mut self, _: &str) -> anyhow::Result<()> {
            self.password_error
                .take()
                .map_or(Ok(()), |error| Err(anyhow::Error::new(error)))
        }
        fn holds_excluded(
            &mut self,
            _: &str,
            _: &Value,
        ) -> anyhow::Result<bool> {
            Ok(self.excluded)
        }
        fn load(
            &mut self,
            _: &str,
        ) -> anyhow::Result<commands::EditableCipher> {
            self.existing.take().expect("an existing item")
        }
        fn save(
            &mut self,
            item: Option<&str>,
            editable: &commands::EditableCipher,
        ) -> anyhow::Result<()> {
            if let Some(error) = self.save_error.take() {
                // A server refusal surfaces from the write, with the
                // context the real vault adds.
                return Err(anyhow::Error::new(error)
                    .context("saving the passkey to the existing item"));
            }
            self.saved.push((
                item.map(str::to_owned),
                serde_json::to_value(editable)?,
            ));
            Ok(())
        }
        fn persisted(
            &mut self,
            _: &str,
            _: &str,
            _: &Value,
            _: &uuid::Uuid,
        ) -> anyhow::Result<bool> {
            Ok(self.persisted)
        }
        fn aaguid(&mut self) -> anyhow::Result<[u8; 16]> {
            Ok(rbw::config::BITWARDEN_AAGUID)
        }
    }

    fn login(passkey_for: Option<&str>) -> commands::EditableCipher {
        commands::EditableCipher {
            name: "Stricknani".into(),
            folder: None,
            notes: None,
            fields: vec![],
            data: commands::EditableData::Login {
                username: Some("philipp@schmitt.co".into()),
                password: None,
                uris: vec![],
                totp: None,
                fido2_credentials: passkey_for
                    .map(|rp| commands::EditableFido2Credential {
                        rp_id: Some(rp.into()),
                        ..Default::default()
                    })
                    .into_iter()
                    .collect(),
            },
        }
    }

    fn failed(result: anyhow::Result<Value>) -> (String, String) {
        let failure = describe(
            &result.expect_err("the registration should fail"),
            FailureContext::default(),
        );
        (failure.message, failure.detail)
    }

    #[test]
    fn bitwarden_aaguid_bytes() {
        let expected =
            uuid::Uuid::parse_str("d548826e-79b4-db40-a3d8-11116f7e8349")
                .unwrap();
        assert_eq!(&rbw::config::BITWARDEN_AAGUID, expected.as_bytes());
    }

    #[test]
    fn new_login_with_password_registers() {
        let mut vault = Fake {
            persisted: true,
            ..Fake::default()
        };
        let response = register_with(
            &mut vault,
            None,
            ORIGIN,
            &stricknani(),
            Some("pw"),
        )
        .unwrap();
        assert_eq!(response["type"], "public-key");
        let (item, saved) = &vault.saved[0];
        assert!(item.is_none());
        assert_eq!(saved["name"], "wolle.anika.blue");
        assert_eq!(saved["data"]["username"], "anika");
        assert_eq!(
            saved["data"]["fido2_credentials"][0]["rp_id"],
            "wolle.anika.blue"
        );
    }

    #[test]
    fn required_verification_without_password_says_so() {
        let (message, detail) = failed(register_with(
            &mut Fake::default(),
            None,
            ORIGIN,
            &stricknani(),
            None,
        ));
        assert!(message.contains("requires user verification"), "{message}");
        assert!(message.contains("master password"));
        assert!(!message.to_lowercase().contains("unlock this account"));
        assert_eq!(detail, message);
    }

    #[test]
    fn preferred_verification_without_password_registers() {
        let mut options = stricknani();
        options["authenticatorSelection"]["userVerification"] =
            json!("preferred");
        let mut vault = Fake {
            persisted: true,
            ..Fake::default()
        };
        register_with(&mut vault, None, ORIGIN, &options, None).unwrap();
    }

    #[test]
    fn wrong_master_password_is_reported() {
        let mut vault = Fake {
            password_error: Some(PasskeyError::PasswordRejected),
            ..Fake::default()
        };
        let (message, _) = failed(register_with(
            &mut vault,
            None,
            ORIGIN,
            &stricknani(),
            Some("nope"),
        ));
        assert_eq!(message, "The master password is incorrect.");
        assert_eq!(vault.saved.len(), 0);
    }

    #[test]
    fn existing_item_with_a_passkey_for_the_site_is_refused() {
        let mut vault = Fake {
            existing: Some(Ok(login(Some("wolle.anika.blue")))),
            persisted: true,
            ..Fake::default()
        };
        let (message, _) = failed(register_with(
            &mut vault,
            Some("item-1"),
            ORIGIN,
            &stricknani(),
            Some("pw"),
        ));
        assert!(message.contains("already contains a passkey"), "{message}");
        assert_eq!(vault.saved.len(), 0);
    }

    #[test]
    fn existing_item_gets_the_passkey() {
        let mut vault = Fake {
            existing: Some(Ok(login(Some("other.example")))),
            persisted: true,
            ..Fake::default()
        };
        register_with(
            &mut vault,
            Some("item-1"),
            ORIGIN,
            &stricknani(),
            Some("pw"),
        )
        .unwrap();
        let (item, saved) = &vault.saved[0];
        assert_eq!(item.as_deref(), Some("item-1"));
        assert_eq!(
            saved["data"]["fido2_credentials"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn item_in_another_account_is_explained() {
        let mut vault = Fake {
            existing: Some(Err(anyhow::Error::new(
                PasskeyError::ItemUnavailable,
            ))),
            ..Fake::default()
        };
        let (message, _) = failed(register_with(
            &mut vault,
            Some("item-in-bw"),
            ORIGIN,
            &stricknani(),
            Some("pw"),
        ));
        assert!(
            message.contains("not available in the selected vault account")
        );
    }

    #[test]
    fn read_only_organization_item_is_explained() {
        let mut vault = Fake {
            existing: Some(Ok(login(None))),
            save_error: Some(rbw::error::Error::RequestFailedWithBody {
                status: 400,
                body: "Cipher is not write accessible".into(),
            }),
            ..Fake::default()
        };
        let (message, detail) = failed(register_with(
            &mut vault,
            Some("org-item"),
            ORIGIN,
            &stricknani(),
            Some("pw"),
        ));
        assert!(message.contains("do not have permission"), "{message}");
        assert!(message.contains("read-only organization collection"));
        assert!(detail.contains("saving the passkey to the existing item"));
        assert!(detail.contains("Cipher is not write accessible"));
    }

    #[test]
    fn server_failures_name_their_status() {
        let mut vault = Fake {
            save_error: Some(rbw::error::Error::RequestFailed {
                status: 503,
            }),
            ..Fake::default()
        };
        let (message, detail) = failed(register_with(
            &mut vault,
            None,
            ORIGIN,
            &stricknani(),
            Some("pw"),
        ));
        assert!(message.contains("HTTP 503"), "{message}");
        assert!(detail.contains("503"));
    }

    #[test]
    fn unsynchronized_registration_is_not_reported_as_locked() {
        let (message, _) = failed(register_with(
            &mut Fake::default(),
            None,
            ORIGIN,
            &stricknani(),
            Some("pw"),
        ));
        assert!(message.contains("did not show up after synchronizing"));
        assert!(!message.to_lowercase().contains("unlock"));
    }

    #[test]
    fn site_options_rbw_cannot_honor_are_named() {
        let mut options = stricknani();
        options["pubKeyCredParams"] =
            json!([{"type": "public-key", "alg": -257}]);
        let (message, _) = failed(register_with(
            &mut Fake::default(),
            None,
            ORIGIN,
            &options,
            Some("pw"),
        ));
        assert!(message.contains("ES256"));

        let (message, _) = failed(register_with(
            &mut Fake {
                excluded: true,
                ..Fake::default()
            },
            None,
            ORIGIN,
            &{
                let mut o = stricknani();
                o["excludeCredentials"] = json!([{"type": "public-key", "id": B64.encode([1u8; 16])}]);
                o
            },
            Some("pw"),
        ));
        assert!(message.contains("already registered"));

        let (message, _) = failed(register_with(
            &mut Fake::default(),
            None,
            "https://evil.example",
            &stricknani(),
            Some("pw"),
        ));
        assert!(message.contains("does not match the page"), "{message}");
    }
}
