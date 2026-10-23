//! Passkey automation keeps private keys inside rbw and the browser CDP socket.
//! Reserve the next counter before injection so an interrupted browser cannot
//! leave the vault behind an assertion already accepted by the relying party.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use super::{actions, commands, FindArgs};

struct Selected {
    entry: rbw::db::Entry,
    /// The entry's name and username, for telling the user which one is used.
    name: String,
    user: Option<String>,
    credential: commands::DecryptedFido2Credential,
    index: usize,
}

fn select(args: &FindArgs, rp_id: Option<&str>) -> anyhow::Result<Selected> {
    actions::sync()?;
    select_cached(args, rp_id)
}

fn select_cached(
    args: &FindArgs,
    rp_id: Option<&str>,
) -> anyhow::Result<Selected> {
    let db = commands::load_db()?;
    let (entry, decrypted) = if args.needles.is_empty() {
        let rp = rp_id.context("name an entry or give --rp-id")?;
        find_by_rp_id(&db, rp)?
    } else {
        commands::find_entry(
            &db,
            args.needles.clone(),
            args.user.as_deref(),
            args.folder.as_deref(),
            args.collection.as_deref(),
            args.org.as_deref(),
            args.ignorecase,
            args.exact,
        )?
    };
    let name = decrypted.name;
    let commands::DecryptedData::Login {
        fido2_credentials,
        username: user,
        ..
    } = decrypted.data
    else {
        anyhow::bail!("passkeys require a login item");
    };
    let mut matches =
        fido2_credentials.into_iter().enumerate().filter(|(_, c)| {
            rp_id.is_none_or(|rp| c.rp_id.as_deref() == Some(rp))
        });
    let (index, credential) =
        matches.next().context("no matching passkey")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "ambiguous passkey; select a unique --rp-id"
    );
    Ok(Selected {
        entry,
        name,
        user,
        credential,
        index,
    })
}

/// Live logins holding a passkey for `rp_id`. Only entries that carry passkeys
/// at all are decrypted.
fn candidates(
    db: &rbw::db::Db,
    rp_id: &str,
) -> anyhow::Result<Vec<(rbw::db::Entry, commands::DecryptedCipher)>> {
    let mut found = Vec::new();
    for entry in &db.entries {
        let has_passkeys = matches!(
            &entry.data,
            rbw::db::EntryData::Login { fido2_credentials, .. }
                if !fido2_credentials.is_empty()
        );
        if entry.deleted || entry.archived || !has_passkeys {
            continue;
        }
        let decrypted = commands::decrypt_cipher(entry)?;
        if let commands::DecryptedData::Login {
            fido2_credentials, ..
        } = &decrypted.data
        {
            if fido2_credentials
                .iter()
                .any(|c| c.rp_id.as_deref() == Some(rp_id))
            {
                found.push((entry.clone(), decrypted));
            }
        }
    }
    Ok(found)
}

/// The one live login holding a passkey for `rp_id`.
fn find_by_rp_id(
    db: &rbw::db::Db,
    rp_id: &str,
) -> anyhow::Result<(rbw::db::Entry, commands::DecryptedCipher)> {
    let mut found = candidates(db, rp_id)?;
    anyhow::ensure!(
        found.len() < 2,
        "several entries hold a passkey for {rp_id}; name one"
    );
    found
        .pop()
        .with_context(|| format!("no passkey for {rp_id} in the vault"))
}

fn stored_counter(
    credential: &commands::DecryptedFido2Credential,
) -> anyhow::Result<u32> {
    // An absent field may mean decryption failed. Never reset it to zero.
    credential
        .counter
        .as_deref()
        .context("missing passkey counter")?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid passkey counter"))
}

fn advance(selected: &Selected, counter: u32) -> anyhow::Result<()> {
    advance_inner(selected, counter, true, false)
}

fn advance_for_browser(
    selected: &Selected,
    counter: u32,
) -> anyhow::Result<()> {
    advance_inner(selected, counter, false, false)
}

fn advance_inner(
    selected: &Selected,
    counter: u32,
    synchronize: bool,
    allow_decrease: bool,
) -> anyhow::Result<()> {
    let old = stored_counter(&selected.credential)?;
    anyhow::ensure!(
        allow_decrease || counter >= old,
        "refusing to decrease the passkey counter"
    );
    if counter == old {
        return Ok(());
    }
    anyhow::ensure!(
        selected.entry.revision_date.is_some(),
        "missing server revision; refusing an unguarded vault update"
    );
    let mut entry = selected.entry.clone();
    let rbw::db::EntryData::Login {
        fido2_credentials, ..
    } = &mut entry.data
    else {
        anyhow::bail!("passkeys require a login item");
    };
    fido2_credentials[selected.index].counter = Some(actions::encrypt(
        &counter.to_string(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?);
    let mut db = commands::load_db()?;
    let access =
        db.access_token.as_deref().context("missing access token")?;
    let refresh = db
        .refresh_token
        .as_deref()
        .context("missing refresh token")?;
    let (tokens, ()) = rbw::actions::edit(
        access,
        refresh,
        &entry.id,
        entry.org_id.as_deref(),
        entry.key.as_deref(),
        &entry.name,
        &entry.data,
        &entry.fields,
        entry.notes.as_deref(),
        entry.folder_id.as_deref(),
        &entry.history,
        &entry.cipher_write_meta(),
    )?;
    if synchronize {
        commands::after_server_write(&mut db, tokens)
    } else {
        if let Some(tokens) = tokens {
            db.access_token = Some(tokens.access_token);
            if let Some(refresh_token) = tokens.refresh_token {
                db.refresh_token = Some(refresh_token);
            }
            commands::save_db(&db)
                .map_err(commands::write_committed_error)?;
        }
        Ok(())
    }
}

/// After a counter write: pull the vault from the server again and check that it
/// holds at least `expected` for this very passkey, so a lost or rejected write
/// is an error before the counter is relied on. Then remind the user that other
/// Bitwarden clients must sync before they sign in with the passkey themselves:
/// a client still holding an older counter is rejected by the site as a clone.
fn confirm_synced(
    args: &FindArgs,
    rp_id: Option<&str>,
    selected: &Selected,
    expected: u32,
) -> anyhow::Result<()> {
    let fresh = select(args, rp_id)?;
    anyhow::ensure!(
        fresh.entry.id == selected.entry.id
            && fresh.credential.credential_id
                == selected.credential.credential_id,
        "passkey changed while synchronizing its counter"
    );
    let stored = stored_counter(&fresh.credential)?;
    anyhow::ensure!(
        stored >= expected,
        "the server holds passkey counter {stored} after the update, expected at least {expected}; reconcile the vault before another login"
    );
    eprintln!(
        "Vault synchronized: passkey counter {stored} for {}. Sync every other Bitwarden client (extension, desktop, mobile) before using this passkey there; a client still on an older counter is rejected as a clone.",
        fresh.name
    );
    Ok(())
}

/// The entries whose passkey would be used, as a JSON array without any secret:
/// all candidates for `--rp-id` when no entry is named (pick one by its id), else
/// the named one. Never prompts for the master password: a locked vault is an
/// error.
pub fn find(args: &FindArgs, rp_id: Option<&str>) -> anyhow::Result<()> {
    commands::unlocked().context("the vault is locked")?;
    let describe =
        |id: &str,
         name: &str,
         user: Option<&String>,
         c: Option<&commands::DecryptedFido2Credential>| {
            json!({
                "id": id,
                "name": name,
                "user": user,
                "rp_id": c.and_then(|c| c.rp_id.as_ref()),
                "passkey_user": c.and_then(|c| c.user_name.as_ref().or(c.user_display_name.as_ref())),
            })
        };
    let list: Vec<Value> = match rp_id {
        Some(rp) if args.needles.is_empty() => {
            actions::sync()?;
            let db = commands::load_db()?;
            candidates(&db, rp)?
                .iter()
                .map(|(entry, d)| {
                    let (user, creds) = match &d.data {
                        commands::DecryptedData::Login {
                            username,
                            fido2_credentials,
                            ..
                        } => {
                            (username.as_ref(), fido2_credentials.as_slice())
                        }
                        _ => (None, &[][..]),
                    };
                    let c =
                        creds.iter().find(|c| c.rp_id.as_deref() == Some(rp));
                    describe(&entry.id, &d.name, user, c)
                })
                .collect()
        }
        _ => {
            let s = select(args, rp_id)?;
            vec![describe(
                &s.entry.id,
                &s.name,
                s.user.as_ref(),
                Some(&s.credential),
            )]
        }
    };
    println!("{}", Value::Array(list));
    Ok(())
}

/// Every live passkey in the vault with its counter, as JSON without secrets.
/// For finding the sites a counter reset could affect.
fn list_all() -> anyhow::Result<()> {
    actions::sync()?;
    let db = commands::load_db()?;
    let mut list = Vec::new();
    for entry in &db.entries {
        let has_passkeys = matches!(
            &entry.data,
            rbw::db::EntryData::Login { fido2_credentials, .. }
                if !fido2_credentials.is_empty()
        );
        if entry.deleted || entry.archived || !has_passkeys {
            continue;
        }
        let decrypted = commands::decrypt_cipher(entry)?;
        let commands::DecryptedData::Login {
            fido2_credentials, ..
        } = &decrypted.data
        else {
            continue;
        };
        for c in fido2_credentials {
            list.push(json!({
                "id": entry.id,
                "name": decrypted.name,
                "rp_id": c.rp_id,
                "counter": stored_counter(c).ok(),
            }));
        }
    }
    println!("{}", Value::Array(list));
    Ok(())
}

pub fn counter(
    args: &FindArgs,
    rp_id: Option<&str>,
    set: Option<u32>,
    reset: bool,
    all: bool,
) -> anyhow::Result<()> {
    commands::unlock(None, None)?;
    if all {
        return list_all();
    }
    let selected = select(args, rp_id)?;
    if reset {
        advance_inner(&selected, 0, true, true)?;
        let fresh = select(args, rp_id)?;
        anyhow::ensure!(
            stored_counter(&fresh.credential)? == 0,
            "the server still holds a passkey counter after the reset; reconcile the vault"
        );
        eprintln!(
            "Passkey counter reset to 0 for {}. Sync every other Bitwarden client. A site that stored a higher counter flags a clone until its record is reset too.",
            fresh.name
        );
        println!("0");
        return Ok(());
    }
    if let Some(value) = set {
        advance(&selected, value)?;
        warn_counter_enabled(stored_counter(&selected.credential)?, value);
        confirm_synced(args, rp_id, &selected, value)?;
        println!("{value}");
    } else {
        println!("{}", stored_counter(&selected.credential)?);
    }
    Ok(())
}

fn warn_counter_enabled(previous: u32, current: u32) {
    if previous == 0 && current > 0 {
        eprintln!("Warning: passkey counter tracking has been enabled. Sync every Bitwarden client before using this passkey there; a client still holding counter zero may skip syncing and trigger a clone warning.");
    }
}

fn normalize_base64(value: &str) -> anyhow::Result<String> {
    let normalized = value.replace('-', "+").replace('_', "/");
    let padded =
        format!("{normalized}{}", "=".repeat((4 - normalized.len() % 4) % 4));
    let bytes = rbw::base64::decode(padded)
        .map_err(|_| anyhow::anyhow!("invalid passkey encoding"))?;
    Ok(rbw::base64::encode(bytes))
}

fn credential_id(value: &str) -> anyhow::Result<String> {
    uuid::Uuid::parse_str(value).map_or_else(
        |_| normalize_base64(value.strip_prefix("b64.").unwrap_or(value)),
        |id| Ok(rbw::base64::encode(id.as_bytes())),
    )
}

fn next_counter(current: u32) -> anyhow::Result<u32> {
    current.checked_add(1).context("passkey counter exhausted")
}

/// Whether a passkey at `current` may be advanced. A passkey that already
/// counts always is; starting to count on a counter-less one (0) needs the
/// `passkeyCounter` setting, because a counter that clients do not all
/// increment makes the lagging ones look like clones to the site.
fn tracking(current: u32) -> anyhow::Result<bool> {
    Ok(current > 0 || rbw::config::Config::load()?.passkey_counter)
}

fn cdp_credential(
    selected: &Selected,
    reserved: u32,
) -> anyhow::Result<Value> {
    let c = &selected.credential;
    anyhow::ensure!(
        c.key_type.as_deref() == Some("public-key")
            && c.key_algorithm.as_deref() == Some("ECDSA")
            && c.key_curve.as_deref() == Some("P-256"),
        "unsupported passkey key type"
    );
    Ok(json!({
        "credentialId": credential_id(c.credential_id.as_deref().context("missing credential ID")?)?,
        "rpId": c.rp_id.as_deref().context("missing relying party")?,
        "privateKey": normalize_base64(c.key_value.as_deref().context("missing passkey key")?)?,
        "userHandle": normalize_base64(c.user_handle.as_deref().context("missing user handle")?)?,
        "isResidentCredential": c.discoverable.as_deref() == Some("true"),
        "signCount": reserved - 1,
        "backupEligibility": true,
        "backupState": true,
    }))
}

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

struct Cdp {
    socket: Socket,
    sequence: u64,
    events: std::collections::VecDeque<Value>,
}

impl Cdp {
    async fn final_counter(
        &mut self,
        authenticator: &str,
        credential: &str,
        asserted: u32,
    ) -> anyhow::Result<u32> {
        self.send(
            "WebAuthn.setAutomaticPresenceSimulation",
            json!({
                "authenticatorId": authenticator, "enabled": false,
            }),
        )
        .await?;
        // Another assertion may have completed before presence was disabled.
        // Read the credential after the disable acknowledgement rather than
        // trusting the first event. The response includes key material: never
        // include it in errors or logs.
        let result = self.send("WebAuthn.getCredential", json!({
            "authenticatorId": authenticator, "credentialId": credential,
        })).await?;
        anyhow::ensure!(
            result["credential"]["credentialId"].as_str() == Some(credential),
            "browser returned a different passkey"
        );
        let count = result["credential"]["signCount"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .context("missing final browser counter")?;
        anyhow::ensure!(
            count >= asserted,
            "final browser counter is behind its assertion"
        );
        Ok(count)
    }

    async fn receive(&mut self) -> anyhow::Result<Value> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        self.receive_wire().await
    }

    async fn receive_wire(&mut self) -> anyhow::Result<Value> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .context("browser disconnected")?
                .map_err(|_| anyhow::anyhow!("CDP connection failed"))?;
            match message {
                Message::Text(text) => {
                    return serde_json::from_str(&text)
                        .map_err(|_| anyhow::anyhow!("invalid CDP response"))
                }
                Message::Close(_) => anyhow::bail!("browser disconnected"),
                _ => {}
            }
        }
    }

    async fn send(
        &mut self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        self.sequence += 1;
        self.socket
            .send(Message::Text(
                json!({
                    "id": self.sequence, "method": method, "params": params,
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|_| anyhow::anyhow!("CDP send failed"))?;
        loop {
            let response = self.receive_wire().await?;
            if response["id"].as_u64() == Some(self.sequence) {
                // CDP errors can echo parameters; never print their content.
                anyhow::ensure!(
                    response.get("error").is_none(),
                    "CDP command failed: {method}"
                );
                return Ok(response["result"].clone());
            }
            if response.get("method").is_some() {
                self.events.push_back(response);
            }
        }
    }
}

/// The page's origin, if it may use a passkey of `rp` (its host is the relying
/// party or a subdomain of it; https, or http on localhost).
fn checked_origin(origin: &str, rp: &str) -> anyhow::Result<String> {
    let page = url::Url::parse(origin)
        .map_err(|_| anyhow::anyhow!("invalid --origin"))?;
    let host = page.host_str().context("--origin has no host")?;
    anyhow::ensure!(
        page.scheme() == "https"
            || (page.scheme() == "http" && host == "localhost"),
        "passkeys need an https origin"
    );
    anyhow::ensure!(
        host == rp || host.ends_with(&format!(".{rp}")),
        "{host} may not use a passkey for {rp}"
    );
    Ok(page.origin().ascii_serialization())
}

/// `clientDataJSON`, `authenticatorData` and the DER signature over both, as a
/// passkey provider produces them for a `get()` request.
fn sign_assertion(
    key: &p256::ecdsa::SigningKey,
    rp: &str,
    origin: &str,
    challenge: &str,
    counter: u32,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    sign_assertion_with_verification(
        key, rp, origin, challenge, counter, true,
    )
}

fn sign_assertion_with_verification(
    key: &p256::ecdsa::SigningKey,
    rp: &str,
    origin: &str,
    challenge: &str,
    counter: u32,
    verified: bool,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use p256::ecdsa::signature::Signer as _;
    use sha2::Digest as _;
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))?;
    // Flags: user present, user verified, backup eligible, backed up (synced).
    let mut auth_data = sha2::Sha256::digest(rp.as_bytes()).to_vec();
    auth_data.push(0x01 | 0x08 | 0x10 | if verified { 0x04 } else { 0 });
    auth_data.extend_from_slice(&counter.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha2::Sha256::digest(&client_data));
    let signature: p256::ecdsa::Signature = key.sign(&signed);
    Ok((
        client_data,
        auth_data,
        signature.to_der().as_bytes().to_vec(),
    ))
}

/// Sign one `WebAuthn` assertion and print it as JSON (base64url fields), for a
/// caller that answers the page's `navigator.credentials.get()` itself, in any
/// browser. `origin` must be the page's real origin as the browser reports it,
/// never one taken from page script: only then can a page not obtain a
/// signature for another site. The key never leaves rbw; the counter is
/// reserved in the vault before signing, like inject.
pub fn assert(
    args: &FindArgs,
    rp_id: Option<&str>,
    origin: &str,
    challenge: &str,
    allow: &[String],
) -> anyhow::Result<()> {
    let assertion =
        assertion_value(args, rp_id, origin, challenge, allow, true, false)?;
    println!("{assertion}");
    Ok(())
}

pub fn browser_assert(
    args: &FindArgs,
    rp_id: Option<&str>,
    origin: &str,
    challenge: &str,
    allow: &[String],
    verified: bool,
) -> anyhow::Result<Value> {
    assertion_value(args, rp_id, origin, challenge, allow, verified, true)
}

pub fn browser_confirm_counter(
    item: &str,
    rp_id: &str,
    expected: u32,
) -> anyhow::Result<()> {
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
    let fresh = select_cached(&args, Some(rp_id))?;
    let stored = stored_counter(&fresh.credential)?;
    anyhow::ensure!(
        stored >= expected,
        "the synchronized vault does not contain the reserved passkey counter"
    );
    Ok(())
}

fn assertion_value(
    args: &FindArgs,
    rp_id: Option<&str>,
    origin: &str,
    challenge: &str,
    allow: &[String],
    verified: bool,
    preserve_zero: bool,
) -> anyhow::Result<Value> {
    use base64::Engine as _;
    use p256::pkcs8::DecodePrivateKey as _;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let std_b64 = |v: &str| -> anyhow::Result<Vec<u8>> {
        rbw::base64::decode(normalize_base64(v)?)
            .map_err(|_| anyhow::anyhow!("invalid passkey encoding"))
    };

    log::set_max_level(log::LevelFilter::Off);
    commands::unlocked().context("the vault is locked")?;
    rbw::dirs::make_all()?;
    let selected = if preserve_zero {
        select_cached(args, rp_id)?
    } else {
        select(args, rp_id)?
    };
    let lock_path = rbw::dirs::pid_file()
        .with_file_name(format!("passkey-{}.lock", selected.entry.id));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    lock.try_lock().map_err(|_| {
        anyhow::anyhow!("another passkey injection is active for this item")
    })?;
    let mut selected = if preserve_zero {
        select_cached(args, rp_id)?
    } else {
        select(args, rp_id)?
    };
    if preserve_zero && stored_counter(&selected.credential)? > 0 {
        selected = select_cached(args, rp_id)?;
    }
    let c = &selected.credential;
    anyhow::ensure!(
        c.key_type.as_deref() == Some("public-key")
            && c.key_algorithm.as_deref() == Some("ECDSA")
            && c.key_curve.as_deref() == Some("P-256"),
        "unsupported passkey key type"
    );
    let rp = c.rp_id.as_deref().context("missing relying party")?;

    let origin = checked_origin(origin, rp)?;

    let raw_id = std_b64(&credential_id(
        c.credential_id
            .as_deref()
            .context("missing credential ID")?,
    )?)?;
    if !allow.is_empty() {
        let mine = b64url.encode(&raw_id);
        anyhow::ensure!(
            allow.iter().any(|a| a.trim_end_matches('=') == mine),
            "the site asks for another passkey than this entry's"
        );
    }
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(&std_b64(
        c.key_value.as_deref().context("missing passkey key")?,
    )?)
    .map_err(|_| anyhow::anyhow!("unreadable passkey key"))?;

    let previous = stored_counter(c)?;
    let reserved = if previous == 0 && (preserve_zero || !tracking(previous)?)
    {
        0
    } else {
        next_counter(previous)?
    };
    if reserved > previous {
        if preserve_zero {
            advance_for_browser(&selected, reserved)?;
        } else {
            advance(&selected, reserved)?;
        }
        warn_counter_enabled(previous, reserved);
        if !preserve_zero {
            confirm_synced(args, rp_id, &selected, reserved)?;
        }
    }
    let (client_data, auth_data, signature) = if verified {
        sign_assertion(&key, rp, &origin, challenge, reserved)?
    } else {
        sign_assertion_with_verification(
            &key, rp, &origin, challenge, reserved, false,
        )?
    };
    let user_handle = c.user_handle.as_deref().map(std_b64).transpose()?;

    Ok(json!({
        "id": b64url.encode(&raw_id),
        "rawId": b64url.encode(&raw_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64url.encode(&client_data),
            "authenticatorData": b64url.encode(&auth_data),
            "signature": b64url.encode(&signature),
            "userHandle": user_handle.map(|u| b64url.encode(u)),
        },
        "counter": reserved,
    }))
}

pub fn inject(
    args: &FindArgs,
    rp_id: Option<&str>,
    cdp_url: &str,
    page_id: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    // Websocket trace logging can contain private key frames.
    log::set_max_level(log::LevelFilter::Off);
    commands::unlock(None, None)?;
    let selected = select(args, rp_id)?;
    // One injection per item on this machine. Across machines, the server's
    // lastKnownRevisionDate rejects competing counter reservations.
    rbw::dirs::make_all()?;
    let lock_path = rbw::dirs::pid_file()
        .with_file_name(format!("passkey-{}.lock", selected.entry.id));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    lock.try_lock().map_err(|_| {
        anyhow::anyhow!("another passkey injection is active for this item")
    })?;
    // Refresh under the lock to avoid using a selection made before a prior
    // session finished its writeback.
    let selected = select(args, rp_id)?;
    let previous = stored_counter(&selected.credential)?;
    // The browser's virtual authenticator always counts up, so injecting
    // would start tracking on its own.
    anyhow::ensure!(
        tracking(previous)?,
        "this passkey has no counter and passkeyCounter is off; inject would start one. Use `rbw passkey assert` or the browser extension, or run `rbw config set passkeyCounter true`"
    );
    let reserved = next_counter(previous)?;
    let credential = cdp_credential(&selected, reserved)?;
    let injected_id = credential["credentialId"]
        .as_str()
        .context("missing injected credential ID")?
        .to_string();

    // Fetch target metadata without logging websocket URLs or query tokens.
    let endpoint = url::Url::parse(cdp_url)
        .map_err(|_| anyhow::anyhow!("invalid --cdp-url"))?;
    anyhow::ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none(),
        "--cdp-url must be an HTTP endpoint without credentials"
    );
    let targets: Vec<Value> = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?
        .get(endpoint.join("/json/list")?)
        .send()
        .map_err(|_| anyhow::anyhow!("cannot fetch browser targets"))?
        .error_for_status()
        .map_err(|_| {
            anyhow::anyhow!("browser target endpoint rejected the request")
        })?
        .json()
        .map_err(|_| anyhow::anyhow!("invalid browser target list"))?;
    let target = targets
        .iter()
        .find(|t| t["id"].as_str() == Some(page_id) && t["type"] == "page")
        .context("no matching browser page; use an exact page ID")?;
    let mut websocket = endpoint
        .join(
            target["webSocketDebuggerUrl"]
                .as_str()
                .context("page has no debugging websocket")?,
        )
        .map_err(|_| anyhow::anyhow!("invalid browser websocket"))?;
    // Browserless may advertise its container-internal hostname. Connect
    // through the trusted endpoint supplied by the caller instead.
    websocket
        .set_scheme(if endpoint.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|()| anyhow::anyhow!("invalid websocket scheme"))?;
    websocket
        .set_host(endpoint.host_str())
        .map_err(|_| anyhow::anyhow!("invalid websocket host"))?;
    websocket
        .set_port(endpoint.port())
        .map_err(|()| anyhow::anyhow!("invalid websocket port"))?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let (socket, _) = tokio::time::timeout(std::time::Duration::from_secs(10),
            tokio_tungstenite::connect_async(websocket.as_str())).await
            .context("CDP connection timed out")?
            .map_err(|_| anyhow::anyhow!("cannot connect to browser CDP"))?;
        let mut cdp = Cdp { socket, sequence: 0, events: std::collections::VecDeque::new() };
        cdp.send("WebAuthn.enable", json!({})).await?;
        // Disable presence until the counter reservation has reached the vault.
        let result = cdp.send("WebAuthn.addVirtualAuthenticator", json!({"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
            "hasUserVerification": true, "isUserVerified": true,
            "automaticPresenceSimulation": false,
            "defaultBackupEligibility": true, "defaultBackupState": true,
        }})).await?;
        let authenticator = result["authenticatorId"].as_str().context("missing authenticator ID")?.to_string();
        let mut removed = false;
        let operation = async {
            cdp.send("WebAuthn.addCredential", json!({"authenticatorId": authenticator, "credential": credential})).await?;
            // The blocking vault API cannot run on an async runtime thread.
            tokio::task::block_in_place(|| {
                advance(&selected, reserved)?;
                confirm_synced(args, rp_id, &selected, reserved)
            })?;
            warn_counter_enabled(previous, reserved);
            cdp.send("WebAuthn.setAutomaticPresenceSimulation", json!({"authenticatorId": authenticator, "enabled": true})).await?;
            println!("Passkey ready; reserved counter {reserved}. Waiting for one browser assertion.");
            std::io::stdout().flush()?;
            loop {
                let event = cdp.receive().await?;
                if event["method"] == "WebAuthn.credentialAsserted"
                    && event["params"]["authenticatorId"] == authenticator {
                    let count = event["params"]["credential"]["signCount"].as_u64()
                        .and_then(|n| u32::try_from(n).ok()).context("missing assertion counter")?;
                    anyhow::ensure!(count >= reserved, "browser counter is behind its reservation");
                    let count = cdp.final_counter(&authenticator, &injected_id, count).await?;
                    // Remove the authenticator before the vault writeback so
                    // it cannot assert again while that update is in flight.
                    let removal = cdp.send("WebAuthn.removeVirtualAuthenticator", json!({"authenticatorId": authenticator})).await;
                    removed = removal.is_ok();
                    tokio::task::block_in_place(|| {
                        let current = select(args, rp_id)?;
                        anyhow::ensure!(current.entry.id == selected.entry.id
                            && current.credential.credential_id == selected.credential.credential_id,
                            "passkey changed during the browser session");
                        let target = count.max(stored_counter(&current.credential)?);
                        advance(&current, target)?;
                        confirm_synced(args, rp_id, &current, target)
                    }).with_context(|| format!("failed to synchronize final browser counter {count}; reconcile the vault before another login"))?;
                    // Even if removal fails, preserve the counter we already
                    // observed before reporting that cleanup needs attention.
                    removal.context("vault counter synchronized but authenticator removal failed; close the browser page")?;
                    println!("Final browser counter {count}; vault synchronized. Check the page to confirm the site accepted the login.");
                    return Ok::<(), anyhow::Error>(());
                }
            }
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(timeout), operation)
            .await.map_err(|_| anyhow::anyhow!("no assertion before timeout; reserved counter retained"))
            .and_then(std::convert::identity);
        if !removed {
            let cleanup = tokio::time::timeout(std::time::Duration::from_secs(5),
                cdp.send("WebAuthn.removeVirtualAuthenticator", json!({"authenticatorId": authenticator}))).await;
            if !matches!(cleanup, Ok(Ok(_))) {
                eprintln!("Could not remove virtual authenticator; close the browser page.");
            }
        }
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_enables_tracking_and_rejects_exhaustion() {
        assert_eq!(next_counter(0).unwrap(), 1);
        assert_eq!(next_counter(u32::MAX - 1).unwrap(), u32::MAX);
        assert!(next_counter(u32::MAX).is_err());
        let missing = commands::DecryptedFido2Credential::default();
        assert!(stored_counter(&missing).is_err());
        let malformed = commands::DecryptedFido2Credential {
            counter: Some("4294967296".to_string()),
            ..Default::default()
        };
        assert!(stored_counter(&malformed).is_err());
    }

    #[tokio::test]
    async fn final_counter_captures_racing_assertions_and_rejects_bad_state()
    {
        for (credential_id, final_count, expected) in [
            ("AQID", json!(7), Some(7)),
            ("AQID", json!(8), Some(8)),
            ("AQID", json!(6), None),
            ("AQID", Value::Null, None),
            ("AQID", json!(4_294_967_296_u64), None),
            ("different", json!(8), None),
        ] {
            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws =
                    tokio_tungstenite::accept_async(stream).await.unwrap();
                let request: Value = serde_json::from_str(
                    ws.next().await.unwrap().unwrap().to_text().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    request["method"],
                    "WebAuthn.setAutomaticPresenceSimulation"
                );
                assert_eq!(
                    request["params"],
                    json!({"authenticatorId": "test", "enabled": false})
                );
                // The first event reported 7. A second assertion completes
                // before the disable acknowledgement and raises the count to 8.
                ws.send(Message::Text(json!({
                    "method": "WebAuthn.credentialAsserted",
                    "params": {"authenticatorId": "test", "credential": {"signCount": 8}},
                }).to_string().into())).await.unwrap();
                ws.send(Message::Text(
                    json!({"id": request["id"], "result": {}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
                let request: Value = serde_json::from_str(
                    ws.next().await.unwrap().unwrap().to_text().unwrap(),
                )
                .unwrap();
                assert_eq!(request["method"], "WebAuthn.getCredential");
                assert_eq!(
                    request["params"],
                    json!({"authenticatorId": "test", "credentialId": "AQID"})
                );
                ws.send(Message::Text(json!({
                    "id": request["id"], "result": {"credential": {
                        "credentialId": credential_id, "signCount": final_count,
                        "privateKey": "DO-NOT-ECHO",
                    }},
                }).to_string().into())).await.unwrap();
            });
            let (socket, _) =
                tokio_tungstenite::connect_async(format!("ws://{address}"))
                    .await
                    .unwrap();
            let mut cdp = Cdp {
                socket,
                sequence: 0,
                events: std::collections::VecDeque::default(),
            };
            let result = cdp.final_counter("test", "AQID", 7).await;
            if let Some(expected) = expected {
                assert_eq!(result.unwrap(), expected);
            } else {
                let error = result.unwrap_err().to_string();
                assert!(!error.contains("DO-NOT-ECHO"));
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cdp_preserves_early_assertions_and_does_not_echo_error_parameters(
    ) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws =
                tokio_tungstenite::accept_async(stream).await.unwrap();
            let first = ws.next().await.unwrap().unwrap();
            let request: Value =
                serde_json::from_str(first.to_text().unwrap()).unwrap();
            // A pending browser get() can assert immediately when presence is
            // enabled, before CDP acknowledges setAutomaticPresenceSimulation.
            ws.send(Message::Text(json!({
                "method": "WebAuthn.credentialAsserted",
                "params": {"authenticatorId": "test", "credential": {"signCount": 7}},
            }).to_string().into())).await.unwrap();
            ws.send(Message::Text(
                json!({"id": request["id"], "result": {}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let request: Value =
                serde_json::from_str(second.to_text().unwrap()).unwrap();
            ws.send(Message::Text(json!({
                "id": request["id"], "error": {"message": "privateKey=DO-NOT-ECHO"},
            }).to_string().into())).await.unwrap();
        });
        let (socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}"))
                .await
                .unwrap();
        let mut cdp = Cdp {
            socket,
            sequence: 0,
            events: std::collections::VecDeque::default(),
        };
        cdp.send("WebAuthn.setAutomaticPresenceSimulation", json!({}))
            .await
            .unwrap();
        let event = cdp.receive().await.unwrap();
        assert_eq!(event["params"]["credential"]["signCount"], 7);
        let error = cdp
            .send("WebAuthn.addCredential", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "CDP command failed: WebAuthn.addCredential"
        );
        server.await.unwrap();
    }
}

#[cfg(test)]
mod assertion_tests {
    use super::*;

    #[test]
    fn origin_must_belong_to_the_relying_party() {
        assert_eq!(
            checked_origin("https://accounts.google.com/x?y", "google.com")
                .unwrap(),
            "https://accounts.google.com"
        );
        assert!(checked_origin("https://evil.example", "google.com").is_err());
        assert!(
            checked_origin("https://notgoogle.com", "google.com").is_err()
        );
        assert!(checked_origin("http://google.com", "google.com").is_err());
    }

    #[test]
    fn assertion_verifies_with_the_public_key() {
        use p256::ecdsa::signature::Verifier as _;
        use sha2::Digest as _;
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (client, auth, sig) = sign_assertion(
            &key,
            "example.com",
            "https://example.com",
            "Y2hhbGxlbmdl",
            42,
        )
        .unwrap();
        assert_eq!(
            &auth[..32],
            sha2::Sha256::digest(b"example.com").as_slice()
        );
        assert_eq!(auth[32], 0x1d);
        assert_eq!(&auth[33..], &42u32.to_be_bytes());
        let parsed: serde_json::Value =
            serde_json::from_slice(&client).unwrap();
        assert_eq!(parsed["type"], "webauthn.get");
        assert_eq!(parsed["challenge"], "Y2hhbGxlbmdl");
        let mut signed = auth;
        signed.extend_from_slice(&sha2::Sha256::digest(&client));
        let sig = p256::ecdsa::Signature::from_der(&sig).unwrap();
        key.verifying_key().verify(&signed, &sig).unwrap();
    }
}
