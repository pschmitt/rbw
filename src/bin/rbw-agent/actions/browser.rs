use super::{load_db, resolve_account, save_db, sync};
use anyhow::Context as _;
use base64::Engine as _;
use rbw::config::{Account, Config};
use rbw::db::{Db, Entry, EntryData, Fido2Credential};
use rbw::remote_api::{
    ApiError, ClientPolicy, ErrorCode, FieldRef, PasskeyAssertionRequest,
    PasskeyItem, PasskeyListResponse, SearchItem, SearchResponse,
};
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::Arc;
use tokio::sync::Mutex;

type Agent = Arc<Mutex<crate::state::State>>;

fn unavailable() -> ApiError {
    ApiError::new(ErrorCode::Unavailable)
}

async fn vault(
    agent: &Agent,
    client: &ClientPolicy,
) -> Result<(Account, Db), ApiError> {
    let name = client
        .account
        .as_deref()
        .ok_or_else(|| ApiError::new(ErrorCode::Forbidden))?;
    let account = resolve_account(Some(name))
        .await
        .map_err(|_| unavailable())?;
    if agent.lock().await.needs_unlock(&account.name) {
        return Err(ApiError::new(ErrorCode::VaultLocked));
    }
    let db = load_db(&account).await.map_err(|_| unavailable())?;
    Ok((account, db))
}

fn item_keys<T>(
    state: &crate::state::State,
    account: &Account,
    entry: &Entry,
    use_keys: impl FnOnce(&rbw::locked::Keys) -> T,
) -> anyhow::Result<T> {
    let keys = state
        .key(&account.name, entry.org_id.as_deref())
        .context("vault keys unavailable")?;
    let key = entry
        .key
        .as_deref()
        .map(|key| {
            anyhow::Ok(rbw::locked::Keys::new(
                rbw::cipherstring::CipherString::new(key)?
                    .decrypt_locked_symmetric(keys)?,
            ))
        })
        .transpose()?;
    Ok(use_keys(key.as_ref().unwrap_or(keys)))
}

fn text(keys: &rbw::locked::Keys, value: Option<&str>) -> Option<String> {
    let encrypted = rbw::cipherstring::CipherString::new(value?).ok()?;
    String::from_utf8(encrypted.decrypt_symmetric(keys, None).ok()?).ok()
}

pub async fn search(
    agent: &Agent,
    client: &ClientPolicy,
    url: &url::Url,
    query: &str,
) -> Result<SearchResponse, ApiError> {
    let (account, db) = vault(agent, client).await?;
    let default = Config::load_async()
        .await
        .map_err(|_| unavailable())?
        .default_uri_match;
    let query = query.to_lowercase();
    let words: Vec<_> = query.split_whitespace().collect();
    let state = agent.lock().await;
    if state.needs_unlock(&account.name) {
        return Err(ApiError::new(ErrorCode::VaultLocked));
    }
    let mut items = Vec::new();
    for entry in db.entries.iter().filter(|entry| {
        !entry.deleted && !entry.archived && !entry.master_password_reprompt()
    }) {
        let EntryData::Login {
            username,
            password,
            totp,
            uris,
            ..
        } = &entry.data
        else {
            continue;
        };
        let fields = client.fields_for(&entry.id);
        if fields.is_empty() {
            continue;
        }
        let result = item_keys(&state, &account, entry, |keys| {
            let name = text(keys, Some(&entry.name))?;
            let username = if fields.contains(&FieldRef::Username) {
                text(keys, username.as_deref())
            } else {
                None
            };
            let folder = if fields.contains(&FieldRef::Name) {
                let personal_key = state.key(&account.name, None)?;
                text(personal_key, entry.folder.as_deref())
            } else {
                None
            };
            let uris: Vec<_> = uris
                .iter()
                .enumerate()
                .filter(|(index, _)| {
                    fields.contains(&FieldRef::UriAll)
                        || fields.contains(&FieldRef::Uri(*index))
                })
                .filter_map(|(_, uri)| {
                    Some((text(keys, Some(&uri.uri))?, uri.match_type))
                })
                .collect();
            let site = uris.iter().any(|(uri, match_type)| {
                !rbw::uri_match::skip_insecure_uri(url, uri)
                    && rbw::uri_match::matches_url(
                        uri,
                        *match_type,
                        url,
                        default,
                    )
            });
            if !site && rbw::uri_match::skip_insecure_uri(url, "") {
                return None;
            }
            let wanted = if words.is_empty() {
                site
            } else {
                let haystack = std::iter::once(name.as_str())
                    .chain(username.as_deref())
                    .chain(folder.as_deref())
                    .chain(uris.iter().map(|(uri, _)| uri.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                words.iter().all(|word| haystack.contains(*word))
            };
            if !wanted {
                return None;
            }
            let favicon_host = uris.iter().find_map(|(uri, _)| {
                let uri = url::Url::parse(uri).ok()?;
                if matches!(uri.scheme(), "http" | "https") {
                    uri.host_str().map(str::to_owned)
                } else {
                    None
                }
            });
            Some(SearchItem {
                id: entry.id.clone(),
                name,
                username,
                folder,
                favicon_host,
                site,
                has_password: fields.contains(&FieldRef::Password)
                    && password.is_some(),
                has_totp: fields.contains(&FieldRef::Totp) && totp.is_some(),
                fields: fields
                    .into_iter()
                    .map(FieldRef::path_token)
                    .collect(),
            })
        });
        if let Ok(Some(item)) = result {
            items.push(item);
        }
    }
    items.sort_by_cached_key(|item| (!item.site, item.name.to_lowercase()));
    items.truncate(50);
    Ok(SearchResponse { items })
}

fn can_use_passkeys(client: &ClientPolicy) -> bool {
    client.all_items.contains(&FieldRef::Passkey)
        || client
            .items
            .values()
            .any(|items| items.contains(&FieldRef::Passkey))
}

fn passkey_entries<'a>(
    db: &'a Db,
    client: &'a ClientPolicy,
) -> impl Iterator<Item = &'a Entry> {
    db.entries.iter().filter(|entry| {
        !entry.deleted
            && !entry.archived
            && !entry.master_password_reprompt()
            && client.permits(&entry.id, &FieldRef::Passkey)
    })
}

pub async fn find_passkeys(
    agent: &Agent,
    client: &ClientPolicy,
    rp: &str,
) -> Result<PasskeyListResponse, ApiError> {
    if !can_use_passkeys(client) {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    if rp.is_empty() || rp.len() > 253 {
        return Err(ApiError::new(ErrorCode::InvalidRequest));
    }
    let (account, db) = vault(agent, client).await?;
    let state = agent.lock().await;
    if state.needs_unlock(&account.name) {
        return Err(ApiError::new(ErrorCode::VaultLocked));
    }
    let items = passkey_entries(&db, client)
        .filter_map(|entry| {
            let EntryData::Login {
                username,
                fido2_credentials,
                ..
            } = &entry.data
            else {
                return None;
            };
            item_keys(&state, &account, entry, |keys| {
                let credential =
                    fido2_credentials.iter().find(|credential| {
                        text(keys, credential.rp_id.as_deref()).as_deref()
                            == Some(rp)
                    })?;
                Some(PasskeyItem {
                    id: entry.id.clone(),
                    name: text(keys, Some(&entry.name)).unwrap_or_default(),
                    user: if client.permits(&entry.id, &FieldRef::Username) {
                        text(keys, username.as_deref())
                    } else {
                        None
                    },
                    rp_id: rp.to_owned(),
                    passkey_user: text(
                        keys,
                        credential
                            .user_name
                            .as_deref()
                            .or(credential.user_display_name.as_deref()),
                    ),
                })
            })
            .ok()
            .flatten()
        })
        .take(50)
        .collect();
    Ok(PasskeyListResponse { items })
}

struct Selection<'a> {
    entry: &'a Entry,
    index: usize,
    raw_id: String,
}

fn select<'a>(
    db: &'a Db,
    client: &'a ClientPolicy,
    state: &crate::state::State,
    account: &Account,
    request: &PasskeyAssertionRequest,
) -> Result<Selection<'a>, ApiError> {
    if state.needs_unlock(&account.name) {
        return Err(ApiError::new(ErrorCode::VaultLocked));
    }
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut selected = None;
    for entry in passkey_entries(db, client).filter(|item| {
        request.item_id.as_ref().is_none_or(|id| id == &item.id)
    }) {
        let EntryData::Login {
            fido2_credentials, ..
        } = &entry.data
        else {
            continue;
        };
        let matching = item_keys(state, account, entry, |keys| {
            fido2_credentials
                .iter()
                .enumerate()
                .filter_map(|(index, credential)| {
                    if text(keys, credential.rp_id.as_deref()).as_deref()
                        != Some(&request.rp_id)
                    {
                        return None;
                    }
                    let id = text(keys, credential.credential_id.as_deref())?;
                    let raw_id = b64url
                        .encode(rbw::passkey::credential_id_bytes(&id).ok()?);
                    (request.allow_credentials.is_empty()
                        || request
                            .allow_credentials
                            .iter()
                            .any(|id| id.trim_end_matches('=') == raw_id))
                    .then_some(Selection {
                        entry,
                        index,
                        raw_id,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
        for candidate in matching {
            if selected.replace(candidate).is_some() {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            }
        }
    }
    selected.ok_or_else(|| ApiError::new(ErrorCode::NotFound))
}

fn credential(
    entry: &Entry,
    index: usize,
) -> anyhow::Result<&Fido2Credential> {
    let EntryData::Login {
        fido2_credentials, ..
    } = &entry.data
    else {
        anyhow::bail!("passkey requires a login item");
    };
    fido2_credentials.get(index).context("passkey missing")
}

fn counter(
    state: &crate::state::State,
    account: &Account,
    selected: &Selection<'_>,
) -> anyhow::Result<u32> {
    let credential = credential(selected.entry, selected.index)?;
    item_keys(state, account, selected.entry, |keys| {
        Ok(text(keys, credential.counter.as_deref())
            .context("missing passkey counter")?
            .parse()?)
    })?
}

async fn reserve_counter(
    agent: &Agent,
    account: &Account,
    db: &Db,
    selected: &Selection<'_>,
    next: u32,
) -> anyhow::Result<()> {
    let mut entry = selected.entry.clone();
    anyhow::ensure!(
        entry.revision_date.is_some(),
        "missing passkey server revision"
    );
    let encrypted = {
        let state = agent.lock().await;
        item_keys(&state, account, &entry, |keys| {
            rbw::cipherstring::CipherString::encrypt_symmetric(
                keys,
                next.to_string().as_bytes(),
            )
        })??
    };
    let EntryData::Login {
        fido2_credentials, ..
    } = &mut entry.data
    else {
        anyhow::bail!("passkey requires a login item");
    };
    fido2_credentials[selected.index].counter = Some(encrypted.to_string());
    let access = db.access_token.clone().context("missing access token")?;
    let refresh =
        db.refresh_token.clone().context("missing refresh token")?;
    let target = account.clone();
    let (tokens, ()) = tokio::task::spawn_blocking(move || {
        rbw::actions::AGENT_ACCOUNT.sync_scope(target, || {
            rbw::actions::edit(
                &access,
                &refresh,
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
            )
        })
    })
    .await??;
    if let Some(tokens) = tokens {
        let mut db = load_db(account).await?;
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(account, &db).await?;
    }
    sync(None, agent.clone(), account).await
}

pub async fn assert_passkey(
    agent: Agent,
    client: &ClientPolicy,
    request: &PasskeyAssertionRequest,
) -> Result<serde_json::Value, ApiError> {
    if !can_use_passkeys(client)
        || request
            .item_id
            .as_ref()
            .is_some_and(|id| !client.permits(id, &FieldRef::Passkey))
    {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    if request.rp_id.is_empty()
        || request.rp_id.len() > 253
        || request.challenge.is_empty()
        || base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(request.challenge.trim_end_matches('='))
            .is_err()
    {
        return Err(ApiError::new(ErrorCode::InvalidRequest));
    }
    let origin =
        rbw::passkey::checked_origin(&request.origin, &request.rp_id)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest))?;
    let (account, db) = vault(&agent, client).await?;
    rbw::actions::AGENT_ACCOUNT
        .scope(
            account.clone(),
            sign(&agent, client, &account, db, request, &origin),
        )
        .await
}

async fn sign(
    agent: &Agent,
    client: &ClientPolicy,
    account: &Account,
    mut db: Db,
    request: &PasskeyAssertionRequest,
    origin: &str,
) -> Result<serde_json::Value, ApiError> {
    let (item_id, raw_id, tracked) = {
        let state = agent.lock().await;
        let selected = select(&db, client, &state, account, request)?;
        let count =
            counter(&state, account, &selected).map_err(|_| unavailable())?;
        (selected.entry.id.clone(), selected.raw_id, count > 0)
    };
    uuid::Uuid::parse_str(&item_id).map_err(|_| unavailable())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(
            rbw::dirs::pid_file()
                .with_file_name(format!("passkey-{item_id}.lock")),
        )
        .map_err(|_| unavailable())?;
    lock.try_lock().map_err(|_| unavailable())?;
    let starts_counter = Config::load_async()
        .await
        .map_err(|_| unavailable())?
        .passkey_counter;
    if tracked || starts_counter {
        sync(None, agent.clone(), account)
            .await
            .map_err(|_| unavailable())?;
    }
    db = load_db(account).await.map_err(|_| unavailable())?;
    let (selected, key, user_handle, previous) = {
        use p256::pkcs8::DecodePrivateKey as _;
        let state = agent.lock().await;
        let selected = select(&db, client, &state, account, request)?;
        if selected.entry.id != item_id || selected.raw_id != raw_id {
            return Err(ApiError::new(ErrorCode::NotFound));
        }
        let previous =
            counter(&state, account, &selected).map_err(|_| unavailable())?;
        let credential = credential(selected.entry, selected.index)
            .map_err(|_| unavailable())?;
        let (key, handle) =
            item_keys(&state, account, selected.entry, |keys| {
                anyhow::ensure!(
                    text(keys, credential.key_type.as_deref()).as_deref()
                        == Some("public-key")
                        && text(keys, credential.key_algorithm.as_deref())
                            .as_deref()
                            == Some("ECDSA")
                        && text(keys, credential.key_curve.as_deref())
                            .as_deref()
                            == Some("P-256"),
                    "unsupported passkey key type",
                );
                let encoded = zeroize::Zeroizing::new(
                    text(keys, credential.key_value.as_deref())
                        .context("missing passkey key")?,
                );
                let key_bytes =
                    zeroize::Zeroizing::new(rbw::passkey::decode(&encoded)?);
                let key =
                    p256::ecdsa::SigningKey::from_pkcs8_der(&key_bytes)?;
                Ok((
                    key,
                    text(keys, credential.user_handle.as_deref())
                        .as_deref()
                        .map(rbw::passkey::decode)
                        .transpose()?,
                ))
            })
            .and_then(|result: anyhow::Result<_>| result)
            .map_err(|_| unavailable())?;
        (selected, key, handle, previous)
    };
    let reserved = if previous == 0 && !starts_counter {
        0
    } else {
        rbw::passkey::next_counter(previous).map_err(|_| unavailable())?
    };
    if reserved > previous {
        reserve_counter(agent, account, &db, &selected, reserved)
            .await
            .map_err(|_| unavailable())?;
        let fresh = load_db(account).await.map_err(|_| unavailable())?;
        let state = agent.lock().await;
        let current = select(&fresh, client, &state, account, request)?;
        if current.entry.id != item_id
            || current.raw_id != raw_id
            || counter(&state, account, &current)
                .map_err(|_| unavailable())?
                < reserved
        {
            return Err(unavailable());
        }
    }
    let state = agent.lock().await;
    if state.needs_unlock(&account.name) {
        return Err(ApiError::new(ErrorCode::VaultLocked));
    }
    let (client_data, auth_data, signature) =
        rbw::passkey::sign_assertion_with_verification(
            &key,
            &request.rp_id,
            origin,
            &request.challenge,
            reserved,
            request.user_verified,
        )
        .map_err(|_| unavailable())?;
    drop(state);
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(serde_json::json!({
        "id": raw_id,
        "rawId": raw_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64url.encode(client_data),
            "authenticatorData": b64url.encode(auth_data),
            "signature": b64url.encode(signature),
            "userHandle": user_handle.map(|handle| b64url.encode(handle)),
        },
        "counter": reserved,
    }))
}
