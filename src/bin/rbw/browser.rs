//! Narrow browser API. Never serialize vault entries or protocol requests here.
use std::io::Read as _;

use anyhow::{ensure, Context as _};
use serde_json::{json, Value};

use crate::{actions, commands};

pub mod attachments;
mod passkeys;
use crate::sends;
mod transfer;

const MAX_MESSAGE: usize = 512 * 1024;

#[derive(serde::Deserialize)]
struct Request {
    id: u64,
    #[serde(default)]
    account: Option<String>,
    #[serde(flatten)]
    operation: Operation,
}

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Operation {
    Status,
    Unlock {
        password: Option<String>,
    },
    Lock,
    Sync,
    Search {
        query: String,
        url: Option<String>,
        site_only: bool,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        folder: Option<String>,
        #[serde(default)]
        collection: Option<String>,
        #[serde(default)]
        view: Option<String>,
        // The extension's override of rbw's `defaultUriMatch`, if any.
        #[serde(default)]
        match_default: Option<String>,
    },
    Credential {
        item: String,
        url: String,
        #[serde(default)]
        match_default: Option<String>,
    },
    Totp {
        item: String,
    },
    Copy {
        item: String,
        field: String,
    },
    PasskeyCandidates {
        origin: String,
        options: Value,
    },
    PasskeyGet {
        password: Option<String>,
        item: String,
        origin: String,
        options: Value,
    },
    PasskeyVerify {
        item: String,
        origin: String,
        options: Value,
        counter: u32,
    },
    PasskeyCreate {
        password: Option<String>,
        item: Option<String>,
        origin: String,
        options: Value,
    },
    Detail {
        item: String,
    },
    Save {
        item: Option<String>,
        revision: Option<String>,
        cipher: commands::EditableCipher,
    },
    Mutate {
        item: String,
        mutation: String,
    },
    Export {
        format: String,
        password: Option<String>,
        attachments: bool,
    },
    Import {
        token: String,
        password: Option<String>,
        overwrite: bool,
    },
    AgentSettings,
    Folders {
        method: String,
        id: Option<String>,
        name: Option<String>,
    },
    SetCollections {
        item: String,
        collections: Vec<String>,
    },
    CopyText {
        text: String,
    },
    AttachmentDownload {
        item: String,
        attachment: String,
    },
    AttachmentDelete {
        item: String,
        attachment: String,
    },
    UploadBegin {
        item: String,
        name: String,
        size: u64,
    },
    UploadChunk {
        token: String,
        offset: u64,
        data: String,
    },
    UploadFinish {
        token: String,
    },
    UploadCancel {
        token: String,
    },
    Send {
        method: String,
        data: Value,
    },
    Audit,
    Generate {
        #[serde(default)]
        mode: Option<String>,
        length: Option<usize>,
        passphrase: bool,
    },
}

// Browser-supplied identities are trusted only when the immediate parent is
// an explicitly enrolled executable. This is not an OS sandbox against the
// same Unix user, who can already invoke the regular rbw CLI.
#[cfg(target_os = "linux")]
fn authorize(arguments: &[std::ffi::OsString]) -> anyhow::Result<()> {
    use rbw::config::BrowserKind;
    let denied = || {
        anyhow::anyhow!(
            "Native messaging caller is not allowed by browser.clients"
        )
    };
    let executable = std::fs::canonicalize(format!("/proc/{}/exe", unsafe {
        libc::getppid()
    }))
    .map_err(|_| denied())?;
    {
        let config = rbw::config::Config::load()?;
        for client in config.browser.clients.values() {
            let identity = match client.browser {
                BrowserKind::Firefox
                    if arguments.len() == 2
                        && std::path::Path::new(&arguments[0])
                            .is_absolute() =>
                {
                    arguments[1].to_str()
                }
                BrowserKind::Chromium if arguments.len() == 1 => arguments[0]
                    .to_str()
                    .and_then(|s| s.strip_prefix("chrome-extension://"))
                    .and_then(|s| s.strip_suffix('/')),
                _ => None,
            };
            if !identity.is_some_and(|id| {
                client.extensions.iter().any(|allowed| allowed == id)
            }) {
                continue;
            }
            for root in &client.executable_roots {
                if root.is_absolute()
                    && std::fs::canonicalize(root).is_ok_and(|root| {
                        executable == root
                            || (root.is_dir() && executable.starts_with(root))
                    })
                {
                    return Ok(());
                }
            }
        }
        Err(denied())
    }
}

#[cfg(not(target_os = "linux"))]
fn authorize(_arguments: &[std::ffi::OsString]) -> anyhow::Result<()> {
    anyhow::bail!("Native messaging browser allowlist requires Linux")
}

fn write_response(
    output: &mut impl std::io::Write,
    response: &Value,
) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(response)?;
    ensure!(encoded.len() <= MAX_MESSAGE, "native response too large");
    output.write_all(&u32::try_from(encoded.len())?.to_ne_bytes())?;
    output.write_all(&encoded)?;
    output.flush()?;
    Ok(())
}

fn authorize_or_report(
    arguments: &[std::ffi::OsString],
    output: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    if authorize(arguments).is_err() {
        // A fixed protocol error lets the UI distinguish policy denial from
        // a missing/crashed host without disclosing caller or config details.
        write_response(
            output,
            &json!({
                "id": null,
                "code": "browser_not_authorized",
                "error": "Browser access denied. This browser or extension is not authorized by rbw. Add it to browser.clients in your rbw configuration, then restart the browser."
            }),
        )?;
        anyhow::bail!("Native messaging browser authorization denied");
    }
    Ok(())
}

pub fn run(arguments: &[std::ffi::OsString]) -> anyhow::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    authorize_or_report(arguments, &mut output)?;
    let mut attachments = attachments::Transfers::default();
    loop {
        let mut header = [0; 4];
        // EOF between frames is normal; partial headers are malformed.
        if input.read(&mut header[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut header[1..])?;
        let length = usize::try_from(u32::from_ne_bytes(header))?;
        ensure!(
            (1..=MAX_MESSAGE).contains(&length),
            "invalid native message length"
        );
        let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
        input.read_exact(&mut bytes)?;
        authorize_or_report(arguments, &mut output)?;
        let parsed = serde_json::from_slice::<Request>(&bytes);
        let response = match parsed {
            Ok(request) => {
                let id = request.id;
                let unlocking =
                    matches!(&request.operation, Operation::Unlock { .. });
                // Backend errors can contain vault data; never forward them.
                dispatch(request, &mut attachments).map_or_else(
                    |error| json!({"id": id, "error": if commands::exit_status(&error) == 2 { "The server write succeeded, but synchronization failed. Sync and inspect your vault before retrying to avoid duplicates." } else if unlocking { "Could not unlock this account. Check your master password and account configuration." } else { "Operation failed. Unlock this account or sync your vault, then try again." }}),
                    |result| json!({"id": id, "result": result}),
                )
            }
            Err(_) => json!({"id": null, "error": "Invalid browser request"}),
        };
        write_response(&mut output, &response)?;
    }
}

fn dispatch(
    request: Request,
    transfers: &mut attachments::Transfers,
) -> anyhow::Result<Value> {
    transfers.prune();
    actions::set_active_account(request.account)?;
    match request.operation {
        Operation::Status => {
            let config = rbw::config::Config::load()?;
            let unlocked = actions::version()
                .is_ok_and(|v| v == rbw::protocol::VERSION)
                && actions::unlocked().is_ok();
            if !unlocked {
                transfers.clear();
            }
            Ok(json!({"unlocked": unlocked,
                "accounts": config.accounts().iter().map(|a| &a.name).collect::<Vec<_>>(),
                "primary": config.primary_account_name()}))
        }
        Operation::Unlock { password } => {
            ensure!(
                password.as_ref().is_none_or(|v| v.len() <= 4096),
                "password too long"
            );
            commands::unlock(password, None)?;
            Ok(json!(true))
        }
        Operation::Lock => {
            transfers.clear();
            commands::lock(false)?;
            Ok(json!(true))
        }
        Operation::Sync => {
            commands::sync(false)?;
            Ok(json!(true))
        }
        Operation::AgentSettings => {
            let config = rbw::config::Config::load()?;
            Ok(
                json!({"lockTimeout": config.agent.lock_timeout, "syncInterval": config.agent.sync_interval, "passwordGen": config.password_gen, "clipboard": config.clipboard, "defaultUriMatch": config.default_uri_match}),
            )
        }
        Operation::CopyText { text } => {
            ensure!(text.len() <= 16384, "clipboard value too long");
            actions::system_clipboard_store(&text)?;
            Ok(json!(true))
        }
        Operation::Generate {
            length,
            passphrase,
            mode,
        } => {
            let config = rbw::config::Config::load()?;
            let (length, ty) = rbw::pwgen::resolve(
                rbw::pwgen::GenFlags {
                    length,
                    diceware: passphrase,
                    ..Default::default()
                },
                rbw::pwgen::GenFlags::from(&config.password_gen),
            );
            ensure!((1..=128).contains(&length), "invalid generator length");
            let ty = match mode.as_deref() {
                Some("all") => rbw::pwgen::Type::AllChars,
                Some("no_symbols") => rbw::pwgen::Type::NoSymbols,
                Some("numbers") => rbw::pwgen::Type::Numbers,
                Some("nonconfusables") => rbw::pwgen::Type::NonConfusables,
                Some("passphrase") => rbw::pwgen::Type::Diceware,
                _ => ty,
            };
            Ok(json!(rbw::pwgen::pwgen(ty, length)))
        }
        operation => {
            // New protocol operations must never reach an older agent.
            ensure!(
                actions::version()? == rbw::protocol::VERSION,
                "agent upgrade required"
            );
            // Passive check prevents searching/filling from implicitly unlocking.
            actions::unlocked()?;
            let db = commands::load_db()?;
            match operation {
                Operation::Search {
                    query,
                    url,
                    site_only,
                    kind,
                    folder,
                    collection,
                    view,
                    match_default,
                } => {
                    ensure!(query.len() <= 1024, "query too long");
                    let url = url.as_deref().map(web_url).transpose()?;
                    let default =
                        uri_match_default(match_default.as_deref())?;
                    let query = query.to_lowercase();
                    let mut items = Vec::new();
                    let mut folders = std::collections::BTreeSet::new();
                    // A search used to open an agent socket for every field (and
                    // decrypt URIs twice). Batch only list metadata, keeping the
                    // plaintext local to this request, never in a browser cache
                    // alongside passwords, notes, TOTP seeds or custom fields.
                    let metadata = search_metadata(
                        &db.entries,
                        view.as_deref(),
                        kind.as_deref(),
                    )?;
                    let decrypt = |entry: &rbw::db::Entry, value: &str| {
                        metadata.get(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    };
                    let matches =
                        |entry: &rbw::db::Entry,
                         uris: &[rbw::db::Uri],
                         url: &url::Url|
                         -> anyhow::Result<bool> {
                            for uri in uris {
                                let value = decrypt(entry, &uri.uri)?;
                                if skip_insecure_uri(url, &value) {
                                    continue;
                                }
                                if commands::matches_url(
                                    &value,
                                    uri.match_type,
                                    url,
                                    default,
                                ) {
                                    return Ok(true);
                                }
                            }
                            Ok(false)
                        };
                    for entry in &db.entries {
                        let in_view = match view.as_deref().unwrap_or("vault")
                        {
                            "trash" => entry.deleted,
                            "archive" => entry.archived && !entry.deleted,
                            "favorites" => {
                                entry.favorite
                                    && !entry.deleted
                                    && !entry.archived
                            }
                            _ => !entry.deleted && !entry.archived,
                        };
                        if !in_view {
                            continue;
                        }
                        let folder_name = entry
                            .folder
                            .as_deref()
                            .map(|f| metadata.get(f, None, None))
                            .transpose()?;
                        if let Some(f) = &folder_name {
                            folders.insert(f.clone());
                        }
                        if folder
                            .as_ref()
                            .is_some_and(|f| Some(f) != folder_name.as_ref())
                            || collection.as_ref().is_some_and(|c| {
                                !entry.collection_ids.contains(c)
                            })
                        {
                            continue;
                        }
                        let ty = match &entry.data {
                            rbw::db::EntryData::Login { .. } => "login",
                            rbw::db::EntryData::Card { .. } => "card",
                            rbw::db::EntryData::Identity { .. } => "identity",
                            rbw::db::EntryData::SecureNote => "secure_note",
                            rbw::db::EntryData::SshKey { .. } => "ssh_key",
                        };
                        if kind.as_ref().is_some_and(|k| k != ty && !(k == "passkey" && matches!(&entry.data, rbw::db::EntryData::Login { fido2_credentials, .. } if !fido2_credentials.is_empty()))) { continue; }
                        let name = decrypt(entry, &entry.name)?;
                        let (subtitle, matched, passkeys) = match &entry.data
                        {
                            rbw::db::EntryData::Login {
                                username,
                                uris,
                                fido2_credentials,
                                ..
                            } => (
                                username
                                    .as_deref()
                                    .map(|s| decrypt(entry, s))
                                    .transpose()?,
                                url.as_ref().is_some_and(|u| {
                                    matches(entry, uris, u).unwrap_or(false)
                                }),
                                fido2_credentials.len(),
                            ),
                            rbw::db::EntryData::Card {
                                brand,
                                number,
                                ..
                            } => {
                                let brand = brand
                                    .as_deref()
                                    .map(|s| decrypt(entry, s))
                                    .transpose()?
                                    .unwrap_or_default();
                                let number = number
                                    .as_deref()
                                    .filter(|_| {
                                        !entry.master_password_reprompt()
                                    })
                                    .map(|s| decrypt(entry, s))
                                    .transpose()?
                                    .unwrap_or_default();
                                (
                                    Some(format!(
                                        "{brand}, •{}",
                                        number
                                            .chars()
                                            .rev()
                                            .take(4)
                                            .collect::<String>()
                                            .chars()
                                            .rev()
                                            .collect::<String>()
                                    )),
                                    false,
                                    0,
                                )
                            }
                            rbw::db::EntryData::Identity {
                                first_name,
                                last_name,
                                ..
                            } => (
                                Some(format!(
                                    "{} {}",
                                    first_name
                                        .as_deref()
                                        .map(|s| decrypt(entry, s))
                                        .transpose()?
                                        .unwrap_or_default(),
                                    last_name
                                        .as_deref()
                                        .map(|s| decrypt(entry, s))
                                        .transpose()?
                                        .unwrap_or_default()
                                )),
                                false,
                                0,
                            ),
                            _ => (folder_name.clone(), false, 0),
                        };
                        if (site_only && !matched)
                            || (view.as_deref() == Some("home")
                                && query.is_empty()
                                && !entry.favorite
                                && !matched)
                        {
                            continue;
                        }
                        if !format!(
                            "{name} {}",
                            subtitle.as_deref().unwrap_or_default()
                        )
                        .to_lowercase()
                        .contains(&query)
                        {
                            continue;
                        }
                        let icon_origin = if let rbw::db::EntryData::Login {
                            uris,
                            ..
                        } = &entry.data
                        {
                            uris.iter()
                                .filter_map(|uri| {
                                    decrypt(entry, &uri.uri).ok()
                                })
                                .filter_map(|uri| url::Url::parse(&uri).ok())
                                .find(|uri| {
                                    uri.scheme() == "https"
                                        || (uri.scheme() == "http"
                                            && uri.host_str()
                                                == Some("localhost"))
                                })
                                .map(|uri| uri.origin().ascii_serialization())
                        } else {
                            None
                        };
                        items.push(json!({"id": entry.id, "name": name, "iconOrigin": icon_origin, "username": subtitle, "matched": matched, "type": ty, "passkeys": passkeys, "favorite": entry.favorite, "folder": folder_name, "archived": entry.archived, "deleted": entry.deleted, "protected": entry.master_password_reprompt()}));
                    }
                    items.sort_by_key(|v| {
                        (
                            !v["matched"].as_bool().unwrap_or(false),
                            !v["favorite"].as_bool().unwrap_or(false),
                            v["name"]
                                .as_str()
                                .unwrap_or_default()
                                .to_lowercase(),
                        )
                    });
                    let total = items.len();
                    items.truncate(200);
                    let collections = db.collections.iter().map(|c| Ok(json!({"id": c.id, "name": actions::decrypt(&c.name, None, Some(&c.org_id))?}))).collect::<anyhow::Result<Vec<_>>>()?;
                    Ok(
                        json!({"items": items, "limit": 200, "total": total, "folders": folders, "collections": collections}),
                    )
                }
                Operation::Credential {
                    item,
                    url,
                    match_default,
                } => {
                    let url = web_url(&url)?;
                    let default =
                        uri_match_default(match_default.as_deref())?;
                    let entry = entry(&db, &item)?;
                    let rbw::db::EntryData::Login {
                        username,
                        password,
                        uris,
                        ..
                    } = &entry.data
                    else {
                        anyhow::bail!("not a login");
                    };
                    ensure!(
                        matches(entry, uris, &url, default)?,
                        "site mismatch"
                    );
                    let custom = entry.fields.iter().map(|f| Ok(json!({"name": f.name.as_deref().map(|v| decrypt(entry, v)).transpose()?, "value": f.value.as_deref().map(|v| decrypt(entry, v)).transpose()?, "type": match f.ty { Some(rbw::api::FieldType::Hidden) => "hidden", Some(rbw::api::FieldType::Boolean) => "boolean", Some(rbw::api::FieldType::Linked) => "linked", _ => "text" }}))).collect::<anyhow::Result<Vec<_>>>()?;
                    Ok(
                        json!({"name": decrypt(entry, &entry.name)?, "custom": custom, "username": username.as_deref().map(|s| decrypt(entry, s)).transpose()?,
                        "password": password.as_deref().map(|s| decrypt(entry, s)).transpose()?}),
                    )
                }
                Operation::Totp { item } => {
                    let entry = entry(&db, &item)?;
                    let rbw::db::EntryData::Login {
                        totp: Some(secret), ..
                    } = &entry.data
                    else {
                        anyhow::bail!("authenticator key unavailable");
                    };
                    let secret = decrypt(entry, secret)?;
                    let (code, period, expires_at) =
                        commands::generate_totp_with_expiry(&secret)?;
                    Ok(
                        json!({"code": code, "period": period, "expiresAt": expires_at}),
                    )
                }
                Operation::Copy { item, field } => {
                    let entry = entry(&db, &item)?;
                    let value = if field == "notes" {
                        decrypt(
                            entry,
                            entry
                                .notes
                                .as_deref()
                                .context("notes unavailable")?,
                        )?
                    } else if let Some(index) = field.strip_prefix("history/")
                    {
                        let history = entry
                            .history
                            .get(index.parse::<usize>()?)
                            .context("password history entry unavailable")?;
                        decrypt(entry, &history.password)?
                    } else if let Some(index) = field.strip_prefix("custom/")
                    {
                        let custom = entry
                            .fields
                            .get(index.parse::<usize>()?)
                            .context("field unavailable")?;
                        decrypt(
                            entry,
                            custom
                                .value
                                .as_deref()
                                .context("field unavailable")?,
                        )?
                    } else {
                        ensure!(
                            [
                                "username",
                                "password",
                                "totp",
                                "cardholder_name",
                                "number",
                                "brand",
                                "exp_month",
                                "exp_year",
                                "code",
                                "title",
                                "first_name",
                                "middle_name",
                                "last_name",
                                "address1",
                                "address2",
                                "address3",
                                "city",
                                "state",
                                "postal_code",
                                "country",
                                "phone",
                                "email",
                                "ssn",
                                "license_number",
                                "passport_number",
                                "public_key",
                                "fingerprint",
                                "private_key"
                            ]
                            .contains(&field.as_str()),
                            "unsupported field"
                        );
                        let encrypted = serde_json::to_value(&entry.data)?;
                        let value = encrypted
                            .as_object()
                            .and_then(|v| v.values().next())
                            .and_then(|v| v.get(&field))
                            .and_then(Value::as_str)
                            .context("field unavailable")?;
                        let value = decrypt(entry, value)?;
                        if field == "totp" {
                            commands::generate_totp(&value)?
                        } else {
                            value
                        }
                    };
                    // Use the agent clipboard so its normal clearing policy applies.
                    actions::system_clipboard_store(&value)?;
                    Ok(json!(true))
                }
                Operation::AttachmentDownload { item, attachment } => {
                    attachments::download(&mut { db }, &item, &attachment)
                }
                Operation::AttachmentDelete { item, attachment } => {
                    let entry = entry(&db, &item)?.clone();
                    commands::tui_attachment_delete(
                        &mut { db },
                        &entry,
                        &attachment,
                    )?;
                    Ok(json!(true))
                }
                Operation::UploadBegin { item, name, size } => {
                    transfers.begin(&db, &item, &name, size)
                }
                Operation::UploadChunk {
                    token,
                    offset,
                    data,
                } => transfers.chunk(&token, offset, &data),
                Operation::UploadFinish { token } => {
                    transfers.finish(&mut { db }, &token)
                }
                Operation::UploadCancel { token } => {
                    transfers.cancel(&token);
                    Ok(json!(true))
                }
                Operation::PasskeyCandidates { origin, options } => {
                    passkeys::candidates(&origin, &options)
                }
                Operation::PasskeyGet {
                    password,
                    item,
                    origin,
                    options,
                } => passkeys::authenticate(
                    &item,
                    &origin,
                    &options,
                    password.as_deref(),
                ),
                Operation::PasskeyVerify {
                    item,
                    origin,
                    options,
                    counter,
                } => passkeys::confirm_counter(
                    &item, &origin, &options, counter,
                ),
                Operation::PasskeyCreate {
                    password,
                    item,
                    origin,
                    options,
                } => passkeys::register(
                    item.as_deref(),
                    &origin,
                    &options,
                    password.as_deref(),
                ),
                Operation::Detail { item } => {
                    let entry = entry(&db, &item)?;
                    let mut result = detail(entry)?;
                    let options = db.collections.iter().filter(|c| Some(&c.org_id) == entry.org_id.as_ref()).map(|c| Ok(json!({"id": c.id, "name": actions::decrypt(&c.name, None, Some(&c.org_id))?}))).collect::<anyhow::Result<Vec<_>>>()?;
                    result["collection_options"] = json!(options);
                    result["collection_ids"] = json!(entry.collection_ids);
                    Ok(result)
                }
                Operation::SetCollections { item, collections } => {
                    let entry = entry(&db, &item)?;
                    ensure!(
                        entry.org_id.is_some()
                            && collections.len() <= 100
                            && collections.iter().all(|id| db
                                .collections
                                .iter()
                                .any(|c| &c.id == id
                                    && Some(&c.org_id)
                                        == entry.org_id.as_ref())),
                        "invalid collections"
                    );
                    let (tokens, ()) = rbw::actions::edit_collections(
                        db.access_token
                            .as_deref()
                            .context("not logged in")?,
                        db.refresh_token
                            .as_deref()
                            .context("not logged in")?,
                        &entry.id,
                        &collections,
                    )?;
                    commands::after_server_write(&mut { db }, tokens)?;
                    Ok(json!(true))
                }
                Operation::Folders { method, id, name } => {
                    let mut db = db;
                    let access = db
                        .access_token
                        .as_deref()
                        .context("not logged in")?;
                    let refresh = db
                        .refresh_token
                        .as_deref()
                        .context("not logged in")?;
                    if method == "list" {
                        let (tokens, folders) =
                            rbw::actions::list_folders(access, refresh)?;
                        let result = folders.iter().map(|(id, name)| Ok(json!({"id": id, "name": actions::decrypt(name, None, None)?}))).collect::<anyhow::Result<Vec<_>>>()?;
                        if let Some(tokens) = tokens {
                            db.access_token = Some(tokens.access_token);
                            if let Some(refresh) = tokens.refresh_token {
                                db.refresh_token = Some(refresh);
                            }
                            commands::save_db(&db)?;
                        }
                        return Ok(json!(result));
                    }
                    let folder_id = id
                        .as_deref()
                        .map(uuid::Uuid::parse_str)
                        .transpose()?;
                    let path = folder_id.map_or_else(
                        || "/folders".to_owned(),
                        |id| format!("/folders/{id}"),
                    );
                    let http = match method.as_str() {
                        "create" if folder_id.is_none() => "POST",
                        "rename" if folder_id.is_some() => "PUT",
                        "delete" if folder_id.is_some() => "DELETE",
                        _ => anyhow::bail!("invalid folder action"),
                    };
                    let body = if http == "DELETE" {
                        None
                    } else {
                        let name = name.context("name required")?;
                        ensure!(
                            !name.trim().is_empty() && name.len() <= 1024,
                            "invalid folder name"
                        );
                        Some(
                            json!({"name": actions::encrypt(&name, None, None)?}),
                        )
                    };
                    let (tokens, _) = rbw::actions::send_request(
                        access,
                        refresh,
                        http,
                        &path,
                        body.as_ref(),
                        None,
                    )?;
                    commands::after_server_write(&mut db, tokens)?;
                    Ok(json!(true))
                }
                Operation::Save {
                    item,
                    revision,
                    mut cipher,
                } => {
                    ensure!(!cipher.name.trim().is_empty(), "name required");
                    let mut db = db;
                    if let Some(item) = item {
                        let mut entry = entry(&db, &item)?.clone();
                        if cipher.folder.is_none() {
                            entry.folder_id = None;
                        }
                        ensure!(
                            entry.revision_date.is_some()
                                && entry.revision_date == revision,
                            "item changed; reload before saving"
                        );
                        let previous = commands::decrypted_to_editable(
                            &commands::decrypt_cipher(&entry)?,
                        );
                        // The browser never sees or supplies passkey private material.
                        if let commands::EditableData::Login {
                            fido2_credentials,
                            ..
                        } = &mut cipher.data
                        {
                            ensure!(
                                fido2_credentials.is_empty(),
                                "browser supplied passkeys"
                            );
                            if let commands::EditableData::Login {
                                fido2_credentials: stored,
                                ..
                            } = previous.data
                            {
                                *fido2_credentials = stored;
                            }
                        } else if matches!(previous.data, commands::EditableData::Login { ref fido2_credentials, .. } if !fido2_credentials.is_empty())
                        {
                            anyhow::bail!(
                                "type change would discard passkeys"
                            );
                        }
                        commands::tui_save_edit(&mut db, &entry, &cipher)?;
                    } else {
                        ensure!(
                            !matches!(&cipher.data, commands::EditableData::Login { fido2_credentials, .. } if !fido2_credentials.is_empty()),
                            "browser supplied passkeys"
                        );
                        commands::tui_save_add(&mut db, &cipher)?;
                    }
                    Ok(json!(true))
                }
                Operation::Mutate { item, mutation } => {
                    let mut db = db;
                    let entry = db
                        .entries
                        .iter()
                        .find(|e| e.id == item)
                        .context("missing item")?
                        .clone();
                    if entry.master_password_reprompt() {
                        commands::decrypt_cipher(&entry)?;
                    }
                    match mutation.as_str() {
                        "delete" => {
                            ensure!(!entry.deleted, "already deleted");
                            commands::tui_delete(&mut db, &entry)?;
                        }
                        "archive" => {
                            commands::tui_toggle_archived(&mut db, &entry)?;
                        }
                        "restore" => {
                            ensure!(entry.deleted, "not deleted");
                            let (tokens, ()) = rbw::actions::restore(
                                db.access_token
                                    .as_deref()
                                    .context("not logged in")?,
                                db.refresh_token
                                    .as_deref()
                                    .context("not logged in")?,
                                &entry.id,
                            )?;
                            commands::after_server_write(&mut db, tokens)?;
                        }
                        "favorite" => {
                            let mut changed = entry.clone();
                            changed.favorite = !entry.favorite;
                            let (tokens, ()) = rbw::actions::edit(
                                db.access_token
                                    .as_deref()
                                    .context("not logged in")?,
                                db.refresh_token
                                    .as_deref()
                                    .context("not logged in")?,
                                &changed.id,
                                changed.org_id.as_deref(),
                                changed.key.as_deref(),
                                &changed.name,
                                &changed.data,
                                &changed.fields,
                                changed.notes.as_deref(),
                                changed.folder_id.as_deref(),
                                &changed.history,
                                &changed.cipher_write_meta(),
                            )?;
                            commands::after_server_write(&mut db, tokens)?;
                        }
                        _ => anyhow::bail!("unknown mutation"),
                    }
                    Ok(json!(true))
                }
                Operation::Send { method, data } => {
                    sends::dispatch(&mut { db }, transfers, &method, &data)
                }
                Operation::Export {
                    format,
                    password,
                    attachments,
                } => transfer::export(
                    &format,
                    password.as_deref(),
                    attachments,
                ),
                Operation::Import {
                    token,
                    password,
                    overwrite,
                } => transfer::import(
                    transfers,
                    &token,
                    password.as_deref(),
                    overwrite,
                ),
                Operation::Audit => {
                    let mut passwords = std::collections::HashMap::<
                        String,
                        Vec<String>,
                    >::new();
                    let mut missing_totp = 0;
                    for entry in db.entries.iter().filter(|e| {
                        !e.deleted
                            && !e.archived
                            && !e.master_password_reprompt()
                    }) {
                        if let rbw::db::EntryData::Login {
                            password: Some(pw),
                            totp,
                            ..
                        } = &entry.data
                        {
                            passwords
                                .entry(decrypt(entry, pw)?)
                                .or_default()
                                .push(decrypt(entry, &entry.name)?);
                            if totp.is_none() {
                                missing_totp += 1;
                            }
                        }
                    }
                    let reused = passwords
                        .values()
                        .filter(|v| v.len() > 1)
                        .collect::<Vec<_>>();
                    let weak = passwords
                        .iter()
                        .filter(|(pw, _)| pw.chars().count() < 12)
                        .flat_map(|(_, names)| names)
                        .collect::<Vec<_>>();
                    Ok(
                        json!({"reused": reused, "short": weak, "without_totp": missing_totp}),
                    )
                }
                _ => unreachable!(),
            }
        }
    }
}

fn web_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    ensure!(
        matches!(url.scheme(), "https" | "http") && url.host_str().is_some(),
        "unsupported URL"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL credentials unsupported"
    );
    Ok(url)
}

fn entry<'a>(
    db: &'a rbw::db::Db,
    id: &str,
) -> anyhow::Result<&'a rbw::db::Entry> {
    let entry = db
        .entries
        .iter()
        .find(|e| e.id == id && !e.deleted)
        .context("item unavailable")?;
    Ok(entry)
}

// Per-search metadata batch; all values are dropped before the next request.
struct SearchMetadata {
    indices: std::collections::HashMap<
        (String, Option<String>, Option<String>),
        usize,
    >,
    results: Vec<rbw::protocol::DecryptResult>,
}
impl SearchMetadata {
    fn get(
        &self,
        value: &str,
        key: Option<&str>,
        org: Option<&str>,
    ) -> anyhow::Result<String> {
        let index = self
            .indices
            .get(&(
                value.to_owned(),
                key.map(str::to_owned),
                org.map(str::to_owned),
            ))
            .context("missing search metadata")?;
        match &self.results[*index] {
            rbw::protocol::DecryptResult::Success { plaintext } => {
                Ok(plaintext.clone())
            }
            rbw::protocol::DecryptResult::Failure { .. } => {
                anyhow::bail!("failed to decrypt search metadata")
            }
        }
    }
}
fn search_metadata(
    entries: &[rbw::db::Entry],
    view: Option<&str>,
    kind: Option<&str>,
) -> anyhow::Result<SearchMetadata> {
    let mut indices = std::collections::HashMap::new();
    let mut requests = Vec::new();
    let mut push = |value: &str, key: Option<&str>, org: Option<&str>| {
        let tuple = (
            value.to_owned(),
            key.map(str::to_owned),
            org.map(str::to_owned),
        );
        if let std::collections::hash_map::Entry::Vacant(slot) =
            indices.entry(tuple)
        {
            slot.insert(requests.len());
            requests.push(rbw::protocol::DecryptRequest {
                cipherstring: value.to_owned(),
                entry_key: key.map(str::to_owned),
                org_id: org.map(str::to_owned),
            });
        }
    };
    for entry in entries {
        let in_view = match view.unwrap_or("vault") {
            "trash" => entry.deleted,
            "archive" => entry.archived && !entry.deleted,
            "favorites" => {
                entry.favorite && !entry.deleted && !entry.archived
            }
            _ => !entry.deleted && !entry.archived,
        };
        if !in_view {
            continue;
        }
        if let Some(folder) = &entry.folder {
            push(folder, None, None);
        }
        let ty = match &entry.data {
            rbw::db::EntryData::Login { .. } => "login",
            rbw::db::EntryData::Card { .. } => "card",
            rbw::db::EntryData::Identity { .. } => "identity",
            rbw::db::EntryData::SecureNote => "secure_note",
            rbw::db::EntryData::SshKey { .. } => "ssh_key",
        };
        if kind.is_some_and(|k| k != ty && !(k == "passkey" && matches!(&entry.data, rbw::db::EntryData::Login { fido2_credentials, .. } if !fido2_credentials.is_empty()))) { continue; }
        let key = entry.key.as_deref();
        let org = entry.org_id.as_deref();
        push(&entry.name, key, org);
        if let Some(folder) = &entry.folder {
            push(folder, None, None);
        }
        match &entry.data {
            rbw::db::EntryData::Login { username, uris, .. } => {
                if let Some(value) = username {
                    push(value, key, org);
                }
                for uri in uris {
                    push(&uri.uri, key, org);
                }
            }
            rbw::db::EntryData::Card { brand, number, .. } => {
                if let Some(value) = brand {
                    push(value, key, org);
                }
                if !entry.master_password_reprompt() {
                    if let Some(value) = number {
                        push(value, key, org);
                    }
                }
            }
            rbw::db::EntryData::Identity {
                first_name,
                last_name,
                ..
            } => {
                for value in [first_name, last_name].into_iter().flatten() {
                    push(value, key, org);
                }
            }
            _ => {}
        }
    }
    let count = requests.len();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        actions::decrypt_batch(requests)?
    };
    ensure!(results.len() == count, "incomplete search metadata batch");
    Ok(SearchMetadata { indices, results })
}

fn decrypt(entry: &rbw::db::Entry, value: &str) -> anyhow::Result<String> {
    actions::decrypt(value, entry.key.as_deref(), entry.org_id.as_deref())
}

/// On a plain-HTTP page (other than loopback) only URIs that are explicitly
/// `http:` may match; `https:` and scheme-less values are skipped.
fn skip_insecure_uri(url: &url::Url, value: &str) -> bool {
    url.scheme() == "http"
        && !matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        )
        && !value.trim_start().to_ascii_lowercase().starts_with("http:")
}

// The extension's override, else rbw's configured `defaultUriMatch`, read per
// request so config changes apply without restarting the browser.
fn uri_match_default(
    value: Option<&str>,
) -> anyhow::Result<rbw::api::UriMatchType> {
    if let Some(value) = value {
        return Ok(commands::parse_uri_match_default(value)?.into());
    }
    Ok(rbw::config::Config::load()
        .map_or(rbw::config::UriMatchDefault::Domain, |config| {
            config.default_uri_match
        })
        .into())
}

fn matches(
    entry: &rbw::db::Entry,
    uris: &[rbw::db::Uri],
    url: &url::Url,
    default: rbw::api::UriMatchType,
) -> anyhow::Result<bool> {
    // Never transfer credentials from an HTTPS entry to an HTTP page, even
    // when the configured URI matching rule would otherwise permit it.
    for uri in uris {
        let value = decrypt(entry, &uri.uri)?;
        if skip_insecure_uri(url, &value) {
            continue;
        }
        if commands::matches_url(&value, uri.match_type, url, default) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn detail(entry: &rbw::db::Entry) -> anyhow::Result<Value> {
    let decrypted = commands::decrypt_cipher(entry)?;
    let mut editable = commands::decrypted_to_editable(&decrypted);
    let mut passkeys = Vec::new();
    if let commands::EditableData::Login {
        fido2_credentials, ..
    } = &mut editable.data
    {
        for c in fido2_credentials.iter() {
            passkeys.push(json!({"rp": c.rp_id, "user": c.user_name, "created": c.creation_date}));
        }
        fido2_credentials.clear();
    }
    // TOTP seeds are only sent when explicitly editing an item, never search.
    Ok(
        json!({"cipher": editable, "revision": entry.revision_date, "passkeys": passkeys, "favorite": entry.favorite, "archived": entry.archived, "attachments": decrypted.attachments, "history": decrypted.history}),
    )
}
