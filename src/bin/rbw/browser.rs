//! Narrow browser API. Never serialize vault entries or protocol requests here.
use std::io::{Read as _, Write as _};

use anyhow::{ensure, Context as _};
use serde_json::{json, Value};

use crate::{actions, commands};

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
    Unlock,
    Lock,
    Sync,
    Search {
        query: String,
        url: Option<String>,
        site_only: bool,
    },
    Credential {
        item: String,
        url: String,
    },
    Copy {
        item: String,
        field: CopyField,
    },
    Generate {
        length: Option<usize>,
        passphrase: bool,
    },
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum CopyField {
    Username,
    Password,
    Totp,
}

pub fn run() -> anyhow::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
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
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        let parsed = serde_json::from_slice::<Request>(&bytes);
        let response = match parsed {
            Ok(request) => {
                let id = request.id;
                // Backend errors can contain vault data; never forward them.
                dispatch(request).map_or_else(
                    |_| json!({"id": id, "error": "Operation failed. Check account configuration, unlock the vault, or sync using rbw."}),
                    |result| json!({"id": id, "result": result}),
                )
            }
            Err(_) => json!({"id": null, "error": "Invalid browser request"}),
        };
        let encoded = serde_json::to_vec(&response)?;
        ensure!(encoded.len() <= MAX_MESSAGE, "native response too large");
        output.write_all(&u32::try_from(encoded.len())?.to_ne_bytes())?;
        output.write_all(&encoded)?;
        output.flush()?;
    }
}

fn dispatch(request: Request) -> anyhow::Result<Value> {
    actions::set_active_account(request.account)?;
    match request.operation {
        Operation::Status => {
            let config = rbw::config::Config::load()?;
            Ok(json!({"unlocked": actions::unlocked().is_ok(),
                "accounts": config.accounts().iter().map(|a| &a.name).collect::<Vec<_>>(),
                "primary": config.primary_account_name()}))
        }
        Operation::Unlock => {
            commands::unlock(None, None)?;
            Ok(json!(true))
        }
        Operation::Lock => {
            commands::lock(false)?;
            Ok(json!(true))
        }
        Operation::Sync => {
            commands::sync(false)?;
            Ok(json!(true))
        }
        Operation::Generate { length, passphrase } => {
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
            Ok(json!(rbw::pwgen::pwgen(ty, length)))
        }
        operation => {
            // Passive check prevents searching/filling from implicitly unlocking.
            actions::unlocked()?;
            let db = commands::load_db()?;
            match operation {
                Operation::Search {
                    query,
                    url,
                    site_only,
                } => {
                    ensure!(query.len() <= 1024, "query too long");
                    let url = url.as_deref().map(web_url).transpose()?;
                    let query = query.to_lowercase();
                    let mut items = Vec::new();
                    for entry in db
                        .entries
                        .iter()
                        .filter(|e| !e.deleted && !e.archived)
                    {
                        let rbw::db::EntryData::Login {
                            username, uris, ..
                        } = &entry.data
                        else {
                            continue;
                        };
                        // Browsing must not trigger prompts for each protected item.
                        if entry.master_password_reprompt() {
                            continue;
                        }
                        let name = decrypt(entry, &entry.name)?;
                        let username = username
                            .as_deref()
                            .map(|s| decrypt(entry, s))
                            .transpose()?;
                        let matched = url.as_ref().is_some_and(|url| {
                            matches(entry, uris, url).unwrap_or(false)
                        });
                        if site_only && !matched {
                            continue;
                        }
                        if !format!(
                            "{name} {}",
                            username.as_deref().unwrap_or_default()
                        )
                        .to_lowercase()
                        .contains(&query)
                        {
                            continue;
                        }
                        items.push(json!({"id": entry.id, "name": name, "username": username, "matched": matched}));
                        if items.len() == 200 {
                            break;
                        }
                    }
                    Ok(json!({"items": items, "limit": 200}))
                }
                Operation::Credential { item, url } => {
                    let url = web_url(&url)?;
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
                    ensure!(matches(entry, uris, &url)?, "site mismatch");
                    Ok(
                        json!({"username": username.as_deref().map(|s| decrypt(entry, s)).transpose()?,
                        "password": password.as_deref().map(|s| decrypt(entry, s)).transpose()?}),
                    )
                }
                Operation::Copy { item, field } => {
                    let entry = entry(&db, &item)?;
                    let rbw::db::EntryData::Login {
                        username,
                        password,
                        totp,
                        ..
                    } = &entry.data
                    else {
                        anyhow::bail!("not a login");
                    };
                    let encrypted = match field {
                        CopyField::Username => username,
                        CopyField::Password => password,
                        CopyField::Totp => totp,
                    };
                    let value = decrypt(
                        entry,
                        encrypted.as_deref().context("field unavailable")?,
                    )?;
                    let value = if matches!(field, CopyField::Totp) {
                        commands::generate_totp(&value)?
                    } else {
                        value
                    };
                    // Use the agent clipboard so its normal clearing policy applies.
                    actions::system_clipboard_store(&value)?;
                    Ok(json!(true))
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
    db.entries
        .iter()
        .find(|e| e.id == id && !e.deleted && !e.archived)
        .context("item unavailable")
}

fn decrypt(entry: &rbw::db::Entry, value: &str) -> anyhow::Result<String> {
    actions::decrypt(value, entry.key.as_deref(), entry.org_id.as_deref())
}

fn matches(
    entry: &rbw::db::Entry,
    uris: &[rbw::db::Uri],
    url: &url::Url,
) -> anyhow::Result<bool> {
    // Never transfer credentials from an HTTPS entry to an HTTP page, even
    // when the configured URI matching rule would otherwise permit it.
    for uri in uris {
        let value = decrypt(entry, &uri.uri)?;
        if url.scheme() == "http" && value.starts_with("https:") {
            continue;
        }
        if commands::matches_url(&value, uri.match_type, url) {
            return Ok(true);
        }
    }
    Ok(false)
}
