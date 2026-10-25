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
    // The accounts the user picked in the extension's settings (two or
    // more), when no single `account` is named; absent means "as the CLI".
    #[serde(default)]
    accounts: Option<Vec<String>>,
    #[serde(flatten)]
    operation: Operation,
}

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Operation {
    Status,
    Unlock {
        password: Option<String>,
        // Unlock with the account's enrolled Secret Service credential after
        // a fingerprint scan instead of a password.
        #[serde(default)]
        fingerprint: bool,
    },
    Lock,
    // Replace an agent left over from another rbw version (see
    // `stale_agent`); this locks every account.
    RestartAgent,
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
        // Look the item up in the trash instead (read-only view there).
        #[serde(default)]
        trashed: bool,
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
    // Moves an item to another configured account (`rbw move`): recreated
    // there, the original goes to its account's trash.
    Move {
        item: String,
        to: String,
    },
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
            // A browser still running from before a Nix upgrade replaced
            // its store path in the config is the same enrolled browser.
            if client
                .executable_roots
                .iter()
                .any(|root| superseded_by(&executable, root))
            {
                return Ok(());
            }
        }
        Err(denied())
    }
}

/// True when `executable` lives in a different Nix store entry than `root`,
/// but at a path that also exists inside `root` (e.g. both have
/// `lib/firefox/firefox`): the same browser, built from an older store path.
#[cfg(target_os = "linux")]
fn superseded_by(
    executable: &std::path::Path,
    root: &std::path::Path,
) -> bool {
    let store = std::path::Path::new("/nix/store");
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    let (Ok(executable_rel), Ok(root_rel)) =
        (executable.strip_prefix(store), root.strip_prefix(store))
    else {
        return false;
    };
    let mut executable_parts = executable_rel.components();
    let mut root_parts = root_rel.components();
    let (Some(executable_entry), Some(root_entry)) =
        (executable_parts.next(), root_parts.next())
    else {
        return false;
    };
    if executable_entry == root_entry
        || store_package_name(executable_entry.as_os_str()).is_none_or(
            |name| store_package_name(root_entry.as_os_str()) != Some(name),
        )
    {
        return false;
    }
    let inner = executable_parts.as_path();
    let root_inner = root_parts.as_path();
    !inner.as_os_str().is_empty()
        && inner.starts_with(root_inner)
        && store.join(root_entry).join(inner).is_file()
}

/// The package name of a store entry, without its hash and version:
/// `<hash>-firefox-149.0.1` -> `firefox`.
#[cfg(target_os = "linux")]
fn store_package_name(entry: &std::ffi::OsStr) -> Option<&str> {
    let (_hash, name) = entry.to_str()?.split_once('-')?;
    let end = name
        .match_indices('-')
        .find(|(i, _)| {
            name[i + 1..].starts_with(|c: char| c.is_ascii_digit())
        })
        .map_or(name.len(), |(i, _)| i);
    Some(&name[..end]).filter(|name| !name.is_empty())
}

#[cfg(not(target_os = "linux"))]
fn authorize(_arguments: &[std::ffi::OsString]) -> anyhow::Result<()> {
    anyhow::bail!("Native messaging browser allowlist requires Linux")
}

// The account's fingerprint-confirmed Secret Service enrollment (`rbw
// security unlock enroll --keyring --fingerprint`), if any. Linux only.
fn fingerprint_unlock(
    config: &rbw::config::Config,
    account: Option<&str>,
) -> Option<rbw::config::SecretServiceUnlock> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    config
        .account(account)
        .ok()?
        .unlock
        .secret_service
        .filter(|desktop| desktop.fingerprint)
}

// Work to do once the response to the current request is on the wire, so a
// sign-in isn't held up by the vault synchronization that follows it. The
// host handles one request at a time, so this runs before the next one.
thread_local! {
    static AFTER_RESPONSE: std::cell::RefCell<Vec<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub fn after_response(work: impl FnOnce() + 'static) {
    AFTER_RESPONSE.with(|queue| queue.borrow_mut().push(Box::new(work)));
}

fn run_after_response() {
    let work = AFTER_RESPONSE.with(std::cell::RefCell::take);
    for work in work {
        work();
    }
}

// Set when the vault could not be synchronized after a passkey sign-in (the
// origin and when); the status reports it until a sync succeeds.
static PASSKEY_SYNC_FAILURE: std::sync::Mutex<Option<(String, u64)>> =
    std::sync::Mutex::new(None);

pub fn set_passkey_sync_failure(origin: Option<&str>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    if let Ok(mut failure) = PASSKEY_SYNC_FAILURE.lock() {
        *failure = origin.map(|origin| (origin.to_owned(), now));
    }
}

fn passkey_sync_failure() -> Value {
    PASSKEY_SYNC_FAILURE
        .lock()
        .ok()
        .and_then(|failure| failure.clone())
        .map_or(
            Value::Null,
            |(origin, time)| json!({"origin": origin, "time": time}),
        )
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
                let fingerprint = matches!(
                    &request.operation,
                    Operation::Unlock {
                        fingerprint: true,
                        ..
                    }
                );
                let moving =
                    matches!(&request.operation, Operation::Move { .. });
                // Backend errors can contain vault data; never forward them.
                dispatch(request, &mut attachments).map_or_else(
                    |error| json!({"id": id, "error": if commands::exit_status(&error) == 2 { "The server write succeeded, but synchronization failed. Sync and inspect your vault before retrying to avoid duplicates." } else if moving { "Could not move the item; it was not deleted. Both accounts must be unlocked, and the other account must not already have an item with the same name and username." } else if fingerprint { "Fingerprint unlock failed. Scan again, or unlock with your master password." } else if unlocking { "Could not unlock this account. Check your master password and account configuration." } else { "Operation failed. Unlock this account or sync your vault, then try again." }}),
                    |result| json!({"id": id, "result": result}),
                )
            }
            Err(_) => json!({"id": null, "error": "Invalid browser request"}),
        };
        write_response(&mut output, &response)?;
        run_after_response();
    }
}

// The accounts a merged request covers: the ones the user picked in the
// extension (even if `exclude_from` would keep them out of the CLI's
// search), or else the ones `rbw search` covers.
fn scoped_states(
    scope: Option<&[String]>,
) -> anyhow::Result<Vec<commands::AccountState>> {
    let mut states =
        commands::account_states(rbw::config::ExcludeContext::Search)?;
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        states.retain(|state| scope.contains(&state.name));
        for state in &mut states {
            state.excluded = false;
        }
    }
    Ok(states)
}

// With several accounts configured, a request that names no account works
// on all of them ("All accounts" in the extension): searches merge the
// accounts `rbw search` would cover (passively: only unlocked ones), and a
// request about one item goes to the account that holds it.
fn merged_mode(account: Option<&String>) -> anyhow::Result<bool> {
    Ok(
        account.is_none()
            && rbw::config::Config::load()?.accounts().len() > 1,
    )
}

// The item a request is about, if any (new items have none).
fn request_item(operation: &Operation) -> Option<&str> {
    match operation {
        Operation::Credential { item, .. }
        | Operation::Totp { item }
        | Operation::Copy { item, .. }
        | Operation::PasskeyGet { item, .. }
        | Operation::PasskeyVerify { item, .. }
        | Operation::Detail { item, .. }
        | Operation::Mutate { item, .. }
        | Operation::SetCollections { item, .. }
        | Operation::AttachmentDownload { item, .. }
        | Operation::AttachmentDelete { item, .. }
        | Operation::UploadBegin { item, .. }
        | Operation::Move { item, .. } => {
            Some(item.as_str()).filter(|item| !item.is_empty())
        }
        Operation::Save { item, .. }
        | Operation::PasskeyCreate { item, .. } => item.as_deref(),
        _ => None,
    }
}

// The configured account whose local vault holds `item`, if any. Reads only
// the local databases (entry ids are not encrypted), so it works for locked
// accounts too; the request itself then fails as usual if it's locked.
fn item_owner(item: &str) -> anyhow::Result<Option<String>> {
    let config = rbw::config::Config::load()?;
    let mut owner = None;
    for account in config.accounts() {
        actions::set_active_account(Some(account.name.clone()))?;
        if commands::load_db()
            .is_ok_and(|db| db.entries.iter().any(|entry| entry.id == item))
        {
            owner = Some(account.name);
            break;
        }
    }
    actions::set_active_account(None)?;
    Ok(owner)
}

fn lookup_copy(operation: &Operation) -> anyhow::Result<Operation> {
    Ok(match operation {
        Operation::Search {
            query,
            url,
            site_only,
            kind,
            folder,
            collection,
            view,
            match_default,
        } => Operation::Search {
            query: query.clone(),
            url: url.clone(),
            site_only: *site_only,
            kind: kind.clone(),
            folder: folder.clone(),
            collection: collection.clone(),
            view: view.clone(),
            match_default: match_default.clone(),
        },
        Operation::PasskeyCandidates { origin, options } => {
            Operation::PasskeyCandidates {
                origin: origin.clone(),
                options: options.clone(),
            }
        }
        _ => anyhow::bail!("not a lookup"),
    })
}

// Tags each element of a result array with the account it came from.
fn tag_account(account: &str, values: &Value) -> Vec<Value> {
    values
        .as_array()
        .into_iter()
        .flatten()
        .map(|value| {
            let mut value = value.clone();
            value["account"] = json!(account);
            value
        })
        .collect()
}

// Runs a search or passkey lookup in every unlocked account the CLI's own
// search would cover, tagging each result with its account.
fn merged_lookup(
    operation: &Operation,
    scope: Option<&[String]>,
    transfers: &mut attachments::Transfers,
) -> anyhow::Result<Value> {
    let states = scoped_states(scope)?;
    let mut parts = Vec::new();
    for state in states.iter().filter(|s| s.unlocked && !s.excluded) {
        let request = Request {
            id: 0,
            accounts: None,
            account: Some(state.name.clone()),
            operation: lookup_copy(operation)?,
        };
        match dispatch(request, transfers) {
            Ok(value) => parts.push((state.name.clone(), value)),
            Err(error) => {
                log::warn!("skipping account '{}': {error:#}", state.name);
            }
        }
    }
    actions::set_active_account(None)?;
    // Nothing unlocked: an empty list (the status says what is locked), but a
    // passkey lookup answers as the first account would (locked).
    if parts.is_empty() && matches!(operation, Operation::Search { .. }) {
        return Ok(
            json!({"items": [], "limit": 200, "total": 0, "folders": [], "collections": []}),
        );
    }
    let Some((_, first)) = parts.first() else {
        let request = Request {
            id: 0,
            accounts: None,
            account: Some(match states.first() {
                Some(state) => state.name.clone(),
                None => rbw::config::Config::load()?.primary_account_name(),
            }),
            operation: lookup_copy(operation)?,
        };
        return dispatch(request, transfers);
    };
    let mut merged = first.clone();
    let mut items: Vec<Value> = parts
        .iter()
        .flat_map(|(account, value)| tag_account(account, &value["items"]))
        .collect();
    if matches!(operation, Operation::Search { .. }) {
        items.sort_by_key(|v| {
            (
                !v["matched"].as_bool().unwrap_or(false),
                !v["favorite"].as_bool().unwrap_or(false),
                v["name"].as_str().unwrap_or_default().to_lowercase(),
            )
        });
        let total: u64 = parts
            .iter()
            .map(|(_, v)| v["total"].as_u64().unwrap_or(0))
            .sum();
        items.truncate(200);
        let folders: std::collections::BTreeSet<String> = parts
            .iter()
            .filter_map(|(_, v)| v["folders"].as_array())
            .flatten()
            .filter_map(|f| f.as_str().map(str::to_string))
            .collect();
        let collections: Vec<Value> = parts
            .iter()
            .flat_map(|(account, v)| tag_account(account, &v["collections"]))
            .collect();
        merged["total"] = json!(total);
        merged["folders"] = json!(folders);
        merged["collections"] = json!(collections);
    }
    merged["items"] = json!(items);
    Ok(merged)
}

// The colors set in the rbw config (`rbw account set --color`), by account.
fn account_colors(config: &rbw::config::Config) -> Value {
    json!(config
        .accounts()
        .iter()
        .filter_map(|a| a.color.as_ref().map(|c| (a.name.clone(), c.clone())))
        .collect::<std::collections::BTreeMap<_, _>>())
}

// The running agent's version, when it isn't this build's: an agent started
// before an upgrade keeps running, and the host can't use it, so the
// extension says so (and offers a restart) instead of just "locked".
fn stale_agent(version: Option<u32>) -> Option<String> {
    version
        .filter(|v| *v != rbw::protocol::VERSION)
        .map(rbw::protocol::version_string)
}

// Status for the merged view: every configured account with its lock
// state, plus the single-account fields (for the primary) older code reads.
fn merged_status(
    scope: Option<&[String]>,
    transfers: &mut attachments::Transfers,
) -> anyhow::Result<Value> {
    let config = rbw::config::Config::load()?;
    let version = actions::version().ok();
    let stale = stale_agent(version);
    let agent_ok = version == Some(rbw::protocol::VERSION);
    let states = scoped_states(scope)?;
    let unlocked =
        agent_ok && states.iter().any(|s| s.unlocked && !s.excluded);
    if !unlocked {
        transfers.clear();
    }
    let primary = config.primary_account_name();
    let fingerprint = fingerprint_unlock(&config, Some(&primary)).is_some();
    Ok(json!({"unlocked": unlocked,
        "merged": true,
        "staleAgent": stale,
        "hostVersion": env!("CARGO_PKG_VERSION"),
        "fingerprint": fingerprint,
        "fingerprint_auto_start": fingerprint && config.browser.fingerprint_auto_start,
        "accounts": config.accounts().iter().map(|a| &a.name).collect::<Vec<_>>(),
        "accountColors": account_colors(&config),
        "passkeySyncFailure": passkey_sync_failure(),
        "accountStates": states.iter().map(|s| json!({"name": s.name, "primary": s.primary, "unlocked": agent_ok && s.unlocked, "excluded": s.excluded, "policy": s.policy, "fingerprint": fingerprint_unlock(&config, Some(&s.name)).is_some()})).collect::<Vec<_>>(),
        "primary": primary}))
}

fn dispatch(
    mut request: Request,
    transfers: &mut attachments::Transfers,
) -> anyhow::Result<Value> {
    transfers.prune();
    if merged_mode(request.account.as_ref())? {
        match &request.operation {
            Operation::Status => {
                return merged_status(request.accounts.as_deref(), transfers);
            }
            Operation::Search { .. }
            | Operation::PasskeyCandidates { .. } => {
                return merged_lookup(
                    &request.operation,
                    request.accounts.as_deref(),
                    transfers,
                );
            }
            // "Lock vault" in the merged view locks every account it covers.
            Operation::Lock => {
                transfers.clear();
                if let Some(scope) =
                    request.accounts.as_deref().filter(|a| !a.is_empty())
                {
                    for name in scope {
                        actions::set_active_account(Some(name.clone()))?;
                        commands::lock(false)?;
                    }
                    actions::set_active_account(None)?;
                } else {
                    actions::set_active_account(None)?;
                    commands::lock(true)?;
                }
                return Ok(json!(true));
            }
            // Likewise "Sync": every unlocked account in scope.
            Operation::Sync => {
                for state in scoped_states(request.accounts.as_deref())?
                    .iter()
                    .filter(|s| s.unlocked && !s.excluded)
                {
                    actions::set_active_account(Some(state.name.clone()))?;
                    commands::sync(false)?;
                }
                actions::set_active_account(None)?;
                set_passkey_sync_failure(None);
                return Ok(json!(true));
            }
            Operation::UploadChunk { token, .. }
            | Operation::UploadFinish { token }
            | Operation::UploadCancel { token } => {
                if let Some(account) = transfers.upload_account(token) {
                    request.account = Some(account);
                }
            }
            operation => {
                if let Some(item) = request_item(operation) {
                    if let Some(owner) = item_owner(item)? {
                        request.account = Some(owner);
                    }
                }
            }
        }
    }
    actions::set_active_account(request.account)?;
    match request.operation {
        Operation::Status => {
            let config = rbw::config::Config::load()?;
            let version = actions::version().ok();
            let stale = stale_agent(version);
            let unlocked = version == Some(rbw::protocol::VERSION)
                && actions::unlocked().is_ok();
            if !unlocked {
                transfers.clear();
            }
            let fingerprint = fingerprint_unlock(
                &config,
                actions::current_account().as_deref(),
            )
            .is_some();
            Ok(json!({"unlocked": unlocked,
                "staleAgent": stale,
                "hostVersion": env!("CARGO_PKG_VERSION"),
                "fingerprint": fingerprint,
                "fingerprint_auto_start": fingerprint && config.browser.fingerprint_auto_start,
                "accounts": config.accounts().iter().map(|a| &a.name).collect::<Vec<_>>(),
                "accountColors": account_colors(&config),
                "passkeySyncFailure": passkey_sync_failure(),
                "primary": config.primary_account_name()}))
        }
        Operation::Unlock {
            password,
            fingerprint: true,
        } => {
            ensure!(
                password.is_none(),
                "fingerprint unlock takes no password"
            );
            let config = rbw::config::Config::load()?;
            let desktop = fingerprint_unlock(
                &config,
                actions::current_account().as_deref(),
            )
            .context("fingerprint unlock is not enrolled")?;
            // Scans (up to three tries, 60 seconds) and then reads the
            // enrolled password from Secret Service. The extension cancels
            // by closing the native port, which ends this process and lets
            // fprintd release the reader.
            let password = rbw::desktop::unlock(&desktop)?;
            commands::unlock(Some(password), None)?;
            Ok(json!(true))
        }
        Operation::Unlock { password, .. } => {
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
        Operation::RestartAgent => {
            transfers.clear();
            commands::restart_agent()?;
            Ok(json!(true))
        }
        Operation::Move { item, to } => transfer::move_item(&item, &to),
        Operation::Sync => {
            commands::sync(false)?;
            set_passkey_sync_failure(None);
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
                                if commands::skip_insecure_uri(url, &value) {
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
                            "all" => true,
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
                        totp,
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
                        "password": password.as_deref().map(|s| decrypt(entry, s)).transpose()?,
                        // Only whether there is one: the extension asks the
                        // native host to copy the current code (`copy`).
                        "hasTotp": totp.is_some()}),
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
                } => passkeys::authenticate_synced(
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
                Operation::Detail { item, trashed } => {
                    let entry = if trashed {
                        db.entries
                            .iter()
                            .find(|e| e.id == item && e.deleted)
                            .context("item unavailable")?
                    } else {
                        entry(&db, &item)?
                    };
                    let mut result = detail(entry)?;
                    let options = db.collections.iter().filter(|c| Some(&c.org_id) == entry.org_id.as_ref()).map(|c| Ok(json!({"id": c.id, "name": actions::decrypt(&c.name, None, Some(&c.org_id))?}))).collect::<anyhow::Result<Vec<_>>>()?;
                    result["collection_options"] = json!(options);
                    result["collection_ids"] = json!(entry.collection_ids);
                    result["account"] = json!(actions::current_account()
                        .unwrap_or_else(|| rbw::config::Config::load()
                            .map(|c| c.primary_account_name())
                            .unwrap_or_default()));
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
                        // Only from the trash, like the Bitwarden clients.
                        "purge" => {
                            ensure!(entry.deleted, "not in the trash");
                            let (tokens, ()) =
                                rbw::actions::delete_permanently(
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
            "all" => true,
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

// The extension's override, else rbw's configured `defaultUriMatch`, read per
// request so config changes apply without restarting the browser.
fn uri_match_default(
    value: Option<&str>,
) -> anyhow::Result<rbw::config::UriMatchDefault> {
    if let Some(value) = value {
        return commands::parse_uri_match_default(value);
    }
    Ok(rbw::config::Config::load()
        .map(|config| config.default_uri_match)
        .unwrap_or_default())
}

fn matches(
    entry: &rbw::db::Entry,
    uris: &[rbw::db::Uri],
    url: &url::Url,
    default: rbw::config::UriMatchDefault,
) -> anyhow::Result<bool> {
    // Never transfer credentials from an HTTPS entry to an HTTP page, even
    // when the configured URI matching rule would otherwise permit it.
    for uri in uris {
        let value = decrypt(entry, &uri.uri)?;
        if commands::skip_insecure_uri(url, &value) {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{fingerprint_unlock, store_package_name, Operation, Request};

    #[test]
    fn unlock_requests_default_to_password() {
        let request: Request = serde_json::from_str(
            r#"{"id":1,"action":"unlock","password":"pw"}"#,
        )
        .unwrap();
        assert!(matches!(
            request.operation,
            Operation::Unlock {
                fingerprint: false,
                ..
            }
        ));
        let request: Request = serde_json::from_str(
            r#"{"id":2,"action":"unlock","password":null,"fingerprint":true}"#,
        )
        .unwrap();
        assert!(matches!(
            request.operation,
            Operation::Unlock {
                password: None,
                fingerprint: true
            }
        ));
    }

    #[test]
    fn fingerprint_unlock_needs_a_fingerprint_enrollment() {
        let config: rbw::config::Config = serde_json::from_str(
            r#"{"accounts":[
                {"name":"plain"},
                {"name":"keyring","unlock":{"secretService":{"id":"k"}}},
                {"name":"finger","unlock":{"secretService":{"id":"f","fingerprint":true}}}
            ],"browser":{"fingerprintAutoStart":true}}"#,
        )
        .unwrap();
        assert!(config.browser.fingerprint_auto_start);
        assert!(fingerprint_unlock(&config, Some("plain")).is_none());
        assert!(fingerprint_unlock(&config, Some("keyring")).is_none());
        assert_eq!(
            fingerprint_unlock(&config, Some("finger")).map(|d| d.id),
            Some("f".to_string())
        );
        assert!(fingerprint_unlock(&config, Some("missing")).is_none());
    }

    #[test]
    fn store_package_names() {
        fn name(s: &str) -> Option<&str> {
            store_package_name(std::ffi::OsStr::new(s))
        }
        assert_eq!(name("0abc-firefox-149.0.1"), Some("firefox"));
        assert_eq!(
            name("0abc-firefox-unwrapped-149.0"),
            Some("firefox-unwrapped")
        );
        assert_eq!(name("0abc-chromium-155.0.8059.79"), Some("chromium"));
        assert_eq!(name("0abc-firefox"), Some("firefox"));
        assert_eq!(name("0abc-"), None);
        assert_eq!(name("nohash"), None);
    }
}
