use super::*;

// What we know about one account without prompting for anything: config,
// whether the agent holds its keys, and a summary of the local database.
struct AccountStatus {
    name: String,
    primary: bool,
    color: Option<String>,
    email: Option<String>,
    server: Option<String>,
    unlocked: bool,
    unlock_policy: String,
    logged_in: bool,
    synced_at: Option<std::time::SystemTime>,
    items: Option<usize>,
    items_by_type: std::collections::BTreeMap<&'static str, usize>,
    trashed_items: usize,
    folders: usize,
    collections: usize,
    organizations: usize,
}

fn agent_pid_if_running() -> Option<u32> {
    let pid = std::fs::read_to_string(rbw::dirs::pid_file()).ok()?;
    let pid: i32 = pid.trim().parse().ok()?;
    let raw = rustix::process::Pid::from_raw(pid)?;
    rustix::process::test_kill_process(raw)
        .is_ok()
        .then_some(pid.unsigned_abs())
}

fn entry_type_name(data: &rbw::db::EntryData) -> &'static str {
    match data {
        rbw::db::EntryData::Login { .. } => "login",
        rbw::db::EntryData::Card { .. } => "card",
        rbw::db::EntryData::Identity { .. } => "identity",
        rbw::db::EntryData::SecureNote => "note",
        rbw::db::EntryData::SshKey { .. } => "ssh-key",
    }
}

fn account_status(
    account: &rbw::config::Account,
    primary: &str,
) -> AccountStatus {
    let email = account.email.as_ref().and_then(|v| v.resolve().ok());
    let server = account.server_name().ok();
    let unlocked = matches!(tui_account_unlocked(&account.name), Ok(true));
    let unlock_policy = serde_json::to_value(account.unlock.policy)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    let mut status = AccountStatus {
        name: account.name.clone(),
        primary: account.name == primary,
        color: account.color.clone(),
        email: email.clone(),
        server: server.clone(),
        unlocked,
        unlock_policy,
        logged_in: false,
        synced_at: None,
        items: None,
        items_by_type: std::collections::BTreeMap::new(),
        trashed_items: 0,
        folders: 0,
        collections: 0,
        organizations: 0,
    };

    let (Some(server), Some(email)) = (server, email) else {
        return status;
    };
    // The db file is only written by a login/sync, so its mtime is the
    // closest thing to a "last synced" time.
    status.synced_at = std::fs::metadata(rbw::dirs::db_file(&server, &email))
        .and_then(|m| m.modified())
        .ok();
    if let Ok(db) = rbw::db::Db::load(&server, &email) {
        status.logged_in = db.access_token.is_some();
        status.items = Some(db.entries.len());
        let mut folders = std::collections::HashSet::new();
        for entry in &db.entries {
            *status
                .items_by_type
                .entry(entry_type_name(&entry.data))
                .or_default() += 1;
            if entry.deleted {
                status.trashed_items += 1;
            }
            if let Some(folder) = &entry.folder_id {
                folders.insert(folder.clone());
            }
        }
        status.folders = folders.len();
        status.collections = db.collections.len();
        status.organizations = db.organizations.len();
    }
    status
}

// The account name in bold, in the account's configured `#rrggbb` color
// (truecolor) when it has a valid one.
fn account_name(account: &AccountStatus, c: bool) -> String {
    let rgb = account
        .color
        .as_deref()
        .filter(|color| rbw::config::is_hex_color(color))
        .and_then(|color| {
            let channel = |i: usize| u8::from_str_radix(&color[i..i + 2], 16);
            Some((channel(1).ok()?, channel(3).ok()?, channel(5).ok()?))
        });
    match rgb {
        Some((r, g, b)) => {
            style::paint_raw(&account.name, &format!("1;38;2;{r};{g};{b}"), c)
        }
        None => style::name(&account.name, c),
    }
}

fn ago(time: std::time::SystemTime) -> String {
    let elapsed = time.elapsed().unwrap_or_default();
    let elapsed = std::time::Duration::from_secs(elapsed.as_secs());
    format!("{} ago", humantime::format_duration(elapsed))
}

pub fn status(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let primary = config.primary_account_name();
    let pid = agent_pid_if_running();
    let mut accounts = config
        .accounts()
        .iter()
        .map(|account| account_status(account, &primary))
        .collect::<Vec<_>>();
    // Primary first; the sort is stable, so the rest keep their config order.
    accounts.sort_by_key(|a| !a.primary);

    if json {
        let accounts = accounts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "primary": a.primary,
                    "color": a.color,
                    "email": a.email,
                    "server": a.server,
                    "unlocked": a.unlocked,
                    "unlock_policy": a.unlock_policy,
                    "logged_in": a.logged_in,
                    "last_synced": a.synced_at.map(|t| {
                        humantime::format_rfc3339_seconds(t).to_string()
                    }),
                    "items": a.items,
                    "items_by_type": a.items_by_type,
                    "trashed_items": a.trashed_items,
                    "folders": a.folders,
                    "collections": a.collections,
                    "organizations": a.organizations,
                })
            })
            .collect::<Vec<_>>();
        let out = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "profile": rbw::dirs::profile(),
            "config_file": rbw::dirs::config_file(),
            "agent": {
                "running": pid.is_some(),
                "pid": pid,
                "socket": rbw::dirs::socket_file(),
                "lock_timeout": config.agent.lock_timeout,
                "sync_interval": config.agent.sync_interval,
            },
            "primary_account": primary,
            "accounts": accounts,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let c = stdout_supports_color();
    // Labels are padded before they are painted so the escape codes don't
    // throw off the alignment.
    let row = |indent: &str, label: &str, value: String| {
        println!(
            "{indent}{} {value}",
            style::label(&format!("{label:<14}"), c)
        );
    };
    let na = || style::empty("N/A", c);
    let duration = |secs: u64| {
        humantime::format_duration(std::time::Duration::from_secs(secs))
            .to_string()
    };

    println!(
        "{} {}",
        style::name("rbw", c),
        style::dim(env!("CARGO_PKG_VERSION"), c)
    );
    row("", "profile:", rbw::dirs::profile());
    row(
        "",
        "config:",
        style::uri(&rbw::dirs::config_file().display().to_string(), c),
    );
    row(
        "",
        "agent:",
        pid.map_or_else(
            || style::danger("not running", c),
            |pid| {
                format!(
                    "{} {}",
                    style::success("running", c),
                    style::dim(&format!("(pid {pid})"), c)
                )
            },
        ),
    );
    row(
        "",
        "socket:",
        style::uri(&rbw::dirs::socket_file().display().to_string(), c),
    );
    row("", "lock timeout:", duration(config.agent.lock_timeout));
    row(
        "",
        "sync interval:",
        if config.agent.sync_interval == 0 {
            style::empty("disabled", c)
        } else {
            duration(config.agent.sync_interval)
        },
    );

    if accounts.is_empty() {
        println!("\n{}", style::empty("no accounts configured", c));
        return Ok(());
    }
    for a in &accounts {
        println!();
        let marker = if a.primary {
            format!(" {}", style::dim("(primary)", c))
        } else {
            String::new()
        };
        println!("{}{marker}", account_name(a, c));
        let i = "  ";
        row(
            i,
            "state:",
            if a.unlocked {
                style::success("unlocked", c)
            } else {
                style::danger("locked", c)
            },
        );
        row(
            i,
            "email:",
            a.email.as_deref().map_or_else(na, |e| style::user(e, c)),
        );
        row(
            i,
            "server:",
            a.server.as_deref().map_or_else(na, |s| style::uri(s, c)),
        );
        row(i, "unlock:", a.unlock_policy.clone());
        row(
            i,
            "logged in:",
            if a.logged_in {
                style::new_val("yes", c)
            } else {
                style::warning("no", c)
            },
        );
        row(
            i,
            "last synced:",
            a.synced_at.map_or_else(
                || style::warning("never", c),
                |t| style::dim(&ago(t), c),
            ),
        );
        let Some(items) = a.items else {
            continue;
        };
        let by_type = a
            .items_by_type
            .iter()
            .map(|(ty, n)| format!("{n} {}", style::entry_type(ty, c)))
            .collect::<Vec<_>>()
            .join(", ");
        let by_type = if by_type.is_empty() {
            String::new()
        } else {
            format!(" ({by_type})")
        };
        let trashed = if a.trashed_items > 0 {
            format!(
                ", {}",
                style::old_val(&format!("{} in trash", a.trashed_items), c)
            )
        } else {
            String::new()
        };
        row(
            i,
            "items:",
            format!(
                "{}{by_type}{trashed}",
                style::name(&items.to_string(), c)
            ),
        );
        row(i, "folders:", style::folder(&a.folders.to_string(), c));
        row(i, "collections:", a.collections.to_string());
        row(i, "orgs:", a.organizations.to_string());
    }
    Ok(())
}
