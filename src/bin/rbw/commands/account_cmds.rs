use super::*;

pub fn account_list() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let primary = config.primary_account_name();
    let mut accounts = config.accounts();
    if accounts.is_empty() {
        eprintln!("no accounts configured");
        return Ok(());
    }
    // The primary account first; the rest keep their configured order.
    accounts.sort_by_key(|account| account.name != primary);

    let columns = [
        TableColumn {
            header: "name",
            style: TableColumnStyle::Name,
        },
        TableColumn {
            header: "status",
            style: TableColumnStyle::Status,
        },
        TableColumn {
            header: "email",
            style: TableColumnStyle::User,
        },
        TableColumn {
            header: "server",
            style: TableColumnStyle::Folder,
        },
    ];

    let rows = accounts
        .iter()
        .map(|account| {
            let marker = if account.name == primary { "*" } else { "" };
            // Queries the agent over its usual IPC socket (same mechanism
            // as `rbw unlocked`/the TUI's lock poll) -- if the agent isn't
            // running at all, every account correctly shows as locked.
            // Leaves the process-global active-account pointer on the
            // last-checked account, which is harmless here since this
            // process exits right after printing (see
            // `tui_account_unlocked`'s own doc comment).
            let status =
                if matches!(tui_account_unlocked(&account.name), Ok(true)) {
                    "unlocked"
                } else {
                    "locked"
                };
            // Best-effort: an unreadable secret file (e.g. not yet
            // decrypted) shows as unset rather than failing the whole
            // listing. "N/A" matches `TableColumnStyle::User`'s existing
            // empty-value treatment in `colorize_table_cell`.
            let email = account
                .email
                .as_ref()
                .and_then(|v| v.resolve().ok())
                .unwrap_or_else(|| "N/A".to_string());
            let server = account
                .base_url
                .as_ref()
                .and_then(|v| v.resolve().ok())
                .unwrap_or_else(|| "https://vault.bitwarden.com".to_string());
            vec![
                format!("{}{marker}", account.name),
                status.to_string(),
                email,
                server,
            ]
        })
        .collect::<Vec<_>>();

    print_table(&columns, &rows, "")?;
    // These states come from whatever agent is running, which may predate
    // an upgrade (see `rbw status`).
    if let Ok(version) = crate::actions::version() {
        if !rbw::protocol::compatible(version) {
            eprintln!(
                "warning: rbw-agent is {}, not {}; run `rbw stop-agent` and unlock again",
                rbw::protocol::version_string(version),
                env!("CARGO_PKG_VERSION")
            );
        }
    }
    Ok(())
}

pub fn account_add(
    name: &str,
    email: Option<String>,
    base_url: Option<String>,
    sso_id: Option<String>,
    primary: bool,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' already exists");
    }
    let old_primary = config.primary_account_name();
    let first = config.accounts.is_empty();
    config.accounts.push(rbw::config::Account {
        name: name.to_string(),
        email: email.map(Into::into),
        sso_id: sso_id.map(Into::into),
        base_url: base_url.map(Into::into),
        identity_url: None,
        ui_url: None,
        notifications_url: None,
        client_cert_path: None,
        unlock: rbw::config::UnlockConfig::default(),
        exclude_from: Vec::new(),
        color: None,
    });
    // The first account is always primary; otherwise only if asked.
    if primary || first {
        config.primary_account = Some(name.to_string());
    }
    config.save()?;

    let now_primary = config.primary_account_name();
    if now_primary != old_primary {
        // Primary changed, so any keys the agent holds are for the wrong
        // account; drop them (mirrors `config set email`).
        stop_agent()?;
    }
    let suffix = if now_primary == name {
        " (primary)"
    } else {
        ""
    };
    println!("added account '{name}'{suffix}");
    Ok(())
}

pub fn account_remove(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let old_primary = config.primary_account_name();
    if config.accounts.iter().any(|account| {
        account.name == name && account.unlock.secret_service.is_some()
    }) {
        anyhow::bail!("remove this account's Secret Service credential first with rbw --account <name> secret-service remove");
    }
    let before = config.accounts.len();
    config.accounts.retain(|a| a.name != name);
    if config.accounts.len() == before {
        anyhow::bail!("account '{name}' not found");
    }
    if config.primary_account.as_deref() == Some(name) {
        config.primary_account =
            config.accounts.first().map(|a| a.name.clone());
    }
    config.save()?;

    if config.primary_account_name() != old_primary {
        stop_agent()?;
    }
    println!("removed account '{name}'");
    Ok(())
}

pub fn account_set_primary(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if !config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' not found");
    }
    let old_primary = config.primary_account_name();
    config.primary_account = Some(name.to_string());
    config.save()?;

    if old_primary != name {
        stop_agent()?;
    }
    println!("primary account is now '{name}'");
    Ok(())
}

// Change one or more per-account settings (currently `unlock.policy`,
// `exclude_from`, and `unlock.credentials` — see `rbw::config::Account`).
// Leaves a setting unchanged when its argument is `None`/empty/`false`.
#[allow(clippy::too_many_arguments)]
pub fn account_set(
    name: &str,
    unlock: Option<rbw::config::UnlockPolicy>,
    exclude_from: Vec<rbw::config::ExcludeContext>,
    clear_exclude_from: bool,
    credential_source_account: Option<String>,
    credential_source_item: Option<String>,
    clear_credential_source: bool,
    color: Option<String>,
    clear_color: bool,
) -> anyhow::Result<()> {
    if let Some(color) = &color {
        anyhow::ensure!(
            rbw::config::is_hex_color(color),
            "--color must be a #rrggbb hex color, got '{color}'"
        );
    }
    if unlock.is_none()
        && exclude_from.is_empty()
        && !clear_exclude_from
        && credential_source_account.is_none()
        && credential_source_item.is_none()
        && !clear_credential_source
        && color.is_none()
        && !clear_color
    {
        anyhow::bail!(
            "nothing to change: pass --unlock, --exclude-from (repeatable) \
            or --clear-exclude-from, --credential-source-account and \
            optionally --credential-source-item, or \
            --clear-credential-source, or --color/--clear-color"
        );
    }
    if clear_exclude_from && !exclude_from.is_empty() {
        anyhow::bail!(
            "--clear-exclude-from can't be combined with --exclude-from"
        );
    }
    if clear_credential_source
        && (credential_source_account.is_some()
            || credential_source_item.is_some())
    {
        anyhow::bail!(
            "--clear-credential-source can't be combined with \
            --credential-source-account/--credential-source-item"
        );
    }

    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    if let Some(unlock) = unlock {
        account.unlock.policy = unlock;
    }
    if clear_exclude_from {
        account.exclude_from = Vec::new();
    } else if !exclude_from.is_empty() {
        account.exclude_from = exclude_from;
    }
    if clear_color {
        account.color = None;
    } else if let Some(color) = color {
        account.color = Some(color.to_lowercase());
    }
    if clear_credential_source {
        account.unlock.credentials = None;
    } else if let Some(source_account) = credential_source_account {
        account.unlock.credentials = Some(rbw::config::CredentialSource {
            account: source_account,
            item: credential_source_item
                .filter(|item| !item.trim().is_empty()),
        });
    }

    // Reject a self-reference or a cycle before persisting, rather than
    // writing a config that would silently fall back to pinentry (or worse)
    // the next time this account tries to unlock.
    config.credential_source_chain(name)?;

    config.save()?;
    println!("updated account '{name}'");
    Ok(())
}
