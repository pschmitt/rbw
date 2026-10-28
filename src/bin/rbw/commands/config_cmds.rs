use super::*;

pub fn config_show(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if json {
        write_json_pretty(&config, "failed to write config to stdout")
    } else {
        write_yaml_pretty(&config, "failed to write config to stdout")
    }
}

// Print a single setting's effective value: account-scoped keys resolve
// through the primary account (matching what rbw actually uses), global
// preferences come straight off the config.
pub fn config_get(key: &str) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let primary = config.primary();
    let resolve = |v: Option<rbw::config::SecretString>| -> anyhow::Result<Option<String>> {
        Ok(v.map(|s| s.resolve()).transpose()?)
    };
    let value = match key {
        "email" => resolve(primary.email)?,
        "ssoId" => resolve(primary.sso_id)?,
        "baseUrl" => resolve(primary.base_url)?,
        "identityUrl" => resolve(primary.identity_url)?,
        "uiUrl" => resolve(primary.ui_url)?,
        "notificationsUrl" => resolve(primary.notifications_url)?,
        "clientCertPath" => {
            primary.client_cert_path.map(|p| p.display().to_string())
        }
        "browser.clients" => {
            Some(serde_json::to_string(&config.browser.clients)?)
        }
        "primaryAccount" => config.primary_account,
        "agent.lockTimeout" => Some(config.agent.lock_timeout.to_string()),
        "agent.syncInterval" => Some(config.agent.sync_interval.to_string()),
        "unlockNoEcho" => Some(config.unlock_no_echo.to_string()),
        "unlockFingerprint" => {
            Some(config.unlock_fingerprint.as_str().to_string())
        }
        "unlockHideFingerprintNotice" => {
            Some(config.unlock_hide_fingerprint_notice.to_string())
        }
        "passkeyCounter" => Some(config.passkey_counter.to_string()),
        "unlockUi" => Some(config.unlock_ui.as_str().to_string()),
        "pinentry.command" => Some(config.pinentry.command),
        "pinentry.timeout" => Some(config.pinentry.timeout.to_string()),
        "termux.keyAlias" => config.termux.key_alias,
        "tui.lockTimeout" => Some(config.tui.lock_timeout.to_string()),
        "hide.archived" => Some(config.hide.archived.to_string()),
        "hide.trashed" => Some(config.hide.trashed.to_string()),
        "fzf.enabled" => Some(config.fzf.enabled.to_string()),
        "fzf.options" => config.fzf.options,
        "browser.fingerprintAutoStart" => {
            Some(config.browser.fingerprint_auto_start.to_string())
        }
        "passwordGen.length" => {
            config.password_gen.length.map(|length| length.to_string())
        }
        "passwordGen.noSymbols" => {
            Some(config.password_gen.no_symbols.to_string())
        }
        "passwordGen.onlyNumbers" => {
            Some(config.password_gen.only_numbers.to_string())
        }
        "passwordGen.nonconfusables" => {
            Some(config.password_gen.nonconfusables.to_string())
        }
        "passwordGen.diceware" => {
            Some(config.password_gen.diceware.to_string())
        }
        "clipboard" => {
            Some(clipboard_mechanism_str(config.clipboard).to_string())
        }
        "defaultUriMatch" => {
            Some(uri_match_default_str(config.default_uri_match).to_string())
        }
        "redact" => Some(config.redact.to_string()),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    };
    let Some(value) = value else {
        anyhow::bail!("{key} is not set");
    };
    println!("{value}");
    Ok(())
}

// Open the whole config.yaml as YAML in $EDITOR, the same
// serialize/edit/strip-comments/reparse shape as entry editing (see
// `edit`/`edit_full`). Mirrors `config_set`'s post-save `stop_agent` call --
// any field could plausibly affect already-cached agent state (accounts,
// urls, timeouts), so this always stops it rather than trying to detect
// exactly which fields changed.
pub fn config_edit() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let serialized = serde_yaml::to_string(&config)?;

    let help = "# Edit the YAML below. Lines starting with # are ignored.";
    let contents = rbw::edit::edit(&serialized, help, "yaml")?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let updated: rbw::config::Config =
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?;
    updated.save()?;

    // See `config_set`'s comment: not using lock() because we don't want to
    // require the agent to be running, and stop_agent() already handles
    // that gracefully.
    stop_agent()?;

    println!("updated config");
    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "browser.clients" => {
            config.browser.clients = serde_json::from_str(value)?;
        }
        "email" => {
            config.primary_mut().email = Some(value.to_string().into());
        }
        "ssoId" => {
            config.primary_mut().sso_id = Some(value.to_string().into());
        }
        "baseUrl" => {
            config.primary_mut().base_url = Some(value.to_string().into());
        }
        "identityUrl" => {
            config.primary_mut().identity_url =
                Some(value.to_string().into());
        }
        "uiUrl" => {
            config.primary_mut().ui_url = Some(value.to_string().into());
        }
        "notificationsUrl" => {
            config.primary_mut().notifications_url =
                Some(value.to_string().into());
        }
        "clientCertPath" => {
            config.primary_mut().client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "primaryAccount" => config.primary_account = Some(value.to_string()),
        "agent.lockTimeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for agent.lockTimeout")?;
            if timeout == 0 {
                log::error!("agent.lockTimeout must be greater than 0");
            } else {
                config.agent.lock_timeout = timeout;
            }
        }
        "agent.syncInterval" => {
            let interval = value
                .parse()
                .context("failed to parse value for agent.syncInterval")?;
            config.agent.sync_interval = interval;
        }
        "unlockNoEcho" => {
            config.unlock_no_echo = value
                .parse()
                .context("unlockNoEcho must be true or false")?;
        }
        "unlockFingerprint" => {
            config.unlock_fingerprint = match value {
                "auto" => rbw::config::UnlockFingerprint::Auto,
                "always" => rbw::config::UnlockFingerprint::Always,
                "never" => rbw::config::UnlockFingerprint::Never,
                _ => anyhow::bail!(
                    "unlockFingerprint must be auto, always, or never"
                ),
            }
        }
        "unlockHideFingerprintNotice" => {
            config.unlock_hide_fingerprint_notice = value.parse().context(
                "unlockHideFingerprintNotice must be true or false",
            )?;
        }
        "passkeyCounter" => {
            config.passkey_counter = value
                .parse()
                .context("passkeyCounter must be true or false")?;
        }
        "unlockUi" => {
            config.unlock_ui = match value {
                "auto" => rbw::config::UnlockUi::Auto,
                "terminal" => rbw::config::UnlockUi::Terminal,
                "gtk" => rbw::config::UnlockUi::Gtk,
                "pinentry" => rbw::config::UnlockUi::Pinentry,
                _ => anyhow::bail!(
                    "unlockUi must be auto, terminal, gtk, or pinentry"
                ),
            }
        }
        "pinentry.command" => config.pinentry.command = value.to_string(),
        "termux.keyAlias" => {
            config.termux.key_alias = Some(value.to_string());
        }
        "pinentry.timeout" => {
            config.pinentry.timeout = value
                .parse()
                .context("failed to parse value for pinentry.timeout")?;
        }
        "tui.lockTimeout" => {
            config.tui.lock_timeout = value
                .parse()
                .context("failed to parse value for tui.lockTimeout")?;
        }
        "hide.archived" => {
            config.hide.archived = value
                .parse()
                .context("failed to parse value for hide.archived")?;
        }
        "hide.trashed" => {
            config.hide.trashed = value
                .parse()
                .context("failed to parse value for hide.trashed")?;
        }
        "fzf.enabled" => {
            config.fzf.enabled =
                value.parse().context("fzf.enabled must be true or false")?;
        }
        "fzf.options" => config.fzf.options = Some(value.to_string()),
        "browser.fingerprintAutoStart" => {
            config.browser.fingerprint_auto_start = value.parse().context(
                "browser.fingerprintAutoStart must be true or false",
            )?;
        }
        "passwordGen.length" => {
            config.password_gen.length =
                Some(value.parse().context(
                    "failed to parse value for passwordGen.length",
                )?);
        }
        "passwordGen.noSymbols" => {
            config.password_gen.no_symbols = value
                .parse()
                .context("failed to parse value for passwordGen.noSymbols")?;
        }
        "passwordGen.onlyNumbers" => {
            config.password_gen.only_numbers = value.parse().context(
                "failed to parse value for passwordGen.onlyNumbers",
            )?;
        }
        "passwordGen.nonconfusables" => {
            config.password_gen.nonconfusables = value.parse().context(
                "failed to parse value for passwordGen.nonconfusables",
            )?;
        }
        "passwordGen.diceware" => {
            config.password_gen.diceware = value
                .parse()
                .context("failed to parse value for passwordGen.diceware")?;
        }
        "clipboard" => {
            config.clipboard = parse_clipboard_mechanism(value)?;
        }
        "defaultUriMatch" => {
            config.default_uri_match = parse_uri_match_default(value)?;
        }
        "redact" => {
            config.redact =
                value.parse().context("failed to parse value for redact")?;
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "browser.clients" => config.browser.clients.clear(),
        "email" => config.primary_mut().email = None,
        "ssoId" => config.primary_mut().sso_id = None,
        "baseUrl" => config.primary_mut().base_url = None,
        "identityUrl" => config.primary_mut().identity_url = None,
        "uiUrl" => config.primary_mut().ui_url = None,
        "notificationsUrl" => config.primary_mut().notifications_url = None,
        "clientCertPath" => config.primary_mut().client_cert_path = None,
        "primaryAccount" => config.primary_account = None,
        "agent.lockTimeout" => {
            config.agent.lock_timeout = rbw::config::default_lock_timeout();
        }
        "agent.syncInterval" => {
            config.agent.sync_interval = rbw::config::default_sync_interval();
        }
        "unlockNoEcho" => config.unlock_no_echo = false,
        "unlockFingerprint" => {
            config.unlock_fingerprint = rbw::config::UnlockFingerprint::Auto;
        }
        "unlockHideFingerprintNotice" => {
            config.unlock_hide_fingerprint_notice = false;
        }
        "passkeyCounter" => config.passkey_counter = false,
        "unlockUi" => config.unlock_ui = rbw::config::UnlockUi::Auto,
        "pinentry.command" => {
            config.pinentry.command = rbw::config::default_pinentry();
        }
        "termux.keyAlias" => config.termux.key_alias = None,
        "fzf.enabled" => config.fzf.enabled = false,
        "fzf.options" => config.fzf.options = None,
        "browser.fingerprintAutoStart" => {
            config.browser.fingerprint_auto_start = false;
        }
        "pinentry.timeout" => {
            config.pinentry.timeout = rbw::config::default_pinentry_timeout();
        }
        "tui.lockTimeout" => {
            config.tui.lock_timeout = rbw::config::default_tui_lock_timeout();
        }
        "hide.archived" => {
            config.hide.archived = rbw::config::default_hide_archived();
        }
        "hide.trashed" => {
            config.hide.trashed = rbw::config::default_hide_trashed();
        }
        "passwordGen.length" => {
            config.password_gen.length = None;
        }
        "passwordGen.noSymbols" => {
            config.password_gen.no_symbols = false;
        }
        "passwordGen.onlyNumbers" => {
            config.password_gen.only_numbers = false;
        }
        "passwordGen.nonconfusables" => {
            config.password_gen.nonconfusables = false;
        }
        "passwordGen.diceware" => {
            config.password_gen.diceware = false;
        }
        "clipboard" => {
            config.clipboard = rbw::config::ClipboardMechanism::default();
        }
        "defaultUriMatch" => {
            config.default_uri_match =
                rbw::config::UriMatchDefault::default();
        }
        "redact" => {
            config.redact = false;
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}
