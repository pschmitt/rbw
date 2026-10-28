use super::*;

pub(super) fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

// `client_id`/`client_secret` come from `--stdin` (e.g. for a fully
// non-interactive first registration on a brand-new host); when absent,
// falls back to the normal interactive pinentry flow, exactly as before.
pub fn register(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register(client_id, client_secret)?;

    Ok(())
}

// `password`/`totp` come from `--stdin`/`--totp` (e.g. for a fully
// non-interactive first login on a brand-new host); when absent, falls back
// to `credential_source` resolution, then the normal interactive pinentry
// flow, exactly as before.
pub fn login(
    password: Option<String>,
    totp: Option<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    password.map_or_else(
        || login_resolving_credential_source(&mut Vec::new()),
        |password| crate::actions::login(Some(password), totp),
    )
}

pub fn unlock_pinentry() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login(None, None)?;
    crate::actions::unlock(None)
}

pub fn unlock(
    password: Option<String>,
    totp: Option<String>,
) -> anyhow::Result<()> {
    unlock_impl(password, totp, &mut Vec::new())
}

// Max hops to follow through `credential_source` chains before giving up.
// `Config::credential_source_chain` already rejects self-references and
// cycles up front (see `resolve_credential_source`), so this is only a
// defense-in-depth backstop against ever recursing unboundedly.
pub(super) const MAX_CREDENTIAL_SOURCE_DEPTH: usize = 16;

// Logs the current active account in, auto-supplying the password (and a
// fresh TOTP code for the 2FA challenge, if the linked entry has one) from
// `credential_source` when configured; falls back to the normal interactive
// pinentry flow otherwise. Shared by `login`, `unlock_impl`, and `sync`'s
// per-account login step, so every path that logs an account in benefits
// equally.
pub(super) fn login_resolving_credential_source(
    visited: &mut Vec<String>,
) -> anyhow::Result<()> {
    let (password, totp) = resolve_unlock_credentials(visited)?;
    crate::actions::login(password, totp)
}

// `visited` accumulates the chain of account names already being unlocked
// on the current call stack, so a `credential_source` chain can't recurse
// into itself even if the static cycle check somehow missed something.
pub(super) fn unlock_impl(
    password: Option<String>,
    totp: Option<String>,
    visited: &mut Vec<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    let force = UNLOCK_FORCE.load(std::sync::atomic::Ordering::Relaxed);
    if force {
        stop_running_unlock()?;
    }
    let _unlocking = lock_unlocking()?;
    if !force && password.is_none() && crate::actions::unlocked().is_ok() {
        return Ok(());
    }
    let (password, totp) = password.map_or_else(
        || resolve_unlock_credentials(visited),
        |password| Ok((Some(password), totp)),
    )?;
    #[cfg(target_os = "linux")]
    let password = match password {
        Some(password) => Some(password),
        None => resolve_password_dialog()?,
    };
    crate::actions::login(password.clone(), totp)?;
    crate::actions::unlock(password)?;
    // Several accounts can unlock in one run; say which one this was.
    match active_account() {
        Ok(account) => eprintln!("✓ Vault unlocked ({}).", account.name),
        Err(_) => eprintln!("✓ Vault unlocked."),
    }

    Ok(())
}

// Serializes unlocks of the active account across rbw processes. Unlocking
// an account makes the agent start `rbw unlock --credentials-only` for the
// accounts that follow it, which can overlap with the unlock that caused it
// (a follower's own unlock unlocks its source first); whoever comes second
// waits here, finds the account unlocked and has nothing left to do, instead
// of logging in a second time with the same TOTP code. The lock is released
// when the returned file is dropped.
pub(super) fn lock_unlocking() -> anyhow::Result<std::fs::File> {
    let path = unlocking_lock_path()?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .context("failed to lock the unlock of this account")?;
    // Record who holds the lock so `unlock --force` can replace it.
    file.set_len(0)?;
    std::io::Write::write_all(
        &mut file,
        std::process::id().to_string().as_bytes(),
    )?;
    Ok(file)
}

fn unlocking_lock_path() -> anyhow::Result<std::path::PathBuf> {
    let name = active_account()?.name;
    Ok(rbw::dirs::pid_file()
        .with_file_name(format!("unlock-{}.lock", name.replace('/', "_"))))
}

// Stops the `rbw unlock` that currently holds this account's unlock lock (and
// so owns its dialog), then waits for the lock to be released.
fn stop_running_unlock() -> anyhow::Result<()> {
    let Ok(text) = std::fs::read_to_string(unlocking_lock_path()?) else {
        return Ok(());
    };
    let Some(pid) = text
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid != 0)
        .filter(|pid| u32::try_from(*pid) != Ok(std::process::id()))
        .and_then(rustix::process::Pid::from_raw)
    else {
        return Ok(());
    };
    if rustix::process::test_kill_process(pid).is_ok() {
        eprintln!("Stopping the unlock already in progress (pid {pid:?}).");
        let _ =
            rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
    Ok(())
}

pub static UNLOCK_FORCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_unlock_force(force: bool) {
    UNLOCK_FORCE.store(force, std::sync::atomic::Ordering::Relaxed);
}

// Unlocks the active account from its `credential_source` alone and never
// prompts: with no source configured, a source that can't supply the
// password, or an account that is already unlocked, it does nothing.
// Returns whether the account was unlocked by this call.
pub fn unlock_from_credential_source() -> anyhow::Result<bool> {
    ensure_agent()?;
    if active_account()?.unlock.credentials.is_none() {
        return Ok(false);
    }
    let _unlocking = lock_unlocking()?;
    if crate::actions::unlocked().is_ok() {
        return Ok(false);
    }
    let Some((password, totp)) = resolve_credential_source(&mut Vec::new())
    else {
        return Ok(false);
    };
    crate::actions::login(Some(password.clone()), totp)?;
    crate::actions::unlock(Some(password))?;
    Ok(true)
}

// Explicit Termux configuration is fail-closed: a configured provider must
// work, rather than silently falling back to a weaker pinentry path.
thread_local! {
    pub(super) static UNLOCK_NO_ECHO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static UNLOCK_NO_FINGERPRINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static UNLOCK_UI_OVERRIDE: std::cell::Cell<Option<rbw::config::UnlockUi>> = const { std::cell::Cell::new(None) };
}

pub fn set_unlock_no_fingerprint(no_fingerprint: bool) {
    UNLOCK_NO_FINGERPRINT.with(|value| value.set(no_fingerprint));
}

// Whether this unlock skips the fingerprint scan and asks for the master
// password instead (`--no-fingerprint`, `RBW_NO_FINGERPRINT`, the
// `unlockFingerprint` setting, or an SSH session).
//
// `enrolled` says the account has a fingerprint unlock to skip: an SSH
// session then gets a note, so the missing fingerprint doesn't look like a
// failure.
fn skip_fingerprint(enrolled: bool) -> bool {
    let policy = rbw::config::Config::load()
        .map(|config| config.unlock_fingerprint)
        .unwrap_or_default();
    let bypass = UNLOCK_NO_FINGERPRINT.with(std::cell::Cell::get)
        || rbw::config::fingerprint_bypass_env();
    let remote = rbw::config::remote_session();
    if enrolled && policy.skipped_for_ssh(bypass, remote) {
        let color = stderr_supports_color();
        eprintln!(
            "{} SSH session: skipping the fingerprint unlock, enter the \
             master password (`rbw config set unlockFingerprint always` \
             scans anyway)",
            style::warning("note:", color)
        );
    }
    policy.skips_scan(bypass, remote)
}

pub fn set_unlock_ui(mode: Option<rbw::config::UnlockUi>, no_echo: bool) {
    UNLOCK_NO_ECHO.with(|value| value.set(no_echo));
    UNLOCK_UI_OVERRIDE.with(|value| value.set(mode));
}

pub(super) fn resolve_unlock_credentials(
    visited: &mut Vec<String>,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let account = active_account()?;
    if account.unlock.termux.is_some()
        && account.unlock.secret_service.is_some()
    {
        anyhow::bail!(
            "configure only one native unlock provider per account"
        );
    }
    let skip_scan = skip_fingerprint(
        account.unlock.termux.is_some()
            || account
                .unlock
                .secret_service
                .as_ref()
                .is_some_and(|desktop| desktop.fingerprint),
    );
    // Skipping the scan also skips the enrolled credential, which is only
    // released after it: the password prompt takes over.
    if let Some(desktop) = account
        .unlock
        .secret_service
        .as_ref()
        .filter(|desktop| !(desktop.fingerprint && skip_scan))
    {
        if desktop.fingerprint {
            let config = rbw::config::Config::load()?;
            let Ok(db) = load_db() else {
                // Initial login has no local verifier yet. Let the agent
                // authenticate the password through its normal pinentry flow.
                return Ok((None, None));
            };
            #[cfg(target_os = "linux")]
            let mode = rbw::unlock_ui::resolve(
                UNLOCK_UI_OVERRIDE
                    .with(std::cell::Cell::get)
                    .unwrap_or(config.unlock_ui),
            )?;
            #[cfg(not(target_os = "linux"))]
            let mode = rbw::config::UnlockUi::Pinentry;
            let password = if mode == rbw::config::UnlockUi::Pinentry {
                rbw::desktop::unlock_with_pinentry(
                    desktop, &config.pinentry, &crate::actions::get_environment(),
                    &format!("Unlock rbw account {}: enter the master password or scan a finger", account.name),
                    |password| verify_cached_password(&account, &db, password),
                )?
            } else {
                #[cfg(target_os = "linux")]
                {
                    let title = format!("Unlock account {}", account.name);
                    let desktop = desktop.clone();
                    rbw::desktop::unlock_with_dialog(
                        Some(&desktop),
                        rbw::unlock_ui::Options {
                            mode,
                            no_echo: config.unlock_no_echo
                                || UNLOCK_NO_ECHO.with(std::cell::Cell::get),
                            hide_fingerprint_notice: config
                                .unlock_hide_fingerprint_notice,
                        },
                        &title,
                        config.pinentry.timeout,
                        std::sync::Arc::new(move |password| {
                            verify_cached_password(&account, &db, password)
                        }),
                    )?
                }
                #[cfg(not(target_os = "linux"))]
                unreachable!()
            };
            return Ok((Some(password), None));
        }
        return Ok((Some(rbw::desktop::unlock(desktop)?), None));
    }
    if let Some(termux) = account.unlock.termux.filter(|_| !skip_scan) {
        let config = rbw::config::Config::load()?;
        let mut termux = termux;
        termux.key_alias = rbw::termux::resolve_key_alias(
            &config,
            &account.name,
            Some(&termux.key_alias),
        );
        return Ok((Some(rbw::termux::unlock(&termux)?), None));
    }
    if let Some((password, totp)) = resolve_credential_source(visited) {
        return Ok((Some(password), totp));
    }
    Ok((None, None))
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_password_dialog() -> anyhow::Result<Option<String>> {
    let account = active_account()?;
    if let Ok(db) = load_db() {
        let config = rbw::config::Config::load()?;
        let mode = rbw::unlock_ui::resolve(
            UNLOCK_UI_OVERRIDE
                .with(std::cell::Cell::get)
                .unwrap_or(config.unlock_ui),
        )?;
        if mode != rbw::config::UnlockUi::Pinentry {
            let title = format!("Unlock account {}", account.name);
            let password = rbw::desktop::unlock_with_dialog(
                None,
                rbw::unlock_ui::Options {
                    mode,
                    no_echo: config.unlock_no_echo
                        || UNLOCK_NO_ECHO.with(std::cell::Cell::get),
                    hide_fingerprint_notice: config
                        .unlock_hide_fingerprint_notice,
                },
                &title,
                config.pinentry.timeout,
                std::sync::Arc::new(move |password| {
                    verify_cached_password(&account, &db, password)
                }),
            )?;
            return Ok(Some(password));
        }
    }
    Ok(None)
}

// If the currently-active account has a `credential_source` configured,
// resolve its master password (and, if the linked entry has one, a current
// TOTP code generated from its secret -- for auto-answering a 2FA challenge
// during login) from the linked item in the source account's vault instead
// of prompting via pinentry: unlock the source account (recursively
// following its own `credential_source`, if it has one), find the linked
// item in its already-unlocked vault, and pull both fields from it.
// Non-Login entry types aren't handled specially -- resolution just fails
// for those.
//
// Returns `None` (falling back to the normal pinentry prompt) if there's no
// `credential_source` configured, or if resolution fails for any reason: a
// misconfigured link should never brick the account's ability to unlock at
// all.
pub(super) fn resolve_credential_source(
    visited: &mut Vec<String>,
) -> Option<(String, Option<String>)> {
    let target = crate::actions::current_account().or_else(|| {
        rbw::config::Config::load()
            .ok()
            .map(|c| c.primary_account_name())
    })?;

    if visited.contains(&target)
        || visited.len() >= MAX_CREDENTIAL_SOURCE_DEPTH
    {
        log::warn!(
            "credential_source chain reaches '{target}' again (or is too \
            deep); falling back to pinentry"
        );
        return None;
    }

    let config = rbw::config::Config::load().ok()?;
    if let Err(e) = config.credential_source_chain(&target) {
        log::warn!(
            "credential_source misconfigured for account '{target}': {e:#}; \
            falling back to pinentry"
        );
        return None;
    }

    let account = config.account(Some(&target)).ok()?;
    let source = account.unlock.credentials.as_ref()?;

    visited.push(target.clone());
    let result =
        resolve_from_credential_source(&target, &account, source, visited);
    visited.pop();

    // Whatever happened, route subsequent api calls back at the account we
    // were actually asked to unlock -- the caller still needs to send the
    // Login/Unlock request to it, not to (some ancestor of) the source.
    let _ = crate::actions::set_active_account(Some(target.clone()));

    match result {
        Ok((password, totp_secret)) => {
            // The linked entry's `totp` field is the raw secret, same as
            // what `rbw code` generates from -- the server needs a
            // computed current code, not the secret itself.
            let totp = totp_secret.and_then(|secret| {
                generate_totp(&secret)
                    .inspect_err(|e| {
                        log::warn!(
                            "failed to generate a TOTP code from the \
                            credential_source-resolved secret for account \
                            '{target}': {e:#}"
                        );
                    })
                    .ok()
            });
            Some((password, totp))
        }
        Err(e) => {
            log::warn!(
                "failed to resolve credential_source for account '{target}' \
                from account '{}': {e:#}; falling back to pinentry",
                source.account
            );
            None
        }
    }
}

// Unlocks `source.account` (recursing into its own `credential_source` if it
// has one) and resolves either the explicitly-configured source item or a
// unique URI match for `target_account`'s server in its vault.
pub(super) fn resolve_from_credential_source(
    target_name: &str,
    target_account: &rbw::config::Account,
    source: &rbw::config::CredentialSource,
    visited: &mut Vec<String>,
) -> anyhow::Result<(String, Option<String>)> {
    crate::actions::set_active_account(Some(source.account.clone()))?;
    // Skip re-authenticating (pinentry, Termux fingerprint, ...) when the
    // source account is already unlocked -- this runs on every credential
    // resolution, including ones for an `unlock: always` account whose
    // source was just unlocked moments earlier in the same call.
    if !active_account_unlocked() {
        unlock_impl(None, None, visited)?;
    }
    if !active_account_unlocked() {
        anyhow::bail!("source account '{}' did not unlock", source.account);
    }

    let db = load_db()?;
    let (decrypted, item_desc) = if let Some(item) = source.item.as_deref() {
        // parse_needle is Infallible -- it always returns Ok.
        let needle = parse_needle(item).unwrap();
        let (_, decrypted) = find_entry(
            &db,
            vec![needle],
            None,
            None,
            None,
            None,
            false,
            false,
        )
        .with_context(|| {
            format!("item '{item}' not found in account '{}'", source.account)
        })?;
        (decrypted, item.to_string())
    } else {
        let target_uri = target_account.ui_url()?;
        let needle = parse_needle(&target_uri).unwrap();
        let (_, decrypted) =
            find_entry(&db, vec![needle], None, None, None, None, false, false)
                .with_context(|| {
                    format!(
                        "no unique item in account '{}' matched '{target_name}' by URI ({target_uri})",
                        source.account
                    )
                })?;
        (decrypted, format!("URI match for {target_uri}"))
    };

    credential_source_login_fields(&decrypted, &item_desc, &source.account)
}

// Pulls the master password (and TOTP secret, if set) out of a decrypted
// credential_source item: a plain Login item's `password`/`totp` fields.
// Non-Login entry types aren't handled specially -- resolution just fails
// (falling back to pinentry) for anything else. An entry with no TOTP
// secret is fine (`totp: None`); only a missing password is fatal, since
// that's the one field every use of `credential_source` actually needs.
pub(super) fn credential_source_login_fields(
    decrypted: &DecryptedCipher,
    item: &str,
    account: &str,
) -> anyhow::Result<(String, Option<String>)> {
    match &decrypted.data {
        DecryptedData::Login {
            password: Some(password),
            totp,
            ..
        } => Ok((password.clone(), totp.clone())),
        DecryptedData::Login { password: None, .. } => Err(anyhow::anyhow!(
            "item '{item}' in account '{account}' has no password set"
        )),
        _ => Err(anyhow::anyhow!(
            "item '{item}' in account '{account}' is not a login item"
        )),
    }
}

// Unlocks every configured account per its `unlock` policy, same target
// selection as `list --all`/`sync --all`. `list_target_accounts` does the
// actual unlocking as a side effect of building its target list; this just
// reports what ended up unlocked.
pub fn unlock_all() -> anyhow::Result<()> {
    let target_accounts = list_target_accounts(
        true,
        rbw::config::ExcludeContext::Unlock,
        true,
    )?;
    let c = stdout_supports_color();
    for account in &target_accounts {
        eprintln!(
            "{} '{}'",
            style::success("unlocked", c),
            style::name(account, c),
        );
    }
    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // This is a passive check: don't start the agent or perform a separate
    // version handshake before asking it for the lock state.
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync(all: bool) -> anyhow::Result<()> {
    // Sync needs a running agent and a server login, but not an unlocked
    // vault. Keep that distinction intact: an ordinary sync must not prompt
    // for the master password just to refresh the local database.
    ensure_agent()?;
    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Sync, false)?;
    let c = stdout_supports_color();

    let mut failed = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        match login_resolving_credential_source(&mut Vec::new())
            .and_then(|()| crate::actions::sync())
        {
            Ok(()) => {
                eprintln!(
                    "{} '{}'",
                    style::success("synced", c),
                    style::name(account, c),
                );
            }
            Err(e) => {
                eprintln!(
                    "{} '{}': {e:#}",
                    style::warning("failed to sync", c),
                    style::name(account, c),
                );
                failed.push(account.clone());
            }
        }
    }

    if !failed.is_empty() {
        anyhow::bail!("failed to sync: {}", failed.join(", "));
    }
    Ok(())
}
