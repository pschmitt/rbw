use super::*;

// Permanently, irrecoverably deletes every entry in the current account's
// personal vault via the server's single-call purge endpoint -- not a loop
// of individual deletes. Named distinctly from the existing `rbw purge`
// (which only clears the *local* db.json cache). Org-owned entries
// (assigned to a collection) aren't touched; purging those needs org
// owner/admin privileges and isn't what this is for (resetting a personal
// test account between imports).
pub fn purge_vault(
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let c = stdout_supports_color();
    let prompt = format!(
        "{} this will permanently delete EVERY entry in this account's \
         personal vault. This cannot be undone! Continue?",
        style_error("DANGER:", c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    crate::actions::purge_vault(password)?;

    eprintln!("{}", style::success("Vault purged.", c));

    Ok(())
}

// `rbw security`: master password, KDF and account key changes. Passwords
// are prompted for client-side via pinentry (like `secret_service_enroll`)
// rather than in the agent, so a new password can also replace a stored
// Secret Service unlock credential.

pub(super) fn security_getpin(
    title: &str,
    description: &str,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let config = rbw::config::Config::load()?;
    let response =
        tokio::runtime::Runtime::new()?.block_on(rbw::pinentry::getpin(
            &config.pinentry.command,
            title,
            description,
            None,
            &crate::actions::get_environment(),
            false,
            None,
            config.pinentry.timeout,
        ))?;
    String::from_utf8(response.password().to_vec())
        .map(zeroize::Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("password is not UTF-8"))
}

pub(super) fn security_current_password(
    account: &rbw::config::Account,
    password: Option<String>,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    password.map_or_else(
        || {
            security_getpin(
                "Current master password",
                &format!(
                    "Enter the master password of account {}",
                    account.name
                ),
            )
        },
        |password| Ok(zeroize::Zeroizing::new(password)),
    )
}

pub(super) fn security_confirm(
    account: &rbw::config::Account,
    what: &str,
    yes: bool,
) -> anyhow::Result<bool> {
    let c = stdout_supports_color();
    let prompt = format!(
        "{} this {what} of account '{}' on the server. Other sessions may \
         be logged out. Continue?",
        style::warning("WARNING:", c),
        account.name,
    );
    Ok(yes || confirm(&prompt)?)
}

// Gets the agent's session (which the server may have ended) and, after a
// key rotation, its unlocked state back, using the now-current password.
// Best effort: the change itself has already happened on the server.
pub(super) fn security_reauthenticate(password: &str, was_unlocked: bool) {
    let c = stdout_supports_color();
    if let Err(e) = crate::actions::login(Some(password.to_string()), None) {
        eprintln!(
            "{} could not log in again ({e:#}); run `rbw login`",
            style::warning("warning:", c)
        );
        return;
    }
    if was_unlocked && !active_account_unlocked() {
        if let Err(e) = crate::actions::unlock(Some(password.to_string())) {
            eprintln!(
                "{} could not unlock again ({e:#}); run `rbw unlock`",
                style::warning("warning:", c)
            );
        }
    }
}

// Changes the current account's master password, optionally rotating the
// account key in the same request. `passwords` (current, new) comes from
// `--stdin`.
pub fn security_change_password(
    yes: bool,
    passwords: Option<(String, String)>,
    hint: Option<String>,
    rotate_key: bool,
) -> anyhow::Result<()> {
    use zeroize::Zeroizing;

    ensure_agent()?;
    let account = active_account()?;
    let c = stdout_supports_color();

    let what = if rotate_key {
        "changes the master password and re-encrypts the vault"
    } else {
        "changes the master password"
    };
    if !security_confirm(&account, what, yes)? {
        return Ok(());
    }

    let (current, new) = if let Some((current, new)) = passwords {
        (Zeroizing::new(current), Zeroizing::new(new))
    } else {
        let current = security_current_password(&account, None)?;
        let new = security_getpin(
            "New master password",
            &format!(
                "Choose a new master password for account {} (at least \
                 {MIN_MASTER_PASSWORD_LEN} characters)",
                account.name
            ),
        )?;
        let confirmation = security_getpin(
            "Confirm new master password",
            "Enter the new master password again",
        )?;
        if new != confirmation {
            anyhow::bail!("new passwords do not match");
        }
        (current, new)
    };

    if new.chars().count() < MIN_MASTER_PASSWORD_LEN {
        anyhow::bail!(
            "new master password must be at least \
             {MIN_MASTER_PASSWORD_LEN} characters long"
        );
    }
    if new == current {
        anyhow::bail!("new master password is the same as the current one");
    }
    if hint.as_deref() == Some(new.as_str()) {
        anyhow::bail!("password hint can't be the password itself");
    }

    let was_unlocked = active_account_unlocked();
    crate::actions::change_password(
        current.to_string(),
        new.to_string(),
        hint,
        rotate_key,
    )?;
    eprintln!("{}", style::success("Master password changed.", c));

    // Everything below is best effort: the password has already changed on
    // the server, so failures only warn about what to fix by hand.
    let warn = |msg: &str| {
        eprintln!("{} {msg}", style::warning("warning:", c));
    };
    if let Some(provider) = &account.unlock.secret_service {
        match rbw::desktop::store(provider, new.as_bytes(), &account.name) {
            Ok(()) => {
                eprintln!("Updated the desktop unlock credential.");
            }
            Err(e) => warn(&format!(
                "could not update the desktop unlock credential \
                 ({e:#}); re-enroll with `rbw security unlock remove` and \
                 `rbw security unlock enroll`"
            )),
        }
    }
    if account.unlock.termux.is_some() {
        warn(
            "the Termux Keystore unlock bundle still holds the old \
             password; re-enroll with `rbw security unlock remove` and \
             `rbw security unlock enroll`",
        );
    }
    if let Some(source) = &account.unlock.credentials {
        warn(&format!(
            "credential_source still points at the old password; update \
             the item{} in account '{}'",
            source
                .item
                .as_deref()
                .map(|item| format!(" '{item}'"))
                .unwrap_or_default(),
            source.account,
        ));
    }
    security_reauthenticate(&new, was_unlocked);

    Ok(())
}

// Replaces the account key and re-encrypts the vault with it, keeping the
// master password.
pub fn security_rotate_key(
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    let account = active_account()?;
    if !security_confirm(
        &account,
        "replaces the account key and re-encrypts the vault",
        yes,
    )? {
        return Ok(());
    }
    let password = security_current_password(&account, password)?;

    let was_unlocked = active_account_unlocked();
    crate::actions::rotate_key(password.to_string())?;
    eprintln!(
        "{}",
        style::success("Account key rotated.", stdout_supports_color())
    );
    security_reauthenticate(&password, was_unlocked);

    Ok(())
}

#[derive(Clone, Copy)]
pub struct KdfArgs {
    pub kdf: Option<rbw::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

pub(super) fn kdf_name(kdf: rbw::api::KdfType) -> &'static str {
    match kdf {
        rbw::api::KdfType::Pbkdf2 => "pbkdf2",
        rbw::api::KdfType::Argon2id => "argon2id",
    }
}

// Shows the KDF settings, or changes them when any of `args` is set.
// Switching the algorithm starts from Bitwarden's defaults for it.
pub fn security_kdf(
    args: KdfArgs,
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    let db = load_db()?;
    let current = rbw::actions::KdfSettings {
        kdf: db.kdf.context("not logged in")?,
        iterations: db.iterations.context("not logged in")?,
        memory: db.memory,
        parallelism: db.parallelism,
    };

    if args.kdf.is_none()
        && args.iterations.is_none()
        && args.memory.is_none()
        && args.parallelism.is_none()
    {
        println!("kdf: {}", kdf_name(current.kdf));
        println!("iterations: {}", current.iterations);
        if let Some(memory) = current.memory {
            println!("memory: {memory} MiB");
        }
        if let Some(parallelism) = current.parallelism {
            println!("parallelism: {parallelism}");
        }
        return Ok(());
    }

    let kdf = args.kdf.unwrap_or(current.kdf);
    let mut new = if kdf == current.kdf {
        current
    } else {
        match kdf {
            rbw::api::KdfType::Pbkdf2 => rbw::actions::KdfSettings {
                kdf,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            },
            rbw::api::KdfType::Argon2id => rbw::actions::KdfSettings {
                kdf,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4),
            },
        }
    };
    if let Some(iterations) = args.iterations {
        new.iterations = iterations;
    }
    match kdf {
        rbw::api::KdfType::Pbkdf2 => {
            if args.memory.is_some() || args.parallelism.is_some() {
                anyhow::bail!(
                    "--memory and --parallelism only apply to argon2id"
                );
            }
            if new.iterations < 100_000 {
                anyhow::bail!("pbkdf2 needs at least 100000 iterations");
            }
        }
        rbw::api::KdfType::Argon2id => {
            if let Some(memory) = args.memory {
                new.memory = Some(memory);
            }
            if let Some(parallelism) = args.parallelism {
                new.parallelism = Some(parallelism);
            }
            if !(2..=10).contains(&new.iterations) {
                anyhow::bail!("argon2id iterations must be between 2 and 10");
            }
            if !new.memory.is_some_and(|m| (16..=1024).contains(&m)) {
                anyhow::bail!(
                    "argon2id memory must be between 16 and 1024 MiB"
                );
            }
            if !new.parallelism.is_some_and(|p| (1..=16).contains(&p)) {
                anyhow::bail!(
                    "argon2id parallelism must be between 1 and 16"
                );
            }
        }
    }
    if new == current {
        anyhow::bail!("these are already the current KDF settings");
    }

    ensure_agent()?;
    let account = active_account()?;
    if !security_confirm(&account, "changes the KDF settings", yes)? {
        return Ok(());
    }
    let password = security_current_password(&account, password)?;

    let was_unlocked = active_account_unlocked();
    crate::actions::change_kdf(password.to_string(), new)?;
    eprintln!(
        "{}",
        style::success("KDF settings changed.", stdout_supports_color())
    );
    security_reauthenticate(&password, was_unlocked);

    Ok(())
}

// Bitwarden's own clients refuse anything shorter.
pub(super) const MIN_MASTER_PASSWORD_LEN: usize = 12;
