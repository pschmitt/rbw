use super::*;

pub(super) fn verify_cached_password(
    account: &rbw::config::Account,
    db: &rbw::db::Db,
    password: &rbw::locked::Password,
) -> anyhow::Result<()> {
    rbw::actions::unlock(
        &account_email(account)?,
        password,
        db.kdf.context("missing vault KDF")?,
        db.iterations.context("missing vault KDF iterations")?,
        db.memory,
        db.parallelism,
        db.protected_key
            .as_deref()
            .context("missing protected vault key")?,
        db.protected_private_key
            .as_deref()
            .context("missing protected private key")?,
        &db.protected_org_keys,
    )
    .map(|_| ())
    .map_err(anyhow::Error::new)
}

// `rbw security unlock`: one front end for the native unlock providers.
// Only one can be configured per account, so `remove` and `status` act on
// whichever one is, and `enroll` picks one from the environment unless
// told which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeUnlock {
    Keyring,
    Termux,
}

// Termux exports TERMUX_VERSION to every shell it starts; its PREFIX lives
// in the app's data directory, as a fallback for stripped environments.
pub(super) fn running_on_termux() -> bool {
    std::env::var_os("TERMUX_VERSION").is_some()
        || std::env::var("PREFIX")
            .is_ok_and(|prefix| prefix.contains("/com.termux/"))
}

// How a desktop (non-Termux) enrollment stores its credential: see
// `rbw::config::SecretServiceUnlock`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DesktopStore {
    pub store: Option<rbw::config::UnlockStore>,
    pub secure_boot: bool,
    pub broker: bool,
}

impl DesktopStore {
    pub(super) fn is_set(self) -> bool {
        self.store.is_some() || self.secure_boot || self.broker
    }
}

pub fn native_unlock_enroll(
    provider: Option<NativeUnlock>,
    fingerprint: bool,
    validity: Option<u32>,
    desktop: DesktopStore,
) -> anyhow::Result<()> {
    let provider = provider.unwrap_or_else(|| {
        if desktop.is_set() {
            NativeUnlock::Keyring
        } else if running_on_termux() {
            NativeUnlock::Termux
        } else {
            NativeUnlock::Keyring
        }
    });
    match provider {
        NativeUnlock::Keyring => {
            if validity.is_some() {
                anyhow::bail!("--validity only applies to Termux unlock");
            }
            secret_service_enroll(fingerprint, desktop)
        }
        NativeUnlock::Termux => {
            if desktop.is_set() {
                anyhow::bail!(
                    "--store, --secure-boot and --broker only apply to \
                     desktop unlock"
                );
            }
            if fingerprint {
                anyhow::bail!(
                    "--fingerprint only applies to keyring unlock; Termux \
                     unlock always asks for device authentication"
                );
            }
            termux_enroll(validity.unwrap_or(300))
        }
    }
}

pub fn native_unlock_remove(yes: bool) -> anyhow::Result<()> {
    let account = active_account()?;
    if account.unlock.secret_service.is_some() {
        secret_service_remove(yes)
    } else if account.unlock.termux.is_some() || running_on_termux() {
        // Also cleans up a leftover key or bundle that isn't configured.
        termux_remove(yes)
    } else {
        println!(
            "No native unlock is configured for account {}.",
            account.name
        );
        Ok(())
    }
}

pub fn native_unlock_status() -> anyhow::Result<()> {
    let account = active_account()?;
    if account.unlock.secret_service.is_some() {
        secret_service_status()
    } else if let Some(termux) = &account.unlock.termux {
        println!(
            "Termux Keystore unlock configured (key {}, bundle {}).",
            termux.key_alias,
            termux.file.display()
        );
        rbw::termux::status(Some(&termux.key_alias))
    } else {
        println!(
            "No native unlock is configured for account {}.",
            account.name
        );
        Ok(())
    }
}

// Where a desktop enrollment keeps its credential, for messages.
pub(super) fn desktop_store_description(
    provider: &rbw::config::SecretServiceUnlock,
) -> String {
    use rbw::config::UnlockStore;
    let store = match provider.store {
        UnlockStore::Keyring => "the desktop keyring (Secret Service)",
        UnlockStore::Tpm2 if provider.secure_boot => {
            "a TPM-sealed credential bound to Secure Boot (PCR 7)"
        }
        UnlockStore::Tpm2 => "a TPM-sealed credential",
        UnlockStore::File => "an unencrypted file",
    };
    if provider.broker {
        format!("{store}, held by rbw-unlockd")
    } else {
        store.to_string()
    }
}

// Enrollment warnings for credentials the user's own programs can read.
pub(super) fn desktop_store_warnings(
    provider: &rbw::config::SecretServiceUnlock,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if provider.broker {
        return warnings;
    }
    if provider.fingerprint {
        warnings.push(format!(
            "the fingerprint is only a convenience check, not a security \
             boundary: any program running as you can read the master \
             password from {} without a scan. Enroll with --broker (needs \
             the rbw-unlockd service) to have the fingerprint enforced.",
            desktop_store_description(provider)
        ));
    }
    if provider.store == rbw::config::UnlockStore::File {
        warnings.push(
            "the master password is saved unencrypted in rbw's data \
             directory, protected only by file permissions; prefer tpm2."
                .to_string(),
        );
    }
    warnings
}

pub fn secret_service_status() -> anyhow::Result<()> {
    let account = active_account()?;
    let Some(provider) = account.unlock.secret_service else {
        println!("Desktop unlock is not configured.");
        return Ok(());
    };
    println!(
        "Desktop unlock configured: {}; fingerprint: {}.",
        desktop_store_description(&provider),
        if provider.broker {
            "required (enforced by rbw-unlockd)"
        } else if provider.fingerprint {
            "required (checked by rbw only)"
        } else {
            "off"
        }
    );
    if provider.broker {
        match rbw::desktop::broker_enrolled(&provider.id) {
            Ok(true) => println!("rbw-unlockd holds the credential."),
            Ok(false) => println!(
                "rbw-unlockd has no credential for this enrollment; enroll \
                 again."
            ),
            Err(error) => println!("rbw-unlockd is unreachable: {error:#}"),
        }
    } else {
        println!("Credential availability is checked during unlock.");
    }
    let c = stdout_supports_color();
    for warning in desktop_store_warnings(&provider) {
        println!("{} {warning}", style::warning("warning:", c));
    }
    Ok(())
}

// The master password for an enrollment: the same dialog `rbw unlock` uses
// (it checks the password against the local vault before accepting it), or
// pinentry when no custom UI is available.
pub(super) fn enroll_password(
    config: &rbw::config::Config,
    account: &rbw::config::Account,
    name: &str,
) -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    if let Ok(db) = load_db() {
        let mode = rbw::unlock_ui::resolve(
            UNLOCK_UI_OVERRIDE
                .with(std::cell::Cell::get)
                .unwrap_or(config.unlock_ui),
        )?;
        if mode != rbw::config::UnlockUi::Pinentry {
            let account = account.clone();
            return rbw::desktop::unlock_with_dialog(
                None,
                rbw::unlock_ui::Options {
                    mode,
                    no_echo: config.unlock_no_echo
                        || UNLOCK_NO_ECHO.with(std::cell::Cell::get),
                    hide_fingerprint_notice: config
                        .unlock_hide_fingerprint_notice,
                },
                &format!("Enroll desktop unlock for account {name}"),
                config.pinentry.timeout,
                std::sync::Arc::new(move |password| {
                    verify_cached_password(&account, &db, password)
                }),
            );
        }
    }
    let _ = account;
    let runtime = tokio::runtime::Runtime::new()?;
    let environment = crate::actions::get_environment();
    let response = runtime.block_on(rbw::pinentry::getpin(
        &config.pinentry.command,
        "Master password",
        &format!("Enroll rbw desktop keyring unlock for account {name}"),
        None,
        &environment,
        false,
        None,
        config.pinentry.timeout,
    ))?;
    String::from_utf8(response.password().to_vec())
        .map_err(|_| anyhow::anyhow!("master password is not UTF-8"))
}

pub fn secret_service_enroll(
    fingerprint: bool,
    desktop: DesktopStore,
) -> anyhow::Result<()> {
    use rbw::config::UnlockStore;
    use zeroize::Zeroizing;
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let account = config.account(Some(&name))?;
    if account.unlock.termux.is_some()
        || account.unlock.secret_service.is_some()
    {
        anyhow::bail!(
            "remove the existing native unlock provider before enrolling"
        );
    }
    // The broker exists to enforce the fingerprint, and keeps credentials in
    // its own (root-owned) storage rather than the user's keyring.
    let fingerprint = fingerprint || desktop.broker;
    let store = desktop.store.unwrap_or(if desktop.broker {
        UnlockStore::Tpm2
    } else {
        UnlockStore::Keyring
    });
    if desktop.broker && store == UnlockStore::Keyring {
        anyhow::bail!("--broker stores the credential with tpm2 or file, not the keyring");
    }
    if desktop.secure_boot && store != UnlockStore::Tpm2 {
        anyhow::bail!("--secure-boot needs --store tpm2");
    }
    let provider = rbw::config::SecretServiceUnlock {
        id: uuid::Uuid::new_v4().to_string(),
        fingerprint,
        store,
        secure_boot: desktop.secure_boot,
        broker: desktop.broker,
    };
    if desktop.broker {
        // Fail before asking for the password if the service is missing.
        rbw::desktop::broker_enrolled(&provider.id)
            .context("--broker needs the rbw-unlockd service")?;
    }
    let c = stderr_supports_color();
    for warning in desktop_store_warnings(&provider) {
        eprintln!("{} {warning}", style::warning("warning:", c));
    }
    crate::actions::set_active_account(Some(name.clone()))?;
    let password = Zeroizing::new(enroll_password(&config, &account, &name)?);
    unlock_impl(Some(password.to_string()), None, &mut Vec::new()).context(
        "password did not unlock the account; enrollment cancelled",
    )?;
    // An already-unlocked agent acknowledges unlock without checking the
    // supplied password. Verify against the encrypted DB independently.
    let db = load_db()?;
    let mut locked_bytes = rbw::locked::Vec::new();
    locked_bytes.extend(password.as_bytes().iter().copied());
    let locked_password = rbw::locked::Password::new(locked_bytes);
    verify_cached_password(&account, &db, &locked_password).context(
        "password did not decrypt the vault; enrollment cancelled",
    )?;
    // rbw-unlockd runs its own scan while saving.
    if fingerprint && !provider.broker {
        rbw::desktop::fingerprint()?;
    }
    if let Err(error) =
        rbw::desktop::store(&provider, password.as_bytes(), &name)
    {
        let _ = rbw::desktop::remove(&provider);
        return Err(error);
    }
    config
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .context("account vanished")?
        .unlock
        .secret_service = Some(provider.clone());
    if let Err(error) = config.save() {
        if rbw::desktop::remove(&provider).is_err() {
            eprintln!(
                "Could not remove the newly saved credential ({}) after the \
                 config save failed; delete it by hand.",
                desktop_store_description(&provider)
            );
        }
        return Err(error.into());
    }
    println!(
        "Desktop unlock enrolled in {}. Fingerprint: {}.",
        desktop_store_description(&provider),
        if provider.broker {
            "required (enforced by rbw-unlockd)"
        } else if fingerprint {
            "required (checked by rbw only)"
        } else {
            "off"
        }
    );
    Ok(())
}

pub fn secret_service_remove(yes: bool) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let Some(provider) = config.account(Some(&name))?.unlock.secret_service
    else {
        return Ok(());
    };
    if !yes && !std::io::stdin().is_terminal() {
        anyhow::bail!("refusing non-interactive removal; pass --yes");
    }
    if !yes
        && !confirm(&format!(
            "Delete this account's saved unlock credential ({})?",
            desktop_store_description(&provider)
        ))?
    {
        return Ok(());
    }
    rbw::desktop::remove(&provider)?;
    config
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .context("account vanished")?
        .unlock
        .secret_service = None;
    config.save()?;
    println!("Desktop unlock removed.");
    Ok(())
}

pub fn termux_enroll(validity: u32) -> anyhow::Result<()> {
    use zeroize::Zeroize as _;

    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let account_name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let account = config.account(Some(&account_name))?;
    if account.unlock.termux.is_some()
        || account.unlock.secret_service.is_some()
    {
        anyhow::bail!(
            "account {account_name:?} already has Termux unlock configured"
        );
    }

    let bundle = rbw::termux::default_bundle_path(&account_name);
    if bundle.exists() {
        anyhow::bail!(
            "Termux unlock bundle {} already exists; remove it before enrolling again",
            bundle.display()
        );
    }

    let environment = crate::actions::get_environment();
    let description = format!(
        "Enroll native Android unlock for rbw account {account_name:?}"
    );
    let runtime = tokio::runtime::Runtime::new()
        .context("failed to initialize the password prompt")?;
    let mut password = runtime
        .block_on(rbw::pinentry::getpin(
            &config.pinentry.command,
            "Master password",
            &description,
            None,
            &environment,
            false,
            None,
            config.pinentry.timeout,
        ))?
        .password()
        .to_vec();

    // Verify the password actually unlocks the account before enrolling a
    // Termux key against it -- otherwise a mistyped password would get
    // baked into the encrypted bundle, and every future Termux unlock would
    // "succeed" at the crypto layer while producing a password that never
    // actually works.
    let mut password_string = String::from_utf8(password.clone())
        .context("master password was not valid UTF-8")?;
    crate::actions::set_active_account(Some(account_name.clone()))?;
    let verified =
        unlock_impl(Some(password_string.clone()), None, &mut Vec::new());
    password_string.zeroize();
    if let Err(error) = verified {
        password.zeroize();
        return Err(error.context(
            "master password did not unlock the account; refusing to \
             enroll a Termux key for a password that doesn't work",
        ));
    }

    let key_alias =
        rbw::termux::resolve_key_alias(&config, &account_name, None);
    let algorithm = "SHA256withRSA";
    let result = (|| {
        let generated_key = !rbw::termux::key_present(&key_alias)?;
        if generated_key {
            rbw::termux::generate(&key_alias, "RSA", Some(2048), validity)?;
        }
        if let Err(error) = rbw::termux::enroll(
            &bundle,
            &key_alias,
            algorithm,
            std::mem::take(&mut password),
        ) {
            if generated_key {
                let _ = rbw::termux::delete(&key_alias);
            }
            return Err(error);
        }

        let account = config
            .accounts
            .iter_mut()
            .find(|account| account.name == account_name)
            .ok_or_else(|| {
                anyhow::anyhow!("account {account_name:?} vanished")
            })?;
        account.unlock.termux = Some(rbw::config::TermuxKeystoreUnlock {
            file: bundle.clone(),
            key_alias: key_alias.clone(),
            algorithm: algorithm.to_string(),
        });
        if let Err(error) = config.save() {
            let _ = std::fs::remove_file(&bundle);
            if generated_key {
                let _ = rbw::termux::delete(&key_alias);
            }
            return Err(anyhow::Error::new(error));
        }
        let _ = stop_agent();
        println!(
            "Termux unlock enrolled for account {account_name:?}.\n\
             Key: {key_alias} ({})\n\
             Bundle: {}\n\
             Future unlocks will ask Android Keystore for authentication.",
            if generated_key { "generated" } else { "reused" },
            bundle.display()
        );
        Ok(())
    })();
    password.zeroize();
    result
}

pub fn termux_remove(yes: bool) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let account_name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let (configured, key_alias, bundle) = {
        let account = config.account(Some(&account_name))?;
        let configured = account.unlock.termux.as_ref();
        let key_alias = rbw::termux::resolve_key_alias(
            &config,
            &account_name,
            configured.map(|termux| termux.key_alias.as_str()),
        );
        let bundle = configured.map_or_else(
            || rbw::termux::default_bundle_path(&account_name),
            |termux| termux.file.clone(),
        );
        (configured.is_some(), key_alias, bundle)
    };

    let key_present = rbw::termux::key_present(&key_alias)?;
    let bundle_present = bundle.exists();
    if !configured && !key_present && !bundle_present {
        println!("No Termux unlock found for account {account_name:?}.");
        return Ok(());
    }
    if !yes && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to remove Termux unlock non-interactively; pass --yes"
        );
    }
    if !yes
        && !confirm(&format!(
            "Permanently delete Termux key {key_alias:?} and {}?",
            bundle.display()
        ))?
    {
        return Ok(());
    }

    if key_present {
        rbw::termux::delete(&key_alias)?;
    }
    if bundle_present {
        std::fs::remove_file(&bundle).with_context(|| {
            format!("failed to remove {}", bundle.display())
        })?;
    }

    let account = config
        .accounts
        .iter_mut()
        .find(|account| account.name == account_name)
        .ok_or_else(|| {
            anyhow::anyhow!("account {account_name:?} vanished")
        })?;
    account.unlock.termux = None;
    config.save()?;
    let _ = stop_agent();

    println!(
        "Removed Termux unlock for account {account_name:?} (key: {key_alias})."
    );
    Ok(())
}
