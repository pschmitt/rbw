use anyhow::Context as _;
use sha2::Digest as _;

fn password_from_env() -> Option<rbw::locked::Password> {
    let val = std::env::var("BW_ACCOUNT_PASSWORD").ok()?;
    if val.is_empty() {
        return None;
    }
    let mut buf = rbw::locked::Vec::new();
    buf.extend(val.bytes());
    Some(rbw::locked::Password::new(buf))
}

// `client_id`/`client_secret` come from `--stdin` (e.g. for a fully
// non-interactive first registration on a brand-new host); when both are
// given, the pinentry prompt and its 3-attempt retry loop are skipped
// entirely -- there's no one to correct a typo interactively, so a bad key
// just fails once with a clear error instead of hanging on a pinentry
// nothing will ever answer. When either is absent, falls back to the
// original interactive pinentry flow, exactly as before.
pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
    account: &rbw::config::Account,
    client_id: Option<&rbw::locked::Password>,
    client_secret: Option<&rbw::locked::Password>,
) -> anyhow::Result<()> {
    let db = load_db(account)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let email = account_email(account)?;

        if let (Some(client_id), Some(client_secret)) =
            (client_id, client_secret)
        {
            let apikey = rbw::locked::ApiKey::new(
                client_id.clone(),
                client_secret.clone(),
            );
            rbw::actions::register(&email, apikey)
                .await
                .context("failed to log in to bitwarden instance")?;

            respond_ack(sock).await?;

            return Ok(());
        }

        let url_str = account.base_url();
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
                Some(sock.inner()),
                config_pinentry_timeout().await?,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
                Some(sock.inner()),
                config_pinentry_timeout().await?,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    password: Option<&rbw::locked::Password>,
    totp: Option<&str>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let db = load_db(account)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let email = account_email(account)?;

        if let Some(password) = password {
            login_with_resolved_password(
                state.clone(),
                password.clone(),
                totp,
                db,
                email,
                account,
            )
            .await?;
        } else {
            login_interactively(sock, state, environment, db, account)
                .await?;
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

// Single-shot login using a password resolved via the client's
// `credential_source` (see `commands::resolve_credential_source` on the
// client side) instead of prompting via pinentry. Doesn't retry on
// `IncorrectPassword` like the interactive path does -- a resolved password
// that turns out to be wrong is a misconfiguration (a stale entry, most
// likely), not a typo worth prompting the user to fix by hand.
async fn login_with_resolved_password(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    password: rbw::locked::Password,
    totp: Option<&str>,
    db: rbw::db::Db,
    email: String,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    match rbw::actions::login(&email, password.clone(), None, None).await {
        Ok((
            access_token,
            refresh_token,
            kdf,
            iterations,
            memory,
            parallelism,
            protected_key,
        )) => {
            login_success(
                state,
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                password,
                db,
                email,
                account,
            )
            .await
        }
        Err(rbw::error::Error::TwoFactorRequired { providers, .. }) => {
            // Only the authenticator (TOTP) method can be satisfied with a
            // pre-computed code; anything else has no way to proceed
            // without an interactive prompt, so surface a clear error
            // instead of silently hanging (there's no pinentry available on
            // this path -- see the caller's doc comment).
            let Some(totp) = totp else {
                anyhow::bail!(
                    "account requires two-factor authentication ({providers:?}) \
                    but no TOTP secret was resolved from credential_source"
                );
            };
            if !providers
                .contains(&rbw::api::TwoFactorProviderType::Authenticator)
            {
                anyhow::bail!(
                    "account requires two-factor authentication via \
                    {providers:?}, which credential_source can't automate \
                    (only TOTP/authenticator codes can be)"
                );
            }
            let (
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            ) = rbw::actions::login(
                &email,
                password.clone(),
                Some(totp),
                Some(rbw::api::TwoFactorProviderType::Authenticator),
            )
            .await
            .context(
                "credential_source-resolved TOTP code was rejected by the \
                server",
            )?;
            login_success(
                state,
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                password,
                db,
                email,
                account,
            )
            .await
        }
        Err(rbw::error::Error::IncorrectPassword { message }) => {
            Err(rbw::error::Error::IncorrectPassword { message }).context(
                "credential_source-resolved password was rejected by the \
                server",
            )
        }
        Err(e) => Err(e).context("failed to log in to bitwarden instance"),
    }
}

// The normal, fully-interactive login flow (pinentry for the password, and
// for a 2FA code if one is required) -- unchanged from before
// `credential_source` existed.
async fn login_interactively(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    db: rbw::db::Db,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let url_str = account.base_url();
    let url =
        reqwest::Url::parse(&url_str).context("failed to parse base url")?;
    let Some(host) = url.host_str() else {
        return Err(anyhow::anyhow!(
            "couldn't find host in rbw base url {url_str}"
        ));
    };

    let email = account_email(account)?;

    let mut err_msg = None;
    let mut env_password_tried = false;
    'attempts: for i in 1_u8..=3 {
        let password = if i == 1 {
            if let Some(pw) = password_from_env() {
                env_password_tried = true;
                pw
            } else {
                rbw::pinentry::getpin(
                    &config_pinentry().await?,
                    "Master Password",
                    &format!("Log in to {host}"),
                    None,
                    environment,
                    true,
                    Some(sock.inner()),
                    config_pinentry_timeout().await?,
                )
                .await
                .context("failed to read password from pinentry")?
            }
        } else {
            let err = Some(format!(
                "{} (attempt {}/3)",
                err_msg.as_ref().unwrap(),
                if env_password_tried { i - 1 } else { i }
            ));
            rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                true,
                Some(sock.inner()),
                config_pinentry_timeout().await?,
            )
            .await
            .context("failed to read password from pinentry")?
        };
        match rbw::actions::login(&email, password.clone(), None, None).await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                login_success(
                    state.clone(),
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                    password,
                    db,
                    email,
                    account,
                )
                .await?;
                break 'attempts;
            }
            Err(rbw::error::Error::TwoFactorRequired {
                providers,
                sso_email_2fa_session_token,
            }) => {
                let supported_types = vec![
                    rbw::api::TwoFactorProviderType::Authenticator,
                    rbw::api::TwoFactorProviderType::Yubikey,
                    rbw::api::TwoFactorProviderType::Email,
                ];

                for provider in supported_types {
                    if providers.contains(&provider) {
                        if provider == rbw::api::TwoFactorProviderType::Email
                        {
                            if let Some(sso_email_2fa_session_token) =
                                sso_email_2fa_session_token
                            {
                                rbw::actions::send_two_factor_email(
                                    &email,
                                    &sso_email_2fa_session_token,
                                )
                                .await?;
                            }
                        }
                        let (
                            access_token,
                            refresh_token,
                            kdf,
                            iterations,
                            memory,
                            parallelism,
                            protected_key,
                        ) = two_factor(
                            sock,
                            environment,
                            &email,
                            password.clone(),
                            provider,
                        )
                        .await?;
                        login_success(
                            state.clone(),
                            access_token,
                            refresh_token,
                            kdf,
                            iterations,
                            memory,
                            parallelism,
                            protected_key,
                            password,
                            db,
                            email,
                            account,
                        )
                        .await?;
                        break 'attempts;
                    }
                }
                return Err(anyhow::anyhow!(
                    "unsupported two factor methods: {providers:?}"
                ));
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    Ok(())
}

async fn two_factor(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
            Some(sock.inner()),
            config_pinentry_timeout().await?,
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(account, &db).await?;

    sync(None, state.clone(), account).await?;
    let db = load_db(account).await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys, rsa_private_key)) => {
            state.lock().await.set_unlocked(
                &account.name,
                keys,
                org_keys,
                rsa_private_key,
            );
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    password: Option<&rbw::locked::Password>,
    mut client: Option<&mut tokio::net::UnixStream>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock(&account.name) {
        let db = load_db(account).await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = account_email(account)?;
        let description =
            format!("Unlock account '{}' ({email})", account.name);

        if let Some(password) = password {
            // Password was passed through stdin
            match rbw::actions::unlock(
                &email,
                password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys, rsa_private_key)) => {
                    return unlock_success(
                        state,
                        keys,
                        org_keys,
                        rsa_private_key,
                        account,
                    )
                    .await
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }

        let mut err_msg = None;
        let mut env_password_tried = false;
        for i in 1_u8..=3 {
            let password = if i == 1 {
                if let Some(pw) = password_from_env() {
                    env_password_tried = true;
                    pw
                } else {
                    rbw::pinentry::getpin(
                        &config_pinentry().await?,
                        "Master Password",
                        &description,
                        None,
                        environment,
                        true,
                        client.as_deref_mut(),
                        config_pinentry_timeout().await?,
                    )
                    .await
                    .context("failed to read password from pinentry")?
                }
            } else {
                let err = Some(format!(
                    "{} (attempt {}/3)",
                    err_msg.as_ref().unwrap(),
                    if env_password_tried { i - 1 } else { i }
                ));
                rbw::pinentry::getpin(
                    &config_pinentry().await?,
                    "Master Password",
                    &description,
                    err.as_deref(),
                    environment,
                    true,
                    client.as_deref_mut(),
                    config_pinentry_timeout().await?,
                )
                .await
                .context("failed to read password from pinentry")?
            };
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys, rsa_private_key)) => {
                    unlock_success(
                        state,
                        keys,
                        org_keys,
                        rsa_private_key,
                        account,
                    )
                    .await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    password: Option<&rbw::locked::Password>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    unlock_state(state, environment, password, Some(sock.inner()), account)
        .await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
    rsa_private_key: rbw::locked::PrivateKey,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    state.lock().await.set_unlocked(
        &account.name,
        keys,
        org_keys,
        rsa_private_key,
    );
    Ok(())
}

// Permanently, irrecoverably deletes every entry in the account's personal
// vault (`rbw purge-vault`). Re-derives the master password hash from a
// freshly entered password -- like `Login`/`Unlock`, this never reuses the
// agent's already-unlocked key material, since a hash proving current
// knowledge of the password is what the server's purge endpoint requires,
// and deriving it doesn't need decrypting anything the unlocked state
// holds.
pub async fn purge_vault(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    password: Option<&rbw::locked::Password>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let mut db = load_db(account).await?;

    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };
    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };
    let memory = db.memory;
    let parallelism = db.parallelism;
    let email = account_email(account)?;

    let password = if let Some(password) = password {
        password.clone()
    } else {
        let description = format!(
            "PERMANENTLY PURGE the entire vault for account '{}' ({email})? \
             Enter the master password to confirm.",
            account.name
        );
        rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            &description,
            None,
            environment,
            true,
            Some(sock.inner()),
            config_pinentry_timeout().await?,
        )
        .await
        .context("failed to read password from pinentry")?
    };

    let identity = rbw::identity::Identity::new(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let access_token = db
        .access_token
        .clone()
        .context("failed to find access token in db")?;
    let refresh_token = db
        .refresh_token
        .clone()
        .context("failed to find refresh token in db")?;

    let new_access_token = rbw::actions::purge_vault(
        &access_token,
        &refresh_token,
        &identity.master_password_hash,
    )
    .await
    .context("failed to purge vault (wrong master password?)")?;

    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(account, &db).await?;
    }

    // Refresh local state to reflect the now-empty vault.
    sync(None, state.clone(), account).await?;

    respond_ack(sock).await?;

    Ok(())
}

// Creates a new organization owned by the current account (`rbw org
// create`). Needs the account's own RSA key pair to encrypt a freshly
// generated org key to itself as the initial (and, at creation time,
// only) member -- so this reads the private key retained in agent state
// from the original unlock, the same one `refresh_org_keys` uses.
pub async fn create_org(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: &rbw::config::Account,
    name: &str,
) -> anyhow::Result<()> {
    let rsa_private_key = {
        let state = state.lock().await;
        state
            .account(&account.name)
            .and_then(|a| a.rsa_private_key.clone())
            .context("account must be unlocked to create an organization")?
    };

    let public_key =
        rbw::cipherstring::rsa_public_key_from_private(&rsa_private_key)
            .context("failed to derive RSA public key")?;

    let org_key = rbw::cipherstring::generate_attachment_keys();
    let org_key_bytes: Vec<u8> = org_key
        .enc_key()
        .iter()
        .chain(org_key.mac_key())
        .copied()
        .collect();
    let encrypted_key = rbw::cipherstring::CipherString::encrypt_asymmetric(
        &public_key,
        &org_key_bytes,
    )?
    .to_string();
    let encrypted_collection_name =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            &org_key,
            b"Default Collection",
        )?
        .to_string();

    let email = account_email(account)?;
    let mut db = load_db(account).await?;
    let access_token = db
        .access_token
        .clone()
        .context("failed to find access token in db")?;
    let refresh_token = db
        .refresh_token
        .clone()
        .context("failed to find refresh token in db")?;

    let (new_access_token, id) = rbw::actions::create_org(
        &access_token,
        &refresh_token,
        name,
        &email,
        &encrypted_key,
        &encrypted_collection_name,
    )
    .await
    .context("failed to create organization")?;

    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(account, &db).await?;
    }

    // Refresh local state so the new org's key (and its default
    // collection) are usable right away.
    sync(None, state.clone(), account).await?;

    sock.send(&rbw::protocol::Response::CreateOrg { id })
        .await?;

    Ok(())
}

// Confirms an org member who has accepted their invite (`rbw org
// confirm`). The org's own key is already cached in agent state (from
// unlock, or `refresh_org_keys` after a later sync) -- this just
// re-encrypts it to the target's public key, which the client already
// fetched (a plain lookup, no secret material of ours involved) and
// passed through.
pub async fn confirm_org_user(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: &rbw::config::Account,
    org_id: &str,
    user_id: &str,
    public_key_der_b64: &str,
) -> anyhow::Result<()> {
    let org_key = {
        let state = state.lock().await;
        state.key(&account.name, Some(org_id)).cloned().context(
            "org key not available -- is the account unlocked and a \
                 member of this org?",
        )?
    };

    let der = rbw::base64::decode(public_key_der_b64)
        .context("invalid base64 public key")?;
    let public_key = rbw::cipherstring::rsa_public_key_from_der(&der)
        .context("failed to parse the target member's public key")?;

    let org_key_bytes: Vec<u8> = org_key
        .enc_key()
        .iter()
        .chain(org_key.mac_key())
        .copied()
        .collect();
    let encrypted_key = rbw::cipherstring::CipherString::encrypt_asymmetric(
        &public_key,
        &org_key_bytes,
    )?
    .to_string();

    let mut db = load_db(account).await?;
    let access_token = db
        .access_token
        .clone()
        .context("failed to find access token in db")?;
    let refresh_token = db
        .refresh_token
        .clone()
        .context("failed to find refresh token in db")?;

    let new_access_token = rbw::actions::confirm_org_user(
        &access_token,
        &refresh_token,
        org_id,
        user_id,
        &encrypted_key,
    )
    .await
    .context("failed to confirm organization member")?;

    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(account, &db).await?;
    }

    sync(None, state.clone(), account).await?;

    respond_ack(sock).await?;

    Ok(())
}

// Permanently deletes an entire organization (`rbw org delete`). Same
// master-password re-proof as `purge_vault`, for the same reason (proving
// current intent/knowledge, not decrypting anything -- deriving the hash
// doesn't need the org's own key at all).
pub async fn delete_org(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    password: Option<&rbw::locked::Password>,
    account: &rbw::config::Account,
    org_id: &str,
) -> anyhow::Result<()> {
    let mut db = load_db(account).await?;

    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };
    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };
    let memory = db.memory;
    let parallelism = db.parallelism;
    let email = account_email(account)?;

    let password = if let Some(password) = password {
        password.clone()
    } else {
        let description = format!(
            "PERMANENTLY DELETE the organization {org_id} for account \
             '{}' ({email})? Enter the master password to confirm.",
            account.name
        );
        rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            &description,
            None,
            environment,
            true,
            Some(sock.inner()),
            config_pinentry_timeout().await?,
        )
        .await
        .context("failed to read password from pinentry")?
    };

    let identity = rbw::identity::Identity::new(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let access_token = db
        .access_token
        .clone()
        .context("failed to find access token in db")?;
    let refresh_token = db
        .refresh_token
        .clone()
        .context("failed to find refresh token in db")?;

    let new_access_token = rbw::actions::delete_org(
        &access_token,
        &refresh_token,
        org_id,
        &identity.master_password_hash,
    )
    .await
    .context("failed to delete organization (wrong master password?)")?;

    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(account, &db).await?;
    }

    sync(None, state.clone(), account).await?;

    respond_ack(sock).await?;

    Ok(())
}

// Lock the account the client named explicitly (`rbw -a NAME lock`), or
// every account when the request doesn't carry one (plain `rbw lock`,
// `rbw lock --all`, and requests from older clients).
pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: Option<&str>,
) -> anyhow::Result<()> {
    {
        let mut state = state.lock().await;
        match account {
            Some(name) => state.clear_account(name),
            None => state.clear(),
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock(&account.name) {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let mut db = load_db(account).await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find refresh token in db"));
    };
    let (
        access_token,
        (
            protected_key,
            protected_private_key,
            protected_org_keys,
            entries,
            collections,
            organizations,
        ),
    ) = match rbw::actions::sync(&access_token, &refresh_token).await {
        Ok(v) => v,
        Err(rbw::error::Error::SessionExpired) => {
            // The refresh token is dead and can't be recovered from, unlike
            // a merely-expired access token -- clear both so needs_login()
            // is true again and the next Login action actually
            // re-authenticates instead of silently no-opping (see
            // `login`, above).
            db.access_token = None;
            db.refresh_token = None;
            save_db(account, &db).await?;
            return Err(rbw::error::Error::SessionExpired.into());
        }
        Err(e) => {
            return Err(anyhow::Error::from(e)
                .context("failed to sync database from server"));
        }
    };
    state
        .lock()
        .await
        .set_master_password_reprompt(&account.name, &entries);
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    db.collections = collections;
    db.organizations = organizations;
    save_db(account, &db).await?;

    // A newly created/joined org's key would otherwise stay undecryptable
    // (and its collections unusable) until the next full lock+unlock --
    // this refreshes it immediately using the private key retained from
    // the original unlock. A no-op if the account isn't currently
    // unlocked.
    state
        .lock()
        .await
        .refresh_org_keys(&account.name, &db.protected_org_keys);

    if let Err(e) = subscribe_to_notifications(state.clone(), account).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    // Set when `cipherstring` is wrapped in an attachment's own key (e.g. an
    // attachment file name) rather than directly in the entry's key.
    attachment_key: Option<&str>,
    mut client: Option<&mut tokio::net::UnixStream>,
    account: &rbw::config::Account,
) -> anyhow::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized(&account.name) {
        let db = load_db(account).await?;
        state.set_master_password_reprompt(&account.name, &db.entries);
    }
    let Some(keys) = state.key(&account.name, org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };
    // An attachment key is itself wrapped in the entry's effective key, same
    // as the entry key is wrapped in the account keys. Kept separate from
    // `entry_key` (rather than shadowing it) because some older Bitwarden
    // attachments — migrated to a dedicated attachment key for their data at
    // some point in Bitwarden's history — still have their file name
    // encrypted with the entry's key from before that migration; decrypting
    // below falls back to `entry_key` if the attachment key doesn't work.
    let attachment_key = attachment_key
        .map(|attachment_key| {
            let key_cipherstring =
                rbw::cipherstring::CipherString::new(attachment_key)
                    .context("failed to parse attachment encryption key")?;
            key_cipherstring
                .decrypt_attachment_key(keys, entry_key.as_ref())
                .context("failed to decrypt attachment encryption key")
        })
        .transpose()?;

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state.master_password_reprompt_contains(
        &account.name,
        &master_password_reprompt,
    ) {
        let db = load_db(account).await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = account_email(account)?;

        let mut err_msg = None;
        let mut env_password_tried = false;
        for i in 1_u8..=3 {
            let password = if i == 1 {
                if let Some(pw) = password_from_env() {
                    env_password_tried = true;
                    pw
                } else {
                    rbw::pinentry::getpin(
                        &config_pinentry().await?,
                        "Master Password",
                        "Accessing this entry requires the master password",
                        None,
                        environment,
                        true,
                        client.as_deref_mut(),
                        config_pinentry_timeout().await?,
                    )
                    .await
                    .context("failed to read password from pinentry")?
                }
            } else {
                let err = Some(format!(
                    "{} (attempt {}/3)",
                    err_msg.as_ref().unwrap(),
                    if env_password_tried { i - 1 } else { i }
                ));
                rbw::pinentry::getpin(
                    &config_pinentry().await?,
                    "Master Password",
                    "Accessing this entry requires the master password",
                    err.as_deref(),
                    environment,
                    true,
                    client.as_deref_mut(),
                    config_pinentry_timeout().await?,
                )
                .await
                .context("failed to read password from pinentry")?
            };
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok(_) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let decrypted = attachment_key
        .as_ref()
        .map_or_else(
            || cipherstring.decrypt_symmetric(keys, entry_key.as_ref()),
            |attachment_key| {
                cipherstring
                    .decrypt_symmetric(keys, Some(attachment_key))
                    .or_else(|_| {
                        cipherstring
                            .decrypt_symmetric(keys, entry_key.as_ref())
                    })
            },
        )
        .context("failed to decrypt encrypted secret")?;
    let plaintext = String::from_utf8(decrypted)
        .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    attachment_key: Option<&str>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let plaintext = decrypt_cipher(
        state,
        environment,
        cipherstring,
        entry_key,
        org_id,
        attachment_key,
        Some(sock.inner()),
        account,
    )
    .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn decrypt_batch(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    entries: &[rbw::protocol::DecryptRequest],
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let result = decrypt_cipher(
            state.clone(),
            environment,
            &entry.cipherstring,
            entry.entry_key.as_deref(),
            entry.org_id.as_deref(),
            None,
            Some(sock.inner()),
            account,
        )
        .await;
        results.push(match result {
            Ok(plaintext) => {
                rbw::protocol::DecryptResult::Success { plaintext }
            }
            Err(e) => rbw::protocol::DecryptResult::Failure {
                error: format!("{e:#}"),
            },
        });
    }

    sock.send(&rbw::protocol::Response::DecryptBatch { results })
        .await?;

    Ok(())
}

pub async fn decrypt_attachment(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    data: &[u8],
    attachment_key: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(&account.name, org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };
    let attachment_keys = if let Some(attachment_key) = attachment_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(attachment_key)
                .context("failed to parse attachment encryption key")?;
        Some(
            key_cipherstring
                .decrypt_attachment_key(keys, entry_key.as_ref())?,
        )
    } else {
        None
    };
    let decrypted = rbw::cipherstring::decrypt_file_data(
        data,
        attachment_keys
            .as_ref()
            .or(entry_key.as_ref())
            .unwrap_or(keys),
    )
    .context("failed to decrypt attachment data")?;

    sock.send(&rbw::protocol::Response::DecryptAttachment {
        data: decrypted,
    })
    .await?;

    Ok(())
}

pub async fn encrypt_attachment(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    data: &[u8],
    filename: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(&account.name, org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    // Resolve the cipher's own key if it has one
    let entry_keys = if let Some(entry_key) = entry_key {
        let key_cs = rbw::cipherstring::CipherString::new(entry_key)
            .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cs.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };
    let effective_keys = entry_keys.as_ref().unwrap_or(keys);

    // Generate a fresh random attachment key
    let attachment_keys = rbw::cipherstring::generate_attachment_keys();

    // Encrypt file data with attachment key
    let encrypted_data =
        rbw::cipherstring::encrypt_file_data(data, &attachment_keys)
            .context("failed to encrypt attachment data")?;

    // Encrypt the 64-byte attachment key with the cipher's effective keys
    let raw_attachment_key: Vec<u8> = attachment_keys
        .enc_key()
        .iter()
        .chain(attachment_keys.mac_key().iter())
        .copied()
        .collect();
    let encrypted_key = rbw::cipherstring::CipherString::encrypt_symmetric(
        effective_keys,
        &raw_attachment_key,
    )
    .context("failed to encrypt attachment key")?;

    // Encrypt filename with the cipher's effective key (its own key, or the
    // account/org key if it has none) -- matching upstream Bitwarden clients,
    // which decrypt attachment file names with the same key used for the
    // rest of the cipher's fields rather than the attachment's own key.
    let encrypted_filename =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            effective_keys,
            filename.as_bytes(),
        )
        .context("failed to encrypt attachment filename")?;

    sock.send(&rbw::protocol::Response::EncryptAttachment {
        encrypted_data,
        encrypted_key: encrypted_key.to_string(),
        encrypted_filename: encrypted_filename.to_string(),
    })
    .await?;
    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(&account.name, org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            anyhow::anyhow!("couldn't store value to clipboard: {e}")
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

// The account's email, or an error if it isn't configured yet.
fn account_email(account: &rbw::config::Account) -> anyhow::Result<String> {
    account.email.clone().ok_or_else(|| {
        anyhow::anyhow!("failed to find email address in config")
    })
}

// Resolve the requested account (by name, or the primary account when None).
pub async fn resolve_account(
    account: Option<&str>,
) -> anyhow::Result<rbw::config::Account> {
    let config = rbw::config::Config::load_async().await?;
    config.account(account).map_err(anyhow::Error::new)
}

// Sync every configured account whose local db has an access token, each
// within its own account scope so api calls target the right server. Used by
// the periodic sync timer and server-pushed sync notifications, neither of
// which carries a target account. Failures (e.g. accounts not logged in) are
// logged and skipped.
pub async fn sync_all(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) {
    let config = match rbw::config::Config::load_async().await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load config for sync: {e:#}");
            return;
        }
    };
    for account in config.accounts() {
        let res = rbw::actions::AGENT_ACCOUNT
            .scope(account.clone(), sync(None, state.clone(), &account))
            .await;
        if let Err(e) = res {
            log::debug!("failed to sync account {}: {e:#}", account.name);
        }
    }
}

async fn load_db(
    account: &rbw::config::Account,
) -> anyhow::Result<rbw::db::Db> {
    let email = account_email(account)?;
    rbw::db::Db::load_async(&account.server_name(), &email)
        .await
        .map_err(anyhow::Error::new)
}

async fn save_db(
    account: &rbw::config::Account,
    db: &rbw::db::Db,
) -> anyhow::Result<()> {
    let email = account_email(account)?;
    db.save_async(&account.server_name(), &email)
        .await
        .map_err(anyhow::Error::new)
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry.command)
}

// See `PinentryConfig::timeout`. Passed straight through to pinentry's own
// `--timeout` flag, so `0` means "no timeout" there too.
async fn config_pinentry_timeout() -> anyhow::Result<u64> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry.timeout)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    account: &rbw::config::Account,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let email = account_email(account)?;
    let db = rbw::db::Db::load_async(account.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        account.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    // The ssh agent has no per-request account, so it operates on the
    // primary account.
    let account = resolve_account(None).await?;
    unlock_state(state.clone(), &environment, None, None, &account).await?;

    let db = load_db(&account).await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                None,
                None,
                &account,
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    // The ssh agent has no per-request account, so it operates on the
    // primary account.
    let account = resolve_account(None).await?;
    unlock_state(state.clone(), &environment, None, None, &account).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db(&account).await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                None,
                None,
                &account,
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                    None,
                    None,
                    &account,
                )
                .await?;

                return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                    private_key_plaintext,
                )
                .map_err(anyhow::Error::new);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
