//! Native desktop D-Bus integration. Fingerprint confirmation is an rbw
//! policy, not a hardware-enforced restriction on Secret Service access.

#[cfg(target_os = "linux")]
pub use native::{
    credential_string, fingerprint, fingerprint_for_user, remove, store,
    unlock, unlock_with_dialog, unlock_with_pinentry,
};

#[cfg(not(target_os = "linux"))]
pub fn fingerprint() -> anyhow::Result<()> {
    anyhow::bail!("desktop unlock is only supported on Linux");
}
#[cfg(not(target_os = "linux"))]
pub fn store(
    _config: &crate::config::SecretServiceUnlock,
    _password: &[u8],
) -> anyhow::Result<()> {
    fingerprint()
}
#[cfg(not(target_os = "linux"))]
pub fn remove(
    _config: &crate::config::SecretServiceUnlock,
) -> anyhow::Result<()> {
    fingerprint()
}
#[cfg(not(target_os = "linux"))]
pub fn unlock(
    _config: &crate::config::SecretServiceUnlock,
) -> anyhow::Result<String> {
    anyhow::bail!("desktop unlock is only supported on Linux");
}

#[cfg(not(target_os = "linux"))]
pub fn unlock_with_pinentry(
    _config: &crate::config::SecretServiceUnlock,
    _pinentry: &crate::config::PinentryConfig,
    _environment: &crate::protocol::Environment,
    _description: &str,
    _validate: impl Fn(&crate::locked::Password) -> anyhow::Result<()> + Sync,
) -> anyhow::Result<String> {
    anyhow::bail!("desktop unlock is only supported on Linux");
}

#[cfg(target_os = "linux")]
mod native {
    use anyhow::Context as _;
    use futures_util::StreamExt as _;
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    use std::future::Future;
    use std::time::Duration;
    use tokio::time::{timeout, timeout_at, Instant};
    use zbus::{Connection, OwnedObjectPath, Proxy, Variant};
    use zeroize::Zeroizing;

    const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
    const FPRINT_SERVICE: &str = "net.reactivated.Fprint";
    const FPRINT_DEVICE: &str = "net.reactivated.Fprint.Device";

    fn run<T>(
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("could not initialize desktop D-Bus runtime")?
            .block_on(future)
    }

    fn attributes(id: &str) -> HashMap<&str, &str> {
        HashMap::from([("application", "rbw"), ("unlock-id", id)])
    }

    // A user-held `tpm2`/`file` credential: rbw's data directory.
    fn credential_file(
        config: &crate::config::SecretServiceUnlock,
    ) -> std::path::PathBuf {
        crate::dirs::unlock_credential_file(
            &config.id,
            if config.store == crate::config::UnlockStore::Tpm2 {
                "cred"
            } else {
                "secret"
            },
        )
    }

    /// The name a `tpm2` credential is sealed under; decryption checks it.
    pub fn credential_name(id: &str) -> String {
        format!("rbw-unlock-{id}")
    }

    /// Saves `password` in the enrollment's store. A broker enrollment hands
    /// it to rbw-unlockd, which first asks for a finger.
    pub fn store(
        config: &crate::config::SecretServiceUnlock,
        password: &[u8],
    ) -> anyhow::Result<()> {
        use crate::config::UnlockStore;
        if password.is_empty() {
            anyhow::bail!("cannot enroll an empty credential");
        }
        if config.broker {
            let password = std::str::from_utf8(password)
                .context("master password is not UTF-8")?;
            eprintln!("Touch the fingerprint reader to let rbw-unlockd save the credential...");
            return run(async {
                crate::unlockd::call(
                    &crate::unlockd::Request::Enroll {
                        id: config.id.clone(),
                        store: config.store,
                        secure_boot: config.secure_boot,
                        password: password.to_string(),
                    },
                    None,
                    async {
                        let _ = tokio::signal::ctrl_c().await;
                    },
                )
                .await
                .map(drop)
            });
        }
        match config.store {
            UnlockStore::Keyring => keyring_store(&config.id, password),
            UnlockStore::Tpm2 => run(async {
                let path = credential_file(config);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                    std::fs::set_permissions(
                        dir,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )?;
                }
                crate::creds::encrypt(
                    crate::creds::Scope::User,
                    &credential_name(&config.id),
                    password,
                    config.secure_boot,
                    &path,
                )
                .await
            }),
            UnlockStore::File => crate::creds::write_private(
                &credential_file(config),
                password,
            ),
        }
    }

    /// Deletes the enrollment's saved credential; missing is not an error.
    pub fn remove(
        config: &crate::config::SecretServiceUnlock,
    ) -> anyhow::Result<()> {
        use crate::config::UnlockStore;
        if config.broker {
            return run(async {
                crate::unlockd::call(
                    &crate::unlockd::Request::Remove {
                        id: config.id.clone(),
                    },
                    None,
                    std::future::pending(),
                )
                .await
                .map(drop)
            });
        }
        match config.store {
            UnlockStore::Keyring => keyring_remove(&config.id),
            UnlockStore::Tpm2 | UnlockStore::File => {
                match std::fs::remove_file(credential_file(config)) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        Err(e)
                            .context("could not delete the unlock credential")
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    // Reads a user-held credential (no fingerprint scan here).
    async fn fetch(
        config: &crate::config::SecretServiceUnlock,
    ) -> anyhow::Result<String> {
        use crate::config::UnlockStore;
        let bytes = match config.store {
            UnlockStore::Keyring => return lookup(&config.id).await,
            UnlockStore::Tpm2 => {
                crate::creds::decrypt(
                    crate::creds::Scope::User,
                    &credential_name(&config.id),
                    &credential_file(config),
                )
                .await?
            }
            UnlockStore::File => {
                crate::creds::read_private(&credential_file(config))?
            }
        };
        credential_string(&bytes)
    }

    pub fn credential_string(bytes: &[u8]) -> anyhow::Result<String> {
        if bytes.is_empty() {
            anyhow::bail!("unlock credential is empty");
        }
        if bytes.len() > crate::locked::CAPACITY {
            anyhow::bail!(
                "unlock credential exceeds the password size limit"
            );
        }
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| anyhow::anyhow!("unlock credential is not UTF-8"))
    }

    // The fingerprint-gated half of an unlock: a broker enrollment asks
    // rbw-unlockd (which scans), otherwise rbw scans and then reads the
    // credential itself.
    async fn scan_and_fetch(
        config: &crate::config::SecretServiceUnlock,
        feedback: Option<
            &tokio::sync::watch::Sender<crate::unlock_ui::FingerprintStatus>,
        >,
        cancel: impl Future<Output = ()>,
        notifications: bool,
    ) -> anyhow::Result<String> {
        tokio::pin!(cancel);
        if config.broker {
            let password =
                crate::unlockd::unlock(&config.id, feedback, cancel).await?;
            return Ok(password.to_string());
        }
        let connection = timeout(CLEANUP_TIMEOUT, Connection::system())
            .await
            .context("connecting to the system bus timed out")??;
        fingerprint_with_feedback(
            connection,
            OPERATION_TIMEOUT,
            notifications,
            &mut cancel,
            false,
            feedback,
            "",
        )
        .await?;
        tokio::select! {
            result = fetch(config) => result,
            () = &mut cancel => anyhow::bail!("fingerprint unlock cancelled"),
        }
    }

    fn keyring_store(id: &str, password: &[u8]) -> anyhow::Result<()> {
        run(async {
            timeout(OPERATION_TIMEOUT, async {
                let service =
                    SecretService::connect(EncryptionType::Dh).await?;
                let collection = service.get_default_collection().await?;
                collection.unlock().await?;
                collection.ensure_unlocked().await?;
                collection
                    .create_item(
                        "rbw account unlock",
                        attributes(id),
                        password,
                        true,
                        "text/plain",
                    )
                    .await?;
                anyhow::Ok(())
            })
            .await
            .context("Secret Service enrollment timed out")?
            .context("could not store the credential in Secret Service")
        })
    }

    fn keyring_remove(id: &str) -> anyhow::Result<()> {
        run(async {
            timeout(OPERATION_TIMEOUT, async {
                let service =
                    SecretService::connect(EncryptionType::Dh).await?;
                let items = service.search_items(attributes(id)).await?;
                for item in items.unlocked.into_iter().chain(items.locked) {
                    item.unlock().await?;
                    item.delete().await?;
                }
                anyhow::Ok(())
            })
            .await
            .context("Secret Service removal timed out")?
            .context("could not remove the credential from Secret Service")
        })
    }

    pub fn unlock(
        config: &crate::config::SecretServiceUnlock,
    ) -> anyhow::Result<String> {
        run(async {
            let ctrl_c = async {
                let _ = tokio::signal::ctrl_c().await;
            };
            if config.broker {
                return scan_and_fetch(config, None, ctrl_c, true).await;
            }
            if config.fingerprint {
                fingerprint_async().await?;
            }
            fetch(config).await
        })
    }

    async fn lookup(id: &str) -> anyhow::Result<String> {
        timeout(OPERATION_TIMEOUT, async {
                let service = SecretService::connect(EncryptionType::Dh).await?;
                let items = service.search_items(attributes(id)).await?;
                let mut items = items.unlocked.into_iter().chain(items.locked);
                let item = items.next().context("Secret Service credential not found; enroll again")?;
                if items.next().is_some() {
                    anyhow::bail!("multiple Secret Service credentials match this enrollment");
                }
                item.unlock().await?;
                item.ensure_unlocked().await?;
                let bytes = Zeroizing::new(item.get_secret().await?);
                if bytes.is_empty() { anyhow::bail!("Secret Service credential is empty"); }
                if bytes.len() > crate::locked::CAPACITY { anyhow::bail!("Secret Service credential exceeds the password size limit"); }
                std::str::from_utf8(&bytes)
                    .map(str::to_owned)
                    .map_err(|_| anyhow::anyhow!("Secret Service credential is not UTF-8"))
            }).await.context("Secret Service lookup timed out")?
                .context("could not retrieve the credential from Secret Service")
    }

    pub fn unlock_with_dialog(
        config: Option<&crate::config::SecretServiceUnlock>,
        options: crate::unlock_ui::Options,
        title: &str,
        timeout_seconds: u64,
        validate: crate::unlock_ui::Validator,
    ) -> anyhow::Result<String> {
        crate::unlock_ui::protect_process()?;
        run(async {
            use crate::unlock_ui::FingerprintStatus;
            let enabled = config.is_some_and(|config| config.fingerprint);
            let (status, receiver) =
                tokio::sync::watch::channel(if enabled {
                    FingerprintStatus::Starting
                } else {
                    FingerprintStatus::Disabled
                });
            let (stop_pin, pin_cancelled) = tokio::sync::oneshot::channel();
            let (stop_bio, mut bio_cancelled) =
                tokio::sync::oneshot::channel();
            let (session_cancel, mut cancelled) =
                tokio::sync::oneshot::channel();
            let pin = crate::unlock_ui::prompt(
                options,
                title,
                timeout_seconds,
                receiver,
                validate.clone(),
                pin_cancelled,
                session_cancel,
            );
            let bio = async {
                let result = async {
                    let config = config
                        .filter(|_| enabled)
                        .context("fingerprint unlock is not configured")?;
                    let password = Zeroizing::new(
                        scan_and_fetch(
                            config,
                            Some(&status),
                            async {
                                let _ = (&mut bio_cancelled).await;
                            },
                            false,
                        )
                        .await?,
                    );
                    let mut bytes = crate::locked::Vec::try_new()?;
                    bytes.extend(password.as_bytes().iter().copied());
                    let candidate = crate::locked::Password::new(bytes);
                    tokio::task::spawn_blocking(move || validate(&candidate))
                        .await??;
                    status.send_replace(FingerprintStatus::Accepted);
                    Ok(password.to_string())
                }
                .await;
                if enabled && result.is_err() {
                    status.send_replace(FingerprintStatus::Unavailable);
                }
                result
            };
            first_success(pin, bio, stop_pin, stop_bio, async {
                tokio::select! {
                    () = async { if (&mut cancelled).await.is_err() { std::future::pending::<()>().await; } } => {},
                    _ = tokio::signal::ctrl_c() => {},
                }
            })
            .await
        })
    }

    pub fn unlock_with_pinentry(
        config: &crate::config::SecretServiceUnlock,
        pinentry: &crate::config::PinentryConfig,
        environment: &crate::protocol::Environment,
        description: &str,
        validate: impl Fn(&crate::locked::Password) -> anyhow::Result<()> + Sync,
    ) -> anyhow::Result<String> {
        run(async {
            let (stop_pin, pin_cancelled) = tokio::sync::oneshot::channel();
            let (stop_bio, mut bio_cancelled) =
                tokio::sync::oneshot::channel();
            let pin = prompt_password(
                pinentry,
                environment,
                description,
                &validate,
                pin_cancelled,
            );
            let bio = async {
                let password = Zeroizing::new(
                    scan_and_fetch(
                        config,
                        None,
                        async {
                            let _ = (&mut bio_cancelled).await;
                        },
                        true,
                    )
                    .await?,
                );
                let mut bytes = crate::locked::Vec::new();
                bytes.extend(password.as_bytes().iter().copied());
                validate(&crate::locked::Password::new(bytes))?;
                Ok(password.to_string())
            };
            first_success(pin, bio, stop_pin, stop_bio, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        })
    }

    async fn prompt_password(
        config: &crate::config::PinentryConfig,
        environment: &crate::protocol::Environment,
        description: &str,
        validate: &(impl Fn(&crate::locked::Password) -> anyhow::Result<()>
              + Sync),
        mut cancel: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<String> {
        let mut error = None;
        loop {
            let (writer, mut reader) = tokio::net::UnixStream::pair()?;
            let prompt = crate::pinentry::getpin(
                &config.command,
                "Master password (or scan a finger)",
                description,
                error,
                environment,
                false,
                Some(&mut reader),
                config.timeout,
            );
            tokio::pin!(prompt);
            let password = tokio::select! {
                result = &mut prompt => result?,
                _ = &mut cancel => {
                    // Use getpin's disconnect path to interrupt and reap
                    // pinentry, including restoring terminal pinentries.
                    drop(writer);
                    let _ = timeout(CLEANUP_TIMEOUT, &mut prompt).await;
                    anyhow::bail!("password prompt cancelled");
                }
            };
            match validate(&password) {
                Ok(()) => {
                    return std::str::from_utf8(password.password())
                        .map(str::to_owned)
                        .map_err(|_| {
                            anyhow::anyhow!("master password is not UTF-8")
                        })
                }
                Err(error_value)
                    if matches!(
                        error_value.downcast_ref::<crate::error::Error>(),
                        Some(crate::error::Error::IncorrectPassword { .. })
                    ) =>
                {
                    error = Some("Password is incorrect. Try again, or scan an enrolled finger.");
                }
                Err(error_value) => return Err(error_value),
            }
        }
    }

    async fn cancel_pending<F: Future<Output = anyhow::Result<String>>>(
        sender: &mut Option<tokio::sync::oneshot::Sender<()>>,
        future: std::pin::Pin<&mut F>,
        pending: bool,
    ) {
        if let Some(sender) = sender.take() {
            let _ = sender.send(());
        }
        if pending {
            // Allow connection setup and bounded reader cleanup to finish.
            if let Ok(Ok(password)) =
                timeout(Duration::from_secs(30), future).await
            {
                // A near-simultaneous second winner is discarded securely.
                let _password = Zeroizing::new(password);
            }
        }
    }

    pub(super) async fn first_success(
        pin: impl Future<Output = anyhow::Result<String>>,
        bio: impl Future<Output = anyhow::Result<String>>,
        stop_pin: tokio::sync::oneshot::Sender<()>,
        stop_bio: tokio::sync::oneshot::Sender<()>,
        cancel: impl Future<Output = ()>,
    ) -> anyhow::Result<String> {
        tokio::pin!(pin, bio, cancel);
        let (mut pin_done, mut bio_done) = (false, false);
        let (mut stop_pin, mut stop_bio) = (Some(stop_pin), Some(stop_bio));
        loop {
            tokio::select! {
                result = &mut pin, if !pin_done => {
                    pin_done = true;
                    if let Ok(password) = result {
                        cancel_pending(&mut stop_bio, bio.as_mut(), !bio_done).await;
                        eprintln!("Master password accepted.");
                        return Ok(password);
                    }
                }
                result = &mut bio, if !bio_done => {
                    bio_done = true;
                    if let Ok(password) = result {
                        cancel_pending(&mut stop_pin, pin.as_mut(), !pin_done).await;
                        eprintln!("Fingerprint accepted.");
                        return Ok(password);
                    }
                    // Pinentry owns the terminal until it finishes. Background
                    // diagnostics must not overwrite its curses display.
                }
                () = &mut cancel => {
                    cancel_pending(&mut stop_pin, pin.as_mut(), !pin_done).await;
                    cancel_pending(&mut stop_bio, bio.as_mut(), !bio_done).await;
                    anyhow::bail!("unlock cancelled");
                }
            }
            if pin_done && bio_done {
                anyhow::bail!(
                    "neither password nor fingerprint unlock succeeded"
                );
            }
        }
    }

    pub fn fingerprint() -> anyhow::Result<()> {
        run(fingerprint_async())
    }

    /// Verifies one of `user`'s enrolled fingers (three tries, 60 seconds),
    /// reporting progress to `feedback`. For rbw-unlockd, which runs as root
    /// and may claim the reader on another user's behalf.
    pub async fn fingerprint_for_user(
        user: &str,
        feedback: &tokio::sync::watch::Sender<
            crate::unlock_ui::FingerprintStatus,
        >,
        cancel: impl Future<Output = ()>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!user.is_empty(), "no user to verify");
        let connection = timeout(CLEANUP_TIMEOUT, Connection::system())
            .await
            .context("connecting to the system bus timed out")??;
        fingerprint_with_feedback(
            connection,
            OPERATION_TIMEOUT,
            false,
            cancel,
            false,
            Some(feedback),
            user,
        )
        .await
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum ScanOutcome {
        Match,
        NoMatch,
        Retry,
    }

    pub(super) fn outcome(
        status: &str,
        done: bool,
    ) -> anyhow::Result<ScanOutcome> {
        match (status, done) {
            ("verify-match", true) => Ok(ScanOutcome::Match),
            ("verify-no-match", true) => Ok(ScanOutcome::NoMatch),
            ("verify-retry-scan" | "verify-swipe-too-short" | "verify-finger-not-centered" | "verify-remove-and-retry" | "verify-too-fast", false) => Ok(ScanOutcome::Retry),
            _ => anyhow::bail!("fingerprint verification returned an unsuccessful or invalid status"),
        }
    }

    async fn notification(
        connection: Option<&Connection>,
        replace_id: u32,
        body: &str,
    ) -> u32 {
        let Some(connection) = connection else {
            return replace_id;
        };
        timeout(Duration::from_secs(2), async {
            let proxy = Proxy::new(
                connection,
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
            )
            .await?;
            proxy
                .call::<_, _, u32>(
                    "Notify",
                    &(
                        "rbw",
                        replace_id,
                        "",
                        "rbw fingerprint confirmation",
                        body,
                        Vec::<&str>::new(),
                        HashMap::<&str, Variant<'_>>::new(),
                        60000_i32,
                    ),
                )
                .await
        })
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(replace_id)
    }

    async fn close_notification(connection: Option<&Connection>, id: u32) {
        if id == 0 {
            return;
        }
        if let Some(connection) = connection {
            let _ = timeout(Duration::from_secs(2), async {
                let proxy = Proxy::new(
                    connection,
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications",
                )
                .await?;
                proxy.call::<_, _, ()>("CloseNotification", &(id,)).await
            })
            .await;
        }
    }

    async fn fingerprint_async() -> anyhow::Result<()> {
        fingerprint_cancelable(
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
            true,
        )
        .await
    }

    async fn fingerprint_cancelable(
        cancel: impl Future<Output = ()>,
        terminal_status: bool,
    ) -> anyhow::Result<()> {
        let connection = timeout(CLEANUP_TIMEOUT, Connection::system())
            .await
            .context("connecting to the system bus timed out")??;
        fingerprint_on_connection(
            connection,
            OPERATION_TIMEOUT,
            true,
            cancel,
            terminal_status,
        )
        .await
    }

    pub(super) async fn fingerprint_on_connection(
        connection: Connection,
        duration: Duration,
        show_notifications: bool,
        cancel: impl Future<Output = ()>,
        terminal_status: bool,
    ) -> anyhow::Result<()> {
        fingerprint_with_feedback(
            connection,
            duration,
            show_notifications,
            cancel,
            terminal_status,
            None,
            "",
        )
        .await
    }

    // `user` is whose fingers to verify; empty means the calling user (a
    // root caller such as rbw-unlockd names the requesting user).
    async fn fingerprint_with_feedback(
        connection: Connection,
        duration: Duration,
        show_notifications: bool,
        cancel: impl Future<Output = ()>,
        terminal_status: bool,
        feedback: Option<
            &tokio::sync::watch::Sender<crate::unlock_ui::FingerprintStatus>,
        >,
        user: &str,
    ) -> anyhow::Result<()> {
        let manager = Proxy::new(
            &connection,
            FPRINT_SERVICE,
            "/net/reactivated/Fprint/Manager",
            "net.reactivated.Fprint.Manager",
        )
        .await?;
        let path: OwnedObjectPath =
            timeout(CLEANUP_TIMEOUT, manager.call("GetDefaultDevice", &()))
                .await
                .context("finding a fingerprint reader timed out")?
                .context("no fingerprint reader available")?;
        let device =
            Proxy::new(&connection, FPRINT_SERVICE, path, FPRINT_DEVICE)
                .await?;
        let notifications = if show_notifications {
            timeout(Duration::from_secs(2), Connection::session())
                .await
                .ok()
                .and_then(Result::ok)
        } else {
            None
        };
        let mut notification_id = 0;
        let mut claimed = false;
        let mut started = false;
        let deadline = Instant::now() + duration;
        let result = tokio::select! {
            result = timeout_at(deadline, verify(&device, &mut claimed, &mut started, notifications.as_ref(), &mut notification_id, terminal_status, feedback, user)) => {
                result.unwrap_or_else(|_| Err(anyhow::anyhow!("fingerprint verification timed out")))
            }
            () = cancel => Err(anyhow::anyhow!("fingerprint verification cancelled")),
        };
        // Cleanup runs outside the scan deadline, including on cancellation.
        // Dropping this dedicated connection also lets fprintd release a claim
        // if a method fails or the process is killed.
        let stopped = if started {
            timeout(
                CLEANUP_TIMEOUT,
                device.call::<_, _, ()>("VerifyStop", &()),
            )
            .await
            .context("stopping fingerprint verification timed out")
            .and_then(|result| {
                result.context("could not stop fingerprint verification")
            })
        } else {
            Ok(())
        };
        let released = if claimed {
            timeout(CLEANUP_TIMEOUT, device.call::<_, _, ()>("Release", &()))
                .await
                .context("releasing fingerprint reader timed out")
                .and_then(|result| {
                    result.context("could not release fingerprint reader")
                })
        } else {
            Ok(())
        };
        close_notification(notifications.as_ref(), notification_id).await;
        result?;
        stopped?;
        released?;
        Ok(())
    }

    async fn verify(
        device: &Proxy<'_>,
        claimed: &mut bool,
        started: &mut bool,
        notifications: Option<&Connection>,
        notification_id: &mut u32,
        terminal_status: bool,
        feedback: Option<
            &tokio::sync::watch::Sender<crate::unlock_ui::FingerprintStatus>,
        >,
        user: &str,
    ) -> anyhow::Result<()> {
        use crate::unlock_ui::FingerprintStatus;
        device
            .call::<_, _, ()>("Claim", &(user,))
            .await
            .context("could not claim fingerprint reader")?;
        *claimed = true;
        if terminal_status {
            eprintln!("Confirm rbw unlock using any enrolled finger (60 second timeout)...");
        }
        for attempt in 0..3 {
            // Subscribe before VerifyStart so even an immediate match cannot
            // be lost. New subscriptions isolate each attempt's signals.
            let mut statuses = device.receive_signal("VerifyStatus").await?;
            let mut fingers =
                device.receive_signal("VerifyFingerSelected").await?;
            *started = true;
            device.call::<_, _, ()>("VerifyStart", &("any",)).await?;
            if let Some(feedback) = feedback {
                feedback.send_replace(FingerprintStatus::Ready);
            }
            *notification_id = notification(
                notifications,
                *notification_id,
                "Touch any enrolled finger to unlock rbw.",
            )
            .await;
            loop {
                tokio::select! {
                    message = statuses.next() => {
                        let message = message.context("fingerprint status stream ended")?;
                        let (status, done): (String, bool) = message.body().deserialize()?;
                        if terminal_status { eprintln!("Fingerprint status: {status}"); }
                        match outcome(&status, done)? {
                            ScanOutcome::Match => {
                                if let Some(feedback) = feedback { feedback.send_replace(FingerprintStatus::Checking); }
                                return Ok(());
                            },
                            ScanOutcome::Retry => { if let Some(feedback) = feedback { feedback.send_replace(FingerprintStatus::Retry); } },
                            ScanOutcome::NoMatch => {
                                if let Some(feedback) = feedback { feedback.send_replace(FingerprintStatus::NoMatch); }
                                break;
                            },
                        }
                    }
                    message = fingers.next() => {
                        let message = message.context("fingerprint selection stream ended")?;
                        let (finger,): (String,) = message.body().deserialize()?;
                        if let Some(feedback) = feedback { feedback.send_replace(FingerprintStatus::selected(&finger)); }
                        if terminal_status { eprintln!("Verifying: {finger}"); }
                        if finger != "any" {
                            *notification_id = notification(notifications, *notification_id, &format!("Touch your {} to unlock rbw.", finger.replace('-', " "))).await;
                        }
                    }
                }
            }
            device.call::<_, _, ()>("VerifyStop", &()).await?;
            *started = false;
            if attempt < 2 && terminal_status {
                eprintln!(
                    "Fingerprint not recognized; touch the reader again."
                );
            }
        }
        anyhow::bail!("fingerprint did not match after three attempts")
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use zeroize::Zeroizing;
    #[test]
    #[ignore = "requires a real unlocked desktop Secret Service"]
    fn live_keyring_roundtrip() {
        keyring_roundtrip(false);
    }

    fn keyring_roundtrip(fingerprint: bool) {
        let id = uuid::Uuid::new_v4().to_string();
        let password = Zeroizing::new(format!(
            "disposable-test-{}\nü\n",
            uuid::Uuid::new_v4()
        ));
        let mut config = crate::config::SecretServiceUnlock {
            id,
            fingerprint,
            store: crate::config::UnlockStore::Keyring,
            secure_boot: false,
            broker: false,
        };
        store(&config, password.as_bytes())
            .expect("store disposable credential");
        let result = unlock(&config).map(Zeroizing::new);
        let removed = remove(&config);
        assert!(removed.is_ok(), "remove disposable credential");
        assert!(remove(&config).is_ok(), "removal is idempotent");
        assert!(result.is_ok(), "lookup disposable credential");
        assert!(
            result.unwrap().as_bytes() == password.as_bytes(),
            "credential bytes must roundtrip unchanged"
        );
        config.fingerprint = false;
        assert!(
            unlock(&config).is_err(),
            "removed credential must fail closed"
        );
    }

    #[test]
    #[ignore = "requires a human touching the enrolled fingerprint reader"]
    fn live_fingerprint_confirmation() {
        keyring_roundtrip(true);
    }

    #[test]
    fn secret_service_config_roundtrip() {
        let config: crate::config::UnlockConfig = serde_yaml::from_str(
            "secretService:\n  id: test-item\n  fingerprint: true\n",
        )
        .unwrap();
        assert!(config.secret_service.as_ref().unwrap().fingerprint);
        let serialized = serde_yaml::to_string(&config).unwrap();
        assert!(serialized.contains("secretService:"));
        assert_eq!(config, serde_yaml::from_str(&serialized).unwrap());
        let defaults: crate::config::UnlockConfig =
            serde_yaml::from_str("{}").unwrap();
        assert!(defaults.secret_service.is_none());
    }

    #[test]
    fn only_terminal_match_authenticates() {
        use native::{outcome, ScanOutcome};
        assert_eq!(
            outcome("verify-match", true).unwrap(),
            ScanOutcome::Match
        );
        assert_eq!(
            outcome("verify-no-match", true).unwrap(),
            ScanOutcome::NoMatch
        );
        for status in [
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
            "verify-too-fast",
        ] {
            assert_eq!(outcome(status, false).unwrap(), ScanOutcome::Retry);
            assert!(outcome(status, true).is_err());
        }
        assert!(outcome("verify-match", false).is_err());
        assert!(outcome("verify-no-match", false).is_err());
        assert!(outcome("verify-unknown-error", true).is_err());
        assert!(outcome("verify-disconnected", true).is_err());
        assert!(outcome("unexpected", false).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "desktop/protocol_tests.rs"]
mod protocol_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "desktop/race_tests.rs"]
mod race_tests;
