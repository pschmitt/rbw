use futures_util::StreamExt as _;

async fn record_agent_event(operation: &'static str, success: bool) {
    record_event("agent", operation, success, None).await;
}

async fn record_socket_event(
    operation: &'static str,
    success: bool,
    reason: Option<&'static str>,
    client: Option<String>,
) {
    let Ok(config) = rbw::config::Config::load_async().await else {
        log::warn!("audit event could not read rbw configuration");
        return;
    };
    let mut event = rbw::audit::Event::new(
        "local-agent-socket",
        operation,
        if success { "success" } else { "failure" },
    );
    if let Some(reason) = reason {
        event = event.with_reason(reason);
    }
    if let Some(client) = client {
        event = event.with_client(&client);
    }
    rbw::audit::record_async_best_effort(config.audit, event).await;
}

/// The program on the other end of the agent socket, for the audit log:
/// the Nix package and path of its binary (`rbw-2.40.0/bin/rbw`), or the
/// binary's file name. Linux only (`/proc/PID/exe`).
fn peer_program(sock: &mut crate::sock::Sock) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let pid = sock.inner().peer_cred().ok()?.pid()?;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        Some(program_label(&exe))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sock;
        None
    }
}

fn program_label(exe: &std::path::Path) -> String {
    let exe = exe.to_string_lossy();
    // A replaced binary reads as "/path/rbw (deleted)".
    let exe = exe.strip_suffix(" (deleted)").unwrap_or(&exe);
    if let Some(rest) = exe.strip_prefix("/nix/store/") {
        // "<hash>-rbw-2.40.0/bin/rbw" -> "rbw-2.40.0/bin/rbw"
        if let Some((_, package)) = rest.split_once('-') {
            return package.to_owned();
        }
    }
    std::path::Path::new(exe)
        .file_name()
        .map_or_else(|| exe.to_owned(), |name| name.to_string_lossy().into())
}

/// Record an agent event that locked accounts, with a fixed reason label.
pub async fn record_agent_lock(
    operation: &'static str,
    reason: Option<&'static str>,
) {
    record_event("agent", operation, true, reason).await;
}

async fn record_event(
    actor: &'static str,
    operation: &'static str,
    success: bool,
    reason: Option<&'static str>,
) {
    let Ok(config) = rbw::config::Config::load_async().await else {
        log::warn!("audit event could not read rbw configuration");
        return;
    };
    let mut event = rbw::audit::Event::new(
        actor,
        operation,
        if success { "success" } else { "failure" },
    );
    if let Some(reason) = reason {
        event = event.with_reason(reason);
    }
    rbw::audit::record_async_best_effort(config.audit, event).await;
}

/// Record that the agent is stopping, then exit. Written synchronously so
/// the event lands before the process ends.
pub fn stop(
    actor: &'static str,
    reason: &'static str,
    client: Option<&str>,
) -> ! {
    log::info!(
        "agent stopping: {reason}{}",
        client.map(|c| format!(" (by {c})")).unwrap_or_default()
    );
    if let Ok(config) = rbw::config::Config::load() {
        let mut event =
            rbw::audit::Event::new(actor, "agent.stop", "success")
                .with_reason(reason)
                .with_version(env!("CARGO_PKG_VERSION"));
        if let Some(client) = client {
            event = event.with_client(client);
        }
        rbw::audit::record_best_effort(&config.audit, &event);
    }
    std::process::exit(0)
}

// Map a client's quit reason to a fixed label: the audit log never stores
// caller-supplied strings.
fn quit_reason(reason: Option<&str>) -> &'static str {
    match reason {
        None => "unspecified",
        Some("stop_agent") => "stop_agent",
        Some("outdated") => "outdated",
        Some("unresponsive") => "unresponsive",
        Some("config_change") => "config_change",
        Some("purge") => "purge",
        Some("native_unlock_change") => "native_unlock_change",
        Some(_) => "other",
    }
}

pub struct Agent {
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl Agent {
    pub fn new(
        timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self {
            timer_r,
            sync_timer_r,
            state,
        }
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        pub enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Timeout(()),
            Logout,
            Sync(()),
        }

        let notifications = self
            .state
            .lock()
            .await
            .notifications_handler
            .get_channel()
            .await;
        let notifications =
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                notifications,
            )
            .map(|message| match message {
                crate::notifications::Message::Logout => Event::Logout,
                crate::notifications::Message::Sync => Event::Sync(()),
            })
            .boxed();

        let mut stream = futures_util::stream::select_all([
            tokio_stream::wrappers::UnixListenerStream::new(listener)
                .map(Event::Request)
                .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.timer_r,
            )
            .map(Event::Timeout)
            .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.sync_timer_r,
            )
            .map(Event::Sync)
            .boxed(),
            notifications,
        ]);
        while let Some(event) = stream.next().await {
            match event {
                Event::Request(res) => {
                    let stream = match res {
                        Ok(stream) => stream,
                        Err(e) => {
                            // a failed accept (e.g. EMFILE) shouldn't kill
                            // the whole agent; keep serving other events
                            log::warn!(
                                "failed to accept incoming connection: {e}"
                            );
                            continue;
                        }
                    };
                    let mut sock = crate::sock::Sock::new(stream);
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let res =
                            handle_request(&mut sock, state.clone()).await;
                        if let Err(e) = res {
                            // The client may already be gone (e.g. it was
                            // interrupted with Ctrl+C while we were prompting
                            // for a pin), in which case sending the error will
                            // itself fail; there's nothing useful to do but
                            // log it.
                            if let Err(send_err) = sock
                                .send(&rbw::protocol::Response::Error {
                                    error: format!("{e:#}"),
                                })
                                .await
                            {
                                log::warn!(
                                    "failed to send error to client: {send_err:#}"
                                );
                            }
                        }
                    });
                }
                Event::Timeout(()) => {
                    self.state.lock().await.clear();
                    tokio::spawn(record_agent_event(
                        "agent.timeout_lock",
                        true,
                    ));
                }
                Event::Logout => {
                    self.state.lock().await.clear();
                    tokio::spawn(record_agent_event(
                        "agent.server_logout",
                        true,
                    ));
                }
                Event::Sync(()) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // Syncs every configured account; failures (e.g.
                        // accounts we aren't logged in to) are logged and
                        // skipped inside sync_all.
                        let success = crate::actions::sync_all(state).await;
                        record_agent_event("agent.sync", success).await;
                    });
                    self.state.lock().await.set_sync_timeout();
                }
            }
        }
        Ok(())
    }
}

fn socket_audit_operation(
    action: &rbw::protocol::Action,
) -> Option<&'static str> {
    use rbw::protocol::Action;

    Some(match action {
        Action::Register { .. } => "socket.register",
        Action::Login { .. } => "socket.login",
        Action::Unlock { .. } => "socket.unlock",
        Action::CheckLock | Action::Version | Action::Quit { .. } => {
            return None
        }
        Action::Lock => "socket.lock",
        Action::Sync => "socket.sync",
        Action::PurgeVault { .. } => "socket.purge_vault",
        Action::ChangePassword { .. } => "socket.change_password",
        Action::ChangeKdf { .. } => "socket.change_kdf",
        Action::RotateKey { .. } => "socket.rotate_key",
        Action::CreateOrg { .. } => "socket.create_org",
        Action::ConfirmOrgUser { .. } => "socket.confirm_org_user",
        Action::DeleteOrg { .. } => "socket.delete_org",
        Action::Decrypt { .. } => "socket.decrypt",
        Action::DecryptBatch { .. } => "socket.decrypt_batch",
        Action::DecryptAttachment { .. } => "socket.decrypt_attachment",
        Action::EncryptAttachment { .. } => "socket.encrypt_attachment",
        Action::Encrypt { .. } => "socket.encrypt",
        Action::VerifyMasterPassword { .. } => {
            "socket.verify_master_password"
        }
        Action::CryptBytes { .. } => "socket.crypt_bytes",
        Action::ClipboardStore { .. } => "socket.clipboard_store",
    })
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let req = sock.recv().await?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let (action, environment, account_name) = req.into_parts();
    let audit_operation = socket_audit_operation(&action);
    let audit_reason =
        matches!(action, rbw::protocol::Action::Lock).then(|| {
            if account_name.is_some() {
                "one_account"
            } else {
                "all_accounts"
            }
        });
    let audit_client = audit_reason.and_then(|_| peer_program(sock));
    // Resolve the target account (by name, or the primary account when the
    // client didn't specify one) and run the whole dispatch within its scope
    // so that any server-bound lib call targets that account's server.
    let dispatch_result = async {
        let account =
            crate::actions::resolve_account(account_name.as_deref()).await?;
        let mut operation_succeeded = true;
        let set_timeout = rbw::actions::AGENT_ACCOUNT
            .scope(
                account.clone(),
                dispatch(
                    action,
                    sock,
                    state.clone(),
                    &environment,
                    &account,
                    account_name.as_deref(),
                    &mut operation_succeeded,
                ),
            )
            .await?;
        Ok::<_, anyhow::Error>((set_timeout, operation_succeeded))
    }
    .await;
    if let Some(operation) = audit_operation {
        let succeeded = dispatch_result
            .as_ref()
            .is_ok_and(|(_, succeeded)| *succeeded);
        tokio::spawn(record_socket_event(
            operation,
            succeeded,
            audit_reason,
            audit_client,
        ));
    }
    let (set_timeout, _) = dispatch_result?;

    let mut state = state.lock().await;
    state.set_last_environment(environment);
    if set_timeout {
        state.set_timeout();
    }

    Ok(())
}

async fn dispatch(
    action: rbw::protocol::Action,
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    account: &rbw::config::Account,
    // The account name as the client sent it: `None` means the client didn't
    // select an account (which `account` above resolves to the primary one).
    // `Lock` uses the distinction to decide between locking one account and
    // locking all of them.
    requested_account: Option<&str>,
    operation_succeeded: &mut bool,
) -> anyhow::Result<bool> {
    let set_timeout = match action {
        rbw::protocol::Action::Register {
            mut client_id,
            mut client_secret,
        } => {
            // Same locked-memory + zeroize treatment as `Unlock`'s password.
            let locked_client_id = client_id.as_deref().map(|s| {
                let mut v = rbw::locked::Vec::new();
                v.extend(s.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut s) = client_id {
                zeroize::Zeroize::zeroize(s);
            }
            let locked_client_secret = client_secret.as_deref().map(|s| {
                let mut v = rbw::locked::Vec::new();
                v.extend(s.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut s) = client_secret {
                zeroize::Zeroize::zeroize(s);
            }

            crate::actions::register(
                sock,
                environment,
                account,
                locked_client_id.as_ref(),
                locked_client_secret.as_ref(),
            )
            .await?;
            true
        }
        rbw::protocol::Action::Login { mut password, totp } => {
            // Same locked-memory + zeroize treatment as `Unlock`'s password.
            let locked_password = password.as_deref().map(|p| {
                let mut v = rbw::locked::Vec::new();
                v.extend(p.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut p) = password {
                zeroize::Zeroize::zeroize(p);
            }

            crate::actions::login(
                sock,
                state.clone(),
                environment,
                locked_password.as_ref(),
                totp.as_deref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::Unlock { mut password } => {
            // Copy the password into locked memory, then zeroize
            // the original String
            let locked_password = password.as_deref().map(|p| {
                let mut v = rbw::locked::Vec::new();
                v.extend(p.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut p) = password {
                zeroize::Zeroize::zeroize(p);
            }

            crate::actions::unlock(
                sock,
                state.clone(),
                environment,
                locked_password.as_ref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(sock, state.clone(), account).await?;
            false
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone(), requested_account)
                .await?;
            false
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(Some(sock), state.clone(), account).await?;
            false
        }
        rbw::protocol::Action::PurgeVault { mut password } => {
            // Same locked-memory + zeroize treatment as `Unlock`'s password.
            let locked_password = password.as_deref().map(|p| {
                let mut v = rbw::locked::Vec::new();
                v.extend(p.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut p) = password {
                zeroize::Zeroize::zeroize(p);
            }

            crate::actions::purge_vault(
                sock,
                state.clone(),
                environment,
                locked_password.as_ref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::ChangePassword {
            current_password,
            new_password,
            hint,
            rotate_key,
        } => {
            let current_password = locked_password(current_password);
            let new_password = locked_password(new_password);
            crate::actions::change_master_key(
                sock,
                state.clone(),
                &current_password,
                crate::actions::MasterKeyChange::Password {
                    new_password: &new_password,
                    hint: hint.as_deref(),
                    rotate_key,
                },
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::ChangeKdf {
            password,
            kdf,
            iterations,
            memory,
            parallelism,
        } => {
            let password = locked_password(password);
            let kdf = match kdf {
                0 => rbw::api::KdfType::Pbkdf2,
                1 => rbw::api::KdfType::Argon2id,
                _ => anyhow::bail!("unknown kdf type {kdf}"),
            };
            crate::actions::change_master_key(
                sock,
                state.clone(),
                &password,
                crate::actions::MasterKeyChange::Kdf(
                    rbw::actions::KdfSettings {
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                    },
                ),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::RotateKey { password } => {
            let password = locked_password(password);
            crate::actions::change_master_key(
                sock,
                state.clone(),
                &password,
                crate::actions::MasterKeyChange::RotateKey,
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::CreateOrg { name } => {
            crate::actions::create_org(sock, state.clone(), account, &name)
                .await?;
            true
        }
        rbw::protocol::Action::ConfirmOrgUser {
            org_id,
            user_id,
            public_key_der_b64,
        } => {
            crate::actions::confirm_org_user(
                sock,
                state.clone(),
                account,
                &org_id,
                &user_id,
                &public_key_der_b64,
            )
            .await?;
            true
        }
        rbw::protocol::Action::DeleteOrg {
            org_id,
            mut password,
        } => {
            // Same locked-memory + zeroize treatment as `Unlock`'s password.
            let locked_password = password.as_deref().map(|p| {
                let mut v = rbw::locked::Vec::new();
                v.extend(p.as_bytes().iter().copied());
                rbw::locked::Password::new(v)
            });
            if let Some(ref mut p) = password {
                zeroize::Zeroize::zeroize(p);
            }

            crate::actions::delete_org(
                sock,
                state.clone(),
                environment,
                locked_password.as_ref(),
                account,
                &org_id,
            )
            .await?;
            true
        }
        rbw::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
            attachment_key,
        } => {
            crate::actions::decrypt(
                sock,
                state.clone(),
                environment,
                &cipherstring,
                entry_key.as_deref(),
                org_id.as_deref(),
                attachment_key.as_deref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::DecryptBatch { entries } => {
            *operation_succeeded = crate::actions::decrypt_batch(
                sock,
                state.clone(),
                environment,
                &entries,
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::DecryptAttachment {
            data,
            attachment_key,
            entry_key,
            org_id,
        } => {
            crate::actions::decrypt_attachment(
                sock,
                state.clone(),
                &data,
                attachment_key.as_deref(),
                entry_key.as_deref(),
                org_id.as_deref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::EncryptAttachment {
            data,
            filename,
            entry_key,
            org_id,
        } => {
            crate::actions::encrypt_attachment(
                sock,
                state.clone(),
                &data,
                &filename,
                entry_key.as_deref(),
                org_id.as_deref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::Encrypt {
            plaintext,
            entry_key,
            org_id,
        } => {
            crate::actions::encrypt(
                sock,
                state.clone(),
                &plaintext,
                entry_key.as_deref(),
                org_id.as_deref(),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::VerifyMasterPassword { password } => {
            let password = zeroize::Zeroizing::new(password);
            anyhow::ensure!(password.len() <= 4096, "password too long");
            let mut bytes = rbw::locked::Vec::new();
            bytes.extend(password.as_bytes().iter().copied());
            crate::actions::verify_master_password(
                sock,
                &rbw::locked::Password::new(bytes),
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::CryptBytes { data, decrypt } => {
            crate::actions::crypt_bytes(
                sock,
                state.clone(),
                &data,
                decrypt,
                account,
            )
            .await?;
            true
        }
        rbw::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(sock, state.clone(), &text)
                .await?;
            true
        }
        rbw::protocol::Action::Quit { reason } => {
            let client = peer_program(sock);
            stop(
                "local-agent-socket",
                quit_reason(reason.as_deref()),
                client.as_deref(),
            )
        }
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            false
        }
    };

    Ok(set_timeout)
}

// Moves a password received over the socket into locked memory and zeroizes
// the original, like `PurgeVault`/`Unlock` do inline.
fn locked_password(mut password: String) -> rbw::locked::Password {
    let mut v = rbw::locked::Vec::new();
    v.extend(password.as_bytes().iter().copied());
    zeroize::Zeroize::zeroize(&mut password);
    rbw::locked::Password::new(v)
}

#[cfg(test)]
mod audit_tests {
    use super::socket_audit_operation;
    use rbw::protocol::Action;

    #[test]
    fn socket_audit_uses_fixed_labels_and_skips_status_probes() {
        assert_eq!(socket_audit_operation(&Action::CheckLock), None);
        assert_eq!(socket_audit_operation(&Action::Version), None);
        assert_eq!(
            socket_audit_operation(&Action::Quit { reason: None }),
            None
        );
        let all_succeeded = Ok::<_, anyhow::Error>((false, true));
        let partial_failure = Ok::<_, anyhow::Error>((false, false));
        assert!(all_succeeded
            .as_ref()
            .is_ok_and(|(_, succeeded)| *succeeded));
        assert!(!partial_failure
            .as_ref()
            .is_ok_and(|(_, succeeded)| *succeeded));
        let login = Action::Login {
            password: Some("sensitive-password".to_owned()),
            totp: Some("sensitive-code".to_owned()),
        };
        let operation = socket_audit_operation(&login).unwrap();
        assert_eq!(operation, "socket.login");
        let serialized = serde_json::to_string(&rbw::audit::Event::new(
            "local-agent-socket",
            operation,
            "failure",
        ))
        .unwrap();
        assert!(!serialized.contains("sensitive-password"));
        assert!(!serialized.contains("sensitive-code"));
        assert_eq!(
            socket_audit_operation(&Action::Decrypt {
                cipherstring: "sensitive-ciphertext".to_owned(),
                entry_key: Some("sensitive-key".to_owned()),
                org_id: None,
                attachment_key: None,
            }),
            Some("socket.decrypt")
        );
    }

    #[test]
    fn quit_reasons_are_fixed_labels() {
        assert_eq!(super::quit_reason(None), "unspecified");
        assert_eq!(super::quit_reason(Some("outdated")), "outdated");
        assert_eq!(super::quit_reason(Some("stop_agent")), "stop_agent");
        assert_eq!(
            super::quit_reason(Some("anything else, verbatim")),
            "other"
        );
    }

    #[test]
    fn program_labels_drop_the_store_hash() {
        use std::path::Path;
        assert_eq!(
            super::program_label(Path::new(
                "/nix/store/489pyl2di4qghgxxj3k12m9shms5j1cz-rbw-2.40.0/bin/rbw"
            )),
            "rbw-2.40.0/bin/rbw"
        );
        assert_eq!(
            super::program_label(Path::new("/usr/local/bin/rbw (deleted)")),
            "rbw"
        );
    }
}
