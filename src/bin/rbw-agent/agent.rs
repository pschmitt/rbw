use futures_util::StreamExt as _;

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
                crate::notifications::Message::Logout => Event::Timeout(()),
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
                }
                Event::Sync(()) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // Syncs every configured account; failures (e.g.
                        // accounts we aren't logged in to) are logged and
                        // skipped inside sync_all.
                        crate::actions::sync_all(state).await;
                    });
                    self.state.lock().await.set_sync_timeout();
                }
            }
        }
        Ok(())
    }
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
    // Resolve the target account (by name, or the primary account when the
    // client didn't specify one) and run the whole dispatch within its scope
    // so that any server-bound lib call targets that account's server.
    let account =
        crate::actions::resolve_account(account_name.as_deref()).await?;
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
            ),
        )
        .await?;

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
            crate::actions::decrypt_batch(
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
        rbw::protocol::Action::Encrypt { plaintext, org_id } => {
            crate::actions::encrypt(
                sock,
                state.clone(),
                &plaintext,
                org_id.as_deref(),
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
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            false
        }
    };

    Ok(set_timeout)
}
