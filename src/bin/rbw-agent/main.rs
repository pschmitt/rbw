use anyhow::Context as _;

mod actions;
mod agent;
mod api;
mod daemon;
mod debugger;
mod notifications;
mod reexec;
mod sock;
mod ssh_agent;
mod state;
mod timeout;
#[cfg(feature = "fido2")]
mod webauthn;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
    inherited: Option<crate::reexec::Inherited>,
) -> anyhow::Result<()> {
    let reexec = inherited.is_some();
    let (listener, connections, handover) = match inherited {
        // Took over from an agent that exec'd this binary: its socket, the
        // connections it held while draining and its unlocked keys.
        Some(inherited) => {
            inherited.listener.set_nonblocking(true)?;
            let listener =
                tokio::net::UnixListener::from_std(inherited.listener)?;
            let connections = inherited
                .connections
                .into_iter()
                .map(|stream| {
                    stream.set_nonblocking(true)?;
                    tokio::net::UnixStream::from_std(stream)
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            (listener, connections, inherited.handover)
        }
        None => (crate::sock::listen()?, Vec::new(), None),
    };
    crate::reexec::set_listener(&listener);

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = rbw::config::Config::load()?;
    let mut start = rbw::audit::Event::new("agent", "agent.start", "success")
        .with_version(env!("CARGO_PKG_VERSION"));
    if reexec {
        start = start.with_reason(if handover.is_some() {
            "reexec"
        } else {
            "reexec_locked"
        });
    }
    rbw::audit::record_async_best_effort(config.audit.clone(), start).await;
    tokio::spawn(stop_on_signal());
    let timeout_duration =
        std::time::Duration::from_secs(config.agent.lock_timeout);
    let sync_timeout_duration =
        std::time::Duration::from_secs(config.agent.sync_interval);
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
    if sync_timeout_duration > std::time::Duration::ZERO {
        sync_timeout.set(sync_timeout_duration);
    }
    let notifications_handler = crate::notifications::Handler::new();
    let state =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::state::State {
            accounts: std::collections::HashMap::new(),
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            last_environment: rbw::protocol::Environment::from_process(
                std::env::var_os("RBW_TTY"),
            ),
            #[cfg(feature = "clipboard")]
            clipboard: arboard::Clipboard::new()
                .inspect_err(|e| {
                    log::warn!("couldn't create clipboard context: {e}");
                })
                .ok(),
        }));

    if let Some(handover) = handover {
        let mut keys = state.lock().await;
        if !handover.accounts.is_empty() {
            keys.accounts = handover.accounts;
            // The rest of the old agent's lock timeout (all of it if none
            // was running, which an unlocked agent always has).
            keys.timeout.set(
                handover.lock_remaining.unwrap_or(keys.timeout_duration),
            );
            log::info!(
                "took over {} unlocked account(s)",
                keys.accounts.len()
            );
            tokio::spawn(resubscribe(state.clone()));
        }
    }
    for stream in connections {
        crate::agent::serve(stream, state.clone());
    }

    let agent =
        crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::spawn(crate::api::supervise(state.clone()));

    tokio::try_join!(agent.run(listener), ssh_agent.run())?;

    Ok(())
}

// The old agent's push-notification connection ended with it; reconnect
// for the primary account (as unlocking does) instead of waiting for the
// next sync.
async fn resubscribe(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) {
    let Ok(account) = crate::actions::resolve_account(None).await else {
        return;
    };
    if state.lock().await.needs_unlock(&account.name) {
        return;
    }
    if let Err(e) =
        crate::actions::subscribe_to_notifications(state, &account).await
    {
        log::warn!("failed to subscribe to notifications: {e:#}");
    }
}

// Record why the agent ends when a signal stops it (a service stop or
// restart, a reboot, Ctrl+C with --no-daemonize). SIGKILL can't be caught;
// the next start without a stop record shows it.
async fn stop_on_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        log::warn!("failed to install signal handlers");
        return;
    };
    let reason = tokio::select! {
        _ = term.recv() => "sigterm",
        _ = int.recv() => "sigint",
        _ = hup.recv() => "sighup",
    };
    crate::agent::stop("agent", reason, None);
}

fn real_main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let first = std::env::args().nth(1);
    let no_daemonize = first.as_deref() == Some("--no-daemonize");

    rbw::dirs::make_all()?;

    // Exec'd in place by the running agent (`reexec`): already a daemon
    // (or not, as before), with the same pid; only the pid file lock
    // went with the old binary's fds.
    let (startup_ack, inherited) = if first.as_deref() == Some(reexec::ARG) {
        let fds = std::env::args().nth(2).unwrap_or_default();
        let inherited = reexec::inherit(&fds)?;
        daemon::lock_pid_file(true).context("failed to lock pid file")?;
        (None, Some(inherited))
    } else {
        let startup_ack =
            daemon::daemonize(no_daemonize).context("failed to daemonize")?;
        (startup_ack, None)
    };

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) = tokio_main(startup_ack, inherited).await {
            // this unwrap is fine because it's the only real option here
            w.send(e).unwrap();
        }
    });

    if let Ok(e) = r.recv() {
        return Err(e);
    }

    Ok(())
}

fn main() {
    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
