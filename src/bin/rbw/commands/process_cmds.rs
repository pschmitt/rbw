use super::*;

// Locks the active account when one is selected via --account/RBW_ACCOUNT
// (the request carries the account name, and the agent only clears that
// account's keys); with no account selected, or with `--all`, every account
// is locked.
pub fn lock(all: bool) -> anyhow::Result<()> {
    ensure_agent()?;
    if all {
        crate::actions::lock_all()?;
    } else {
        crate::actions::lock()?;
    }

    Ok(())
}

pub fn purge(yes: bool) -> anyhow::Result<()> {
    let account = active_account()?;
    let native_configured = account.unlock.termux.is_some()
        || account.unlock.secret_service.is_some();
    let what = if native_configured {
        "the local database and its configured native unlock credentials"
    } else {
        "the local copy of the password database"
    };
    if !yes
        && !confirm(&format!(
            "Remove {what} for {}?",
            style::name(&account_email(&account)?, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    stop_agent()?;

    remove_db()?;
    termux_remove(true)?;
    secret_service_remove(true)?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

// Replaces the running agent (which locks every account) with this build's.
pub fn restart_agent() -> anyhow::Result<()> {
    check_config()?;
    crate::actions::quit()?;
    run_agent()?;
    check_agent_version()
}

pub fn kill_agent() -> anyhow::Result<()> {
    crate::actions::kill()?;

    Ok(())
}

pub fn inject(
    input: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let ctx = InjectContext::load()?;
    let rendered = ctx.render_input(input)?;

    match output {
        Some(path) => write_rendered_template_file(path, &rendered)?,
        None => {
            std::io::stdout()
                .write_all(rendered.as_bytes())
                .context("failed to write rendered template to stdout")?;
        }
    }

    Ok(())
}

pub fn run(
    env_file: &std::path::Path,
    command: &[OsString],
) -> anyhow::Result<std::process::ExitStatus> {
    let ctx = InjectContext::load()?;
    let env_bindings = ctx.env_bindings_from_file(env_file)?;
    run_inject_command(command, &env_bindings)
}

pub(super) fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

pub(super) fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

pub(super) fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

pub(super) fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}
