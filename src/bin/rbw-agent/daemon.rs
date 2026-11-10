use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

// Lock the pid file and write this process's pid into it. `reexec`: this
// process was exec'd in place by the agent, which may have held the lock
// on an fd that survived the exec; a pid file naming this process then
// counts as locked.
pub fn lock_pid_file(reexec: bool) -> anyhow::Result<()> {
    let mut pidfile = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666)
        .open(rbw::dirs::pid_file())
        .context("failed to open pid file")?;
    if let Err(e) = rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        let mut pid = String::new();
        let ours = reexec
            && e == rustix::io::Errno::WOULDBLOCK
            && std::io::Read::read_to_string(&mut pidfile, &mut pid).is_ok()
            && pid.trim() == std::process::id().to_string();
        if ours {
            return Ok(());
        }
        return Err(e).context("failed to lock pid file");
    }
    pidfile.set_len(0).context("failed to write pid file")?;
    writeln!(pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    // don't close the pidfile until the process exits, to ensure it
    // stays locked
    std::mem::forget(pidfile);
    Ok(())
}

pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        lock_pid_file(false)?;
        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    let daemonize = daemonix::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonix::Outcome::Parent(_) => {
            drop(w);
            let mut buf = [0; 1];
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            rustix::io::read(&r, &mut buf).unwrap();
            drop(r);
            std::process::exit(0);
        }
        daemonix::Outcome::Child(res) => res,
    };

    drop(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            // XXX super gross, but daemonize removed the ability to match
            // on specific error types for some reason?
            if e.to_string().contains("unable to lock pid file") {
                // this means that there is already an agent running, so
                // return a special exit code to allow the cli to detect
                // this case and not error out
                std::process::exit(23);
            }
            panic!("failed to daemonize: {e}");
        }
    }

    Ok(Some(StartupAck { writer: w }))
}
