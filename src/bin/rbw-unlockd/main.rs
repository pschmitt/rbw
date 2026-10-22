//! rbw-unlockd: holds native unlock credentials for `broker` enrollments
//! and only releases one after fprintd verifies a finger of the user who
//! asks. It runs as root (see `nix/nixos-module.nix`), so the credentials
//! are out of reach of programs running as that user; see `rbw::unlockd`
//! for the protocol.

#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format_timestamp(None)
    .init();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(server::run()));
    if let Err(error) = result {
        log::error!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rbw-unlockd is only supported on Linux");
    std::process::exit(1);
}
