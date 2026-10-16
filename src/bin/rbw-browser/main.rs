//! Browser entry point. Native messaging manifests cannot supply arguments.
use std::os::unix::process::CommandExt as _;

fn main() {
    let result = std::env::current_exe().map(|path| {
        let mut command =
            std::process::Command::new(path.with_file_name("rbw"));
        command.arg("native-messaging").env_remove("RUST_LOG");
        if std::env::var_os("RBW_AGENT").is_none() {
            command.env("RBW_AGENT", path.with_file_name("rbw-agent"));
        }
        command.exec()
    });
    eprintln!("failed to start rbw native messaging host: {result:?}");
    std::process::exit(1);
}
