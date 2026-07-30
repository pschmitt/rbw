// OSC 52 ("Operating System Command 52") lets an application ask the
// terminal emulator itself to set the system clipboard, by writing a
// specially-formatted escape sequence to its own stdout. Unlike the
// `arboard`-based system clipboard (see `rbw-agent`'s `state::clipboard`),
// this works over a plain SSH session, inside containers, and anywhere else
// the process has no direct X11/Wayland/pasteboard access -- as long as the
// *terminal emulator* on the other end supports OSC 52 (most modern ones
// do: xterm, kitty, alacritty, wezterm, foot, iTerm2, VTE-based terminals,
// and both tmux and GNU screen once passed through). See
// `rbw::config::ClipboardMechanism`.
//
// Terminals that don't understand OSC 52 simply ignore the escape sequence.
// Keep ordinary redirected output clean, but allow it for SSH sessions: an
// `ssh host rbw get ... --clipboard` command commonly has no remote PTY even
// though its stdout still goes directly to the local terminal emulator.

use std::io::Write as _;

use is_terminal::IsTerminal as _;

// GNU screen refuses to forward any single DCS passthrough sequence longer
// than this many bytes; xterm/tmux/etc. have no such limit, but chunking is
// harmless for them too, so this is only used when wrapping for screen.
const SCREEN_CHUNK_LIMIT: usize = 750;

pub fn copy(text: &str) -> anyhow::Result<()> {
    if !std::io::stdout().is_terminal() && !is_ssh_session() {
        return Err(anyhow::anyhow!(
            "stdout is not a terminal or SSH session, can't use OSC 52 to set the clipboard"
        ));
    }

    let sequence = wrap_for_multiplexer(&format!(
        "\x1b]52;c;{}\x07",
        rbw::base64::encode(text.as_bytes())
    ));

    let mut stdout = std::io::stdout();
    stdout.write_all(sequence.as_bytes())?;
    stdout.flush()?;

    Ok(())
}

fn is_ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .into_iter()
        .any(|name| {
            std::env::var_os(name).is_some_and(|value| !value.is_empty())
        })
}

// tmux and GNU screen both intercept escape sequences from the programs
// they host instead of passing them straight through to the real terminal,
// so OSC 52 has to be wrapped in a multiplexer-specific "passthrough" (DCS)
// sequence to reach the terminal underneath. Detected via the same
// environment variables tmux/screen themselves set (`$TMUX`, `$STY`) rather
// than `$TERM`, since `$TERM` is frequently overridden independently of
// whether a multiplexer is actually in use (e.g. set to "tmux-256color"
// outside of a real tmux session, or "xterm-256color" inside one).
fn wrap_for_multiplexer(sequence: &str) -> String {
    if std::env::var_os("TMUX").is_some() {
        // Each embedded ESC must be doubled for tmux to pass it through
        // literally instead of interpreting it itself.
        format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
    } else if std::env::var_os("STY").is_some() {
        // GNU screen wants the same doubled-ESC treatment, but also caps
        // each DCS passthrough at roughly 750 bytes, so long payloads have
        // to be split across multiple DCS blocks.
        sequence
            .replace('\x1b', "\x1b\x1b")
            .as_bytes()
            .chunks(SCREEN_CHUNK_LIMIT)
            .fold(String::new(), |mut acc, chunk| {
                // Safe: the payload is entirely ASCII (base64 plus our own
                // escape bytes), so chunk boundaries always fall on
                // character boundaries.
                use std::fmt::Write as _;
                let _ = write!(
                    acc,
                    "\x1bP{}\x1b\\",
                    String::from_utf8_lossy(chunk)
                );
                acc
            })
    } else {
        sequence.to_string()
    }
}

#[cfg(test)]
mod test {
    use super::{is_ssh_session, wrap_for_multiplexer};

    // Serializes tests that mutate `$TMUX`/`$STY`, since env vars are
    // process-global and `cargo test` runs tests in parallel by default.
    // Mirrors the same pattern used in `commands.rs`'s env-var tests.
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    fn with_multiplexer_env<T>(
        tmux: Option<&str>,
        sty: Option<&str>,
        f: impl FnOnce() -> T,
    ) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();

        match tmux {
            Some(v) => std::env::set_var("TMUX", v),
            None => std::env::remove_var("TMUX"),
        }
        match sty {
            Some(v) => std::env::set_var("STY", v),
            None => std::env::remove_var("STY"),
        }

        let result = f();

        std::env::remove_var("TMUX");
        std::env::remove_var("STY");

        result
    }

    fn with_ssh_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();
        let old_values = [
            ("SSH_CONNECTION", std::env::var_os("SSH_CONNECTION")),
            ("SSH_CLIENT", std::env::var_os("SSH_CLIENT")),
            ("SSH_TTY", std::env::var_os("SSH_TTY")),
        ];

        for (name, _) in &old_values {
            std::env::remove_var(name);
        }
        if let Some(value) = value {
            std::env::set_var("SSH_CONNECTION", value);
        }

        let result = f();

        for (name, value) in old_values {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }

        result
    }

    #[test]
    fn ssh_session_is_detected_without_a_pty() {
        with_ssh_env(Some("192.0.2.1 192.0.2.2 22 54321"), || {
            assert!(is_ssh_session());
        });
    }

    #[test]
    fn empty_ssh_environment_is_not_a_session() {
        with_ssh_env(None, || {
            assert!(!is_ssh_session());
        });
    }

    // With no multiplexer detected, the sequence passes through unchanged.
    #[test]
    fn wrap_passthrough_outside_multiplexer() {
        with_multiplexer_env(None, None, || {
            assert_eq!(
                wrap_for_multiplexer("\x1b]52;c;AA==\x07"),
                "\x1b]52;c;AA==\x07"
            );
        });
    }

    // Under tmux, the whole sequence is wrapped in a tmux DCS passthrough,
    // with the single embedded ESC doubled.
    #[test]
    fn wrap_doubles_escape_under_tmux() {
        with_multiplexer_env(
            Some("/tmp/tmux-1000/default,1234,0"),
            None,
            || {
                assert_eq!(
                    wrap_for_multiplexer("\x1b]52;c;AA==\x07"),
                    "\x1bPtmux;\x1b\x1b]52;c;AA==\x07\x1b\\"
                );
            },
        );
    }

    // Under GNU screen, a short sequence still gets a single DCS wrapper
    // (chunking only kicks in past `SCREEN_CHUNK_LIMIT` bytes).
    #[test]
    fn wrap_doubles_escape_under_screen() {
        with_multiplexer_env(None, Some("1234.pts-0.host"), || {
            assert_eq!(
                wrap_for_multiplexer("\x1b]52;c;AA==\x07"),
                "\x1bP\x1b\x1b]52;c;AA==\x07\x1b\\"
            );
        });
    }

    // `TMUX` takes priority if (implausibly) both are set.
    #[test]
    fn tmux_takes_priority_over_screen() {
        with_multiplexer_env(
            Some("/tmp/tmux-1000/default,1234,0"),
            Some("1234.pts-0.host"),
            || {
                assert!(wrap_for_multiplexer("\x1b]52;c;AA==\x07")
                    .starts_with("\x1bPtmux;"));
            },
        );
    }

    // A payload long enough to cross `SCREEN_CHUNK_LIMIT` is split across
    // multiple DCS blocks under screen.
    #[test]
    fn wrap_chunks_long_payload_under_screen() {
        with_multiplexer_env(None, Some("1234.pts-0.host"), || {
            let long_payload = format!(
                "\x1b]52;c;{}\x07",
                "A".repeat(super::SCREEN_CHUNK_LIMIT * 2)
            );
            let wrapped = wrap_for_multiplexer(&long_payload);
            assert!(wrapped.matches("\x1bP").count() > 1);
            assert!(wrapped.ends_with("\x1b\\"));
        });
    }
}
