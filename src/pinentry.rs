use crate::prelude::*;

use std::convert::TryFrom as _;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub async fn getpin(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
    // When present, this is the client connection that requested the pin. If
    // the client goes away (e.g. the user hits Ctrl+C in the rbw process)
    // while we're waiting for the pin, we interrupt pinentry rather than
    // leaving it as an orphan competing for the terminal. See
    // https://github.com/doy/rbw/issues/352.
    cancel: Option<&mut tokio::net::UnixStream>,
) -> Result<crate::locked::Password> {
    let mut opts = tokio::process::Command::new(pinentry);
    opts.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut args = vec!["--timeout".into(), "0".into()];
    if let Some(tty) = environment.tty() {
        args.extend(["--ttyname".into(), tty.into()]);
    }

    let env_vars = environment.env_vars();
    // Not all pinentry appear to respect the --display flag, so we also keep the environment
    // variable.
    if let Some(display) =
        env_vars.get(std::ffi::OsString::from("DISPLAY").as_os_str())
    {
        args.extend(["--display".into(), display.clone()]);
    }
    if !grab {
        args.push("--no-global-grab".into());
    }
    opts.args(args);

    for env_var in &*crate::protocol::ENVIRONMENT_VARIABLES_OS {
        if let Some(val) = env_vars.get(env_var) {
            opts.env(env_var, val);
        } else {
            opts.env_remove(env_var);
        }
    }
    opts.envs(env_vars);

    let mut child = opts.spawn().map_err(|source| Error::Spawn { source })?;
    // unwrap is safe because we specified stdin as piped in the command opts
    // above
    let mut stdin = child.stdin.take().unwrap();

    let mut ncommands = 1;
    stdin
        .write_all(b"SETTITLE rbw\n")
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    stdin
        .write_all(format!("SETPROMPT {prompt}\n").as_bytes())
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    stdin
        .write_all(format!("SETDESC {desc}\n").as_bytes())
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    if let Some(err) = err {
        stdin
            .write_all(format!("SETERROR {err}\n").as_bytes())
            .await
            .map_err(|source| Error::WriteStdin { source })?;
        ncommands += 1;
    }
    stdin
        .write_all(b"GETPIN\n")
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    drop(stdin);

    let mut buf = crate::locked::Vec::new();
    buf.zero();
    // unwrap is safe because we specified stdout as piped in the command opts
    // above. Take it out of the child so that the cancellation branch below is
    // free to borrow the child (to signal and reap it) without conflicting
    // with the in-flight read.
    let mut stdout = child.stdout.take().unwrap();
    let len = if let Some(cancel) = cancel {
        tokio::select! {
            res = read_password(ncommands, buf.data_mut(), &mut stdout) => {
                res?
            }
            () = wait_for_client_disconnect(cancel) => {
                // The client that asked for this pin is gone. Interrupt
                // pinentry so it stops reading the terminal, then reap it.
                interrupt_pinentry(&child);
                let _ = child.wait().await;
                return Err(Error::PinentryCancelled);
            }
        }
    } else {
        read_password(ncommands, buf.data_mut(), &mut stdout).await?
    };
    buf.truncate(len);

    child
        .wait()
        .await
        .map_err(|source| Error::PinentryWait { source })?;

    Ok(crate::locked::Password::new(buf))
}

// Resolves once the client connection is closed (EOF) or otherwise
// unreadable. The client isn't expected to send anything while we prompt for
// a pin, so any data it does send is ignored and we keep waiting.
async fn wait_for_client_disconnect(sock: &mut tokio::net::UnixStream) {
    let mut buf = [0u8; 64];
    loop {
        match sock.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

// Send SIGINT (rather than killing outright) so that terminal-based pinentry
// programs get a chance to restore the terminal before exiting, mirroring
// what would happen if the user had pressed Ctrl+C at the pinentry prompt.
fn interrupt_pinentry(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: calling kill with a valid pid and signal number has no
            // memory-safety implications.
            unsafe {
                libc::kill(pid, libc::SIGINT);
            }
        }
    }
}

async fn read_password<R>(
    mut ncommands: u8,
    data: &mut [u8],
    mut r: R,
) -> Result<usize>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin + Send,
{
    let mut len = 0;
    loop {
        let nl = data.iter().take(len).position(|c| *c == b'\n');
        if let Some(nl) = nl {
            if data.starts_with(b"OK") {
                if ncommands == 1 {
                    len = 0;
                    break;
                }
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
                ncommands -= 1;
            } else if data.starts_with(b"D ") {
                data.copy_within(2..nl, 0);
                len = nl - 2;
                break;
            } else if data.starts_with(b"S ") {
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
            } else if data.starts_with(b"ERR ") {
                let line: Vec<u8> = data.iter().take(nl).copied().collect();
                let line = String::from_utf8(line).unwrap();
                let mut split = line.splitn(3, ' ');
                let _ = split.next(); // ERR
                let code = split.next();
                match code {
                    Some("83886179") => {
                        return Err(Error::PinentryCancelled);
                    }
                    Some(code) => {
                        if let Some(error) = split.next() {
                            return Err(Error::PinentryErrorMessage {
                                error: error.to_string(),
                            });
                        }
                        return Err(Error::PinentryErrorMessage {
                            error: format!("unknown error ({code})"),
                        });
                    }
                    None => {
                        return Err(Error::PinentryErrorMessage {
                            error: "unknown error".to_string(),
                        });
                    }
                }
            } else {
                return Err(Error::FailedToParsePinentry {
                    out: String::from_utf8_lossy(data)
                        .trim_end_matches('\0')
                        .to_string(),
                });
            }
        } else {
            let bytes = r
                .read(&mut data[len..])
                .await
                .map_err(|source| Error::PinentryReadOutput { source })?;
            if bytes == 0 {
                return Err(Error::PinentryReadOutput {
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ),
                });
            }
            len += bytes;
        }
    }

    len = percent_decode(&mut data[..len]);

    Ok(len)
}

// not using the percent-encoding crate because it doesn't provide a way to do
// this in-place, and we want the password to always live within the locked
// vec. should really move something like this into the percent-encoding crate
// at some point.
fn percent_decode(buf: &mut [u8]) -> usize {
    let mut read_idx = 0;
    let mut write_idx = 0;
    let len = buf.len();

    while read_idx < len {
        let mut c = buf[read_idx];

        if c == b'%' && read_idx + 2 < len {
            if let Some(h) = char::from(buf[read_idx + 1]).to_digit(16) {
                if let Some(l) = char::from(buf[read_idx + 2]).to_digit(16) {
                    // h and l were parsed from a single hex digit, so they
                    // must be in the range 0-15, so these unwraps are safe
                    c = u8::try_from(h).unwrap() * 0x10
                        + u8::try_from(l).unwrap();
                    read_idx += 2;
                }
            }
        }

        buf[write_idx] = c;
        read_idx += 1;
        write_idx += 1;
    }

    write_idx
}

#[test]
fn test_read_password() {
    let good_inputs = &[
        (0, &b"D super secret password\n"[..]),
        (4, &b"OK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (12, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (24, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
    ];
    for (ncommands, input) in good_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(*ncommands, &mut buf, &input[..])
                .await
                .unwrap();
            assert_eq!(&buf[0..len], b"super secret password");
        });
    }

    let match_inputs = &[
        (&b"OK\nOK\nOK\nOK\n"[..], &b""[..]),
        (&b"D foo%25bar\n"[..], &b"foo%bar"[..]),
        (&b"D foo%0abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Gbar\n"[..], &b"foo%0Gbar"[..]),
        (&b"D foo%0\n"[..], &b"foo%0"[..]),
        (&b"D foo%\n"[..], &b"foo%"[..]),
        (&b"D %25foo\n"[..], &b"%foo"[..]),
        (&b"D %25\n"[..], &b"%"[..]),
    ];

    for (input, output) in match_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(4, &mut buf, &input[..]).await.unwrap();
            assert_eq!(&buf[0..len], &output[..]);
        });
    }
}

#[tokio::test]
async fn test_getpin_cancelled_when_client_disconnects() {
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let ready_dir = tempfile::tempdir().unwrap();
    let ready_path = ready_dir.path().join("pinentry-ready");

    // Stand-in for pinentry: acknowledges the greeting and the three SET*
    // commands with OK, then goes silent (simulating pinentry blocked waiting
    // for the user to type at the terminal) instead of answering GETPIN. It
    // sleeps long enough that the test's cancellation, rather than its own
    // exit, is what ends getpin.
    let mut script = tempfile::NamedTempFile::new().unwrap();
    script
        .write_all(
            b"#!/bin/sh\n\
              printf 'OK\\n'\n\
              count=0\n\
              while IFS= read -r _line; do\n\
              \tcount=$((count + 1))\n\
              \tif [ \"$count\" -le 3 ]; then\n\
              \t\tprintf 'OK\\n'\n\
              \telse\n\
              \t\tbreak\n\
              \tfi\n\
              done\n\
              : > ",
        )
        .unwrap();
    script.write_all(ready_path.as_os_str().as_bytes()).unwrap();
    script
        .write_all(
            b"\n\
              exec sleep 30\n",
        )
        .unwrap();
    script.flush().unwrap();
    let path = script.into_temp_path();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .unwrap();

    let (mut agent_side, client_side) =
        tokio::net::UnixStream::pair().unwrap();
    let environment = crate::protocol::Environment::default();

    let (res, ()) = tokio::join!(
        getpin(
            path.to_str().unwrap(),
            "prompt",
            "desc",
            None,
            &environment,
            false,
            Some(&mut agent_side),
        ),
        async {
            // Wait until the fake pinentry has acknowledged the setup
            // commands and is blocked waiting for GETPIN, then simulate the
            // client being interrupted with Ctrl+C by dropping its end of the
            // socket.
            loop {
                if tokio::fs::try_exists(&ready_path).await.unwrap() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10))
                    .await;
            }
            drop(client_side);
        }
    );

    assert!(matches!(res, Err(Error::PinentryCancelled)));
}
