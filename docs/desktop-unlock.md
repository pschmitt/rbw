# Desktop keyring unlock

`rbw secret-service enroll` verifies your master password and saves it in the
session's Secret Service (for example GNOME Keyring). Each account receives
an independent random item ID; account names and server URLs are not keyring
lookup attributes. The password is transferred through an encrypted Secret Service D-Bus session.

```shell
rbw --account personal secret-service enroll --fingerprint
rbw --account personal secret-service status
rbw --account personal lock
rbw --account personal unlock
# Password-only override:
rbw --account personal unlock --pinentry
rbw --account personal secret-service remove
```

Omit `--fingerprint` to use the unlocked keyring without a scan. Enrollment
and removal update the selected account's YAML configuration; for declarative
Home Manager configurations, copy the resulting `unlock.secretService` into
the account settings (keep identifiers in your private configuration repo):

```yaml
unlock:
  secretService:
    id: <opaque ID from enrollment>
    fingerprint: true
```

The Linux implementation uses Rust `zbus` and `secret-service` clients for
fingerprint verification, notifications, and encrypted keyring sessions.
It requires a session bus with a Secret Service provider and, when fingerprint
confirmation is enabled, the system fprintd service. Fingerprint, keyring, and notification operations use D-Bus directly.
## Unlock interfaces

Normal unlock uses the integrated terminal dialog when standard input is a
terminal. It displays password entry and live fingerprint status together;
either method can unlock the account. No fingerprint output is printed over
the dialog. The optional `gtk-ui` build feature adds a native GTK4 window,
with the same authentication and cancellation behavior. The Nix flake exports
`rbw-gtk` for that build; the default package has no GTK dependency.

```shell
rbw unlock --ui terminal
rbw unlock --ui gtk
rbw config set unlockUi gtk
# Restore automatic selection:
rbw config unset unlockUi
# Optional: show no password input feedback (off by default):
rbw unlock --no-echo
rbw config set unlockNoEcho true
# Password-only recovery with the existing configured pinentry:
rbw unlock --pinentry
```

`unlockUi` accepts `auto` (default), `terminal`, `gtk`, and `pinentry` and is
also available in Home Manager's declarative settings. Automatic selection
uses GTK when there is no terminal and a display is available in a GTK-enabled
build; otherwise it uses pinentry. Explicit GTK selection fails clearly when
GTK support is absent. `--ui pinentry` keeps the concurrent fingerprint method;
`--pinentry` bypasses automatic providers. `--stdin` still supplies an explicit
password. Initial login without a cached vault uses the agent's pinentry flow.
Keyring enrollment without fingerprint confirmation retains direct keyring
unlock. Termux and linked-account credential providers keep their own flows.

Candidates are checked against the cached encrypted vault before choosing a
winner. Password submission is disabled during verification, with a checking
indicator; failed verification re-enables it. Both integrated interfaces show
a brief green verification confirmation before closing, and the CLI reports
unlock success only after the agent confirms it. The terminal animates its
verification spinner and fingerprint scan; GTK adds a scan sweep and a success
ring, with its drawing animation respecting the desktop animation setting. An incorrect password leaves the dialog open; a stale keyring password
leaves password entry available. The winner cancels and cleans up the other
method. Escape, Ctrl+C, the GTK Cancel button, and closing the GTK window cancel
the whole dialog, including fingerprint scanning. In the legacy pinentry mode,
closing pinentry leaves fingerprint scanning available until its timeout.

The GTK dialog registers application ID `org.rbw.Unlock` and requests a
non-resizable modal window. Tiling compositors can use that application ID
for floating and centering rules. The GTK Nix package installs the matching
desktop entry and rbw app icon.

### Password handling

The integrated Linux dialog disables core dumps and same-user process-memory
inspection using `PR_SET_DUMPABLE`. Its application input buffer must be locked
in memory; failure to lock it stops the prompt. Removed input is wiped on
backspace, clear, submission, and exit. The terminal reads raw bytes into a
wiped temporary buffer, never a password-bearing paste event or render string.
By default it displays one masked character per typed character. Optional
`--no-echo` / `unlockNoEcho: true` hides all input feedback in both integrated
interfaces; the default is false. Multiline/control-character paste and excessive
input are rejected and cleared rather than submitted in truncated form.
Terminal settings are restored on normal exit, error, and cancellation.

GTK uses `GtkPasswordEntry` without reveal or undo, copying its borrowed text
directly into the locked application buffer before clearing the widget. GTK,
input methods, and the compositor remain part of the trusted desktop: this
does not guarantee every toolkit or operating-system copy is locked or wiped.
Likewise, the existing CLI/agent protocol still transfers a password String
after successful local validation. No password values are included in status
messages, application logs, or render buffers. This is not a trusted-path UI
against a compromised desktop or root process.

The provider requests any enrolled finger with `VerifyStart("any")`. Readers
that lack identification support may still select one finger; the live status
and desktop notification report the finger requested by the service. Scans
have a 60-second timeout with up to three attempts after a non-matching scan.
Ctrl+C cancels verification. rbw stops verification and releases the reader
before returning, including after errors, cancellation, or timeout.
Notifications are closed when verification finishes. Each keyring operation
also has a 60-second timeout. A missing item, unavailable service, or ambiguous
item match fails the keyring method; the password dialog remains
available. The standalone keyring API never silently bypasses a failed scan.
Removing an already-absent keyring credential succeeds.

Fingerprint verification is an rbw policy, not hardware enforcement: a
process with access to the unlocked keyring can potentially retrieve the
credential without asking rbw. This differs from Android's authentication-
gated Keystore. Fingerprints cannot decrypt a locked GNOME keyring; unlock
the keyring through login or its normal password prompt first. Avoid a
circular dependency where keyring unlock itself retrieves its password from
rbw. Remote SSH sessions may be denied fingerprint access by PolicyKit;
run interactive enrollment and unlock from the local desktop session.

This stores the master password, not a derived vault key. After changing the
master password, remove the enrollment and enroll again. `rbw lock` clears
agent keys but leaves the persistent enrollment in place. `rbw purge`
removes enrollment too. Remove enrollment before removing its account.
Status reports configuration only and never reads a credential. Use the
keyring manager to remove an orphaned item if saving configuration fails
and automatic cleanup also fails.

Live integration tests are ignored by default. On a desktop with an unlocked
keyring, run `cargo test --lib desktop::tests::live_keyring_roundtrip -- --ignored`.
The test uses a disposable random credential and removes it. The
`live_fingerprint_confirmation` test requires a human at the reader.
