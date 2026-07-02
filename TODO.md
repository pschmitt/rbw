# TODO

- [x] `rbw export --attachments`: include decrypted attachment contents in
      the export, not just entry data.
- [x] `rbw export --encrypt PASSPHRASE`: produce a gpg-encrypted tar.gz
      archive instead of raw JSON to stdout.
- [ ] `rbw import`: import data produced by `rbw export`, including
      attachments. Reference implementation:
      `/home/pschmitt/devel/private/pschmitt/bw-backup.git`.
- [ ] `rbw create --generate`/`-g`: generate a password with the same flags
      as `rbw gen` (length, no-symbols, numbers-only, etc). Backed by a
      configurable default password-generation policy in config.json, with
      a TUI view to edit it (general settings panel).
- [ ] Cross-account credential linking: let an entry in one account's vault
      hold another configured account's login credentials (username,
      password, TOTP), configurable via config.json and the TUI. Use it to
      auto-unlock the dependent account.
- [ ] TUI: detect the background agent getting locked while the TUI is
      open, clear in-memory secrets, and show a dialog that on accept opens
      pinentry to unlock again.
- [ ] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      the password-generation policy and account-linking config above,
      etc.) — keep this in sync whenever a new config option is added.

## Known gaps

- The TUI's status-bar hints and Help screen show default keybindings even
  when `tui_keybindings` overrides them.
