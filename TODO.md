# TODO

- [x] `rbw export --attachments`: include decrypted attachment contents in
      the export, not just entry data.
- [x] `rbw export --encrypt PASSPHRASE`: produce a gpg-encrypted tar.gz
      archive instead of raw JSON to stdout.
- [x] `rbw import`: import data produced by `rbw export`, including
      attachments. Reference implementation:
      `/home/pschmitt/devel/private/pschmitt/bw-backup.git`.
- [x] `rbw create --generate`/`-g`: generate a password with the same flags
      as `rbw gen` (length, no-symbols, numbers-only, etc). Backed by a
      configurable default password-generation policy in config.json
      (`password_gen`), with a TUI view to edit it (`S` from the main
      screen, `Mode::Settings`). The settings panel is deliberately generic
      (a flat list of editable key/value fields, currently just the
      password-gen policy) so the cross-account credential linking config
      below can be added to it later without restructuring.
- [ ] Cross-account credential linking: let an entry in one account's vault
      hold another configured account's login credentials (username,
      password, TOTP), configurable via config.json and the TUI. Use it to
      auto-unlock the dependent account.
- [ ] TUI: detect the background agent getting locked while the TUI is
      open, clear in-memory secrets, and show a dialog that on accept opens
      pinentry to unlock again.
- [x] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      the password-generation policy and account-linking config above,
      etc.) — keep this in sync whenever a new config option is added.
      Done for everything currently in `src/config.rs` (see
      `nix/hm-module.nix`) as of when this module was added; the
      account-linking config still doesn't exist in `Config` yet, so it
      isn't modeled. **Gap:** `password_gen`/`PasswordGenPolicy` (see the
      `rbw create --generate` item above) landed in `src/config.rs` after
      `nix/hm-module.nix` was written and isn't mirrored there yet — extend
      the module with a `programs.rbw.declarative.settings.password_gen`
      option (`length`, `no_symbols`, `only_numbers`, `nonconfusables`,
      `diceware`) to close this.

## Known gaps

- The TUI's status-bar hints and Help screen show default keybindings even
  when `tui_keybindings` overrides them.
- SSH key entries can't be created through the API (`rbw::api::Client::add`/
  `edit` both hit `unreachable!()` for `EntryData::SshKey`), so `rbw import`
  skips them with a warning instead of creating them. Fixing that upstream
  would let `rbw import` restore them too.
