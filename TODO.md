# TODO

- [x] `rbw export --attachments`: include decrypted attachment contents in
      the export, not just entry data.
- [x] `rbw export --encrypt PASSPHRASE`: produce a gpg-encrypted tar.gz
      archive instead of raw JSON to stdout.
- [x] `rbw import`: import data produced by `rbw export`, including
      attachments. Reference implementation:
      `/home/pschmitt/devel/private/pschmitt/bw-backup.git`.
- [ ] `rbw create --generate`/`-g`: generate a password with the same flags
      as `rbw gen` (length, no-symbols, numbers-only, etc). Backed by a
      configurable default password-generation policy in config.json, with
      a TUI view to edit it (general settings panel).
- [x] Cross-account credential linking: let an entry in one account's vault
      hold another configured account's login credentials (username,
      password, TOTP), configurable via config.json and the TUI. Use it to
      auto-unlock the dependent account. Config/CLI landed as
      `Account::credential_source` + `rbw account set --credential-source-
      account/--credential-source-entry` (or `--clear-credential-source`);
      the TUI accounts panel now exposes it too: `l` opens a prompt to link
      (or edit) the highlighted account's source, `L` clears it (with a
      y/n confirm), and a linked account shows a "→ linked to
      account/entry" line beneath it in the panel. Only the master
      password is pulled from the linked entry today (not username/TOTP).
- [ ] TUI: detect the background agent getting locked while the TUI is
      open, clear in-memory secrets, and show a dialog that on accept opens
      pinentry to unlock again.
- [x] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      the password-generation policy and account-linking config above,
      etc.) — keep this in sync whenever a new config option is added.
      Done for everything currently in `src/config.rs` (see
      `nix/hm-module.nix`), including `credential_source` now that it
      exists on `Account`; the password-generation policy still doesn't
      exist in `Config` yet, so it's not modeled yet — extend the module
      when it lands.

## Known gaps

- The TUI's status-bar hints and Help screen show default keybindings even
  when `tui_keybindings` overrides them.
- SSH key entries can't be created through the API (`rbw::api::Client::add`/
  `edit` both hit `unreachable!()` for `EntryData::SshKey`), so `rbw import`
  skips them with a warning instead of creating them. Fixing that upstream
  would let `rbw import` restore them too.
