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
- [x] Cross-account credential linking: `Account::credential_source` points
      at a Login entry in another configured account's vault; `rbw account
      set --credential-source-account/--credential-source-entry` (or
      `--clear-credential-source`) configures it, with cycle/self-reference
      detection via `Config::credential_source_chain`. The agent's unlock
      flow resolves it automatically, recursing through chained accounts
      and falling back to pinentry on any failure. **Gap:** not yet exposed
      in the TUI settings panel or `nix/hm-module.nix` — see below.
- [x] TUI: detect the background agent getting locked while the TUI is
      open (`App::poll_agent_lock`, throttled to every few seconds), clear
      in-memory secrets, and show `Mode::LockedPrompt` that on accept opens
      pinentry to unlock again.
- [x] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      etc.) — keep this in sync whenever a new config option is added.
      **Gaps:** `password_gen`/`PasswordGenPolicy` and
      `Account::credential_source` (see above) both landed in
      `src/config.rs` after `nix/hm-module.nix` was written and aren't
      mirrored there yet — extend the module with
      `programs.rbw.declarative.settings.password_gen` (`length`,
      `no_symbols`, `only_numbers`, `nonconfusables`, `diceware`) and a
      per-account `credential_source` (`account`, `entry`) option to close
      this.
- [ ] TUI: expose `credential_source` in the settings/accounts panel (it's
      currently CLI-only via `rbw account set`).

## Known gaps

- The TUI's status-bar hints and Help screen show default keybindings even
  when `tui_keybindings` overrides them.
- SSH key entries can't be created through the API (`rbw::api::Client::add`/
  `edit` both hit `unreachable!()` for `EntryData::SshKey`), so `rbw import`
  skips them with a warning instead of creating them. Fixing that upstream
  would let `rbw import` restore them too.
