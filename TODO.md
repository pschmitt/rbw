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
      password-gen policy) so other config.json knobs can be added to it
      later without restructuring.
- [x] Cross-account credential linking: `Account::credential_source` points
      at a Login entry in another configured account's vault; `rbw account
      set --credential-source-account/--credential-source-entry` (or
      `--clear-credential-source`) configures it, with cycle/self-reference
      detection via `Config::credential_source_chain`. The agent's unlock
      flow resolves it automatically, recursing through chained accounts
      and falling back to pinentry on any failure. The TUI accounts panel
      exposes it too: `l` opens a prompt to link (or edit) the highlighted
      account's source, `L` clears it (with a y/n confirm), and a linked
      account shows a "→ linked to account/entry" line beneath it in the
      panel. Only the master password is pulled from the linked entry today
      (not username/TOTP).
- [x] TUI: detect the background agent getting locked while the TUI is
      open (`App::poll_agent_lock`, throttled to every few seconds), clear
      in-memory secrets, and show `Mode::LockedPrompt` that on accept opens
      pinentry to unlock again.
- [x] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      `password_gen`/`PasswordGenPolicy`, per-account `credential_source`,
      etc.) — keep this in sync whenever a new config option is added.

## Known gaps

- `README.md` still needs first-class docs for the newer collection workflow
  (`rbw collection ...`), destructive confirmations (`--yes`, `purge -y`),
  and per-account locking (`rbw lock --all` plus account-scoped lock state).

## Pending ship work

- [ ] Deploy the current `main` tip (`8474745`) through `nixos-config`:
      `nix flake lock --update-input rbw`, `just hm fnuc`, then restart the
      deployed `rbw-agent` so it picks up the new Nix store path.

- [ ] Extend the user-facing docs/help for the shipped UX work:
      document `rbw collection list/create/delete/rename/assign/
      propagate-permissions`, note the hidden compatibility shims for the old
      flat commands, and cover destructive confirmations plus account-scoped
      locking.

- [ ] After deploy, prune stale merged worktrees/branches that are no longer
      needed (`worktree-agent-a666928e233ad75ce`,
      `worktree-agent-a5147e5e3cf5f349c`, and any older merged agent
      worktrees that still exist locally).
