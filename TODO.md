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

- `README.md` and some CLI help text are stale around export/import: they
  still document `rbw export --encrypt PASSPHRASE` /
  `rbw import --decrypt-passphrase PASSPHRASE` only, and still claim SSH key
  entries cannot be restored even though API support has landed.

## Pending ship work

- [ ] Push the current local `main` tip (`59588af`, `feat(cli): close
      consistency gaps across subcommands`) to `origin/main`, then deploy it
      through `nixos-config` (`nix flake lock --update-input rbw`, `just hm
      fnuc`, restart `rbw-agent`). The local checkout is currently ahead of
      `origin/main` by one commit.

- [ ] Finish and merge the CI branch (`worktree-agent-a666928e233ad75ce`,
      also `origin/ci/checks`): the workflow modernization and `cargo-deny`
      updates are committed there, plus `fix(locked): drop mlock guard before
      freeing the locked buffer`, but GitHub Actions still fails on
      `pinentry::test_getpin_cancelled_when_client_disconnects` in the musl
      job. Once green, merge to `main` and delete `origin/ci/checks`.

- [ ] Redo the export/import security hardening work from scratch; the first
      agent died without leaving a branch. Remaining scope:
      keep passphrases out of argv/history (`--encrypt[=PASSPHRASE]`,
      `RBW_EXPORT_PASSPHRASE`, interactive tty prompt with confirmation,
      `rbw import --decrypt` plus legacy `--decrypt-passphrase` compat),
      stream plaintext to/from `gpg` via a dedicated passphrase fd instead of
      temp files, add `rbw export -o/--output FILE` created with mode `0600`,
      and update help/README/tests for the new flow.

- [ ] Finish the collections/destructive-UX branch in
      `.claude/worktrees/agent-a5147e5e3cf5f349c`. That worktree still has
      uncommitted edits in `src/bin/rbw/main.rs`, `src/bin/rbw/commands.rs`,
      `src/bin/rbw/actions.rs`, `src/bin/rbw-agent/actions.rs`,
      `src/bin/rbw-agent/agent.rs`, and `src/bin/rbw-agent/state.rs`.
      Intended scope: `rbw collection` subcommand group
      (`list/create/delete/rename/assign/propagate-permissions`) with hidden
      compat shims for the old command names, better collection-assign UX,
      `--org-id` consistency + auto-detect, confirmation prompts / `--yes`
      for destructive commands, and per-account locking in the agent.

- [ ] After the CI, hardening, and collections work land: merge the pending
      branches, re-run build/test/clippy on a scratch host, delete stale
      worktrees/branches (`worktree-agent-aabda72fad7ec68ec`,
      `worktree-agent-adf703ce5bdcfa902`, `worktree-agent-a635ef0d91b14a7d1`,
      `worktree-agent-ae868b9c299825d23`, plus any merged CI/collections
      worktrees), push `main`, then do the normal deploy/restart cycle.
