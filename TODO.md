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
      panel. Pulls both the master password and a live-generated TOTP code
      (if the linked entry has a secret) from the linked entry.
- [x] TUI: detect the background agent getting locked while the TUI is
      open (`App::poll_agent_lock`, throttled to every few seconds), clear
      in-memory secrets, and show `Mode::LockedPrompt` that on accept opens
      pinentry to unlock again.
- [x] Home-manager module exposing every config.json option as Nix options
      (accounts, `unlock` policy, `exclude_from_list`, `tui_keybindings`,
      `password_gen`/`PasswordGenPolicy`, per-account `credential_source`,
      etc.) — keep this in sync whenever a new config option is added.
- [x] `--from-file FILE` on `rbw list`/`rbw search`/`rbw tui`: browse a
      `rbw export` file directly (plain JSON or gpg-encrypted, passphrase
      auto-prompted if needed) instead of a configured account — no
      config/agent/account touched at all, entirely in-memory and read-only
      for that one invocation. `tui --from-file` shows a single synthetic
      vault; every mutating action (edit/add/delete/sync/attachment
      upload-or-delete/the accounts panel) is rejected with a clear
      "read-only: loaded from a file" status instead of being attempted.
      Attachment viewing/download still works (the bytes are already
      embedded in the export by `rbw export --attachments`).
- [x] `--from-file` writeback: `rbw set/edit/remove/add --from-file FILE`
      and `rbw tui --from-file FILE --write` modify the file in place
      (`--bulk` stays account-only; `set --from-file --attach` and TUI
      attachment upload/delete both work, embedding bytes directly since
      there's no server to upload to). A `.bak` snapshot of the pre-edit
      file is made once — before the first CLI write, and at TUI startup
      when `--write` is given. `org_id`/`collection_ids` (not on
      `DecryptedCipher`, tracked separately per entry) and `collections`
      round-trip through untouched on every save.

## Pending ship work

- [ ] Deploy the `v2.6.5` release through `nixos-config`:
      `nix flake lock --update-input rbw`, `just hm fnuc`, then restart the
      deployed `rbw-agent` so it picks up the new Nix store path.

- [x] Extend the user-facing docs/help for the shipped UX work:
      document `rbw collection list/create/delete/rename/assign/
      propagate-permissions`, note the hidden compatibility shims for the old
      flat commands, and cover destructive confirmations plus account-scoped
      locking.

- [x] Prune stale merged worktrees/branches that are no longer needed
      (`worktree-agent-a666928e233ad75ce`, `worktree-agent-a5147e5e3cf5f349c`,
      and older merged agent worktrees).

- [x] SSH-key (cipher type 5) support verified against a live Vaultwarden
      (bw.brkn.lol, 1.36.0): the original wiring sent PascalCase `sshKey`
      fields that Vaultwarden silently discarded (HTTP 200, `sshKey: null`) —
      imports created invisible husks and `rbw set` wiped key material. Fixed
      by serializing camelCase `privateKey`/`publicKey`/`keyFingerprint`
      (old spellings kept as deserialize aliases) and re-verified live:
      import, exact round-trip, and edit all preserve the key material.

- [x] Item archiving and trash restore, matching Bitwarden's own Archive
      feature (`ArchivedDate`/`archivedDate`, parallel to the existing
      `DeletedDate`/`deletedDate` trash field): `rbw archive`/`rbw
      unarchive <entry>` and `rbw restore <entry>` (undoes `rbw remove`/`rbw
      delete`), all with `--bulk` (find every match across needles, preview,
      confirm once, one bulk API call) and `-y`/`--yes`. Archived and
      trashed entries now survive sync instead of being dropped, but are
      hidden from `rbw list`/`rbw search` by default — overridable with
      `--archived`/`--include-archived` and `--trashed`(`--deleted`)/
      `--include-trashed`(`--include-deleted`), each backed by a config.json
      default (`hide_archived`, `hide_trashed`, both `true`; mirrored in the
      home-manager module). `find_entry`/`find_entry_multi`/
      `find_entries_all` (used by `get`/`edit`/`set`/`remove`/etc.)
      unconditionally exclude trashed entries, so a plain `rbw remove` can
      never accidentally re-target (and permanently purge) something
      already in the trash; `rbw restore` resolves against a dedicated
      trashed-only lookup instead. The TUI hides both by default too (own
      `archived_filter`/`trash_filter`, initialized from config), with `x`
      to archive/unarchive the selected entry and `X` to cycle the
      archived-visibility filter (Hide/Only/Include) -- trash browsing/
      restore isn't wired into the TUI yet, just the safe-by-default
      hiding. Verified live against bitwarden.com (the account that
      actually had Archive-eligible + trashed items) with a temporary
      build: archive/unarchive round-tripped correctly, `--archived`/
      `--trashed` filtered correctly, and organically surfaced real
      pre-existing archived/trashed entries. `rbw export`/`import` and
      `--from-file` don't round-trip either flag yet (deferred, no local
      file semantics for either concept today).
- [x] Removed the hidden flat-command compatibility shims for collections
      (`list-collections`/`lsc`, `create-collection`, `delete-collection`,
      `edit-collections`, `rename-collection`,
      `propagate-collection-permissions`) -- `rbw collection <subcommand>`
      is now the only interface.
