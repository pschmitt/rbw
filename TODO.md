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

- [x] `rbw import`: accept upstream Bitwarden export dumps directly, not
      just `rbw export`'s own JSON shape. New `src/bin/rbw/import_bitwarden.rs`
      parses Bitwarden's own "JSON" export, password-protected "Encrypted
      JSON" export, and "zip (with attachments)" (new `zip` crate
      dependency). `--format <auto|rbw|bitwarden-json|
      bitwarden-encrypted-json|bitwarden-zip>` (aliased `--type`, default
      auto-detected from magic bytes/JSON shape) selects the parser;
      `--decrypt`/`--decrypt-passphrase` now also supply the Bitwarden
      export password. `--collection DEST` redirects every imported entry
      into one existing collection (resolved via the same
      `resolve_collection` lookup as elsewhere), overriding whatever
      org/collection/folder metadata the export carries. CSV wasn't
      implemented (many fields -- TOTP, custom fields, SSH keys -- don't
      round-trip cleanly through Bitwarden's CSV shape); left as a
      possible follow-up.

      Verified against 4 real exports from the user's own vault (2026-07-29,
      `bw export --format {json,encrypted_json,zip}` and the web vault's
      CSV export) -- this caught two real bugs a synthetic round-trip
      couldn't have:
      - The encrypted-JSON export's PBKDF2 salt is the `salt` field's raw
        *string* bytes, not that string base64-decoded (confirmed by
        brute-forcing candidate derivations against the real file's
        `encKeyValidation_DO_NOT_EDIT` field until one MAC-verified).
        Decoding it first makes every decrypt fail. The overall KDF +
        HKDF-expand("enc"/"mac") + AES-256-CBC-HMAC scheme itself matches
        `Identity::new`'s login-unlock math exactly, salt handling aside.
      - The zip export lays attachments out as `attachments/<sanitized
        item display name>/<file name>` (illegal path characters like `/`
        and `:` replaced with `_`, confirmed against real folder names),
        *not* `attachments/<item id>/<attachment id>-<file name>` as
        originally assumed -- and an item's `attachments` metadata array
        is always empty in every real export, including inside a zip
        export's own `data.json`, so the sanitized name is the *only*
        association available in the archive at all. Matching is now
        `sanitize_zip_folder_name(item.name)` -> attach everything found
        under that folder; two items sharing an identical name are
        inherently ambiguous (whichever converts first claims the shared
        folder) since the format itself has no id-based mapping to
        disambiguate them.
      Both fixes are covered by unit tests; the encrypted-JSON test
      exercises a real encrypt-then-decrypt round trip through the actual
      derive/decrypt code (not a mock), and the zip test uses the
      confirmed real path layout. Live-verified end to end against a
      dedicated test account (`ai@brkn.lol` on bw.brkn.lol, set up
      specifically for this): plain JSON, `--collection`, zip-with-
      attachments (attachment bytes hash-verified byte-for-byte against
      the source zip), and encrypted JSON (a hand-crafted envelope using
      the same confirmed derivation) all created real entries correctly,
      with `--collection` entries landing in the right org/collection and
      personal-vault entries not.

- [x] `rbw purge-vault`: permanently wipe every entry in the current
      account's personal vault via the server's own `POST /ciphers/purge`
      endpoint (one call, not a client loop of deletes) -- named apart
      from the pre-existing `rbw purge` (which only clears the local
      db.json cache, unrelated). Needed a real master-password-hash
      proof, so it's agent-mediated like `login`/`unlock`: new
      `protocol::Action::PurgeVault { password }`, an agent handler that
      derives `Identity::new(...).master_password_hash` from a freshly
      entered (or `--stdin`-supplied) password and calls the new async
      `Client::purge_vault`, never reusing the agent's already-cached
      unlock keys. Gated behind a `This cannot be undone!`-style
      confirmation (`-y`/`--yes` to skip) plus the password re-entry
      itself (`--stdin` to skip that too, for scripted resets --
      `--yes --stdin` together purge fully non-interactively). Live-
      verified against the `ai@brkn.lol` test account: wiped exactly the
      10 personal-vault entries, left the 5 org-collection entries
      untouched, matching the documented scope (org-owned entries need
      org owner/admin privileges to purge, not implemented here).

- [x] `rbw export --format`: produce upstream Bitwarden export shapes, not
      just rbw's own -- the export-side mirror of the `rbw import` work
      above, reusing the same `BwVault`/`BwItem`/etc. types (now
      `Serialize` as well as `Deserialize`) via a new `exported_vault_to_bw`
      conversion (the inverse of `bw_vault_to_imported`). `--format
      <rbw|bitwarden-json|bitwarden-encrypted-json|bitwarden-zip|
      bitwarden-csv>` (aliased `--type`, default `rbw`, unchanged
      behavior). `--format bitwarden-encrypted-json` always prompts for a
      password on its own (from $RBW_EXPORT_PASSPHRASE or the tty, like
      rbw's own `--encrypt`) even without `--encrypt` -- that flag is only
      needed there to supply it inline instead of prompting; new
      `encrypt_encrypted_json` builds the envelope with the real KDF
      quirks already confirmed on the import side. `--format bitwarden-csv`
      only emits Login/SecureNote rows (with a skipped-count warning) since
      real Bitwarden CSV exports have no columns for Card/Identity/SSH-key
      items either (confirmed against a real CSV export: rows for those
      types are silently absent even though the source vault has them).
      New `csv` crate dependency for correct RFC4180 quoting (custom
      fields/notes can contain anything). Unit-tested (encrypted-json
      round trip through the real derive/encrypt/decrypt code, zip
      write/parse round trip, CSV column/skip-count checks, and the
      `exported_vault_to_bw` conversion itself) plus live-verified against
      the `ai@brkn.lol` account for all four formats: JSON structure,
      zip layout (`unzip -l`), CSV parsed with Python's `csv` module
      (correct record count despite multi-line quoted `fields` values),
      and the encrypted-JSON file independently decrypted outside rbw
      entirely to confirm it round-trips through the real scheme.

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
- [x] **Data-loss bug fix**: `rbw remove`/`rbw delete` (`Client::remove()`)
      was calling `DELETE /ciphers/{id}`, which both official Bitwarden
      (`CiphersController.Delete`/`_cipherService.DeleteAsync`) and
      Vaultwarden (`delete_cipher()`) treat as a *permanent, unrecoverable*
      delete -- not the trash-recoverable soft delete the command's name,
      aliases (`rm`/`delete`/`del`), and help text all promise. The real
      soft-delete route is `PUT /ciphers/{id}/delete`
      (`PutDelete`/`SoftDeleteAsync` server-side, `delete_cipher_put()` on
      Vaultwarden) -- confirmed against both projects' source and fixed.
      Found live: restoring an old trashed test item and then removing it
      again made it vanish entirely from the server's sync response
      instead of going back to trash, which is exactly what a permanent
      delete on the wrong endpoint would do. Since the bare `DELETE
      /ciphers/{id}` genuinely is the real permanent delete, added `rbw
      remove --force` (bypasses trash entirely; falls back to a trashed
      entry if no live one matches, so it also purges something already
      in the trash) so that capability isn't lost -- with a stronger
      confirmation prompt ("This cannot be undone!") than the plain
      soft-delete path.
