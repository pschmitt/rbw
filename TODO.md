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

- [x] `rbw org rename <new-name>`: rename an organization, mirroring `rbw
      collection rename`'s shape (`--org-id`, auto-detected if the vault
      has a single org). Org names are plaintext (unlike collection
      names, which are per-org-key-encrypted), so this is a direct,
      unencrypted `PUT /organizations/{id}` with `{name, billingEmail}`
      (confirmed against Vaultwarden's actual route handler/request
      struct, not guessed) -- no agent mediation needed beyond the
      `unlock(None, None)` every CLI command already does. The server
      requires `billingEmail` on every update even though this only ever
      changes `name`; there's no local cache of an org's *current*
      billing email to preserve it, so this always sends the active
      account's own email instead -- fine for the common case (a
      self-hosted instance where the account owns the org it's renaming),
      possibly surprising otherwise. Requested from `bw-backup.git` after
      renaming a `rbw org create`-d test/staging org into its intended
      final name. Verified with `cargo build/test/clippy/fmt` on
      `rofl-13` (210 tests, clippy clean), then live-verified for real:
      built the binary, ran it against a throwaway isolated profile
      (separate `HOME`/config, --stdin login+unlock, no pinentry) to
      avoid a protocol-version mismatch with the long-running main
      agent, renamed a real org, confirmed via a fresh `org list`.
      Caveat for next time: isolating `HOME`/`RBW_AGENT` alone doesn't
      isolate the agent socket, which is resolved from `XDG_RUNTIME_DIR`
      (unaffected by `HOME`) -- `stop-agent` under that "isolated"
      profile ended up killing the real main agent instead, locking every
      account there. `XDG_RUNTIME_DIR` needs overriding too for genuine
      isolation, not just `HOME`.

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

- [x] `rbw org` organization management: `list`/`ls`, `create`, `invite`,
      `accept` (parses either the individual
      `--org-id`/`--user-id`/`--token` flags or a single `--url` with the
      full `.../#/accept-organization/?...` invite link -- less copy-paste
      for the invitee), `confirm`, `remove-user`, and `delete`. Org
      key-sharing is real RSA: `create` generates a random org key and
      RSA-encrypts it to the creator's own public key (retained from
      unlock); `confirm` fetches the invitee's public key
      (`GET /users/{id}/public-key`) and RSA-encrypts the cached org key to
      it. New `CipherString::encrypt_asymmetric` (RSA-OAEP-SHA1, using the
      `rand_8` `OsRng` alias -- the `rsa` crate's `CryptoRngCore` bound
      needs `rand_core` 0.6, incompatible with the `rand` 0.9 default, same
      workaround already used in `ssh_agent.rs`). `delete` is
      confirmation-gated exactly like `purge-vault` (`-y`/`--yes` plus
      `--stdin` for the required password re-proof, both skippable
      together for scripting).

      Two real bugs found via live testing against a throwaway org on
      bw.brkn.lol (created with the `bw` account, since `ai` isn't
      Vaultwarden-policy-authorized to create orgs -- `ai` was used for
      everything else): (1) newly-joined orgs weren't usable until a
      lock/unlock cycle -- `sync` learns about new org memberships but
      never re-derived the org's decryption key into the in-memory keyring,
      fixed with `State::refresh_org_keys`, called right after `sync`; (2)
      `org confirm` 404'd with "User doesn't exist" -- was passing the
      org-user *relationship* id (`OrgUser.id`) to the public-key lookup,
      which needs the invitee's *global account* id instead (`OrgUser.
      user_id`, a separate field the sync response also returns). Also
      confirmed live that `confirm` correctly requires the invitee's status
      to already be `Accepted` (a real 400 "User in invalid state"
      otherwise), which is what `org accept` is for.

- [x] `rbw collection grant`: a generic "set one member's permissions on
      one collection" primitive, added after reviewing the pre-existing
      `propagate-permissions` and finding it very opinionated (infers
      edit/manage from hierarchy position rather than letting you just set
      a permission directly). `--read-only`/`--hide-passwords`/`--manage`
      flags, replaces the member's existing permissions on that collection
      entirely (mirrors Vaultwarden/Bitwarden's own PUT semantics --
      there's no partial-update).

- [x] `rbw collection assign --bulk`: bulk-assign the same collection list
      to several entries at once. Needed a CLI redesign since two variadic
      positional lists (entries, collections) can't be disambiguated by
      clap -- `collections` became a repeatable `--collection` flag
      (breaking change from the old trailing-positional syntax), freeing
      `needles` to stay a plain variadic positional list. `--bulk` previews
      every matched entry and confirms once (unless `-y`), same convention
      as `archive --bulk`.

- [x] `rbw collection assign --personal` / `rbw collection unassign`:
      moving items between an organization and the personal vault, and
      between collections without leaving the org. `unassign` removes the
      given `--collection` values (or, with none given, every collection
      the entry currently belongs to) via the same `PUT /ciphers/{id}/
      collections` call `assign` uses, staying org-owned throughout --
      distinct from `--personal`, which actually changes ownership.
      `--personal` initially tried the obvious thing (re-encrypt with the
      personal key, `PUT /ciphers/{id}` with `organizationId: null`,
      mirroring how `import_create_entry` moves personal entries *into* an
      org via a plain edit) but the server rejected it live: `400
      Organization mismatch. Please resync the client before updating the
      cipher`. Bitwarden/Vaultwarden accepts moving *into* an org through a
      plain edit but not back out -- there's no "unshare" endpoint, only
      the reverse of what official clients call "clone to individual
      vault". Reimplemented to match that: re-encrypt with the personal
      key, `add` it as a brand-new personal entry (`add` has no org
      parameter -- always personal), copy password history over with a
      follow-up edit (safe now that both sides are personal), and only
      then permanently delete the original org entry -- create-before-
      delete so a failure leaves a harmless duplicate instead of losing
      data. Entries with attachments are refused for both operations
      (attachment keys aren't re-wrapped by any of this yet). Live-verified
      end-to-end against `ai@brkn.lol`/bw.brkn.lol: a fresh test entry
      imported into `rbw-tests`/`rbw-test-import`, `unassign` (collection
      list cleared, still org-owned), then `assign --personal` (server
      accepted the create+delete path, entry fully personal afterward,
      password/decrypt confirmed correct).

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

- [x] `rbw mirror --from A --to B`: copy vault contents from one
      configured account to another, natively -- replacing the standalone
      `bw-backup.git`/`bw-sync.sh` script, which drove two separate `bw`
      CLI logins via client-id/secret env vars, temp files on disk, and a
      Python helper (`bw.py match`) to map attachment ids between the two
      accounts by re-listing items after import. None of that machinery
      exists here: `rbw` already has multi-account config and a
      per-process "active account" switch used internally by the
      multi-account TUI (`crate::actions::set_active_account`, wrapping
      both the CLI-level account selector and the direct-api-call
      selector) -- `mirror` just calls it twice, once per side, in the
      same process.

      Deliberately named `mirror`, not `sync`: `rbw sync` already exists
      and means "pull the latest vault from the server for the active
      account" (unrelated to copying between two accounts), so reusing
      the name would have shadowed a real command.

      Implementation reuses the existing export/import conversion
      machinery instead of re-deriving it: `build_exported_vault` (a new
      function factored out of `export`'s body, export's own behavior
      unchanged) builds rbw's own decrypted `ExportedVault` shape from the
      source account, now with optional `--collection`/`--org-id`
      scoping (resolved via the same `resolve_collection` lookup
      `import --collection` already uses -- passing `--org-id` alone
      filters directly, passing `--collection` restricts the search to
      that org first so a same-named collection in a different org can't
      collide). That vault is converted through the exact same
      `exported_vault_to_bw` -> `bw_vault_to_imported` pipeline
      `rbw export --format bitwarden-json`/`rbw import` already use --
      entirely in memory, no temp file -- and fed into a new
      `import_vault` function (the tail of `import` after it finishes
      parsing whatever format the input came from, extracted verbatim so
      both callers get identical create-vs-update-vs-skip matching,
      collection creation/reuse, the "organization not available locally
      -> falls back to the personal vault" behavior, and the per-entry
      summary output). `--attachments` downloads and decrypts source
      attachments the same way `export --attachments` does, then feeds
      them through the same zip-attachment map (`ZipAttachment`,
      `sanitize_zip_folder_name`) `bw_vault_to_imported` already knows how
      to consume, rather than adding a second attachment-matching scheme.

      Flags: `--from`/`--to` (both must already be configured accounts,
      unlocked exactly like any other named-account command),
      `--collection`/`--org-id` (source-side scoping, mutually
      compatible), `--attachments`, `--overwrite` (same semantics as
      `import --overwrite`), `--purge-dest`, `-y`/`--yes`, `--stdin`.
      `--purge-dest` only supports a whole-vault mirror in this version --
      combined with `--collection`/`--org-id` it's refused outright with
      an explanatory error rather than attempting a scoped delete-
      everything-in-a-collection loop under time pressure (there was no
      way to build and live-verify that safely in the time available, and
      a safe refusal beats a half-built scoped purge). This also answers
      the "do we even support purging collections yet?" question that
      prompted this feature: no, only whole-vault (`purge-vault`) and
      whole-org (`org delete`) destructive operations exist right now;
      scoped collection/org purging is a real gap, left as a follow-up.
      When `--purge-dest` *is* given (whole-vault only), it calls the
      exact same `purge_vault` function `rbw purge-vault` uses (so the
      same `POST /ciphers/purge` server call, not a client loop of
      deletes), passing `yes: true` since `mirror`'s own preview/
      confirmation already covers it -- but it still requires the
      destination's master password re-proof, `--stdin`-suppliable the
      same way.

      Destructive-adjacent (can overwrite entries; with `--purge-dest` can
      wipe the destination entirely), so it prints a preview -- source/
      destination account + email, scope, entry/collection counts,
      attachment/overwrite/purge-dest flags -- and confirms unless
      `-y`/`--yes`, matching `purge-vault`/`org delete`'s gating
      convention.

      Verified: `cargo test` (198 passed, up from 194 -- four new tests:
      two guard-clause tests for `mirror_vault` itself -- rejecting
      `--from`/`--to` naming the same account, and refusing
      `--purge-dest` combined with `--collection`/`--org-id` -- plus two
      CLI-parsing tests for the new `rbw mirror` subcommand, one checking
      `--from`/`--to` are required and one exercising every flag) and
      `cargo clippy --all-targets` (clean) on `rofl-13`, then `cargo fmt
      --all` there before syncing back. Both guard clauses were also
      live-verified with the built binary (`rbw mirror --from ai --to ai`
      and `rbw mirror --from ai --to bw --collection x --purge-dest`,
      each failing immediately with the expected error, no account/agent
      touched) -- these don't need an unlocked account since they run
      before any config/agent access.

      Full end-to-end live verification (actually copying entries between
      the `ai`/`bw` test accounts on bw.brkn.lol) could *not* be completed
      in this session: no agent was running for either account, and the
      sandboxed environment this was built in has no controlling TTY and
      no `DISPLAY`/`WAYLAND_DISPLAY`, so pinentry has no way to prompt for
      either account's master password and there's no safe way to guess
      or bypass that. A built `v2.12.0` binary is staged for whoever picks
      this up to finish that check by hand: unlock `ai` and `bw` (each
      needs its own real pinentry prompt -- `bw`'s configured
      `credential_source` chain pulls from the `default` account, which is
      off limits for this feature entirely, so it needs its actual master
      password entered directly, not the chained shortcut), create one or
      two fresh disposable entries in a brand-new test collection in one
      account, then run `rbw mirror --from ai --to bw --collection
      <that-collection> -y` (or the reverse direction) and confirm they
      land correctly on the other side -- and clean up the test collection
      and entries afterward either way.

      **Update (2026-07-30): live-verified for real**, via `bw-backup.git`'s
      new `bw-sync.service` on `rofl-10` -- not the `ai`/`bw` test accounts
      above, but an actual production run (`--from personal --to
      vaultwarden --attachments --overwrite --purge-dest -y`, no
      `--dest-collection`, whole-vault purge path): purged the destination
      personal vault, then mirrored 2211 entries (2 collections skipped --
      "organization not available locally", expected since that org
      doesn't exist on the destination yet) and 41 attachments in 1m42s
      wall clock, zero errors, exit 0. Notably faster and cleaner than the
      old bw-cli/bw.py pipeline it replaced (which took ~6 minutes and
      logged several "Not found." attachment-upload failures on the same
      vault the night before). Three unrelated bugs surfaced and were
      fixed in `bw-backup.git`'s own NixOS module along the way (wrong
      package path for `rbw` in a generated helper script, `rbw-agent` not
      reachable via PATH from that same script, and the account's
      TOTP-based 2FA needing a live-generated code) -- none in `mirror`
      itself, which worked exactly as designed once those were sorted out.

- [x] `rbw mirror --dry-run`: print the same plan (accounts/emails, scope,
      entry/collection counts, attachments/overwrite/purge-dest flags) and
      stop there -- no confirmation prompt, destination account never
      unlocked or touched. Requested from `bw-backup.git` after it started
      relying on `mirror` for both its sync jobs, to preview a run
      (particularly the entry counts, which need the real source vault
      decrypted to be accurate) without any risk of the purge-dest paths
      firing. Guard clauses (`--from`/`--to` identical, `--purge-dest` with
      source-side `--collection`/`--org-id`) still run before `--dry-run`
      is even checked, same as before. Verified: `cargo test` (still 210
      passed -- extended the existing CLI-parsing and guard-clause tests
      rather than adding new ones) and `cargo clippy --all-targets` (clean)
      on `rofl-13`, `cargo fmt --all` there before syncing back. Not live-
      verified against a real account for the same sandbox reasons as
      `mirror` itself above (no pinentry/TTY here).

- [x] `rbw mirror --dest-org`: a production `bw-sync-collections` run
      (`bw-backup.git`) hit `rbw mirror: multiple collections found for
      'Default collection': ... use the collection ID instead` -- two
      different destination orgs each had a same-named collection (one
      real, one leftover test-org cruft from earlier live-testing of this
      fork). `--dest-collection`'s name resolution had no way to scope by
      org. Added `--dest-org <name-or-id>` to restrict that lookup to one
      destination org, resolved via a new `resolve_organization` (mirrors
      `resolve_collection`: exact ID, then exact name, then case-
      insensitive substring, erroring with candidates listed on
      ambiguity) against `db.organizations` (plaintext, no decrypt
      needed). Threaded through `import_vault`/`purge_collection_entries`
      (both previously hardcoded `None` for collection org-scoping) and
      `mirror_vault`'s own plan preview.
- [x] `--collection <name-or-id>`/`--org <name-or-id>` on every entry-
      lookup command (`get`, `show`, `code`, `edit`, `set`, `rm`,
      `archive`, `unarchive`, `restore`, `history`, `list`, `search`, and
      `attachment list`/`get`/`rm`), not just `mirror` -- same disambiguation
      problem, just as likely to bite `rbw get some-name` directly once an
      account has entries with the same name in more than one
      collection/org. Implementation:
      - `entry_in_collection_org_scope` (renamed/generalized from what was
        `export_entry_in_scope`'s inline body) filters raw `db.entries` by
        `collection_ids`/`org_id` -- both plain IDs on every synced entry,
        no decryption needed, so this runs *before* the batch-decrypt step
        in `find_entry`/`find_entry_multi`/`find_entries_all`/
        `find_deleted_entry`/`find_deleted_entries_all`/`list`/`search`.
      - `resolve_entry_scope` resolves the CLI's `--collection`/`--org`
        needles (name or ID) into concrete IDs once per account, reusing
        `resolve_organization`/`resolve_collection`.
      - Multi-account (`--all`) lookups: a needle that doesn't resolve in
        one particular account (name not found there, or ambiguous there)
        just means that account contributes nothing, rather than aborting
        the whole search -- matches how `--folder` already behaves loosely
        there, and keeps `--all` usable when only one of several accounts
        actually has the given collection/org.
      - Deliberately *not* wired into `--from-file` variants (`edit
        --from-file`, `set --from-file`, `list --from-file`, `search
        --from-file`) or the collection-reassignment commands
        (`assign-collections`/`unassign-collections`, which already have
        their own differently-scoped `--collection` meaning) -- out of
        scope for this pass.
      Verified: `cargo test` (213 passed, up from 210 -- two new
      `resolve_organization` unit tests plus a CLI-parsing test covering
      `--collection`/`--org` across all the commands above, including
      asserting the parsed values on `get`/`list`/`search`), `cargo clippy
      --all-targets` (clean after removing two accidentally-duplicated
      `#[allow(clippy::too_many_arguments)]` attributes), `cargo fmt --all`
      -- all on `rofl-13`. Not live-verified against a real account in this
      session (no pinentry/TTY here, same constraint as above); the
      `--dest-org` fix specifically *is* live-verified indirectly, since
      it's what unblocked the real `bw-sync-collections` run that
      surfaced the bug in the first place.
- [x] Shell completions updated for both of the above:
      - bash/zsh: `--collection`/`--org` value completion added
        unconditionally (any subcommand), dynamically listing real
        collection/org names via `rbw collection list --output name`/`rbw
        org list --output name`. `rbw mirror` gets its own more precise
        version: `--collection`/`--dest-collection`/`--dest-org` complete
        against whichever account was already typed for `--from`/`--to`
        respectively (not the default account), and `--from`/`--to`
        themselves complete configured account names via `rbw account
        list`. `--org-id` (mirror's source-side flag) is deliberately left
        uncompleted -- it takes a raw ID, never resolved by name anywhere,
        so completing it with names would be misleading.
      - fish: added `--collection`/`--org` to the existing `get`/
        `attachment` dynamic-completion functions' `argparse` calls (their
        flag allowlists would otherwise reject the new flags outright,
        breaking existing name completion the moment either is typed),
        plus new `--collection`/`--dest-collection`/`--dest-org`/`--from`/
        `--to` completions for `mirror` mirroring the bash/zsh behavior.
        `get`'s entry-name completion also now scopes its `rbw list` call
        by `--collection`/`--org` when either is already typed, same as it
        already did for `--folder`.
      Verified: `bash -n`/`zsh -n` on both scripts (clean), `fish -n`
      against a `fish 4.8.1` shell on `rofl-13` (clean) -- no interactive
      completion trigger tested (would need a live account), but all three
      scripts at least parse and the logic mirrors the already-working
      `--folder` patterns closely enough to trust it.

## Passkey (fido2Credentials) support

49. [x] **Real, confirmed data-loss bug found and fixed**: passkeys synced
        onto a login item were entirely absent from every layer of
        rbw -- `CipherLogin` (the wire-format struct used for both
        `/sync` deserialization and outgoing create/update requests) only
        ever had `username`/`password`/`totp`/`uris`, no
        `fido2Credentials` field, and there was no catch-all/flatten field
        anywhere to preserve unknown JSON either. Consequence, confirmed
        by reading Vaultwarden's own `update_cipher_from_data` source: it
        stores a cipher's whole `login` object as one opaque blob with no
        per-field merge, so any `rbw edit`/`rbw set`/`rbw mirror
        --overwrite` on a login item that had a passkey didn't just fail
        to copy it -- it *destroyed* the passkey server-side, since the
        outgoing request's `login` object simply omitted the field
        entirely. This affected `rbw mirror` (the reported symptom: "why
        aren't passkeys transferred") and, independently, plain `rbw
        edit`/`rbw set` on any passkey-bearing entry.
50. [x] Added full fido2Credentials support at every layer, following the
        exact same pattern already used for TOTP/URIs (each field an
        individually-encrypted CipherString except `creation_date`, which
        Bitwarden stores unencrypted): `api::CipherFido2Credential`
        (wire format, both directions -- `SyncResCipher`'s login arm and
        both outgoing-request builders, `cipher_type_and_fields` and the
        separate hand-rolled one in the PUT path), `db::Fido2Credential`
        (local sync-db storage, `#[serde(default)]` so an existing
        on-disk `db.json` from before this change still parses),
        `commands::DecryptedFido2Credential`/`EditableFido2Credential`/
        `ImportedFido2Credential` (decrypt/edit/import layers), and
        `import_bitwarden::BwFido2Credential` (the Bitwarden-JSON
        interchange shape `rbw mirror` itself round-trips through
        between export and import). Schema confirmed against
        `bitwarden/clients`' own TypeScript models
        (`fido2-credential.api.ts`/`fido2-credential.ts`) rather than
        guessed -- 13 fields, all `EncString` except `creationDate`.
51. [x] `rbw set`'s direct field-update path (`apply_entry_update`) now
        explicitly carries the entry's existing (encrypted)
        `fido2_credentials` through unchanged, exactly like it already
        does for `password_history` -- `rbw set` never touches passkeys,
        so this can never destroy one. `rbw edit`'s $EDITOR-based path
        shows passkeys in the YAML/JSON (there's nothing meaningful to
        hand-edit in opaque key material, but hiding them would mean an
        editor session that doesn't touch them still round-trips them
        correctly, same principle as SSH private keys already being shown
        there) and re-encrypts them like any other field if left alone.
52. [x] `rbw show` and the TUI detail pane both gained a `Passkey` summary
        row (relying party + account name) -- never the raw key
        material, just enough to confirm one is present, same spirit as
        how `password` is masked unless revealed.
53. [x] Added two dedicated tests (existing ones were extended to cover
        an empty-fido2 case where the field was newly required, but
        these two actually exercise real passkey data):
        `test_imported_data_to_decrypted_login_carries_fido2_credentials`
        and `test_mirror_round_trip_carries_fido2_credentials` -- the
        latter specifically exercises `rbw mirror`'s own two-hop
        internal conversion (`DecryptedData` -> `BwLogin` ->
        `ImportedData`, the exact path a mirror run takes between
        exporting the source and importing into the destination) with
        real (fake but correctly-shaped) credential data, confirming the
        original reported bug is fixed at the level that's testable
        without a live account's real encryption keys.
        Verified: `cargo build --all-targets`/`cargo test` (215 passed,
        up from 213) /`cargo clippy --all-targets` (all clean) on
        `rofl-13`, `cargo fmt --all` there before syncing back. Full
        live verification (an actual passkey round-tripping through a
        real `rbw mirror` run against production accounts) deferred to
        `bw-auto.git`'s redeploy on rofl-10, where source/destination
        accounts and their real rbw-agent instances already exist
        without needing any ad-hoc local account isolation (the kind
        that caused a prior incident this session).
