# Backup and restore (`rbw export`/`rbw import`)

`rbw export` writes the entire active vault (including archived and trashed
entries, fully decrypted, plus collections) as JSON to stdout. Native rbw
exports preserve both status flags; Bitwarden JSON-based exports preserve
archived and trash status through `archivedDate` and `deletedDate`. CSV
cannot represent either status:

```sh
rbw export > backup.json
```

You can also write directly to a file without shell redirection (the file
is created with mode 0600, since it contains the fully decrypted vault):

```sh
rbw export --output backup.json
```

To inspect an export without unlocking an account or exposing its contents,
use `rbw export-info`. It reports entry types, entries containing notes,
passkeys, collections, folders, attachments, custom fields, password history,
and other counts available in the selected format. JSON output is available for
scripts, and the format is auto-detected across rbw JSON/gpg, Bitwarden JSON,
Encrypted JSON, zip, and CSV exports:

```sh
rbw export-info backup.json
rbw export-info --json backup.json
rbw export-info --decrypt backup-encrypted.json
```

`rbw import` reads that JSON back and recreates the entries and collections
in the target account's vault (use the global `--account`/`-a` flag to pick
a different account than the primary one):

```sh
rbw import backup.json
# or, piped:
rbw export | rbw import
```

If no file is given, `rbw import` reads from stdin. Entries that already
exist (matched by name, and by username for logins) are left untouched and
reported as skipped; pass `--overwrite` to update them in place instead.
Entries that belonged to an organization the target account isn't a member
of are imported into the personal vault instead of failing. Pass
`--collection <name-or-id>` to redirect every imported entry into one
existing collection instead, ignoring whatever organization/collection/
folder metadata the export carries; add `--org <name-or-id>` to disambiguate
`--collection`'s name when it exists in more than one organization (it has
no effect without `--collection`).

By default `rbw export` writes the entire vault (personal vault plus
everything in every organization the account belongs to). Pass
`--collection <name-or-id>` and/or `--org <name-or-id>` to export just one
collection or organization instead -- the same name-or-ID resolution (and
`--org`-to-disambiguate-`--collection`) as `rbw list`/`rbw search`:

```sh
rbw export --org acme --output acme-backup.json
rbw export --collection Infra --org acme --output infra-backup.json
```

Pass `--attachments` on export to also download and embed decrypted
attachment contents (base64-encoded) in the export; this makes the export
considerably larger and slower to produce, but lets `import` restore
attachments too.

## Upstream Bitwarden export formats

`--format` (aliased `--type`) selects the export/import shape. `rbw export`
defaults to `rbw`'s own JSON; `rbw import` auto-detects between it and
Bitwarden's own formats, so `--format` is usually only needed to force a
specific one:

* `rbw` -- the format shown above (optionally gpg-encrypted, see below).
* `bitwarden-json` -- Bitwarden's own plain JSON export.
* `bitwarden-encrypted-json` -- Bitwarden's password-protected "Encrypted
  JSON" export (a different scheme from `rbw export --encrypt` below; see
  the passphrase handling note further down).
* `bitwarden-zip` -- Bitwarden's "zip (with attachments)" export.
* `bitwarden-csv` -- Bitwarden's CSV export. Only Login and Secure Note
  items have CSV columns upstream, so Card/Identity/SSH-key items are
  skipped on export (with a warning) and can't round-trip through this
  format at all.

```sh
rbw export --format bitwarden-json --output vault.json
rbw import --format bitwarden-zip vault_export.zip
rbw import vault_export.csv   # auto-detected as bitwarden-csv
```

## Encryption

Pass `--encrypt` to write the export as a symmetrically gpg-encrypted
tar.gz archive instead of raw JSON, and `--decrypt` to read one back on
import. Both take the passphrase from `$RBW_EXPORT_PASSPHRASE` if set, and
prompt for it on the terminal (export asks twice, to confirm) otherwise:

```sh
rbw export --encrypt --output backup.tar.gz.gpg
rbw import --decrypt backup.tar.gz.gpg
```

`--format bitwarden-encrypted-json` always prompts for its own password the
same way (from `$RBW_EXPORT_PASSPHRASE` or the tty) even without `--encrypt`
-- that flag is only needed there to supply the password inline instead of
prompting:

```sh
rbw export --format bitwarden-encrypted-json --encrypt PASSWORD --output backup.json
```

For non-interactive use, set `RBW_EXPORT_PASSPHRASE` for both export and
import:

```sh
RBW_EXPORT_PASSPHRASE='correct horse battery staple' rbw export --encrypt --output backup.tar.gz.gpg
RBW_EXPORT_PASSPHRASE='correct horse battery staple' rbw import --decrypt backup.tar.gz.gpg
```

The passphrase can also be passed inline (`rbw export --encrypt PASSPHRASE`,
`rbw import --decrypt-passphrase PASSPHRASE`, or `--passphrase PASSPHRASE`
for commands reading `--from-file`), but that exposes it to
`ps` output and shell history, so prefer the prompt or the environment
variable.

## Working with an export file directly

This fork can use an export file as a temporary, already-decrypted vault. The
commands do not contact Bitwarden, use the configured account, or start the
agent. rbw JSON/gpg exports and upstream Bitwarden JSON, Encrypted JSON, and
zip-with-attachments exports are all accepted. For encrypted input, prefer
`RBW_EXPORT_PASSPHRASE`; `--passphrase` is available for automation where an
inline argument is acceptable:

```sh
export RBW_EXPORT_PASSPHRASE='correct horse battery staple'

rbw list --from-file backup.tar.gz.gpg
rbw search --from-file backup.tar.gz.gpg github
rbw get --from-file backup.tar.gz.gpg github
rbw show --from-file backup.tar.gz.gpg github
rbw code --from-file backup.tar.gz.gpg github
rbw history --from-file backup.tar.gz.gpg github
```

The same option is available for `add`, `edit`, `set`, `remove`/`delete`,
`archive`, `unarchive`, `restore`, and the attachment commands (`list`, `get`,
`create`, and `rm`). Write operations update the export in place and leave a
`FILE.bak` copy of the original. Use `--attachments` when creating the
original export if attachment contents need to be available to
`attachment get`, `attachment create`, or the TUI. Write operations preserve
the input format, including upstream Bitwarden formats.

The TUI can browse an export without touching the live vault, or edit it with
`--write`:

```sh
rbw tui --from-file backup.tar.gz.gpg
rbw tui --from-file backup.tar.gz.gpg --write
```

An export can also be converted to an upstream Bitwarden format without
logging in. This is useful for producing JSON, CSV, zip-with-attachments, or
Bitwarden's password-protected Encrypted JSON export:

```sh
rbw export --from-file backup.tar.gz.gpg \
  --format bitwarden-json --output vault.json
rbw export --from-file backup.tar.gz.gpg \
  --format bitwarden-csv --output vault.csv
rbw export --from-file backup.tar.gz.gpg \
  --format bitwarden-zip --output vault.zip
rbw export --from-file backup.tar.gz.gpg \
  --passphrase 'old password' \
  --format bitwarden-encrypted-json --encrypt 'new password' \
  --output vault.json
```

The `--passphrase` value is only for decrypting the input file;
`--encrypt` (or `RBW_EXPORT_PASSPHRASE` when the target format requires it)
controls encryption of the output. Inline passphrases can be visible in
process listings and shell history, so environment variables or a terminal
prompt are safer.

`rbw import` prints a summary when it's done (entries created/updated/
skipped, attachments restored, collections created) and exits non-zero if
any entry failed to import.

## Wiping a vault (`rbw purge-vault`)

`rbw purge-vault` **permanently** deletes every entry in the current
account's personal vault via the server's own purge endpoint, in a single
call rather than a loop of individual deletes -- useful before a full
restore from backup. This is not the same as `rbw purge`, which only clears
the local database cache. See the confirmation/password-reproof behavior
described above; entries assigned to an organization collection aren't
touched (purging those needs org owner/admin privileges, not currently
implemented in `rbw`).

```sh
rbw purge-vault                       # asks for confirmation, then pinentry for the password
rbw purge-vault --yes --stdin <<< "$MASTER_PASSWORD"   # fully non-interactive
```
