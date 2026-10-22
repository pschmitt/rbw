# Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries (but will
not attempt to log in to the server), `rbw sync` will automatically run `rbw
login` to log in to the server before downloading the password database (but
will not unlock the database), and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw agent stop` (`rbw stop-agent` remains as a compatibility
alias). If the agent is unresponsive, use `rbw agent stop --kill`.

Locking is account-aware: with multiple accounts configured, `rbw lock` with
no account selected locks every account, while `rbw -a <name> lock` (or
`RBW_ACCOUNT=<name> rbw lock`) locks only that account. `rbw lock --all`
always locks every configured account, even when an account is selected.

The TUI can also lock manually with `l`, or automatically after an inactivity
timeout configured by `tui.lockTimeout` or overridden with
`--screen-lock-timeout`. Press Enter or `y` on the lock screen to re-enter the
master password; press `q` to quit.

Destructive commands (`rbw remove`, `rbw attachment rm`, `rbw collection
delete`, and `rbw purge`/`rbw panic`) ask for confirmation before making changes when
stdin is a terminal; pass `-y`/`--yes` to skip the prompt. When stdin is not a
tty (scripts and pipelines), no prompt is shown and the historical no-prompt
behavior is kept.

The more destructive, unrecoverable operations -- `rbw purge-vault` and `rbw
org delete` -- go further: they always ask for confirmation (`-y`/`--yes` to
skip) *and* re-prompt for the master password to prove intent, the same way
`rbw login`/`rbw unlock` do. Pass `--stdin` to supply that password
non-interactively instead of via pinentry; `--yes --stdin` together makes
either command fully scriptable.

`rbw security` changes the master key of the current account on the server:

```sh
rbw security change-password            # prompts for current + new password
rbw security change-password --rotate-key
rbw security rotate-key                 # new account key, same password
rbw security kdf                        # show the KDF settings
rbw security kdf --kdf argon2id         # Bitwarden's argon2id defaults
rbw security kdf --iterations 800000    # tune the current algorithm
rbw security secret-service enroll      # desktop keyring/fingerprint unlock
rbw security termux enroll              # Termux Android Keystore unlock
```

`secret-service` and `termux` are described in
[desktop-unlock.md](desktop-unlock.md) and [termux.md](termux.md); the old
top-level `rbw secret-service`/`rbw termux` spellings still work.

Each asks for confirmation (`-y`/`--yes` to skip) and prompts for the
current master password via pinentry; `--stdin` reads it from stdin instead
(for `change-password`: the current password on the first line, the new one
on the second). Other sessions of the account may be logged out; rbw logs
itself back in with the new password.

`change-password` and `kdf` only re-wrap the account key, so the vault itself
is not re-encrypted. The server replaces the password hint on a password
change: `--hint` sets a new one, leaving it out clears it. A Secret Service
unlock credential is updated with the new password; Termux Keystore and
`credential_source` unlocks still hold the old one and need updating by hand.

`rotate-key` (or `change-password --rotate-key`) replaces the account key and
re-encrypts everything in the personal vault that used it -- items, folders,
attachment and send keys and the account's private key -- in one request
the server rejects unless it covers the whole vault. Organization items are
not affected. It is refused while emergency access is granted, while the
account is enrolled in an organization's account recovery, and for items
whose attachments have no key of their own. It has been tested against
Vaultwarden; bitwarden.com may require additional data for accounts that use
trusted devices or passkey login.

`rbw purge` also removes the active account's configured Termux Keystore key
and encrypted unlock bundle. Use `rbw security termux remove` when you want to remove
only that native unlock. Both destructive paths are irreversible for the key
and bundle.

`rbw remove` moves an entry to the trash rather than deleting it outright;
pass `--force` for an actual permanent delete (this also catches an
already-trashed entry with no live match, letting `--force` double as a
trash-purge for a single item). `rbw restore` undoes a trash move. Deleted
and archived entries (see below) are hidden from `list`/`search` by default;
pass `--trashed`/`--include-trashed` or `--archived`/`--include-archived` (or
set `hide.trashed`/`hide.archived` to `false` in the config) to show them.

`rbw help` can be used to get more information about the available
functionality.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag (or `--json`) will show the output as JSON. On a terminal, JSON output is
colorized automatically; when piped, plain JSON is emitted. In addition to
matching against the name, you can pass a UUID as the name to search for the
entry with that id, or a URL to search for an entry with a matching website
entry.

Every entry-lookup command (`get`, `show`, `code`, `edit`, `set`, `rm`,
`archive`, `unarchive`, `restore`, `history`, `list`, `search`, and
`attachment list`/`get`/`rm`) also accepts `--collection <name-or-id>` and
`--org <name-or-id>` to narrow matches to entries in a specific collection or
organization -- handy when the same entry name exists in more than one place.
Combine both to disambiguate a collection name that exists in more than one
org. With `--all` (searching across multiple accounts), an account that
doesn't have a matching collection/org just contributes nothing rather than
failing the whole lookup.

`rbw list` also accepts an optional search term (`rbw list google`) to show only
matching entries, and `rbw list --with-attachments` restricts the results to
items that have attachments. Interactive table-style output uses uppercase
headers, smart coloring, and default `UID`, `NAME`, `USER`, and
`ATTACHMENTS` columns. To inspect attachments directly, run
`rbw attachment list <entry>` (or `rbw attachment list <entry> --json`). To
download one, run
`rbw attachment get <entry> --attachment <attachment-id-or-filename>`, and to
delete one, `rbw attachment rm <entry> --attachment <attachment-id-or-filename>`
(aliases: `remove`, `delete`). When an entry has exactly one attachment,
`--attachment` can be omitted. If you omit or mistype the attachment name,
`rbw` will print the available attachments. Use
`rbw attachment get <entry> --attachment <attachment-id-or-filename> --output -`
to write the attachment to stdout instead of a file. Using the entry UUID is
the most precise option and avoids shell quoting issues for names with spaces.

Search terms support field scopes such as `u:alice`, `uri:github`, `n:git`,
`f:work`, `org:acme`, and `col:production`; the same syntax works in the TUI
and in `rbw list <term>`.

For commands that support formatted output, use `-o name`, `-o json`, or
`-o yaml`. `-o json` is equivalent to `--json`, and `-o yaml` emits YAML.

`rbw create --generate` (`-g`) generates the password instead of prompting
for one, using the same flags as `rbw gen` (`--length`/`-l`, `--no-symbols`,
`--only-numbers`, `--nonconfusables`, `--diceware`); any of those flags
implies `--generate`. Omitted flags fall back to the `passwordGen` config
policy, then to a 20-character password from the full character set. This
is mutually exclusive with piping a fully-formed entry into `rbw create` via
stdin.

`rbw create --secure-note NAME` creates a secure note instead of a login:
the editor opens with an empty `notes` field and a `secure_note` data type.
Piped stdin is stored verbatim as the note (`echo foo | rbw create
--secure-note NAME`) rather than parsed as a YAML/JSON entry. It conflicts
with the `USER` argument, `--uri`, and password generation.

## Archiving and trash

Entries can be archived (hidden from `list`/`search` without deleting them)
independently of the trash:

* `rbw archive <entry>`: archive an entry. Pass `--bulk` to treat every
  needle as matching every entry it finds and archive all of them at once
  (asks for confirmation unless `-y`/`--yes`).
* `rbw unarchive <entry>`: undo it (same `--bulk`/`-y` support).

Archived entries are hidden by default, same as trashed ones -- see
`--archived`/`--include-archived` and `hide.archived` above.

## Using the official Bitwarden server

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).
Pass `--stdin` to supply the client ID and client secret non-interactively
instead (one per line, client ID first) -- useful for a scripted first-run
registration on a freshly provisioned host:

```sh
printf '%s\n%s\n' "$API_CLIENT_ID" "$API_CLIENT_SECRET" | rbw register --stdin
```

## 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)
* WebAuthn / Passkey (FIDO2 security key; requires building with
  `--features fido2`, which needs libudev on Linux)

Duo security is an unsupported 2FA mechanism.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Cipher write failures and editor recovery

Full cipher edits preserve the item's master-password reprompt policy,
favorite flag, archive timestamp, item key, and server revision. CLI `edit`
and `set` synchronize before resolving selectors; revision checks still reject
changes made while an editor or confirmation prompt is open.

For `create`, `generate`, `edit`, `set`, and passkey counter writes, a failure
exits with status 2 when a server write has succeeded but local follow-up work
failed. Run `rbw sync` and inspect the affected entries
before retrying. Bulk updates can also return 2 after partial success; do not
repeat the entire batch blindly. Other failures return status 1.

When an interactive `create` or `edit` fails before a confirmed write, rbw
keeps the entered plaintext in its profile's data directory under
`unsaved-edits` and reports the path. The directory has mode 0700 and files
have mode 0600. Delete the recovery file after recovering the edit. Piped input
is never saved as a recovery file, and confirmed writes do not leave one.
