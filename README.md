# rbw

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Installation

### Cargo

With a working Rust toolchain, install this fork directly from Git:

```sh
cargo install --locked --git https://github.com/pschmitt/rbw
```

This requires the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program to be installed (to display password prompts).

### Home Manager

This fork also exports a Home Manager module (`homeManagerModules.default`)
that exposes `config.json` as declarative Nix options (mirroring `Config`
and `Account` in `src/config.rs`), and installs `rbw` itself.

Its options live under `programs.rbw.declarative`, not `programs.rbw`
directly: recent Home Manager releases ship their own built-in, minimal
`programs.rbw` module (freeform-typed, install-only), and its `enable`/
`package`/`settings` options are unconditionally declared as soon as Home
Manager is imported. This module can't redeclare those same option paths,
so it lives at a sibling path instead. It's fully independent of the
built-in module -- don't set both `programs.rbw.settings` (upstream,
freeform) and `programs.rbw.declarative.enable` (this module) at once, as
only this module actually renders `config.json`.

Add the flake as an input:

```nix
inputs.rbw.url = "github:pschmitt/rbw";
```

Import the module in your Home Manager configuration:

```nix
{
  imports = [ inputs.rbw.homeManagerModules.default ];
}
```

Then configure it:

```nix
programs.rbw.declarative = {
  enable = true;
  settings = {
    pinentry = "pinentry-gnome3";
    lock_timeout = 3600;
    primary_account = "personal";
    accounts.personal = {
      email = "me@example.com";
      base_url = "https://vault.bitwarden.com";
    };
  };
};
```

This writes `~/.config/rbw/config.json` (or
`$XDG_CONFIG_HOME/rbw/config.json`) from `programs.rbw.declarative.settings`;
unset options are omitted from the generated file rather than written as
`null`. See the module's option documentation (e.g. via `home-manager
option programs.rbw.declarative` or your editor's Nix LSP) for the full
list of settings, including `accounts.<name>.unlock`,
`accounts.<name>.exclude_from_list`, and `tui_keybindings`.

## Configuration

Configuration options are set using the `rbw config` command (`rbw config set
<key> <value>`, `rbw config get <key>`, `rbw config unset <key>`, `rbw config
show`, or `rbw config edit` to edit the whole config.json in `$EDITOR`).
Available configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory for
  before requiring the password to be entered again. Defaults to `3600` (one
  hour).
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.
* `password_gen`: The default password-generation policy used by `rbw gen`
  and `rbw create --generate` whenever the equivalent flag isn't passed
  explicitly (`length`, `no_symbols`, `only_numbers`, `nonconfusables`,
  `diceware` -- same fields as those commands' flags). Not settable via `rbw
  config set`; edit `config.json` directly, or use the TUI's settings view
  (`S` from the main screen).

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

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
`rbw lock` or `rbw stop-agent`.

Locking is account-aware: with multiple accounts configured, `rbw lock` with
no account selected locks every account, while `rbw -a <name> lock` (or
`RBW_ACCOUNT=<name> rbw lock`) locks only that account. `rbw lock --all`
always locks every configured account, even when an account is selected.

Destructive commands (`rbw remove`, `rbw attachment rm`, `rbw collection
delete`, and `rbw purge`) ask for confirmation before making changes when
stdin is a terminal; pass `-y`/`--yes` to skip the prompt. When stdin is not a
tty (scripts and pipelines), no prompt is shown and the historical no-prompt
behavior is kept.

The more destructive, unrecoverable operations -- `rbw purge-vault` and `rbw
org delete` -- go further: they always ask for confirmation (`-y`/`--yes` to
skip) *and* re-prompt for the master password to prove intent, the same way
`rbw login`/`rbw unlock` do. Pass `--stdin` to supply that password
non-interactively instead of via pinentry; `--yes --stdin` together makes
either command fully scriptable.

`rbw remove` moves an entry to the trash rather than deleting it outright;
pass `--force` for an actual permanent delete (this also catches an
already-trashed entry with no live match, letting `--force` double as a
trash-purge for a single item). `rbw restore` undoes a trash move. Deleted
and archived entries (see below) are hidden from `list`/`search` by default;
pass `--trashed`/`--include-trashed` or `--archived`/`--include-archived` (or
set `hide_trashed`/`hide_archived` to `false` in the config) to show them.

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

For commands that support formatted output, use `-o name`, `-o json`, or
`-o yaml`. `-o json` is equivalent to `--json`, and `-o yaml` emits YAML.

`rbw create --generate` (`-g`) generates the password instead of prompting
for one, using the same flags as `rbw gen` (`--length`/`-l`, `--no-symbols`,
`--only-numbers`, `--nonconfusables`, `--diceware`); any of those flags
implies `--generate`. Omitted flags fall back to the `password_gen` config
policy, then to a 20-character password from the full character set. This
is mutually exclusive with piping a fully-formed entry into `rbw create` via
stdin.

### Archiving and trash

Entries can be archived (hidden from `list`/`search` without deleting them)
independently of the trash:

* `rbw archive <entry>`: archive an entry. Pass `--bulk` to treat every
  needle as matching every entry it finds and archive all of them at once
  (asks for confirmation unless `-y`/`--yes`).
* `rbw unarchive <entry>`: undo it (same `--bulk`/`-y` support).

Archived entries are hidden by default, same as trashed ones -- see
`--archived`/`--include-archived` and `hide_archived` above.

### Organization collections (`rbw collection`)

Collections belonging to your organizations are managed with the `rbw
collection` command group:

* `rbw collection list` (alias: `ls`): list all collections in the
  organization. Supports the usual output flags (`-o name|json|yaml`,
  `--raw`/`--json`, `--yaml`).
* `rbw collection create <name>` (alias: `add`): create a new collection.
* `rbw collection delete <collection>` (aliases: `rm`, `remove`, `del`):
  delete a collection, given by name or ID (asks for confirmation on a
  terminal; `-y`/`--yes` skips it).
* `rbw collection rename <collection> <new-name>`: rename a collection,
  given by name or ID.
* `rbw collection assign <entry>... --collection <name-or-id>...`: replace
  the matched entry's (or, with `--bulk`, entries') current collection list
  with the given `--collection` values (repeat the flag for more than one).
  Collections can be given by name or ID; names are resolved against each
  entry's own organization. Without `--bulk`, exactly one needle must
  resolve to exactly one entry; with `--bulk`, every needle is matched
  independently, previewed, and confirmed once unless `-y` is given.
* `rbw collection assign <entry> --personal`: move the entry out of its
  organization entirely and back into your personal vault, instead of
  assigning collections (mutually exclusive with `--collection`). Entries
  with attachments aren't supported yet.
* `rbw collection unassign <entry> [--collection <name-or-id>...]`: the
  complement to `assign` -- removes the given collections from the entry
  without leaving the organization (any other collections it belongs to are
  left untouched). With no `--collection` given at all, removes every
  collection the entry currently belongs to. To move an entry out of the
  organization entirely, use `assign --personal` instead.
* `rbw collection grant <collection> <user>`: grant a member access to a
  collection directly, replacing their existing permissions on it entirely.
  `--read-only`, `--hide-passwords`, and `--manage` control the grant; omit
  all three for unrestricted read/write access. This is the generic
  primitive underneath `propagate-permissions` below, for when you just want
  to set one permission on one (collection, member) pair.
* `rbw collection propagate-permissions`: grant members access to nested
  collections (the topmost collection they hold gets edit permissions, its
  descendants get manage). This is a dry-run by default; pass `--apply` to
  execute the changes, and `-v`/`--verbose` for per-run counts.

`create`, `delete`, `rename`, `grant`, and `propagate-permissions` accept an
optional `--org-id`; when the vault contains exactly one organization, it is
auto-detected and the flag can be omitted.

### Organization management (`rbw org`)

Organizations themselves (as opposed to their collections) are managed with
the `rbw org` command group:

* `rbw org list` (alias: `ls`): list all organizations this account is a
  member of. Supports the usual output flags.
* `rbw org create <name>`: create a new organization owned by the current
  account. Whether an account is allowed to create organizations at all is a
  server-side policy setting, not something `rbw` controls.
* `rbw org invite <email>`: invite a user into an organization by email.
  `--role` sets their role (`owner`, `admin`, `user`, or `manager`; defaults
  to `user`).
* `rbw org accept --url <invite-link>`: accept an invite, called by the
  invitee. Takes either the whole invite link pasted from the invite email
  (`--url`) or the individual `--org-id`/`--user-id`/`--token` values it
  encodes. This alone doesn't make the org usable yet -- the inviter still
  needs to run `confirm` afterward.
* `rbw org confirm <user>`: confirm a member who has accepted their invite.
  Required before they can decrypt anything in the org -- this re-encrypts
  the org's key to their now-known public key, which only happens once
  they've accepted.
* `rbw org remove-user <user>` (aliases: `rm`, `remove`, `del`): remove a
  member from an organization (asks for confirmation unless `-y`/`--yes`).
* `rbw org delete`: **permanently** delete an organization and everything in
  it. Prompts for the master password (like `rbw purge-vault`) and, unless
  `--yes` is given, a confirmation; `--stdin` supplies the password without a
  pinentry prompt. This cannot be undone.

`invite`, `remove-user`, and `delete` accept an optional `--org-id`; when the
vault contains exactly one organization, it is auto-detected and the flag can
be omitted. `invite`/`remove-user`/`confirm`/`accept` take the member by
email or user ID.

### Template and command injection

`rbw inject` can render templates containing secret references. References use
the format `bw://<uuid-or-name>?field=<field>`, where the item can be addressed
by UUID or by an exact name consisting only of letters, digits, `-`, and `_`.
For items whose names contain spaces or other punctuation, use the item UUID
instead. If `field` is omitted, the entry password is used. References can be
written directly in the template or wrapped in `{{ bw://... }}`.

By default, `rbw inject` reads the template from stdin and writes the rendered
output to stdout. Use `--in-file` and `--out-file` to work with files instead:

```sh
echo 'database_password={{ bw://db-prod?field=password }}' | rbw inject
rbw inject --in-file config.tpl --out-file config.yaml
```

`rbw run` reads environment bindings from `./.env` by default (or another file
with `--env-file`), parses them using dotenv syntax, resolves any `bw://`
references in the resulting values, and then runs the requested command without
going through a shell:

```sh
cat > .env <<'EOF'
DATABASE_URL=postgres://app:bw://db-prod?field=password@db.example/app
API_TOKEN=bw://deploy-token
EOF

rbw run -- env
rbw run --env-file .env.local -- docker compose up -d
```

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

### Backup and restore (`rbw export`/`rbw import`)

`rbw export` writes the entire active vault (all entries, fully decrypted,
plus collections) as JSON to stdout:

```sh
rbw export > backup.json
```

You can also write directly to a file without shell redirection (the file
is created with mode 0600, since it contains the fully decrypted vault):

```sh
rbw export --output backup.json
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
folder metadata the export carries.

Pass `--attachments` on export to also download and embed decrypted
attachment contents (base64-encoded) in the export; this makes the export
considerably larger and slower to produce, but lets `import` restore
attachments too.

#### Upstream Bitwarden export formats

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

#### Encryption

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

The passphrase can also be passed inline (`rbw export --encrypt PASSPHRASE`
and `rbw import --decrypt-passphrase PASSPHRASE`), but that exposes it to
`ps` output and shell history, so prefer the prompt or the environment
variable.

`rbw import` prints a summary when it's done (entries created/updated/
skipped, attachments restored, collections created) and exits non-zero if
any entry failed to import.

#### Wiping a vault (`rbw purge-vault`)

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

### SSH Agent

`rbw-agent` includes a built-in SSH agent for signing SSH authentication
challenges directly. To use it, ensure that rbw is running (in order to make
it start handling ssh agent requests), and then point your SSH client to the
SSH agent socket:

```sh
rbw unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"
```

If you're using a profile, the socket will be located at
`"XDG_RUNTIME_DIR/rbw-<profile>/ssh-agent-socket"`.

### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
