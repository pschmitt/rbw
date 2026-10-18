# Organizations and collections

## Organization collections (`rbw collection`)

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

## Organization management (`rbw org`)

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
* `rbw org rename <new-name>`: rename an organization. Organization names
  are plaintext (unlike collection names), so this is a simple metadata
  update.
* `rbw org remove-user <user>` (aliases: `rm`, `remove`, `del`): remove a
  member from an organization (asks for confirmation unless `-y`/`--yes`).
* `rbw org delete`: **permanently** delete an organization and everything in
  it. Prompts for the master password (like `rbw purge-vault`) and, unless
  `--yes` is given, a confirmation; `--stdin` supplies the password without a
  pinentry prompt. This cannot be undone.

`invite`, `remove-user`, `rename`, and `delete` accept an optional `--org-id`; when the
vault contains exactly one organization, it is auto-detected and the flag can
be omitted. `invite`/`remove-user`/`confirm`/`accept` take the member by
email or user ID.
