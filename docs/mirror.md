# Vault mirroring (`rbw mirror`)

`rbw mirror --from <account> --to <account>` copies entries from one
configured account's vault into another's -- e.g. keeping a self-hosted
Vaultwarden instance in sync with a bitwarden.com account. Both accounts must
already be configured (`rbw config add`/`rbw account add`); mirroring unlocks
each as needed.

By default the whole source vault is copied. Scope the source side with
`--collection <name-or-id>` (only that collection) or `--org-id <id>` (only
that organization); these two can be combined, and `--collection` alone
resolves against every org the source account belongs to unless `--org-id`
narrows it first.

On the destination side, `--dest-collection <name-or-id>` imports every
copied entry into one existing collection instead of preserving whatever
organization/collection metadata the source carries. `--dest-org
<name-or-id>` scopes *that* name lookup to one destination organization, for
when the same collection name exists in more than one org there.

`--overwrite` updates entries that already exist at the destination (matched
by name/username) instead of skipping them. `--attachments` also copies
attachment contents, downloaded from the source and re-uploaded to the
destination.

`--purge-dest` permanently wipes the destination before copying: the whole
personal vault, or just `--dest-collection`'s entries if given. It can't be
combined with a source-side `--collection`/`--org-id` scope (there's no
scoped-purge implementation for a partial source copy). This is a
`DANGER`-labeled prompt by default; `--stdin` supplies the destination
account's master password non-interactively (only meaningful with
`--purge-dest`), and `-y`/`--yes` skips the confirmation prompt entirely.

`--dry-run` prints the same plan (accounts, scope, entry/collection counts,
flags) and exits without touching the destination or prompting -- useful for
checking what a mirror run would do before committing to it.

```sh
# Full 1:1 mirror of the source account's personal vault, wiping the
# destination first.
rbw mirror --from personal --to vaultwarden --purge-dest --overwrite --attachments

# Mirror only a source-side collection into a same-named destination
# collection, without touching anything else already there.
rbw mirror --from personal --to vaultwarden \
  --collection "Shared" --dest-collection "Shared" --overwrite
```

For unattended runs, `--config <file>` executes a sequential list of mirror
specifications. The file is YAML when it ends in `.yaml`/`.yml`, otherwise
JSON. It contains a top-level `mirrors` list; each entry uses the same names
as the command-line options in camelCase:

```yaml
mirrors:
  - from: personal
    to: vaultwarden
    attachments: true
    overwrite: true
    purgeDest: true
  - from: personal
    to: vaultwarden
    collection: Shared
    destCollection: Shared
    destOrg: Example-Org
    overwrite: true
```

`destCollection` causes a missing destination organization or collection to
be created. `fallbackToWholeVault: true` makes a spec with `collection` use
the whole source vault when that source collection does not exist; this is
useful when a destination collection should hold either a same-named source
collection or a full-vault copy. `--yes`, `--stdin`, and `--dry-run` remain
command-line controls and can be combined with `--config`.
