# Unattended backups and mirrors

rbw runs scheduled jobs itself, without wrapper scripts:

- `rbw backup DIR` writes a rotated, optionally gpg-encrypted backup of an
  account ([backup.md](backup.md#rotated-backups-rbw-backup)).
- `rbw mirror --config FILE` mirrors one account into another, one way: into
  the destination's personal vault, or into organization collections
  reconciled by source id ([mirror.md](mirror.md)).

What a scheduled job needs beyond that comes from the account configuration:
an account whose `unlock.files` names its credential files logs in, registers
a new device with the personal API key when bitwarden.com asks for it, and
unlocks without prompting, generating a fresh TOTP code from the stored
secret for every login.

It ships two ways:

| | How the jobs run |
|---|---|
| NixOS module (`nixosModules.auto`) | `services.rbw`: sandboxed systemd units and timers, credentials via `LoadCredential` |
| Container image `ghcr.io/pschmitt/rbw-auto` | rbw as the entrypoint, cron for schedules, credentials as mounted files (Docker secrets) |

## Accounts and credentials

Each account a job uses is an rbw account in `config.json` with an
`unlock.files` block. Paths may start with `$CREDENTIALS_DIRECTORY`, which
rbw expands, so systemd credentials work directly:

```json
{
  "accounts": [
    {
      "name": "personal",
      "email": "me@example.com",
      "unlock": {
        "files": {
          "passwordFile": "/run/secrets/personal-password",
          "totpSecretFile": "/run/secrets/personal-totp",
          "clientIdFile": "/run/secrets/personal-client-id",
          "clientSecretFile": "/run/secrets/personal-client-secret"
        }
      }
    },
    {
      "name": "vaultwarden",
      "email": "me@example.com",
      "baseUrl": "https://vault.example.com",
      "unlock": { "files": { "passwordFile": "/run/secrets/vaultwarden-password" } }
    }
  ],
  "primaryAccount": "personal"
}
```

Only `passwordFile` is required. `totpSecretFile` is the base32 secret of the
account's TOTP two-step login. `clientIdFile`/`clientSecretFile` are the
[personal API key](https://bitwarden.com/help/article/personal-api-key/)
that bitwarden.com wants before a new device's first login; rbw registers
with it only when the server asks. Keep rbw's data directory
(`~/.local/share/rbw`, with the device id) between runs, or every run is a
new device.

## Container image

The image has `rbw` as its entrypoint, so a one-off job is a plain rbw
command:

```shell
docker run --rm \
  -v ./config:/root/.config/rbw:ro \
  -v rbw-state:/root/.local/share/rbw \
  -v ./data:/data \
  -v ./secrets:/run/secrets:ro \
  ghcr.io/pschmitt/rbw-auto:latest \
  --account personal backup /data --retention-days 30 \
  --passphrase-file /run/secrets/backup-passphrase
```

For schedules, run cron in the foreground and mount a crontab (system format,
with a user field) at `/etc/cron.d/rbw`:

```shell
# /etc/cron.d/rbw
0 3 * * *    root rbw --account personal backup /data --retention-days 30 --passphrase-file /run/secrets/backup-passphrase >/proc/1/fd/1 2>&1
10 */6 * * * root rbw mirror --config /root/.config/rbw/mirrors.yaml --yes >/proc/1/fd/1 2>&1
```

```shell
docker run -d --entrypoint cron ... ghcr.io/pschmitt/rbw-auto:latest -f
```

[auto/docker-compose.yaml](../auto/docker-compose.yaml) is a complete
example with Docker secrets. The image is built from
[auto/Dockerfile](../auto/Dockerfile) on top of `ghcr.io/pschmitt/rbw` and
carries rbw's version.

## Backups

A backup is what `rbw export` writes: rbw's JSON, as a gpg-encrypted tar.gz
archive when a passphrase is given. Archives from the older `bw`-CLI-based
rbw-auto have another format and need that old tooling.

### Restoring

Read a backup with rbw itself, with the passphrase in
`RBW_EXPORT_PASSPHRASE`:

```shell
export RBW_EXPORT_PASSPHRASE='mySecret1234'
rbw list --from-file data/bw-export-xxx.tar.gz.gpg
rbw tui --from-file data/bw-export-xxx.tar.gz.gpg
rbw import --decrypt data/bw-export-xxx.tar.gz.gpg
```

[backup.md](backup.md#working-with-an-export-file-directly) lists every
command that reads `--from-file`, and how to convert a backup to the upstream
Bitwarden formats. Attachments are only in backups made with attachments on
(the default).

## Mirrors

`rbw mirror --config` runs a list of mirror specifications in turn
([mirror.md](mirror.md)). Into a destination collection, the mirror is
reconciled by source id: unchanged entries are skipped, changed ones
rewritten, missing ones created, and with `prune: true` copies whose source
entry is gone move to the trash. A destination collection with no
equally-named source collection receives the source's personal vault
(`fallbackToPersonalVault: true`) or the whole vault
(`fallbackToWholeVault: true`).

```yaml
mirrors:
  - from: personal
    to: vaultwarden
    collection: Personal vault
    destCollection: Personal vault
    destOrg: Example-Org
    attachments: true
    prune: true
    fallbackToPersonalVault: true
```

## NixOS module

The flake exports `nixosModules.auto`, which provides `services.rbw`. It runs
rbw itself, without the scripts above: `rbw backup DIR` for backups
([backup.md](backup.md)) and `rbw mirror --config` for the mirror
([mirror.md](mirror.md)). Accounts unlock unattended from systemd
credentials (`unlock.files` in rbw's `config.json`): rbw reads the master
password, generates a fresh TOTP code from the stored secret, and registers a
new device with the personal API key when bitwarden.com asks for it. No
secret enters the Nix store or a unit's environment.

```nix
{
  imports = [ inputs.rbw.nixosModules.auto ];

  services.rbw = {
    accounts = {
      personal = {
        email = "me@example.com";
        passwordFile = config.sops.secrets."rbw/personal/password".path;
        totpSecretFile = config.sops.secrets."rbw/personal/totp".path;
        apiKey = {
          clientIdFile = config.sops.secrets."rbw/personal/client-id".path;
          clientSecretFile = config.sops.secrets."rbw/personal/client-secret".path;
        };
      };
      vaultwarden = {
        email = "me@example.com";
        baseUrl = "https://vault.example.com";
        passwordFile = config.sops.secrets."rbw/vaultwarden/password".path;
      };
    };

    backups.personal = {
      account = "personal";
      path = "/srv/bw-backup";
      retentionDays = 30;
      passphraseFile = config.sops.secrets."rbw/backup/passphrase".path;
      schedule = "0/6:00:00";
    };

    mirror = {
      enable = true;
      from = "personal";
      to = "vaultwarden";
      collections = {
        org = "Example-Org";
        # A source collection of the same name is copied 1:1; any other
        # name gets the source's personal vault (`fallback`).
        names = [ "Personal vault" "Shared" ];
      };
      schedule = "0/6:10:00";
    };
  };
}
```

How the module runs them:

- Each backup is a `rbw-backup-<name>` service and timer; the mirror is one
  `rbw-mirror` service and timer that runs every collection in turn.
- Backups run as the `rbw-backup` system user, the mirror as `rbw-mirror`
  (`backupUser`/`mirrorUser`). Each user's rbw `config.json` lists the
  accounts its jobs use; the local vault cache is kept between runs.
- Credentials reach the units through `LoadCredential`; the units are
  sandboxed (read-only system, private `/tmp` and devices, no capabilities,
  a system-call filter) and stop their rbw agents afterwards.
- The mirror is reconciled by source id and, with `prune` (on by default),
  moves copies whose source is gone to the trash ([mirror.md](mirror.md)).
- `healthcheckUrlFile` pings a Healthchecks.io-style URL on start, success
  and failure; `monit.enable` (on by default) adds a Monit check on the age of
  the last success (`LAST_BACKUP` in the backup directory, `LAST_MIRROR` in
  the mirror user's home).
- `randomizedDelaySec` (default `"5m"`) sets the timers' `RandomizedDelaySec`.
  Jobs that log into the same account should be scheduled apart: bitwarden.com
  rejects a TOTP code that was already used.

`services.rbw-auto` was removed; evaluating a configuration that still sets it
fails with a pointer to these options. Its environment files become one file
per credential. The full option list is in
[nix/services-module.nix](../nix/services-module.nix).
