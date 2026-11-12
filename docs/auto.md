# Scheduled backup and sync (`rbw-auto`)

`rbw-auto` runs unattended vault backups and vault-to-vault syncs. It is a
thin layer of shell scripts around `rbw export` ([backup.md](backup.md)) and
`rbw mirror` ([mirror.md](mirror.md)) that adds what a scheduled job needs:

- non-interactive login and unlock, with TOTP codes generated from a stored
  secret and the one-time `rbw register` for bitwarden.com done for you;
- backup rotation;
- [Healthchecks.io](https://healthchecks.io) pings (start, success, failure);
- creation of missing destination organizations and collections.

It ships two ways, both from this repository and with rbw's own version:

| | Backup | Sync |
|---|---|---|
| Container image | `ghcr.io/pschmitt/rbw-auto` (default command) | same image, `sync` command |
| Nix package | `rbw-auto-backup` | `rbw-auto-sync` |
| NixOS module | `services.rbw.backups.<name>` (runs `rbw backup`) | `services.rbw.mirror` (runs `rbw mirror`) |

The scripts, the container files and the NixOS module are licensed
GPL-3.0 ([auto/LICENSE](../auto/LICENSE)), unlike the rest of rbw.

## Accounts and credentials

Each account a job uses must be an rbw account (name, email, server URL).
The container renders rbw's `config.json` from environment variables on every
start; the NixOS module renders it from its options. Only that non-secret
metadata is written to disk. Master passwords, TOTP secrets and personal API
keys stay in environment variables (an env file for Docker,
`environmentFiles` for NixOS) and reach rbw over stdin.

The official bitwarden.com server requires a one-time `rbw register` with a
[personal API key](https://bitwarden.com/help/article/personal-api-key/)
before a script can log in (bot detection). Both jobs run it before logging
in when the account's `*_REGISTER_CLIENT_ID` and `*_REGISTER_CLIENT_SECRET`
variables are set, and skip it otherwise.

## Backup

```shell
podman run -it --rm \
  -v /tmp/data:/data \
  -e ACCOUNT_EMAIL=me@example.com \
  -e BW_PASSWORD=xxxx \
  -e ENCRYPTION_PASSPHRASE=mySecret1234 \
  -e BW_BACKUP_RETENTION=30 \
  -e CRON="0 23 * * *" \
  ghcr.io/pschmitt/rbw-auto:latest
```

| Variable | Default | Meaning |
|---|---|---|
| `ACCOUNT` | `backup` | The rbw account name. |
| `ACCOUNT_EMAIL` | | The account's email address. |
| `ACCOUNT_BASE_URL` | | The account's server URL. Omit for bitwarden.com. |
| `BW_PASSWORD` | | The account's master password. |
| `BW_TOTP_SECRET` | | Base32 TOTP secret, if the account uses TOTP 2FA. A fresh code is generated for each login and unlock (`oathtool`). |
| `BW_BACKUP_REGISTER_CLIENT_ID`, `BW_BACKUP_REGISTER_CLIENT_SECRET` | | Personal API key for `rbw register` on bitwarden.com. |
| `BW_BACKUP_ATTACHMENTS` | `1` | `0` skips attachment contents: faster and smaller, but attachments cannot be restored from that backup. |
| `ENCRYPTION_PASSPHRASE` | | When set, backups are gpg-encrypted (`rbw export --encrypt`). |
| `BW_BACKUP_RETENTION` | `30` | Backups to keep; `0` keeps all. Replaces the deprecated `KEEP`. |
| `BW_BACKUP_RETENTION_DAYS` | unset | Also delete backups older than this many days; the newest is always kept. The NixOS module sets this from `retentionDays` (and `BW_BACKUP_RETENTION=0`). |
| `CRON` | | Run on this schedule instead of once. |
| `HEALTHCHECK_URL` | | Healthchecks.io (or compatible) URL to ping. |
| `BW_BACKUP_DIR` | `/data` | Where backups are written. Mount your volume there. |

A backup is whatever `rbw export` writes: rbw's JSON, as a gpg-encrypted
tar.gz archive when a passphrase is set. Archives from the older
`bw`-CLI-based rbw-auto have another format and need that old tooling.

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

## Sync between two vaults

The `sync` command mirrors one account's vault into another with
`rbw mirror` (entries and attachments, no temporary files). The source
account is only read.

```shell
podman run -it --rm \
  -e SRC_ACCOUNT_EMAIL=you@example.com \
  -e SRC_BW_PASSWORD=xxxx \
  -e DEST_ACCOUNT_EMAIL=you@vaultwarden.example \
  -e DEST_ACCOUNT_BASE_URL=https://vault.example.com \
  -e DEST_BW_PASSWORD=xxxx \
  ghcr.io/pschmitt/rbw-auto:latest sync
```

| Variable | Default | Meaning |
|---|---|---|
| `SRC_ACCOUNT`, `DEST_ACCOUNT` | `source`, `destination` | The rbw account names. |
| `SRC_ACCOUNT_EMAIL`, `DEST_ACCOUNT_EMAIL` | | Email addresses. |
| `SRC_ACCOUNT_BASE_URL`, `DEST_ACCOUNT_BASE_URL` | | Server URLs. Omit for bitwarden.com. |
| `SRC_BW_PASSWORD`, `DEST_BW_PASSWORD` | | Master passwords. |
| `SRC_BW_TOTP_SECRET`, `DEST_BW_TOTP_SECRET` | | TOTP secrets, as for backups. |
| `SRC_REGISTER_CLIENT_ID`, `SRC_REGISTER_CLIENT_SECRET`, `DEST_REGISTER_CLIENT_ID`, `DEST_REGISTER_CLIENT_SECRET` | | Personal API keys for `rbw register`. |
| `BW_SYNC_MODE` | `personal` | `personal` or `collections`, see below. |
| `DEST_BW_PURGE_VAULT` | | `personal` mode: `1` wipes the destination's personal vault first (server-side, like `rbw purge-vault`). Organization items are never touched. |
| `BW_SYNC_PURGE_DEST_COLLECTION` | unset | `collections` mode: `1` wipes the destination collection before a whole-vault fallback. By default, existing destination entries are preserved. |
| `BW_SYNC_PRUNE` | unset | `collections` mode: `1` moves destination entries whose source entry is gone to the trash (`rbw mirror --prune`). |
| `DEST_BW_ORG`, `DEST_BW_COLLECTIONS` | | `collections` mode: the destination organization and a comma-separated list of collections, e.g. `default,Some Other Collection`. Missing ones are created. |
| `BW_SYNC_ATTACHMENTS` | `1` | `0` skips attachments. |
| `BW_SYNC_OVERWRITE` | `1` | `0` leaves existing destination entries alone. |
| `HEALTHCHECK_URL` | | As for backups. |

Modes:

- `personal` mirrors the whole source vault into the destination's personal
  vault, 1:1.
- `collections` mirrors into one or more destination collections. A
  collection whose name also exists on the source side gets a scoped 1:1
  mirror of just that source collection. Any other gets the whole source
  vault (useful for a "whole vault" collection). When that fallback runs,
  destination entries are preserved by default; set
  `BW_SYNC_PURGE_DEST_COLLECTION=1` to clear the collection first.

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

## Running from a checkout

`auto/run.sh` builds the image and runs the scripts from the working tree
through `auto/docker-compose.yaml` (backups land in `auto/data/`), with
credentials in `auto/secrets.env` (start from
[auto/secrets.env.sample](../auto/secrets.env.sample)). `-d` sets `DEBUG=1`.

```shell
auto/run.sh backup
auto/run.sh sync
```
