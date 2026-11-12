# rbw-auto container image

`ghcr.io/pschmitt/rbw-auto` is rbw packaged for unattended jobs: `rbw backup`
and `rbw mirror`, with gpg for encrypted backups and cron for schedules. It
has no wrapper scripts; rbw unlocks accounts from credential files itself.

Documentation: [docs/auto.md](../docs/auto.md). The NixOS module for the
same jobs is [nix/services-module.nix](../nix/services-module.nix).
