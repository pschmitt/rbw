# rbw-auto

Scheduled, unattended vault backups and vault-to-vault syncs built on rbw:
the container image `ghcr.io/pschmitt/rbw-auto`, the `rbw-auto-backup` and
`rbw-auto-sync` scripts, and the NixOS module `services.rbw-auto`.

Documentation: [docs/auto.md](../docs/auto.md).

This directory holds the scripts and the container files. The Nix packages
and the NixOS module are in [nix/](../nix/) (`rbw-auto-*.nix`,
`auto-module.nix`).

## License

rbw-auto (this directory and the `nix/rbw-auto-*.nix` and
`nix/auto-module.nix` files) is licensed under the GNU General Public License
v3.0 only; see [LICENSE](LICENSE). The rest of rbw has its own license (see
the repository root).
