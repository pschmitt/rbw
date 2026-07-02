# Agent notes

## Build/test

Don't run `cargo build`/`test`/`clippy` on `fnuc` (it hosts Home Assistant
and other live infra). Do it on a scratch host instead: `rsync -az --delete
--exclude target --exclude .git ./ <host>:~/rbw-build/`, then `nix shell
nixpkgs#cargo nixpkgs#rustc nixpkgs#clippy nixpkgs#pkg-config
nixpkgs#openssl nixpkgs#gcc -c cargo <build|test|clippy>`. Run `cargo fmt
--all` before committing.

## Deploy

This repo is consumed by `nixos-config` (flake input `rbw`, `just hm fnuc`).
After pushing to `main`: bump the lock (`nix flake lock --update-input rbw`
in `nixos-config.git`), `just hm fnuc`, then `rbw stop-agent` and relaunch
the agent so it picks up the new Nix store path (plain `rbw`/`rbw-agent` on
`$PATH` resolve to the last-deployed build, not a local `target/debug`).
Commit the `nixos-config` flake.lock bump locally only — never push that
repo unless separately asked.

## Ongoing TODOs

- Every config.json option (accounts, `unlock` policy, `exclude_from_list`,
  `tui_keybindings`, etc.) should stay configurable through the
  home-manager module — when adding a new config option, add the matching
  Nix option in the same change.
- The TUI's status-bar hints and Help screen still show default keybindings
  even when `tui_keybindings` overrides them — known gap, not yet fixed.
