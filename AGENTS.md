# Agent notes

## Build/test

Don't run `cargo build`/`test`/`clippy` on the machine the agent runs on (it
may host live infra; see the `brkn-infra` skill). Do it on a build host instead: `rsync -az --delete
--exclude target --exclude .git ./ <host>:~/build/rbw/`, then `nix shell
nixpkgs#cargo nixpkgs#rustc nixpkgs#clippy nixpkgs#pkg-config
nixpkgs#openssl nixpkgs#gcc -c cargo <build|test|clippy>`. Run `cargo fmt
--all` before committing.

## Post-push CI follow-up

After every push, follow GitHub Actions for the exact pushed commit through to
completion. Inspect failing jobs, fix problems within the task's scope, push
the correction, and follow the new runs again. Do not stop at a successful
push or infer success from local checks, an older commit, or a few passing jobs.
If CI cannot finish because of an external blocker, report the specific blocker
and leave release and deployment actions pending.

## Agent protocol

`rbw`, `rbw-browser` and `rbw-agent` work together when they share
`major.minor` (`rbw::protocol::compatible`): an agent from another patch
release keeps running across an upgrade. So any change to the agent
protocol (`src/protocol.rs`: actions, responses, their fields) needs at
least a minor version bump, never just a patch release.

## Deploy

Never release a version with failing CI. Before publishing a version tag or
release, updating the consumer's flake pin, or deploying that version, verify
that every release CI workflow (`build`, `lint`, `test`, and `docker`) has completed
successfully for the exact commit being released. Pending, running, cancelled,
or missing checks do not count as green. A version-bump commit may be pushed
to trigger CI; fix failures and wait for green checks before releasing it.

Before every release, try to land the open dependency PRs (Renovate,
Dependabot): `gh pr list`, merge those whose checks are green (Renovate
rebases the ones that conflict; wait for it), and let CI finish on the
resulting `main` before tagging. Leave out PRs with failing checks or major
bumps that need real work, and say which.

The browser extension shares rbw's version (from `Cargo.toml`). Release with
`just release-prepare X.Y.Z`, then `just release-tag` (see
`tools/release.sh`); the tag must be GPG-signed, so unlock GPG first. The
tag's release workflow signs the extension (AMO, CRX), publishes it,
and commits the hashes of the signed packages (`browser/packages/metadata.json`;
the packages themselves are only release assets) to `main`. Signing, pinning and
the pin check come from the reusable workflows in `pschmitt/ci-workflows`,
shared with browser-daemon and bruvtab, and `tools/release.sh` is a verbatim
copy of that repository's script. Any extension source change needs a new
version, because AMO signs each version only once.

This repo is consumed by `nixos-config` (flake input `rbw`, following
`main`). After a release's workflow has finished (the pin commit has landed on
`main`): bump the lock (`nix flake lock --update-input rbw` in
`nixos-config.git`), then deploy to the hosts that run rbw (`just deploy <host>`; the
`brkn-infra` skill lists them and their roles). `rbw`/`rbw-agent` on
a deployed host's `$PATH` resolve to the last-deployed Nix store path, not a local
`target/debug`; the deploy's `home-manager-pschmitt.service` restart picks
up a new rbw build automatically, but re-run `rbw stop-agent` if a stale
agent process seems to survive it. Commit the `nixos-config` flake.lock
bump and push it, then deploy.

`browser-daemon` (`~/devel/private/pschmitt/browser-daemon.git`) has its
own `rbw` flake input (rbw's `main`, for its live view's vault extension).
After each release, bump it to the same pin commit: `nix flake lock
--override-input rbw github:pschmitt/rbw/<pin commit>`, then set
`.nodes.rbw.original` in its flake.lock back to
`{"owner":"pschmitt","repo":"rbw","type":"github"}` (`nix flake lock` must
then change nothing), commit and push. In `nixos-config`, browser-daemon
and rbw-auto follow its own `rbw` input (`rbw.follows = "rbw"`), so there
is only ever one rbw there.

## Ongoing TODOs

- Every config.json option (accounts, `unlock` policy, `exclude_from_list`,
  `tui_keybindings`, etc.) should stay configurable through the
  home-manager module — when adding a new config option, add the matching
  Nix option in the same change.
- Add V2 encryption support (Bitwarden's newer per-item/account encryption
  scheme, server-gated by `MinimumClientVersionForV2Encryption =
  "2025.11.0"` in `bitwarden/server`'s `Constants.cs`). Until this lands,
  keep `BITWARDEN_CLIENT_VERSION` in `src/api.rs` below that threshold —
  bumping it without implementing V2 encryption would make the server
  start sending/expecting data rbw can't decrypt/encrypt correctly.
