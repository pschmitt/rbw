# Agent notes

## Build/test

Don't run `cargo build`/`test`/`clippy` on `fnuc` (it hosts Home Assistant
and other live infra). Do it on a scratch host instead: `rsync -az --delete
--exclude target --exclude .git ./ <host>:~/build/rbw/`, then `nix shell
nixpkgs#cargo nixpkgs#rustc nixpkgs#clippy nixpkgs#pkg-config
nixpkgs#openssl nixpkgs#gcc -c cargo <build|test|clippy>`. Run `cargo fmt
--all` before committing.

## Deploy

This repo is consumed by `nixos-config` (flake input `rbw`). After pushing
to `main`: bump the lock (`nix flake lock --update-input rbw` in
`nixos-config.git`), then deploy with `just deploy fnuc` (fnuc is a full
NixOS host now, not a standalone Home Manager one — `hosts/fnuc/nixos.nix`
is the source of truth, `hosts/fnuc/default.nix`/`just hm fnuc` is the old
pre-migration path and shouldn't be relied on). `rbw`/`rbw-agent` on
fnuc's `$PATH` resolve to the last-deployed Nix store path, not a local
`target/debug`; the deploy's `home-manager-pschmitt.service` restart picks
up a new rbw build automatically, but re-run `rbw stop-agent` if a stale
agent process seems to survive it. Commit the `nixos-config` flake.lock
bump locally only — never push that repo unless separately asked.

## Ongoing TODOs

- Every config.json option (accounts, `unlock` policy, `exclude_from_list`,
  `tui_keybindings`, etc.) should stay configurable through the
  home-manager module — when adding a new config option, add the matching
  Nix option in the same change.
- V2 encryption (Bitwarden's COSE/XChaCha20-Poly1305 account-key wrapping,
  CipherString type 7 / `CoseEncrypt0B64`) read-only decrypt support has
  landed: `src/cose.rs` (new module), `CipherString::CoseEncrypt0` +
  `decrypt_locked_cose_symmetric` in `src/cipherstring.rs`, and
  `actions::unlock()` dispatches per-field on whichever CipherString
  variant `protected_key`/`protected_private_key` actually parse as.
  **Not yet verified against a real V2-migrated account** (none exist for
  this user yet — all 4 configured accounts are still V1, and Vaultwarden
  doesn't support V2 at all). The specific unverified assumption: a V2
  account's decrypted user key is a native 32-byte XChaCha20-Poly1305 key
  (so `wrapping_key.enc_key()`, the first 32 bytes of the existing 64-byte
  `locked::Keys` shape, is the right thing to feed `crate::cose::decrypt`)
  rather than something requiring a different key-derivation step. If
  that's wrong, decryption fails cleanly (`Error::CoseDecrypt`, an AEAD
  auth-tag mismatch) rather than silently corrupting data — but it does
  mean this hasn't actually been proven correct end-to-end. Re-verify (or
  get this confirmed by someone with a real V2 account) before leaning on
  it. Server-gated by `MinimumClientVersionForV2Encryption = "2025.11.0"`
  in `bitwarden/server`'s `Constants.cs` — keep `BITWARDEN_CLIENT_VERSION`
  in `src/api.rs` below that threshold until the above is confirmed;
  bumping it prematurely would make the server start expecting a client
  that can actually handle V2 traffic correctly.
- Every `reqwest::blocking::Client::new()` call site in `src/api.rs` (~30
  of them, for cipher/folder/attachment/etc. CRUD) builds a bare client
  with no default headers, unlike `self.reqwest_client()` (used by
  `sync`/login/2FA flows). That means none of them send
  `Bitwarden-Client-Version`/`Bitwarden-Client-Name`/`Device-Type` unless
  a call site adds them individually (as `edit()` now does, to dodge the
  FIDO2 cipher-edit version gate — see 2026-09-22 fix). Any of these bare
  clients could hit the same or a future server-side version gate the
  same way; consider making them all share `reqwest_client()`'s headers
  instead of patching call sites one at a time as they're discovered.
