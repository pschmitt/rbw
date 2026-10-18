# Installation

## Cargo

With a working Rust toolchain, install this fork directly from Git:

```sh
cargo install --locked --git https://github.com/pschmitt/rbw
```

This requires the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program to be installed (to display password prompts).

## Release artifacts

Tagged releases build each target with the Rust version declared by
`package.rust-version`, set `SOURCE_DATE_EPOCH` to the tagged commit, remap
workspace paths, and normalize tar/gzip metadata. This makes the release
archives reproducible when rebuilt from the same commit with the same target
toolchain. The runner and linker versions are not pinned, so this does not
guarantee bit-for-bit binary reproduction across different build environments.
Release archives also have GitHub artifact attestations.

Verify a downloaded release with:

```sh
sha256sum --check SHA256SUMS
gh attestation verify rbw-<version>-<target>.tar.gz --repo pschmitt/rbw
```

The attestation establishes how GitHub built the published archive; it does
not replace independently rebuilding the archive and comparing its checksum.

## Home Manager

This fork also exports a Home Manager module (`homeManagerModules.default`)
that exposes `config.yaml` as declarative Nix options (mirroring `Config`
and `Account` in `src/config.rs`), and installs `rbw` itself.

Its options live under `programs.rbw.declarative`, not `programs.rbw`
directly: recent Home Manager releases ship their own built-in, minimal
`programs.rbw` module (freeform-typed, install-only), and its `enable`/
`package`/`settings` options are unconditionally declared as soon as Home
Manager is imported. This module can't redeclare those same option paths,
so it lives at a sibling path instead. It's fully independent of the
built-in module -- don't set both `programs.rbw.settings` (upstream,
freeform) and `programs.rbw.declarative.enable` (this module) at once, as
only this module actually renders the configuration file.

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
    pinentry.command = "pinentry-gnome3";
    agent.lockTimeout = 3600;
    primaryAccount = "personal";
    accounts.personal = {
      email = "me@example.com";
      baseUrl = "https://vault.bitwarden.com";
    };
  };
};
```

This writes `~/.config/rbw/config.yaml` (or
`$XDG_CONFIG_HOME/rbw/config.yaml`) from `programs.rbw.declarative.settings`;
unset options are omitted from the generated file rather than written as
`null`. See the module's option documentation (e.g. via `home-manager
option programs.rbw.declarative` or your editor's Nix LSP) for the full
list of settings, including `accounts.<name>.unlock`,
`accounts.<name>.excludeFrom`, and `tui.keys`.

rbw reads both `config.yaml` and the legacy `config.json`; when both exist,
`config.yaml` takes precedence. Configuration written by rbw itself, including
`rbw config set` and `rbw config edit`, uses YAML and writes `config.yaml`.
