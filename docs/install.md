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

## Nix and Home Manager

The flake provides rbw, the browser extension and native messaging host, an
overlay and a Home Manager module. See [nix.md](nix.md).
