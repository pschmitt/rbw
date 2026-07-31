# `just` is the entry point for development tasks.  Builds and tests that
# compile Rust default to rofl-13 because fnuc is a live infrastructure host.

set shell := ["bash", "-euo", "pipefail", "-c"]

export RUST_BACKTRACE := "1"
export CARGO_TERM_COLOR := "always"

default-target := "x86_64-unknown-linux-musl"
native-target := "x86_64-unknown-linux-gnu"
default-host := "rofl-13"
remote-build-base := "~/rbw-build"
remote-cargo-tools := "nixpkgs#cargo nixpkgs#rustc nixpkgs#clippy nixpkgs#pkg-config nixpkgs#openssl nixpkgs#gcc"

# Running just without arguments lists the available recipes.
[private]
default:
    @just -l

# Build rbw and rbw-agent remotely, then fetch both binaries locally.
build target=default-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo build --locked --all-targets --all-features --target '$target'"
    just _fetch "$target" "$host" debug "$remote_dir"

# Build release binaries remotely, then fetch both binaries locally.
release target=default-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo build --locked --all-targets --all-features --release --target '$target'"
    just _fetch "$target" "$host" release "$remote_dir"

# Explicit local equivalents for hosts where compiling locally is appropriate.
build-local target=default-target:
    cargo build --locked --all-targets --all-features --target "{{ target }}"

release-local target=default-target:
    cargo build --locked --all-targets --all-features --release --target "{{ target }}"

# Run the test suite on the remote build host.
test target=native-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo test --locked --all-features --target '$target'"

# Run cargo check on the remote build host.
cargo-check target=native-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo check --locked --all-targets --all-features --target '$target'"

# Run clippy with warnings promoted to errors on the remote build host.
clippy target=native-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo clippy --locked --all-targets --all-features --target '$target' -- -Dwarnings"

# Build documentation and run doctests on the remote build host.
doc target=native-target host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    target="{{ target }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c env RUSTDOCFLAGS=-Dwarnings cargo doc --locked --all-features --target '$target'"
    ssh -- "$host" "cd '$remote_dir' && nix shell {{ remote-cargo-tools }} -c cargo test --locked --doc --all-features --target '$target'"

# Format Rust, justfile, and Nix sources.
format:
    cargo fmt --all
    just --fmt
    nixfmt flake.nix nix/hm-module.nix

# Check Rust, justfile, and Nix formatting.
format-check:
    cargo fmt --all -- --check
    just --fmt --check
    nixfmt --check flake.nix nix/hm-module.nix

# Run cargo-deny locally; it only analyzes dependency metadata.
deny:
    cargo deny check

# Evaluate all flake checks remotely and show build logs.
nix-check host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix flake check --print-build-logs"

# Build the default flake package remotely and show build logs.
nix-build host=default-host:
    #!/usr/bin/env bash
    set -euo pipefail
    host="{{ host }}"
    remote_dir="$(ssh -- "$host" "mkdir -p {{ remote-build-base }} && mktemp -d {{ remote-build-base }}/rbw.XXXXXX")"
    cleanup() {
      ssh -- "$host" rm -rf -- "$remote_dir"
    }
    trap cleanup EXIT
    just _sync "$host" "$remote_dir"
    ssh -- "$host" "cd '$remote_dir' && nix build --print-build-logs '.#'"

# Run the full local/remote validation suite.
check: format-check cargo-check clippy deny test doc nix-check

# Remove Cargo's build output.
clean:
    cargo clean

# Remove all temporary and stale remote build directories.
clean-remote host=default-host:
    ssh -- "{{ host }}" "rm -rf -- {{ remote-build-base }}"

[private]
_sync host remote_dir:
    rsync -az --delete --exclude target --exclude .git ./ "{{ host }}:{{ remote_dir }}/"

[private]
_fetch target host profile remote_dir:
    mkdir -p "target/{{ target }}/{{ profile }}"
    rsync -az "{{ host }}:{{ remote_dir }}/target/{{ target }}/{{ profile }}/rbw" "target/{{ target }}/{{ profile }}/"
    rsync -az "{{ host }}:{{ remote_dir }}/target/{{ target }}/{{ profile }}/rbw-agent" "target/{{ target }}/{{ profile }}/"
