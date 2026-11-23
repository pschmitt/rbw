# shellcheck shell=bash
# Project specifics for the shared release script (pschmitt/ci-workflows).
# Besides Cargo.toml and Cargo.lock, a release moves rbw's own entries in the
# advisory exceptions (deny-exceptions.toml: allow = ["rbw X.Y.Z"]) to the new
# version, so a version is one release commit and the advisory-exceptions lint
# stays green. tools/check_advisory_exceptions.py still fails when the scope
# changes in any other way (a new depender, another crate version).

# Keep the shared Cargo bump under another name and extend it.
eval "$(declare -f bump_version | sed '1s/^bump_version/cargo_bump_version/')"

bump_version() {
  local version="$1"
  cargo_bump_version "$version" || return 1
  sed -i -E "s/\"rbw [0-9]+\.[0-9]+\.[0-9]+\"/\"rbw $version\"/g" \
    "$(repo_root)/deny-exceptions.toml"
}

release_files() {
  printf '%s\n' Cargo.toml Cargo.lock deny-exceptions.toml
}
