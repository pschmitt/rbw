#!/usr/bin/env bash
# Package a release build of TARGET as rbw-VERSION-TARGET.tar.gz (binaries,
# license, README and shell completions), reproducibly (SOURCE_DATE_EPOCH).
#
#   tools/package-release.sh TARGET

set -euo pipefail

target="${1:?usage: package-release.sh TARGET}"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"
pkg="rbw-${version}-${target}"
bin="target/${target}/release/rbw"

mkdir "$pkg"
cp "$bin" \
  "target/${target}/release/rbw-agent" \
  "target/${target}/release/rbw-browser" \
  LICENSE README.md "$pkg/"

if [[ "$target" == "aarch64-linux-android" ]]
then
  # The android binary can't run on the x86_64 runner: run it through
  # qemu-user with a real bionic runtime (see the release workflow).
  run_bin() {
    local qemu
    qemu="$(command -v qemu-aarch64-static || command -v qemu-aarch64)"
    "$qemu" -L "$PWD/android-bionic-sysroot" "$bin" "$@"
  }
else
  run_bin() { "./$bin" "$@"; }
fi

mkdir -p "$pkg/completions/bash" "$pkg/completions/zsh" "$pkg/completions/fish"
run_bin completions bash > "$pkg/completions/bash/rbw"
run_bin completions zsh > "$pkg/completions/zsh/_rbw"
run_bin completions fish > "$pkg/completions/fish/rbw.fish"

if command -v gtar >/dev/null 2>&1
then
  tar_bin=gtar
else
  tar_bin=tar
fi
"$tar_bin" --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner -cf - "$pkg" |
  gzip -n -9 > "$pkg.tar.gz"
gzip -t "$pkg.tar.gz"
"$tar_bin" -tzf "$pkg.tar.gz" > "$pkg.contents"
grep -Fqx "$pkg/rbw" "$pkg.contents"
grep -Fqx "$pkg/rbw-agent" "$pkg.contents"
grep -Fqx "$pkg/rbw-browser" "$pkg.contents"

# vim: set ft=sh et ts=2 sw=2 :
