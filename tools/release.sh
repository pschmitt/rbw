#!/usr/bin/env bash
# Release rbw and its browser extension under one version (Cargo.toml).
#
#   prepare VERSION  bump Cargo.toml/Cargo.lock, date the CHANGELOG, commit, push
#   packages         wait for main's build, commit its signed browser packages, push
#   tag              require green build/test/docker for HEAD, then push a signed vVERSION
#
# The release workflow (on v* tags) publishes the CLI binaries together with
# the checked-in signed XPI and CRX.

usage() {
  cat <<EOF
Usage: $(basename "$0") prepare VERSION | packages | tag

  prepare VERSION  Bump to VERSION (X.Y.Z), date the changelog, commit and push.
  packages         Wait for HEAD's build workflow, then commit and push the
                   signed browser packages it produced (skipped when the
                   checked-in packages already match the source).
  tag              Push the GPG-signed vVERSION tag once build, test and docker are green
                   for HEAD.
EOF
}

die() {
  printf '%s\n' "$*" >&2
  return 1
}

repo_root() {
  git rev-parse --show-toplevel
}

current_version() {
  sed -n 's/^version = "\(.*\)"$/\1/p' "$(repo_root)/Cargo.toml" | head -n 1
}

# Wait until every run of WORKFLOW for COMMIT has finished; succeed only if all passed.
wait_for_workflow() {
  local commit="$1" workflow="$2" pending conclusions
  while true
  do
    pending="$(gh run list --commit "$commit" --workflow "$workflow" --json status \
      -q '[.[] | select(.status != "completed")] | length' 2>/dev/null)"
    conclusions="$(gh run list --commit "$commit" --workflow "$workflow" --json conclusion \
      -q '.[].conclusion' 2>/dev/null)"
    if [[ "$pending" == 0 && -n "$conclusions" ]]
    then
      break
    fi
    printf 'Waiting for %s on %s…\n' "$workflow" "${commit:0:7}" >&2
    sleep 30
  done
  if grep -qvx success <<< "$conclusions"
  then
    die "Workflow $workflow did not succeed for ${commit:0:7}: $(tr '\n' ' ' <<< "$conclusions")"
    return 1
  fi
}

# Verify the checked-in signed packages against COMMIT's source, ignoring any
# uncommitted work in progress. Extra arguments replace the packages first.
verify_packages() {
  local commit="$1" firefox="${2:-}" chromium="${3:-}" tree status
  tree="$(mktemp -d)"
  git -C "$(repo_root)" archive "$commit" Cargo.toml browser | tar -x -C "$tree"
  if [[ -n "$firefox" ]]
  then
    cp "$firefox" "$tree/browser/packages/rbw-firefox.xpi"
    cp "$chromium" "$tree/browser/packages/rbw-chromium.crx"
  fi
  python3 "$tree/browser/release.py" --output "$tree/out" >/dev/null 2>&1
  status=$?
  rm -rf "$tree"
  return "$status"
}

prepare() {
  local version="$1" root today
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  then
    # Firefox only accepts numeric versions, so no pre-release suffixes.
    die "VERSION must be X.Y.Z (numeric), got: ${version:-<empty>}"
    return 2
  fi
  root="$(repo_root)"
  today="$(date +%F)"
  if ! grep -qx '## \[Unreleased\]' "$root/CHANGELOG.md"
  then
    die "CHANGELOG.md has no '## [Unreleased]' section"
    return 1
  fi
  sed -i "0,/^version = \".*\"$/s//version = \"$version\"/" "$root/Cargo.toml"
  # Only the rbw package entry, which directly follows its name line.
  sed -i "/^name = \"rbw\"$/{n;s/^version = \".*\"$/version = \"$version\"/}" "$root/Cargo.lock"
  sed -i "s/^## \[Unreleased\]$/## [Unreleased]\n\n## [$version] - $today/" "$root/CHANGELOG.md"
  git -C "$root" commit -m "Release rbw $version" -- Cargo.toml Cargo.lock CHANGELOG.md || return 1
  git -C "$root" push origin HEAD:main
}

packages() {
  local root commit version run artifacts firefox chromium
  root="$(repo_root)"
  commit="$(git -C "$root" rev-parse HEAD)"
  version="$(current_version)"
  if verify_packages "$commit"
  then
    printf 'Checked-in browser packages already match %s; nothing to sign.\n' "$version"
    return 0
  fi
  wait_for_workflow "$commit" build || return 1
  run="$(gh run list --commit "$commit" --workflow build --json databaseId -q '.[0].databaseId')"
  artifacts="$(mktemp -d)"
  gh run download "$run" -n browser-extensions -D "$artifacts" || return 1
  firefox="$artifacts/rbw-browser-$version-firefox.xpi"
  chromium="$artifacts/rbw-browser-$version-chromium.crx"
  if ! verify_packages "$commit" "$firefox" "$chromium"
  then
    die "Signed packages from build run $run do not match the source of ${commit:0:7}"
    return 1
  fi
  cp "$firefox" "$root/browser/packages/rbw-firefox.xpi"
  cp "$chromium" "$root/browser/packages/rbw-chromium.crx"
  rm -rf "$artifacts"
  git -C "$root" commit -m "release: package signed browser extension v$version" \
    -- browser/packages/rbw-firefox.xpi browser/packages/rbw-chromium.crx || return 1
  git -C "$root" push origin HEAD:main
}

tag() {
  local root commit version workflow
  root="$(repo_root)"
  commit="$(git -C "$root" rev-parse HEAD)"
  version="$(current_version)"
  if ! git -C "$root" merge-base --is-ancestor "$commit" origin/main
  then
    die "HEAD ${commit:0:7} is not on origin/main; push it first"
    return 1
  fi
  if ! verify_packages "$commit"
  then
    die "Checked-in browser packages do not match $version; run '$(basename "$0") packages' first"
    return 1
  fi
  for workflow in build test docker
  do
    wait_for_workflow "$commit" "$workflow" || return 1
  done
  git -C "$root" tag -s "v$version" -m "Release $version" "$commit" || return 1
  git -C "$root" push origin "v$version"
}

main() {
  case "${1:-}" in
    -h|--help)
      usage
      return 0
      ;;
    prepare)
      prepare "${2:-}"
      ;;
    packages)
      packages
      ;;
    tag)
      tag
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]
then
  main "$@"
  exit "$?"
fi

# vim: set ft=sh et ts=2 sw=2 :
