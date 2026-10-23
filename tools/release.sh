#!/usr/bin/env bash
# Release rbw and its browser extension under one version (Cargo.toml).
#
#   prepare VERSION  bump Cargo.toml/Cargo.lock, date the CHANGELOG, commit, push
#   tag              require green build/test/docker for HEAD, then push a signed vVERSION
#
# The release workflow (on v* tags) signs the browser extension, publishes it
# with the CLI binaries, commits the signed XPI and CRX on top of the tag,
# points the `release` branch (what consumers follow) at that commit and
# merges it into main.

usage() {
  cat <<EOF
Usage: $(basename "$0") prepare VERSION | tag

  prepare VERSION  Bump to VERSION (X.Y.Z), date the changelog, commit and push.
  tag              Push the GPG-signed vVERSION tag once build, test and docker are green
                   for HEAD. The release workflow then signs and publishes.
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
  for workflow in build lint test docker
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
