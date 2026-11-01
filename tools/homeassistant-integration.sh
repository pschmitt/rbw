#!/usr/bin/env bash

usage() {
  cat <<EOF_USAGE
Usage: $(basename "$0") export ARCHIVE_PATH
       $(basename "$0") install [--port PORT] SSH_TARGET

Export the rbw Home Assistant integration as a deterministic tar archive, or
install a versioned copy to a Home Assistant configuration over SSH.
The install target must provide the Home Assistant SSH shell and scp access.
EOF_USAGE
}

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

make_archive() {
  local destination="$1"
  local source_root="$2"

  tar \
    --sort=name \
    --mtime='@0' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --exclude='*/__pycache__' \
    --exclude='*.pyc' \
    -cf "$destination" \
    -C "$source_root" \
    custom_components/rbw || return 1
}

export_archive() {
  local output="$1"
  local source_root="$2"
  local temporary
  local archive_id

  if [[ -z "$output" ]]
  then
    printf 'Archive path is required\n' >&2
    return 2
  fi

  if [[ -e "$output" || -L "$output" ]]
  then
    printf 'Refusing to overwrite existing archive: %s\n' "$output" >&2
    return 1
  fi

  temporary="$(mktemp "${TMPDIR:-/tmp}/rbw-ha-export.XXXXXX")" || return 1
  if ! make_archive "$temporary" "$source_root"
  then
    rm -f "$temporary"
    return 1
  fi
  archive_id="$(sha256sum "$temporary" | cut -d ' ' -f1)" || {
    rm -f "$temporary"
    return 1
  }
  if ! mv -- "$temporary" "$output"
  then
    rm -f "$temporary"
    return 1
  fi
  printf 'Exported Home Assistant integration archive (sha256 %s): %s\n' \
    "$archive_id" "$output"
}

install_archive() {
  local target="$1"
  local source_root="$2"
  local port="${3:-}"
  local archive
  local archive_id
  local remote_stage
  local port_number
  local -a ssh_options=(-o BatchMode=yes)
  local -a scp_options=(-o BatchMode=yes)

  if [[ -z "$target" || "$target" == -* || ! "$target" =~ ^[A-Za-z0-9_.@-]+$ ]]
  then
    printf 'A valid SSH target is required\n' >&2
    return 2
  fi
  if [[ -n "$port" ]]
  then
    if [[ ! "$port" =~ ^[0-9]+$ || "${#port}" -gt 5 ]]
    then
      printf 'SSH port must be between 1 and 65535\n' >&2
      return 2
    fi
    port_number="$((10#$port))"
    if ((port_number < 1 || port_number > 65535))
    then
      printf 'SSH port must be between 1 and 65535\n' >&2
      return 2
    fi
    ssh_options+=(-p "$port_number")
    scp_options+=(-P "$port_number")
  fi

  command -v ssh >/dev/null || {
    printf 'ssh is required\n' >&2
    return 1
  }
  command -v scp >/dev/null || {
    printf 'scp is required\n' >&2
    return 1
  }

  archive="$(mktemp "${TMPDIR:-/tmp}/rbw-ha-install.XXXXXX")" || return 1
  if ! make_archive "$archive" "$source_root"
  then
    rm -f "$archive"
    return 1
  fi
  archive_id="$(sha256sum "$archive" | cut -d ' ' -f1)" || {
    rm -f "$archive"
    return 1
  }

  remote_stage="$(ssh "${ssh_options[@]}" "$target" \
    'umask 077; mktemp -d /tmp/rbw-ha.XXXXXXXXXX')" || {
    rm -f "$archive"
    return 1
  }
  if [[ ! "$remote_stage" =~ ^/tmp/rbw-ha\.[A-Za-z0-9]+$ ]]
  then
    printf 'HA host returned an invalid private staging path\n' >&2
    rm -f "$archive"
    return 1
  fi

  if ! scp "${scp_options[@]}" -- "$archive" "$target:$remote_stage/archive.tar"
  then
    rm -f "$archive"
    # The staging path was validated against the strict mktemp output format.
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$target" "rm -rf '$remote_stage'" >/dev/null 2>&1 || true
    return 1
  fi
  rm -f "$archive"

  # The digest is generated locally and contains only lowercase hexadecimal.
  # shellcheck disable=SC2029
  if ! ssh "${ssh_options[@]}" "$target" "sh -s $archive_id $remote_stage" <<'REMOTE_SCRIPT'
set -eu
archive_id="$1"
remote_stage="$2"
case "$archive_id" in
  ''|*[!0-9a-f]*)
    printf 'Invalid archive identifier\n' >&2
    exit 2
    ;;
esac
if [ "${#archive_id}" -ne 64 ]
then
  printf 'Invalid archive identifier\n' >&2
  exit 2
fi
case "$remote_stage" in
  /tmp/rbw-ha.*)
    ;;
  *)
    printf 'Invalid private staging directory\n' >&2
    exit 2
    ;;
esac
stage_suffix="${remote_stage#/tmp/rbw-ha.}"
case "$stage_suffix" in
  ''|*[!A-Za-z0-9]*)
    printf 'Invalid private staging directory\n' >&2
    exit 2
    ;;
esac

root=/config/custom_components-local
versioned="$root/rbw-integration-$archive_id"
link=/config/custom_components/rbw
link_target="../custom_components-local/rbw-integration-$archive_id/custom_components/rbw"
archive="$remote_stage/archive.tar"
stage="$root/.rbw-stage-$archive_id-$$"
stage_created=0
git_root=/config/.git
git_info="$git_root/info"
ignore_file="$git_info/exclude"
ignore_pattern='/custom_components-local/rbw-integration-*'

cleanup() {
  if [ "$stage_created" -eq 1 ] && [ -n "$stage" ]
  then
    rm -rf "$stage"
  fi
  rm -rf "$remote_stage"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
actual_hash="$(sha256sum "$archive" | cut -d ' ' -f1)"
if [ "$actual_hash" != "$archive_id" ]
then
  printf 'Integration archive checksum did not match\n' >&2
  exit 1
fi

for metadata_dir in "$git_root" "$git_info"
do
  if [ -L "$metadata_dir" ] || { [ -e "$metadata_dir" ] && [ ! -d "$metadata_dir" ]; }
  then
    printf 'Refusing to use a symlink or non-directory Git metadata path: %s\n' \
      "$metadata_dir" >&2
    exit 1
  fi
done
if [ -L "$ignore_file" ] || { [ -e "$ignore_file" ] && [ ! -f "$ignore_file" ]; }
then
  printf 'Refusing to append to a non-regular Git exclude file\n' >&2
  exit 1
fi
for install_root in "$root" /config/custom_components
do
  if [ -L "$install_root" ] || { [ -e "$install_root" ] && [ ! -d "$install_root" ]; }
  then
    printf 'Refusing to use a symlink or non-directory install root: %s\n' \
      "$install_root" >&2
    exit 1
  fi
done
if [ -e "$link" ] && [ ! -L "$link" ]
then
  printf 'Refusing to replace a non-symlink at %s\n' "$link" >&2
  exit 1
fi
if [ -L "$link" ]
then
  current_target="$(readlink "$link")"
  case "$current_target" in
    ../custom_components-local/rbw-integration-*)
      ;;
    *)
      printf 'Refusing to replace an unmanaged symlink at %s\n' "$link" >&2
      exit 1
      ;;
  esac
fi

install -d -m 0755 "$root" /config/custom_components
for package_path in "$versioned" "$versioned/custom_components" \
  "$versioned/custom_components/rbw"
do
  if [ -L "$package_path" ] || { [ -e "$package_path" ] && [ ! -d "$package_path" ]; }
  then
    printf 'Refusing to use a symlink or non-directory version path: %s\n' \
      "$package_path" >&2
    exit 1
  fi
done
if [ -e "$versioned" ] && [ ! -d "$versioned/custom_components/rbw" ]
then
  printf 'Refusing to use an incomplete version directory\n' >&2
  exit 1
fi
if [ ! -d "$versioned/custom_components/rbw" ]
then
  mkdir -m 0700 "$stage"
  stage_created=1
  tar -xf "$archive" -C "$stage"
  if [ ! -d "$stage/custom_components/rbw" ]
  then
    printf 'Archive does not contain the rbw integration\n' >&2
    exit 1
  fi
  chmod -R go-w "$stage/custom_components/rbw"
  chmod 0755 "$stage"
  mv "$stage" "$versioned"
  stage=
  stage_created=0
fi

ln -sfn "$link_target" "$link"
if [ -f "$ignore_file" ] && ! grep -Fqx "$ignore_pattern" "$ignore_file"
then
  printf '\n# rbw Home Assistant integration deployment copies\n%s\n' \
    "$ignore_pattern" >> "$ignore_file"
fi
printf 'Installed rbw integration version %s\n' "$archive_id"
REMOTE_SCRIPT
  then
    # The staging path was validated against the strict mktemp output format.
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$target" "rm -rf '$remote_stage'" >/dev/null 2>&1 || true
    return 1
  fi
}

main() {
  local root
  local source_root
  local action

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]
  then
    usage
    return 0
  fi

  action="${1:-}"
  root="$(repo_root)" || return 1
  source_root="$root/homeassistant"
  if [[ ! -d "$source_root/custom_components/rbw" ]]
  then
    printf 'Home Assistant integration source is missing\n' >&2
    return 1
  fi

  case "$action" in
    export)
      if [[ -z "${2:-}" || -n "${3:-}" ]]
      then
        usage >&2
        return 2
      fi
      export_archive "$2" "$source_root"
      ;;
    install)
      if [[ "${2:-}" == "--port" && -n "${3:-}" && -n "${4:-}" && -z "${5:-}" ]]
      then
        install_archive "$4" "$source_root" "$3"
      elif [[ -n "${2:-}" && -z "${3:-}" ]]
      then
        install_archive "$2" "$source_root"
      else
        usage >&2
        return 2
      fi
      ;;
    *)
      if [[ -z "$action" ]]
      then
        usage >&2
        return 2
      fi
      printf 'Unknown action: %s\n' "$action" >&2
      usage >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]
then
  main "$@"
fi

# vim: set ft=sh et ts=2 sw=2 :
