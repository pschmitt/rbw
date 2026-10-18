#!/usr/bin/env bash
# Run the inline-UI end-to-end checks in an isolated HOME with a stub native
# host. Needs Nix; run it on a scratch host, not fnuc (see AGENTS.md).

usage() {
  cat <<EOF
Usage: $(basename "$0") chromium|firefox [page.html|csp.html]

csp.html is page.html with a strict Content-Security-Policy (frame-src 'none').
EOF
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]
  then
    kill "$SERVER_PID" 2>/dev/null
  fi
  if [[ -n "${WORK_DIR:-}" ]]
  then
    rm -rf "$WORK_DIR"
  fi
}

nix_python() {
  local package="$1"
  nix build --no-link --print-out-paths --impure --expr \
    "(builtins.getFlake \"nixpkgs\").legacyPackages.\${builtins.currentSystem}.python3.withPackages (p: [ p.${package} ])"
}

prepare() {
  local here="$1" root="$2" chromium_id
  python3 "$root/browser/build.py" >/dev/null || return 1
  cp "$here/stub_host.py" "$here/page.html" "$WORK_DIR/"
  sed "s#<meta charset=utf-8>#<meta charset=utf-8><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self' 'unsafe-inline'; frame-src 'none'; child-src 'none'\">#" \
    "$here/page.html" > "$WORK_DIR/csp.html"
  chmod +x "$WORK_DIR/stub_host.py"
  chromium_id="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["chromiumId"])' "$root/browser/packages/metadata.json")"
  mkdir -p "$HOME/.mozilla/native-messaging-hosts" "$WORK_DIR/profile/NativeMessagingHosts"
  printf '{"name":"org.rbw.browser","description":"stub","path":"%s","type":"stdio","allowed_extensions":["rbw-browser@pschmitt.dev"]}\n' \
    "$WORK_DIR/stub_host.py" > "$HOME/.mozilla/native-messaging-hosts/org.rbw.browser.json"
  printf '{"name":"org.rbw.browser","description":"stub","path":"%s","type":"stdio","allowed_origins":["chrome-extension://%s/"]}\n' \
    "$WORK_DIR/stub_host.py" "$chromium_id" > "$WORK_DIR/profile/NativeMessagingHosts/org.rbw.browser.json"
}

run_tests() {
  local browser="$1" here="$2" root="$3" url="$4" python
  if [[ "$browser" == chromium ]]
  then
    python="$(nix_python playwright)" || return 1
    PLAYWRIGHT_BROWSERS_PATH="$(nix build --no-link --print-out-paths nixpkgs#playwright-driver.browsers)" \
      "$python/bin/python3" "$here/e2e.py" chromium "$root/browser/dist/chromium" "$url" "$WORK_DIR/profile"
  else
    python="$(nix_python selenium)" || return 1
    nix shell nixpkgs#firefox nixpkgs#geckodriver -c \
      "$python/bin/python3" "$here/e2e.py" firefox "$root/browser/dist/firefox" "$url" "$WORK_DIR/profile"
  fi
}

main() {
  case "${1:-}" in
    -h|--help)
      usage
      return 0
      ;;
    chromium|firefox)
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac

  local browser="$1" page="${2:-page.html}" here root
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  root="$(cd "$here/../../.." && pwd)"
  WORK_DIR="$(mktemp -d)"
  trap cleanup EXIT
  export HOME="$WORK_DIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export RBW_E2E_LOG="$WORK_DIR/stub_host.log"

  prepare "$here" "$root" || return 1
  (cd "$WORK_DIR" && exec python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1) &
  SERVER_PID=$!
  sleep 1
  run_tests "$browser" "$here" "$root" "http://localhost:8765/$page"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]
then
  main "$@"
  exit "$?"
fi

# vim: set ft=sh et ts=2 sw=2 :
