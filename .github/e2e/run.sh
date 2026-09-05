#!/usr/bin/env bash
# End-to-end tests against a real Vaultwarden server (started as a CI
# service container by .github/workflows/test.yaml's `e2e` job). Unlike
# the unit tests, these exercise the actual wire protocol -- catching the
# class of bug fixed in commit "Thread individual cipher keys through
# edits, soften history decrypt failures" and the follow-up "Don't let
# one corrupt entry break vault-wide list/search/find", where a real
# server round trip silently dropped/hid data that mocked-HTTP unit tests
# can't see at all.
#
# Assumes `cargo build --workspace` has already produced
# target/debug/{rbw,rbw-agent}, and that VAULTWARDEN_URL points at a
# reachable, freshly-started (empty) Vaultwarden instance with
# SIGNUPS_ALLOWED=true.
set -euo pipefail

BASE_URL="${VAULTWARDEN_URL:-http://localhost:8000}"
EMAIL="e2e@example.com"
PASSWORD="E2eTestPassword123!"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RBW="$REPO_ROOT/target/debug/rbw"
export RBW_AGENT="$REPO_ROOT/target/debug/rbw-agent"
# Isolate this run's config/data/cache from anything else on the runner.
export HOME="${E2E_HOME:-$(mktemp -d)}"

log() { echo "[e2e] $*" >&2; }

log "waiting for Vaultwarden at $BASE_URL"
for _ in $(seq 1 30); do
    curl -4 -fsS "$BASE_URL/alive" >/dev/null 2>&1 && break
    sleep 1
done
curl -4 -fsS "$BASE_URL/alive" >/dev/null || {
    log "Vaultwarden never became reachable"
    exit 1
}

log "registering test account $EMAIL"
"$REPO_ROOT/target/debug/examples/e2e_register_account" \
    --base-url "$BASE_URL" --email "$EMAIL" --password "$PASSWORD" \
    --name "rbw e2e"

log "configuring rbw and logging in"
"$RBW" account add e2e --email "$EMAIL" --base-url "$BASE_URL" --primary
echo "$PASSWORD" | "$RBW" login --stdin
echo "$PASSWORD" | "$RBW" unlock --stdin
"$RBW" unlocked

assert_fields_preserved() {
    # $1 = entry JSON before, $2 = entry JSON after, $3 = new password
    python3 - "$1" "$2" "$3" <<'PYEOF'
import json, sys
before, after, new_password = json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]
assert after["data"]["password"] == new_password, "password wasn't updated"
for field in ("username", "totp", "uris"):
    assert after["data"][field] == before["data"][field], f"{field} was lost"
assert after["notes"] == before["notes"], "notes were lost"
PYEOF
}

log "test 1: editing one field must not disturb any other field"
"$RBW" generate e2e-entry-1 e2e-user-1 --length 20 >/dev/null
"$RBW" sync
ID1="$("$RBW" list e2e-entry-1 --fields id | head -1)"
"$RBW" set -y \
    --uri "https://example.com/login" \
    --totp "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&issuer=Example" \
    --notes "some notes to preserve" \
    "$ID1"
"$RBW" sync
BEFORE="$("$RBW" get --json "$ID1")"
"$RBW" set -y --password "aBrandNewPassword456!" "$ID1"
"$RBW" sync
AFTER="$("$RBW" get --json "$ID1")"
assert_fields_preserved "$BEFORE" "$AFTER" "aBrandNewPassword456!"
log "test 1 passed"

log "test 2: --bulk editing across several entries must preserve all of them"
"$RBW" generate e2e-entry-2 e2e-user-2 --length 20 >/dev/null
"$RBW" generate e2e-entry-3 e2e-user-3 --length 20 >/dev/null
"$RBW" sync
ID2="$("$RBW" list e2e-entry-2 --fields id | head -1)"
ID3="$("$RBW" list e2e-entry-3 --fields id | head -1)"
"$RBW" set -y --uri "https://example.com/2" --notes "notes 2" "$ID2"
"$RBW" set -y --uri "https://example.com/3" --notes "notes 3" "$ID3"
"$RBW" sync
"$RBW" set --bulk -y --password "bulkTestPassword789!" "$ID1" "$ID2" "$ID3"
"$RBW" sync
for id in "$ID1" "$ID2" "$ID3"; do
    "$RBW" get --json "$id" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d['data']['password'] == 'bulkTestPassword789!', f'password wrong for {d[\"id\"]}'
assert d['data']['uris'], f'uris lost for {d[\"id\"]}'
assert d['notes'], f'notes lost for {d[\"id\"]}'
"
done
log "test 2 passed"

log "test 3: remove must trash, --force must permanently delete, and neither may disturb other entries"
"$RBW" generate e2e-entry-4 e2e-user-4 --length 20 >/dev/null
"$RBW" sync
ID4="$("$RBW" list e2e-entry-4 --fields id | head -1)"
"$RBW" remove -y "$ID4"
"$RBW" sync
if "$RBW" list --fields name | grep -qx 'e2e-entry-4'; then
    log "test 3 failed: a trashed entry still shows up in the default list"
    exit 1
fi
"$RBW" list --trashed --fields name | grep -qx 'e2e-entry-4' # but recoverable from the trash
"$RBW" list e2e-entry-3 --fields id,name | grep -q e2e-entry-3 # an unrelated entry is unaffected
"$RBW" remove --force -y "$ID4"
"$RBW" sync
if "$RBW" list --trashed --fields name | grep -q '^e2e-entry-4$'; then
    log "test 3 failed: entry survived a --force removal"
    exit 1
fi
if "$RBW" get --json "$ID4" >/dev/null 2>&1; then
    log "test 3 failed: a permanently-removed entry is still gettable"
    exit 1
fi
log "test 3 passed"

log "test 4: one corrupted entry must not break list/get for every other entry"
if command -v docker >/dev/null 2>&1 &&
    CONTAINER="$(docker ps --filter ancestor=vaultwarden/server:latest -q | head -1)" &&
    [ -n "$CONTAINER" ]; then
    WORKDIR="$(mktemp -d)"
    docker stop "$CONTAINER" >/dev/null
    docker cp "$CONTAINER:/data/db.sqlite3" "$WORKDIR/db.sqlite3"
    docker cp "$CONTAINER:/data/db.sqlite3-wal" "$WORKDIR/db.sqlite3-wal" 2>/dev/null || true
    docker cp "$CONTAINER:/data/db.sqlite3-shm" "$WORKDIR/db.sqlite3-shm" 2>/dev/null || true
    python3 - "$WORKDIR/db.sqlite3" "$ID2" <<'PYEOF'
import sqlite3, sys
db_path, uuid = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA wal_checkpoint(FULL)")
cur = conn.cursor()
cur.execute("SELECT password_history FROM ciphers WHERE uuid = ?", (uuid,))
ph = cur.fetchone()[0]
idx = ph.index('"Password":"') + len('"Password":"') + 10
chars = list(ph)
chars[idx] = "Z" if chars[idx] != "Z" else "Q"
cur.execute(
    "UPDATE ciphers SET password_history = ? WHERE uuid = ?",
    ("".join(chars), uuid),
)
conn.commit()
conn.close()
PYEOF
    docker cp "$WORKDIR/db.sqlite3" "$CONTAINER:/data/db.sqlite3"
    # `docker exec` needs a running container, which this isn't right now
    # -- overwrite the old WAL/SHM with empty files instead of removing
    # them, so Vaultwarden doesn't replay stale pre-corruption writes from
    # them over the file we just replaced.
    : >"$WORKDIR/empty"
    docker cp "$WORKDIR/empty" "$CONTAINER:/data/db.sqlite3-wal"
    docker cp "$WORKDIR/empty" "$CONTAINER:/data/db.sqlite3-shm"
    docker start "$CONTAINER" >/dev/null
    for _ in $(seq 1 30); do
        curl -4 -fsS "$BASE_URL/alive" >/dev/null 2>&1 && break
        sleep 1
    done

    "$RBW" sync
    "$RBW" get --json "$ID2" >/dev/null # must not error even though its history is now unreadable
    "$RBW" get --json "$ID1" >/dev/null # a totally unrelated entry must still work
    "$RBW" list e2e-entry-3 --fields id,name | grep -q e2e-entry-3
    log "test 4 passed"
else
    log "test 4 skipped: docker not available to corrupt the service container's database"
fi

log "test 5: restore must undo remove, without disturbing other entries"
"$RBW" generate e2e-entry-5 e2e-user-5 --length 20 >/dev/null
"$RBW" sync
ID5="$("$RBW" list e2e-entry-5 --fields id | head -1)"
"$RBW" remove -y "$ID5"
"$RBW" sync
"$RBW" restore -y "$ID5"
"$RBW" sync
"$RBW" list --fields name | grep -qx 'e2e-entry-5' # restored entries are visible again by default
if "$RBW" list --trashed --fields name | grep -qx 'e2e-entry-5'; then
    log "test 5 failed: a restored entry still shows up in --trashed"
    exit 1
fi
"$RBW" list e2e-entry-1 --fields id,name | grep -q e2e-entry-1 # an unrelated entry is unaffected
log "test 5 passed"

log "test 6: archive/unarchive must hide/show without disturbing other entries"
"$RBW" generate e2e-entry-6 e2e-user-6 --length 20 >/dev/null
"$RBW" sync
ID6="$("$RBW" list e2e-entry-6 --fields id | head -1)"
"$RBW" archive -y "$ID6"
"$RBW" sync
if "$RBW" list --fields name | grep -qx 'e2e-entry-6'; then
    log "test 6 failed: an archived entry still shows up in the default list"
    exit 1
fi
"$RBW" list --archived --fields name | grep -qx 'e2e-entry-6' # but visible with --archived
"$RBW" unarchive -y "$ID6"
"$RBW" sync
"$RBW" list --fields name | grep -qx 'e2e-entry-6' # visible again after unarchiving
"$RBW" list e2e-entry-1 --fields id,name | grep -q e2e-entry-1 # an unrelated entry is unaffected
log "test 6 passed"

log "test 7: history must record superseded passwords"
"$RBW" history --json "$ID1" | python3 -c "
import json, sys
history = json.load(sys.stdin)
assert history, 'history is empty'
passwords = [h['password'] for h in history]
assert 'aBrandNewPassword456!' in passwords, f'expected superseded password missing from history: {passwords}'
"
log "test 7 passed"

log "test 8: code must generate a valid-looking TOTP code from a stored secret"
CODE="$("$RBW" code "$ID1")"
if ! [[ "$CODE" =~ ^[0-9]{6}$ ]]; then
    log "test 8 failed: expected a 6-digit code, got: $CODE"
    exit 1
fi
log "test 8 passed"

log "test 9: attachments must round-trip byte-for-byte and be removable"
"$RBW" generate e2e-entry-7 e2e-user-7 --length 20 >/dev/null
"$RBW" sync
ID7="$("$RBW" list e2e-entry-7 --fields id | head -1)"
ATTACH_SRC="$(mktemp)"
head -c 4096 /dev/urandom >"$ATTACH_SRC"
"$RBW" attachment create "$ID7" "$ATTACH_SRC"
"$RBW" sync
"$RBW" attachment list "$ID7" --json | python3 -c "
import json, sys
attachments = json.load(sys.stdin)
assert len(attachments) == 1, f'expected exactly 1 attachment, got {len(attachments)}'
"
ATTACH_DST="$(mktemp)"
"$RBW" attachment get "$ID7" --raw >"$ATTACH_DST"
cmp -s "$ATTACH_SRC" "$ATTACH_DST" || {
    log "test 9 failed: downloaded attachment doesn't match the uploaded content"
    exit 1
}
"$RBW" attachment rm -y "$ID7"
"$RBW" sync
REMAINING_ATTACHMENTS="$("$RBW" attachment list "$ID7" --json | python3 -c "import json, sys; print(len(json.load(sys.stdin)))")"
if [ "$REMAINING_ATTACHMENTS" -ne 0 ]; then
    log "test 9 failed: attachment survived rm"
    exit 1
fi
log "test 9 passed"

log "test 10: add must create an entry non-interactively from piped YAML"
"$RBW" add --yaml e2e-entry-8 e2e-user-8 <<'YAML'
name: e2e-entry-8
notes: added via rbw add --yaml
data:
  type: login
  username: e2e-user-8
  password: manualAddPassword321!
YAML
"$RBW" sync
ID8="$("$RBW" list e2e-entry-8 --fields id | head -1)"
"$RBW" get --json "$ID8" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d['data']['username'] == 'e2e-user-8', d
assert d['data']['password'] == 'manualAddPassword321!', d
assert d['notes'] == 'added via rbw add --yaml', d
"
log "test 10 passed"

log "test 11: export -> purge-vault -> import must restore an equivalent vault"
"$RBW" sync
EXPORT_FILE="$(mktemp)"
"$RBW" export --output "$EXPORT_FILE"
NAMES_BEFORE="$(python3 -c "
import json
d = json.load(open('$EXPORT_FILE'))
print('\n'.join(sorted(e['name'] for e in d['entries'])))
")"
COUNT_BEFORE="$(echo "$NAMES_BEFORE" | grep -c .)"
echo "$PASSWORD" | "$RBW" purge-vault -y --stdin
"$RBW" sync
REMAINING="$("$RBW" list --include-trashed --include-archived --fields name | grep -c . || true)"
if [ "$REMAINING" -ne 0 ]; then
    log "test 11 failed: $REMAINING entries survived purge-vault"
    exit 1
fi
"$RBW" import "$EXPORT_FILE"
"$RBW" sync
NAMES_AFTER="$("$RBW" list --include-trashed --include-archived --fields name | sort)"
if [ "$NAMES_AFTER" != "$NAMES_BEFORE" ]; then
    log "test 11 failed: imported vault entry names don't match the pre-purge export"
    log "before: $NAMES_BEFORE"
    log "after: $NAMES_AFTER"
    exit 1
fi
log "test 11 passed ($COUNT_BEFORE entries round-tripped)"

log "test 12: lock must actually block access, and a locked vault must auto-unlock via pinentry"
# Real pinentry needs a tty/DISPLAY, neither of which exist on a CI runner --
# so rather than skipping lock/unlock entirely, point rbw at a fake pinentry
# that speaks just enough of the real Assuan-ish protocol (see
# `src/pinentry.rs::getpin` and its own `test_getpin_cancelled_when_client_disconnects`
# fake pinentry, which this mirrors) to answer GETPIN with the real password
# non-interactively. This exercises the real agent unlock-via-pinentry code
# path instead of only the --stdin shortcut every other test in this suite
# uses.
FAKE_PINENTRY="$(mktemp)"
cat >"$FAKE_PINENTRY" <<'SCRIPT'
#!/bin/sh
# Minimal pinentry stand-in: ack the startup greeting and every SET* command
# with OK, then answer GETPIN with the (baked-in at test setup) password.
printf 'OK\n'
while IFS= read -r line; do
    case "$line" in
        GETPIN)
            printf 'D %s\n' "__RBW_E2E_PINENTRY_PASSWORD__"
            printf 'OK\n'
            break
            ;;
        *)
            printf 'OK\n'
            ;;
    esac
done
SCRIPT
sed -i "s/__RBW_E2E_PINENTRY_PASSWORD__/$PASSWORD/" "$FAKE_PINENTRY"
chmod +x "$FAKE_PINENTRY"
"$RBW" config set pinentry.command "$FAKE_PINENTRY"

"$RBW" lock
if "$RBW" unlocked >/dev/null 2>&1; then
    log "test 12 failed: vault reports unlocked immediately after rbw lock"
    exit 1
fi

ID1_AFTER_REIMPORT="$("$RBW" list e2e-entry-1 --fields id | head -1)"
"$RBW" get --json "$ID1_AFTER_REIMPORT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d['data']['password'], 'no password after auto-unlock via fake pinentry'
"
"$RBW" unlocked # must succeed now -- the fake pinentry unlock above should have left the vault unlocked
log "test 12 passed"

log "all e2e tests passed"
