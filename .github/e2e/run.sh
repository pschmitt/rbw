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

log "test 3: one corrupted entry must not break list/get for every other entry"
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
    log "test 3 passed"
else
    log "test 3 skipped: docker not available to corrupt the service container's database"
fi

log "all e2e tests passed"
