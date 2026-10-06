#!/usr/bin/env bats
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
#
# Tests run in file order (bats' default) and share one login session and
# vault: logging in/registering an account fresh per test would be
# needlessly slow, and several tests specifically check that an action on
# one entry doesn't disturb another. Bats forks a fresh process per
# @test/setup_file, so nothing one of them assigns carries into another
# automatically -- state that must survive across tests (the once-only
# login, and the couple of entry IDs later tests need) is passed through
# files in $BATS_FILE_TMPDIR via setup()/save(), not shell variables.
bats_require_minimum_version 1.5.0

BASE_URL="${VAULTWARDEN_URL:-http://localhost:8000}"
EMAIL="e2e@example.com"
PASSWORD="E2eTestPassword123!"
REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
RBW="$REPO_ROOT/target/debug/rbw"

save() { echo "$1=$2" >>"$BATS_FILE_TMPDIR/state.sh"; }

setup() {
    source "$BATS_FILE_TMPDIR/env.sh"
    [ -f "$BATS_FILE_TMPDIR/state.sh" ] && source "$BATS_FILE_TMPDIR/state.sh"
    true
}

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

setup_file() {
    export HOME="${E2E_HOME:-$(mktemp -d)}"
    export RBW_AGENT="$REPO_ROOT/target/debug/rbw-agent"

    for _ in $(seq 1 30); do
        curl -4 -fsS "$BASE_URL/alive" >/dev/null 2>&1 && break
        sleep 1
    done
    curl -4 -fsS "$BASE_URL/alive" >/dev/null

    "$REPO_ROOT/target/debug/examples/e2e_register_account" \
        --base-url "$BASE_URL" --email "$EMAIL" --password "$PASSWORD" \
        --name "rbw e2e"

    "$RBW" account add e2e --email "$EMAIL" --base-url "$BASE_URL" --primary
    echo "$PASSWORD" | "$RBW" login --stdin
    echo "$PASSWORD" | "$RBW" unlock --stdin
    "$RBW" unlocked

    {
        echo "export HOME=$HOME"
        echo "export RBW_AGENT=$RBW_AGENT"
    } >"$BATS_FILE_TMPDIR/env.sh"
}

teardown_file() {
    source "$BATS_FILE_TMPDIR/env.sh"
    # Without this, bats itself never exits after the last test: the
    # rbw-agent daemon spawned in setup_file outlives every test (that's
    # the point of it), but bats' own process-tree bookkeeping apparently
    # waits on it too. Confirmed empirically -- all 12 tests pass either
    # way, but `bats` only returns once the agent is gone.
    "$RBW" stop-agent --kill >/dev/null 2>&1 || true
}

@test "editing one field must not disturb any other field" {
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
    save ID1 "$ID1"
}

@test "bulk editing across several entries must preserve all of them" {
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
    save ID2 "$ID2"
}

@test "remove must trash, --force must permanently delete, and neither may disturb other entries" {
    "$RBW" generate e2e-entry-4 e2e-user-4 --length 20 >/dev/null
    "$RBW" sync
    ID4="$("$RBW" list e2e-entry-4 --fields id | head -1)"
    "$RBW" remove -y "$ID4"
    "$RBW" sync
    ! "$RBW" list --fields name | grep -qx 'e2e-entry-4' # a trashed entry must not show up in the default list
    "$RBW" list --trashed --fields name | grep -qx 'e2e-entry-4' # but recoverable from the trash
    "$RBW" list e2e-entry-3 --fields id,name | grep -q e2e-entry-3 # an unrelated entry is unaffected
    "$RBW" remove --force -y "$ID4"
    "$RBW" sync
    ! "$RBW" list --trashed --fields name | grep -qx 'e2e-entry-4' # must not survive a --force removal
    ! "$RBW" get --json "$ID4" >/dev/null 2>&1 # a permanently-removed entry must not be gettable
}

@test "corrupting one entry's history must not break list/get for other entries" {
    if ! command -v docker >/dev/null 2>&1; then
        skip "docker not available to corrupt the service container's database"
    fi
    CONTAINER="$(docker ps --filter ancestor=vaultwarden/server:latest -q | head -1)"
    [ -n "$CONTAINER" ] || skip "no running vaultwarden/server container found to corrupt"

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
}

@test "restore must undo remove, without disturbing other entries" {
    "$RBW" generate e2e-entry-5 e2e-user-5 --length 20 >/dev/null
    "$RBW" sync
    ID5="$("$RBW" list e2e-entry-5 --fields id | head -1)"
    "$RBW" remove -y "$ID5"
    "$RBW" sync
    "$RBW" restore -y "$ID5"
    "$RBW" sync
    "$RBW" list --fields name | grep -qx 'e2e-entry-5' # restored entries are visible again by default
    ! "$RBW" list --trashed --fields name | grep -qx 'e2e-entry-5'
    "$RBW" list e2e-entry-1 --fields id,name | grep -q e2e-entry-1 # an unrelated entry is unaffected
}

@test "archive/unarchive must hide/show without disturbing other entries" {
    "$RBW" generate e2e-entry-6 e2e-user-6 --length 20 >/dev/null
    "$RBW" sync
    ID6="$("$RBW" list e2e-entry-6 --fields id | head -1)"
    "$RBW" archive -y "$ID6"
    "$RBW" sync
    ! "$RBW" list --fields name | grep -qx 'e2e-entry-6' # an archived entry must not show up in the default list
    "$RBW" list --archived --fields name | grep -qx 'e2e-entry-6' # but visible with --archived
    "$RBW" unarchive -y "$ID6"
    "$RBW" sync
    "$RBW" list --fields name | grep -qx 'e2e-entry-6' # visible again after unarchiving
    "$RBW" list e2e-entry-1 --fields id,name | grep -q e2e-entry-1 # an unrelated entry is unaffected
}

@test "history must record superseded passwords" {
    "$RBW" history --json "$ID1" | python3 -c "
import json, sys
history = json.load(sys.stdin)
assert history, 'history is empty'
passwords = [h['password'] for h in history]
assert 'aBrandNewPassword456!' in passwords, f'expected superseded password missing from history: {passwords}'
"
}

@test "code must generate a valid-looking TOTP code from a stored secret" {
    CODE="$("$RBW" code "$ID1")"
    [[ "$CODE" =~ ^[0-9]{6}$ ]]
}

@test "attachments must round-trip byte-for-byte and be removable" {
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
    cmp -s "$ATTACH_SRC" "$ATTACH_DST"
    "$RBW" attachment rm -y "$ID7"
    "$RBW" sync
    REMAINING_ATTACHMENTS="$("$RBW" attachment list "$ID7" --json | python3 -c "import json, sys; print(len(json.load(sys.stdin)))")"
    [ "$REMAINING_ATTACHMENTS" -eq 0 ]
}

@test "add must create an entry non-interactively from piped YAML" {
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
}

@test "set must take secrets from stdin/file/env/--generate and set custom fields" {
    "$RBW" generate e2e-entry-9 e2e-user-9 --length 20 >/dev/null
    "$RBW" sync
    ID9="$("$RBW" list e2e-entry-9 --fields id | head -1)"
    pw() { "$RBW" get --json "$ID9" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["password"])'; }

    echo "stdinPassword1!" | "$RBW" set -y --password-stdin "$ID9"
    "$RBW" sync
    [ "$(pw)" = "stdinPassword1!" ]

    printf 'filePassword2!\n' >"$BATS_TEST_TMPDIR/pw"
    "$RBW" set -y --password-file "$BATS_TEST_TMPDIR/pw" "$ID9"
    "$RBW" sync
    [ "$(pw)" = "filePassword2!" ]

    E2E_PW="envPassword3!" "$RBW" set -y --password-env E2E_PW "$ID9"
    "$RBW" sync
    [ "$(pw)" = "envPassword3!" ]

    # nothing printed; the password only goes to --output-file (0600)
    OUT="$BATS_TEST_TMPDIR/generated"
    run --separate-stderr "$RBW" set -y -g -l 32 --output-file "$OUT" "$ID9"
    [ "$status" -eq 0 ]
    [[ "$output" != *"$(cat "$OUT")"* ]]
    [ "$(stat -c %a "$OUT")" = 600 ]
    "$RBW" sync
    [ "$(pw)" = "$(cat "$OUT")" ]
    [ "$(wc -m <"$OUT")" -eq 33 ] # 32 chars + newline
    "$RBW" history --json "$ID9" | python3 -c "
import json, sys
h = [e['password'] for e in json.load(sys.stdin)]
assert h[:3] == ['envPassword3!', 'filePassword2!', 'stdinPassword1!'], h
"

    E2E_FIELD="from-env" "$RBW" set -y --field api-token=tok1 \
        --field-env other=E2E_FIELD "$ID9"
    "$RBW" set -y --field api-token=tok2 "$ID9"
    "$RBW" sync
    "$RBW" get --json "$ID9" | python3 -c "
import json, sys
fields = {f['name']: f for f in json.load(sys.stdin)['fields']}
assert set(fields) == {'api-token', 'other'}, fields
assert fields['api-token']['value'] == 'tok2', fields
assert fields['api-token']['type'] == 'hidden', fields
assert fields['other']['value'] == 'from-env', fields
"
    save ID9 "$ID9"
}

@test "revision dates must guard set --if-revision, filter list --older-than, and history --restore must roll back" {
    rev() { "$RBW" get --json "$ID9" | python3 -c 'import json,sys; print(json.load(sys.stdin)["revision_date"])'; }
    REV="$(rev)"
    [ -n "$REV" ]

    "$RBW" set -y --if-revision "$REV" --notes "guarded 1" "$ID9"
    "$RBW" sync
    [ "$(rev)" != "$REV" ]
    # stale revision: must refuse and leave the entry alone
    run ! "$RBW" set -y --if-revision "$REV" --notes "guarded 2" "$ID9"
    "$RBW" sync
    "$RBW" get --json "$ID9" | python3 -c "
import json, sys
assert json.load(sys.stdin)['notes'] == 'guarded 1'
"

    ! "$RBW" list --older-than 1h --fields name | grep -qx e2e-entry-9
    sleep 2
    "$RBW" list --older-than 1s --fields name | grep -qx e2e-entry-9
    "$RBW" list --fields name,modified | grep -q "^e2e-entry-9[[:space:]]*20[0-9][0-9]-"

    "$RBW" history -y --restore "$ID9"
    "$RBW" sync
    "$RBW" get --json "$ID9" | python3 -c "
import json, sys
assert json.load(sys.stdin)['data']['password'] == 'envPassword3!'
"
}

@test "an edit based on a stale local copy must be rejected, not revert a newer change" {
    # a second client (own HOME/agent) changes the entry server-side ...
    H2="$(mktemp -d)"
    sleep 2 # Vaultwarden tolerates <=1s of revision date skew
    (
        # own config/cache/agent socket, not just HOME: the agent socket
        # lives in $XDG_RUNTIME_DIR, which both clients would share
        export HOME="$H2" RBW_PROFILE=e2e-second-client
        "$RBW" account add e2e --email "$EMAIL" --base-url "$BASE_URL" --primary
        echo "$PASSWORD" | "$RBW" login --stdin
        echo "$PASSWORD" | "$RBW" unlock --stdin
        "$RBW" set -y --notes "from the other client" "$ID9"
        "$RBW" stop-agent --kill >/dev/null 2>&1 || true
    )
    # ... so this client's cached copy is stale: the full-object PUT must
    # be refused (lastKnownRevisionDate) instead of reverting that change
    run ! "$RBW" set -y --notes "from a stale copy" "$ID9"
    "$RBW" sync
    "$RBW" get --json "$ID9" | python3 -c "
import json, sys
assert json.load(sys.stdin)['notes'] == 'from the other client'
"
}

@test "audit must report weak and reused passwords without printing them" {
    "$RBW" generate e2e-entry-10 e2e-user-10 --length 20 >/dev/null
    "$RBW" generate e2e-entry-11 e2e-user-11 --length 20 >/dev/null
    "$RBW" sync
    for n in 10 11; do
        "$RBW" set -y --password "aaaaaaaa" "$("$RBW" list "e2e-entry-$n" --fields id | head -1)"
    done
    "$RBW" sync
    run --separate-stderr "$RBW" audit --json
    [ "$status" -eq 0 ]
    [[ "$output" != *aaaaaaaa* ]]
    python3 -c "
import json, sys
findings = {f['name']: {i['kind'] for i in f['issues']} for f in json.loads(sys.argv[1])}
for name in ('e2e-entry-10', 'e2e-entry-11'):
    assert findings.get(name) == {'weak', 'reused'}, findings
assert 'e2e-entry-9' not in findings, findings
" "$output"
    run ! "$RBW" audit --fail
}

@test "audit --hibp must flag a known-breached password" {
    # opt-in: talks to the real Have I Been Pwned range API
    [ "${RBW_E2E_HIBP:-}" = 1 ] || skip "set RBW_E2E_HIBP=1 to query api.pwnedpasswords.com"
    run --separate-stderr "$RBW" audit --hibp --json
    [ "$status" -eq 0 ]
    python3 -c "
import json, sys
findings = {f['name']: f['issues'] for f in json.loads(sys.argv[1])}
breached = [i for i in findings['e2e-entry-10'] if i['kind'] == 'breached']
assert breached and breached[0]['count'] > 0, findings
" "$output"
}

@test "export -> purge-vault -> import must restore an equivalent vault" {
    "$RBW" sync
    EXPORT_FILE="$(mktemp)"
    "$RBW" export --output "$EXPORT_FILE"
    NAMES_BEFORE="$(python3 -c "
import json
d = json.load(open('$EXPORT_FILE'))
print('\n'.join(sorted(e['name'] for e in d['entries'])))
")"
    echo "$PASSWORD" | "$RBW" purge-vault -y --stdin
    "$RBW" sync
    REMAINING="$("$RBW" list --include-trashed --include-archived --fields name | grep -c . || true)"
    [ "$REMAINING" -eq 0 ]
    "$RBW" import "$EXPORT_FILE"
    "$RBW" sync
    NAMES_AFTER="$("$RBW" list --include-trashed --include-archived --fields name | sort)"
    [ "$NAMES_AFTER" = "$NAMES_BEFORE" ]
}

@test "lock must actually block access, and a locked vault must auto-unlock via pinentry" {
    # Real pinentry needs a tty/DISPLAY, neither of which exist on a CI
    # runner -- so rather than skipping lock/unlock entirely, point rbw at
    # a fake pinentry that speaks just enough of the real Assuan-ish
    # protocol (see `src/pinentry.rs::getpin` and its own
    # `test_getpin_cancelled_when_client_disconnects` fake pinentry, which
    # this mirrors) to answer GETPIN with the real password
    # non-interactively. This exercises the real agent unlock-via-pinentry
    # code path instead of only the --stdin shortcut every other test in
    # this suite uses.
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
    ! "$RBW" unlocked >/dev/null 2>&1

    ID1_AFTER_REIMPORT="$("$RBW" list e2e-entry-1 --fields id | head -1)"
    "$RBW" get --json "$ID1_AFTER_REIMPORT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d['data']['password'], 'no password after auto-unlock via fake pinentry'
"
    "$RBW" unlocked # must succeed now -- the fake pinentry unlock above should have left the vault unlocked
}
