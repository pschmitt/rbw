#!/usr/bin/env python3
"""Fake org.rbw.browser native host with canned test data (no real vault)."""
import json, os, struct, sys, time

LOGIN = {"id": "login-1", "name": "Test Login", "username": "alice", "iconOrigin": None, "matched": True, "type": "login", "passkeys": 0, "favorite": False, "folder": None, "archived": False, "deleted": False, "protected": False}
CARD = {"id": "card-1", "name": "Test Visa", "username": "Visa, •1111", "iconOrigin": None, "matched": False, "type": "card", "passkeys": 0, "favorite": False, "folder": None, "archived": False, "deleted": False, "protected": False}
generated = set()  # Logins saved with a generated password.
saved_logins = {}
log_path = os.environ.get("RBW_E2E_LOG", sys.argv[0] + ".log")
log = open(log_path, "a")
# The first host the browser starts is an old one left over from before an
# upgrade; the extension should replace it with a fresh (current) one.
first = not os.path.exists(log_path + ".spawned")
open(log_path + ".spawned", "a").close()
host_version = "0.0.1" if first else "999.0.0"
log.write(f"spawn:{host_version}\n"); log.flush()

def reply(message):
    data = json.dumps(message).encode()
    sys.stdout.buffer.write(struct.pack("@I", len(data)) + data); sys.stdout.buffer.flush()

while True:
    header = sys.stdin.buffer.read(4)
    if len(header) < 4: break
    request = json.loads(sys.stdin.buffer.read(struct.unpack("@I", header)[0]))
    action = request.get("action"); log.write(f"{action}:{request.get('item') or ''}\n"); log.flush()
    if action == "copy": log.write(f"copy-field:{request.get('field')}\n"); log.flush()
    if action == "mutate":
        log.write(f"mutation:{request.get('mutation')}:{request.get('item')}\n"); log.flush()
        time.sleep(0.5)
        if request.get("mutation") == "delete" and request.get("item") == os.environ.get("RBW_E2E_FAIL_ITEM"):
            reply({"id": request["id"], "error": "Test failure"}); continue
    if action == "status": result = {"unlocked": True, "accounts": ["test"], "primary": "test", "hostVersion": host_version, "staleAgent": None}
    elif action == "search":
        logins = [LOGIN] + [{**LOGIN, "id": f"login-{n}", "name": f"Other Login {n}", "username": f"user{n}"} for n in range(2, 8)] + [{**LOGIN, "id": item, "name": cipher["name"], "username": cipher["data"]["username"]} for item, cipher in saved_logins.items()]
        items = [CARD] if request.get("kind") == "card" else logins if request.get("kind") in (None, "login") else []
        query = (request.get("query") or "").lower()
        items = [item for item in items if query in f"{item['name']} {item['username']}".lower()]
        result = {"items": items, "limit": 200, "total": len(items), "folders": [], "collections": []}
    elif action == "credential": result = {"name": "Test Login", "custom": [], "username": saved_logins[request["item"]]["data"]["username"] if request.get("item") in saved_logins else "alice", "hasTotp": True, "password": saved_logins[request["item"]]["data"]["password"] if request.get("item") in saved_logins else "generated-pw" if request.get("item") in generated else "pw-from-rbw"}
    elif action == "detail" and request.get("item") in saved_logins: result = {"cipher": saved_logins[request["item"]], "revision": "r1", "passkeys": [], "history": []}
    elif action == "detail" and str(request.get("item")).startswith("login-"): result = {"cipher": {"name": "Test Login", "data": {"type": "login", "username": "alice", "password": "pw-from-rbw", "uris": []}, "fields": []}, "revision": "r1", "passkeys": [], "history": []}
    elif action == "detail": result = {"cipher": {"name": "Test Visa", "data": {"type": "card", "cardholder_name": "Alice Test", "number": "4111111111111111", "brand": "Visa", "exp_month": "12", "exp_year": "2030", "code": "123"}, "fields": []}, "revision": "r1"}
    elif action == "totp": result = {"code": "123456"}
    elif action == "generate": result = "generated-pw"
    elif action == "save":
        if request.get("item") is None:
            time.sleep(3)
            saved_logins["login-new"] = request["cipher"]
        if ((request.get("cipher") or {}).get("data") or {}).get("password") == "generated-pw": generated.add(request.get("item"))
        result = True
    else: result = True
    reply({"id": request["id"], "result": result})
