#!/usr/bin/env python3
"""Fake org.rbw.browser native host with canned test data (no real vault)."""
import json, os, struct, sys

LOGIN = {"id": "login-1", "name": "Test Login", "username": "alice", "iconOrigin": None, "matched": True, "type": "login", "passkeys": 0, "favorite": False, "folder": None, "archived": False, "deleted": False, "protected": False}
CARD = {"id": "card-1", "name": "Test Visa", "username": "Visa, •1111", "iconOrigin": None, "matched": False, "type": "card", "passkeys": 0, "favorite": False, "folder": None, "archived": False, "deleted": False, "protected": False}
log = open(os.environ.get("RBW_E2E_LOG", sys.argv[0] + ".log"), "a")

def reply(message):
    data = json.dumps(message).encode()
    sys.stdout.buffer.write(struct.pack("@I", len(data)) + data); sys.stdout.buffer.flush()

while True:
    header = sys.stdin.buffer.read(4)
    if len(header) < 4: break
    request = json.loads(sys.stdin.buffer.read(struct.unpack("@I", header)[0]))
    action = request.get("action"); log.write(f"{action}:{request.get('item') or ''}\n"); log.flush()
    if action == "status": result = {"unlocked": True, "accounts": ["test"], "primary": "test"}
    elif action == "search":
        logins = [LOGIN] + [{**LOGIN, "id": f"login-{n}", "name": f"Other Login {n}", "username": f"user{n}"} for n in range(2, 8)]
        items = [CARD] if request.get("kind") == "card" else logins if request.get("kind") in (None, "login") else []
        query = (request.get("query") or "").lower()
        items = [item for item in items if query in f"{item['name']} {item['username']}".lower()]
        result = {"items": items, "limit": 200, "total": len(items), "folders": [], "collections": []}
    elif action == "credential": result = {"name": "Test Login", "custom": [], "username": "alice", "password": "pw-from-rbw"}
    elif action == "detail": result = {"cipher": {"name": "Test Visa", "data": {"type": "card", "cardholder_name": "Alice Test", "number": "4111111111111111", "brand": "Visa", "exp_month": "12", "exp_year": "2030", "code": "123"}, "fields": []}, "revision": "r1"}
    elif action == "save": result = True
    else: result = True
    reply({"id": request["id"], "result": result})
