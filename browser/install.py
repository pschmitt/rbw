#!/usr/bin/env python3
"""Register a previously built rbw-browser native host for Linux browsers."""
import argparse
import json
import os
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host", required=True, type=Path, help="Absolute path to the built rbw-browser executable (rbw must be alongside it)")
parser.add_argument("--firefox", action="store_true")
parser.add_argument("--chromium-id", help="Extension ID shown by chrome://extensions")
parser.add_argument("--chrome", action="store_true", help="Also register the supplied Chromium ID for Google Chrome")
args = parser.parse_args()
host = args.host.expanduser().resolve()
if not os.access(host, os.X_OK) or not os.access(host.with_name("rbw"), os.X_OK):
    parser.error("rbw-browser and rbw must both exist and be executable in the same directory")
if not args.firefox and not args.chromium_id:
    parser.error("select --firefox and/or --chromium-id")
if args.chromium_id and not re.fullmatch(r"[a-p]{32}", args.chromium_id):
    parser.error("invalid Chromium extension ID")
if args.chrome and not args.chromium_id:
    parser.error("--chrome requires --chromium-id")
home = Path.home()
config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
targets = []
if args.firefox:
    targets.append((home / ".mozilla/native-messaging-hosts", "allowed_extensions", ["rbw-browser@pschmitt.dev"]))
if args.chromium_id:
    origins = [f"chrome-extension://{args.chromium_id}/"]
    targets.append((config / "chromium/NativeMessagingHosts", "allowed_origins", origins))
    if args.chrome:
        targets.append((config / "google-chrome/NativeMessagingHosts", "allowed_origins", origins))
for directory, allow_key, allowed in targets:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "org.rbw.browser.json"
    manifest = {"name": "org.rbw.browser", "description": "rbw-agent browser bridge", "path": str(host), "type": "stdio", allow_key: allowed}
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(path)
