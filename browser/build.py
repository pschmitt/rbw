#!/usr/bin/env python3
"""Package the shared extension without a JS toolchain or dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
# The extension shares rbw's version: one release ships the CLI, native host
# and both browser packages.
VERSION = tomllib.loads((ROOT.parent / "Cargo.toml").read_text())["package"]["version"]
# What browser-daemon's live-view extension (browser-daemon/) takes from this
# one, so both look alike.
SHARED = ["theme.css", "icons.js", "feedback.css", "feedback.js", "icons/rbw-48.png"]


def browser_daemon(dest):
    """browser-daemon's live-view extension: its pages, the shared files and
    rbw's version. Not part of the signed browser packages."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for source in (ROOT / "browser-daemon").iterdir():
        if source.is_file() and source.name not in {"manifest.json", "README.md"}:
            shutil.copy2(source, dest / source.name)
    for name in SHARED:
        (dest / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "extension" / name, dest / name)
    manifest = json.loads((ROOT / "browser-daemon" / "manifest.json").read_text())
    manifest["version"] = VERSION
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(dest)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--browser-daemon", type=Path, metavar="DIR", help="build only browser-daemon's live-view extension, into DIR")
args = parser.parse_args()
if args.browser_daemon:
    browser_daemon(args.browser_daemon)
    raise SystemExit
for target in ("firefox", "chromium"):
    dest = ROOT / "dist" / target
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for source in (ROOT / "extension").iterdir():
        if source.is_dir():
            shutil.copytree(source, dest / source.name, dirs_exist_ok=True)
        else:
            shutil.copy2(source, dest / source.name)
    toolbar_icons = {}
    for size in [16, 19, 24, 32, 38, 48, 64]:
        source = ROOT / "extension" / "icons" / f"toolbar-{size}.png"
        digest = hashlib.sha256(source.read_bytes()).hexdigest()[:12]
        name = f"icons/toolbar-{size}-{digest}.png"
        shutil.copy2(source, dest / name)
        toolbar_icons[str(size)] = name
    manifest = {
        "manifest_version": 3,
        "name": "rbw",
        "version": VERSION,
        "description": "Use your existing rbw-agent vault in the browser.",
        "permissions": ["nativeMessaging", "activeTab", "scripting", "storage", "contextMenus", "webNavigation", "alarms", "clipboardWrite"],
        "host_permissions": ["https://*/*", "http://*/*"],
        "content_scripts": [
            {"matches": ["https://*/*", "http://*/*"], "js": ["webauthn.js"], "run_at": "document_start", "all_frames": True, "world": "MAIN"},
            {"matches": ["https://*/*", "http://*/*"], "js": ["icons.js", "content.js"], "run_at": "document_start", "all_frames": True},
        ],
        "web_accessible_resources": [{"resources": ["inline.html"], "matches": ["https://*/*", "http://*/*"]}],
        "options_ui": {"page": "options.html", "open_in_tab": True},
        "commands": {
            "open-vault": {"suggested_key": {"default": "Ctrl+Shift+Y"}, "description": "Open rbw vault"},
            "fill-login": {"suggested_key": {"default": "Ctrl+Shift+L"}, "description": "Fill matching login"},
        },
        "icons": {str(size): f"icons/rbw-{size}.png" for size in [16, 32, 48, 64, 96, 128, 256]},
        "action": {"default_popup": "popup.html", "default_title": "rbw", "default_icon": toolbar_icons},
        "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'none'"},
    }
    if target == "firefox":
        manifest["background"] = {"scripts": ["fill.js", "background.js"]}
        manifest["sidebar_action"] = {"default_panel": "popup.html?surface=window", "default_title": "rbw", "default_icon": "icons/rbw-32.png"}
        manifest["browser_specific_settings"] = {"gecko": {
            "id": "rbw-browser@pschmitt.dev",
            "strict_min_version": "142.0",
            "data_collection_permissions": {"required": ["none"]},
        }}
    else:
        manifest["background"] = {"service_worker": "background.js"}
        manifest["storage"] = {"managed_schema": "managed-schema.json"}
        manifest["permissions"].append("sidePanel")
        manifest["side_panel"] = {"default_path": "popup.html?surface=window"}
        metadata = ROOT / "packages" / "metadata.json"
        if metadata.exists():
            manifest["key"] = json.loads(metadata.read_text())["chromiumKey"]
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(ROOT / "dist" / f"rbw-{target}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(dest.rglob("*")):
            if source.is_file():
                archive.write(source, source.relative_to(dest))
    print(dest)
browser_daemon(ROOT / "dist" / "browser-daemon")
