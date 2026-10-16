#!/usr/bin/env python3
"""Package the shared extension without a JS toolchain or dependencies."""
import json
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent
for target in ("firefox", "chromium"):
    dest = ROOT / "dist" / target
    dest.mkdir(parents=True, exist_ok=True)
    for source in (ROOT / "extension").iterdir():
        shutil.copy2(source, dest / source.name)
    manifest = {
        "manifest_version": 3,
        "name": "rbw",
        "version": "0.1.0",
        "description": "Use your existing rbw-agent vault in the browser.",
        "permissions": ["nativeMessaging", "activeTab", "scripting"],
        "action": {"default_popup": "popup.html", "default_title": "rbw"},
        "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'none'"},
    }
    if target == "firefox":
        manifest["background"] = {"scripts": ["background.js"]}
        manifest["browser_specific_settings"] = {"gecko": {
            "id": "rbw-browser@pschmitt.dev",
            "strict_min_version": "142.0",
            "data_collection_permissions": {"required": ["none"]},
        }}
    else:
        manifest["background"] = {"service_worker": "background.js"}
        metadata = ROOT / "packages" / "metadata.json"
        if metadata.exists():
            manifest["key"] = json.loads(metadata.read_text())["chromiumKey"]
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(ROOT / "dist" / f"rbw-{target}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(dest.iterdir()):
            archive.write(source, source.name)
    print(dest)
