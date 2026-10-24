#!/usr/bin/env python3
"""Verify the signed browser packages against the source and name them for a GitHub release."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent


def verify(package, source):
    with zipfile.ZipFile(package) as archive:
        if archive.testzip() is not None:
            raise RuntimeError(f"Corrupt browser package: {package.name}")
        manifest = json.loads(archive.read("manifest.json"))
        expected_names = set()
        for path in source.rglob("*"):
            if not path.is_file() or path.name in {".amo-upload-uuid", ".web-extension-id"}:
                continue
            name = path.relative_to(source).as_posix()
            expected_names.add(name)
            expected = path.read_bytes()
            actual = archive.read(name)
            matches = (
                json.loads(actual) == json.loads(expected)
                if name == "manifest.json"
                else actual == expected
            )
            if not matches:
                raise RuntimeError(f"Signed package differs from source: {package.name}: {name}")
        unexpected = {
            name for name in archive.namelist()
            if not name.endswith("/") and not name.startswith("META-INF/")
        } - expected_names
        if unexpected:
            raise RuntimeError(f"Unexpected files in signed package: {package.name}")
        return manifest, archive.namelist()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--source", type=Path, default=ROOT.parent,
                        help="checkout whose extension source the packages must match")
    parser.add_argument("--packages", type=Path, default=ROOT / "dist/signed",
                        help="directory with rbw-firefox.xpi and rbw-chromium.crx")
    args = parser.parse_args()
    source = args.source / "browser"
    subprocess.run([sys.executable, str(source / "build.py")], check=True)

    firefox = args.packages / "rbw-firefox.xpi"
    chromium = args.packages / "rbw-chromium.crx"
    ff_manifest, entries = verify(firefox, source / "dist/firefox")
    chrome_manifest, _ = verify(chromium, source / "dist/chromium")
    version = ff_manifest["version"]
    if version != chrome_manifest["version"]:
        raise RuntimeError("Firefox and Chromium versions differ")
    if not any(name.startswith("META-INF/") and name.endswith((".rsa", "cose.sig")) for name in entries):
        raise RuntimeError("Firefox package has no Mozilla signature")
    with chromium.open("rb") as stream:
        magic, crx_version, header_size = struct.unpack("<4sII", stream.read(12))
        stream.seek(12 + header_size)
        if magic != b"Cr24" or crx_version != 3 or stream.read(4) != b"PK\x03\x04":
            raise RuntimeError("Chromium package is not a CRX3 signed container")

    args.output.mkdir(parents=True, exist_ok=True)
    for browser, source, extension in [("firefox", firefox, "xpi"), ("chromium", chromium, "crx")]:
        destination = args.output / f"rbw-browser-{version}-{browser}.{extension}"
        shutil.copyfile(source, destination)
        print(destination)


if __name__ == "__main__":
    main()
