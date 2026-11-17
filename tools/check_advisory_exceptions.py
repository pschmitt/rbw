"""Enforce the expiry and locked dependency scope of maintenance exceptions."""

import datetime
import sys
import tomllib
from pathlib import Path


def check(policy, lock, exceptions, today):
    ignored = {
        entry if isinstance(entry, str) else entry["id"]
        for entry in policy["advisories"]["ignore"]
    }
    errors = []
    seen = set()
    for exception in exceptions["exceptions"]:
        advisory = exception["id"]
        if advisory in seen:
            errors.append(f"{advisory}: duplicate exception")
        seen.add(advisory)
        if advisory not in ignored:
            errors.append(f"{advisory}: remove its obsolete deny-exceptions.toml entry")
            continue
        if today >= exception["expires"]:
            errors.append(f"{advisory}: exception expired on {exception['expires']}")
        name = exception["crate"]
        versions = {
            package["version"] for package in lock["package"] if package["name"] == name
        }
        if versions != {exception["version"]}:
            errors.append(f"{advisory}: {name} versions changed: {sorted(versions)}")
        dependers = {
            f"{package['name']} {package['version']}"
            for package in lock["package"]
            if any(
                dependency.split()[0] == name
                for dependency in package.get("dependencies", [])
            )
        }
        if dependers != set(exception["allow"]):
            errors.append(
                f"{advisory}: {name} direct dependers changed: {sorted(dependers)}"
            )
    return errors


def main():
    root = Path(__file__).resolve().parent.parent
    documents = []
    for name in ("deny.toml", "Cargo.lock", "deny-exceptions.toml"):
        with (root / name).open("rb") as source:
            documents.append(tomllib.load(source))
    today = datetime.datetime.now(datetime.UTC).date()
    errors = check(*documents, today)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("Maintenance exceptions are unexpired and match the locked dependency scope")
    return 0


if __name__ == "__main__":
    sys.exit(main())
