#!/usr/bin/env python3
"""Write or verify the paper artifact's SHA-256 inventory (standard library only)."""
import argparse
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs" / "validation" / "CHECKSUMS.sha256"
EXCLUDED = {".git", ".idea", ".gradle", ".build-home", "build", "__pycache__",
            ".pytest_cache", ".test-tmp", "runs", "telemetry-data"}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED for part in relative.parts):
            continue
        if path == MANIFEST or path.name in {".DS_Store", "local.properties"} or path.name.startswith("._"):
            continue
        if path.suffix in {".pyc", ".pyo", ".keystore", ".jks"}:
            continue
        if relative.parts[:2] == ("adb_tools", "configs") and path.name.startswith("local"):
            continue
        if path.is_symlink():
            raise ValueError(f"Symlinks are not supported in the submission: {relative}")
        if path.is_file():
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("write", "verify"))
    args = parser.parse_args()
    if args.action == "write":
        rows = [f"{digest(path)}  {path.relative_to(ROOT).as_posix()}" for path in files()]
        MANIFEST.write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"Wrote CHECKSUMS.sha256: {len(rows)} files")
        return 0
    seen, failures = set(), []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("Malformed checksum row")
        expected, name = match.groups()
        relative = Path(name)
        path = ROOT / relative
        if relative.is_absolute() or ".." in relative.parts or name in seen or not path.resolve().is_relative_to(ROOT):
            raise ValueError(f"Invalid inventory path: {name}")
        seen.add(name)
        if not path.is_file() or path.is_symlink() or digest(path) != expected:
            failures.append(name)
    unlisted = {p.relative_to(ROOT).as_posix() for p in files()} - seen
    failures.extend(f"Unlisted: {name}" for name in sorted(unlisted))
    if failures:
        print("Inventory verification failed:\n" + "\n".join(failures))
        return 1
    print(f"Verified {len(seen)} files against CHECKSUMS.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
