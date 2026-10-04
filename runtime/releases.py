"""Bounded, content-addressed releases. Integrity hashes are not signatures."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from common import atomic_write, encoded, locked, no_symlinks, private_directory, read_bytes, sha

MANIFEST = "release-manifest.json"
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
TOP = {"package.json", "LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.txt"}
REQUIRED = TOP | {"dist/server.mjs", "dist/live-smoke.mjs", "dist/dependency-lock.json",
                  "runtime/manage.py", "runtime/invocations.sql", "src/hardened-policy.mjs",
                  "scripts/investigate.mjs"}


def eligible(name):
    return name in TOP or bool(re.fullmatch(
        r"(?:runtime/(?!test_)[A-Za-z0-9_-]+\.(?:py|sql)|(?:src|scripts)/[A-Za-z0-9_-]+\.mjs|"
        r"dist/[A-Za-z0-9_.-]+\.(?:mjs|LEGAL\.txt)|dist/dependency-lock\.json)", name))


def component(root, name):
    path = no_symlinks(root / name)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise ValueError("Unsafe release component")
    value = read_bytes(path, MAX_FILE)
    after = path.stat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_dev, after.st_ino, len(value), after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Release component changed during verification")
    return value


def create_manifest(root):
    root = no_symlinks(root)
    lock = root / "package-lock.json"
    if lock.exists():
        data = component(root, "package-lock.json")
        if not isinstance(json.loads(data), dict):
            raise ValueError("Invalid dependency lock")
        atomic_write(root / "dist/dependency-lock.json", data)
    paths = sorted(p.relative_to(root).as_posix() for folder in ("runtime", "src", "scripts", "dist")
                   for p in (root / folder).iterdir() if eligible(p.relative_to(root).as_posix()))
    files, total = {}, 0
    for name in sorted(set(paths) | TOP):
        data = component(root, name)
        total += len(data)
        files[name] = {"sha256": sha(data), "bytes": len(data)}
    if not REQUIRED <= files.keys() or len(files) > 512 or total > MAX_TOTAL:
        raise ValueError("Incomplete or oversized release")
    package = json.loads(component(root, "package.json"))
    value = {"schema": 1, "version": package["version"], "files": files}
    atomic_write(root / MANIFEST, encoded(value))
    return verify(root)


def verify(root, sealed=False):
    root = no_symlinks(Path(root))
    raw = component(root, MANIFEST)
    if len(raw) > 256 * 1024:
        raise ValueError("Oversized release manifest")
    value = json.loads(raw)
    files = value.get("files")
    if (value.get("schema") != 1 or not isinstance(value.get("version"), str)
            or not isinstance(files, dict) or not REQUIRED <= files.keys() or len(files) > 512):
        raise ValueError("Invalid release manifest")
    if sealed and root.name != sha(raw):
        raise ValueError("Release identity mismatch")
    total = 0
    for name, record in files.items():
        if not eligible(name) or not isinstance(record, dict) or set(record) != {"sha256", "bytes"}:
            raise ValueError("Invalid release component declaration")
        if (not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])) or type(record["bytes"]) is not int
                or not 0 <= record["bytes"] <= MAX_FILE):
            raise ValueError("Invalid release digest or size")
        total += record["bytes"]
        if total > MAX_TOTAL:
            raise ValueError("Oversized release")
        data = component(root, name)
        if len(data) != record["bytes"] or sha(data) != record["sha256"]:
            raise ValueError("Release component hash mismatch; original preserved")
        if sealed and (root / name).stat().st_mode & 0o222:
            raise ValueError("Installed release is writable")
    return {"id": sha(raw), "root": str(root), "version": value["version"],
            "files": files, "bytes": total, "sealed": sealed}


def materialize(home, source):
    release = verify(source)
    releases = home.path / "releases"
    private_directory(releases)
    target = no_symlinks(releases / release["id"])
    with locked(home.path / "releases.lock"):
        if target.exists():
            return verify(target, sealed=True)
        if len(list(releases.iterdir())) >= 8:
            raise ValueError("Release retention limit; review old releases before installing another")
        temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=releases))
        try:
            for name, expected in release["files"].items():
                data = component(Path(source), name)
                if sha(data) != expected["sha256"] or len(data) != expected["bytes"]:
                    raise ValueError("Release changed before copy")
                private_directory((temporary / name).parent)
                atomic_write(temporary / name, data)
                (temporary / name).chmod(0o400)
            raw = component(Path(source), MANIFEST)
            if sha(raw) != release["id"]:
                raise ValueError("Release manifest changed before copy")
            atomic_write(temporary / MANIFEST, raw)
            (temporary / MANIFEST).chmod(0o400)
            verify(temporary)
            for directory in sorted((p for p in temporary.rglob("*") if p.is_dir()), reverse=True):
                directory.chmod(0o500)
            temporary.chmod(0o500)
            os.rename(temporary, target)
            return verify(target, sealed=True)
        finally:
            if temporary.exists():
                temporary.chmod(0o700)
                for directory in temporary.rglob("*"):
                    if directory.is_dir():
                        directory.chmod(0o700)
                shutil.rmtree(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    result = create_manifest(args.root) if args.action == "build" else verify(args.root)
    print(json.dumps({key: result[key] for key in ("id", "version", "bytes")}))
