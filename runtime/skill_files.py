"""Owned global skill files participate in the native install transaction."""

import re
from pathlib import Path

from common import no_symlinks, private_directory, read_bytes, sha

FILES = ("SKILL.md", "references/typed-judgments.md", "references/typesafe-guidance.md", "references/LICENSES.txt")
PREFIX = "skills/codex-jev/"


def declarations(value):
    if not isinstance(value, dict) or set(value) - set(FILES) or any(
            not re.fullmatch(r"[a-f0-9]{64}", str(digest)) for digest in value.values()):
        raise ValueError("Invalid skill ownership; preserved")
    return value


def prepare(home, release, previous):
    from releases import component

    current = declarations(previous.get("skill", {}))
    prior = declarations(previous.get("previous_owned", {}).get("skill", {})) if previous.get("status") == "pending" else {}
    files = release["files"]
    included = {name for name in FILES if PREFIX + name in files}
    if included and included != set(FILES):
        raise ValueError("Incomplete bundled skill")
    changes, owned = {}, {}
    for name in FILES:
        path = no_symlinks(home.codex / PREFIX / name)
        if path.exists():
            digest = sha(read_bytes(path))
            allowed = {value for value in (current.get(name), prior.get(name)) if value}
            if digest not in allowed:
                raise ValueError("Unowned or owner-edited skill file; preserved")
        elif name in current and previous.get("status") != "pending":
            raise ValueError("Owner removed a managed skill file; preserved")
        if name in included:
            data = component(Path(release["root"]), PREFIX + name)
            if sha(data) != files[PREFIX + name]["sha256"]:
                raise ValueError("Bundled skill changed")
            private_directory(path.parent)
            changes[path] = data
            owned[name] = sha(data)
        elif name in current:
            changes[path] = None
    return changes, owned


def removal(home, manifest):
    current = declarations(manifest.get("skill", {}))
    prior = declarations(manifest.get("previous_owned", {}).get("skill", {})) if manifest.get("status") == "pending" else {}
    changes, retained, conflicts = {}, {}, []
    for name, digest in current.items():
        path = no_symlinks(home.codex / PREFIX / name)
        if path.exists() and sha(read_bytes(path)) not in {digest, prior.get(name)}:
            retained[name] = digest
            conflicts.append("skill:" + name)
        else:
            changes[path] = None
    return changes, retained, conflicts
