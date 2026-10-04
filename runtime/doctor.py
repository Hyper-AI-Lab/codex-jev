"""Local configuration/integrity inspection; no network and no trust changes."""

from pathlib import Path
import tomllib

from common import read_bytes, read_json
from installer import same_owned
from releases import verify


def inspect(home):
    record = read_json(home.path / "installation.json")
    native = tomllib.loads(read_bytes(home.codex / "config.toml").decode())
    release = {"state": "legacy_or_not_installed", "verified": False}
    if record.get("release_root"):
        try:
            value = verify(Path(record["release_root"]), sealed=True)
            if record.get("release_id") != value["id"]:
                raise ValueError("Installed release identifier mismatch")
            release = {"state": "immutable_release", "verified": True, "id": value["id"],
                       "version": value["version"], "components": len(value["files"])}
        except (OSError, ValueError, KeyError):
            release = {"state": "integrity_failed", "verified": False}
    hooks = read_json(home.codex / "hooks.json").get("hooks", {})
    hook_matches = {event: groups.get("group") in hooks.get(event, [])
                    for event, groups in record.get("hooks", {}).items()}
    server = native.get("mcp_servers", {}).get("jev_context", {})
    fragments = {name: same_owned(read_bytes(home.codex / ("AGENTS.md" if name == "guidance" else "config.toml")).decode(), block)
                 for name, block in record.get("blocks", {}).items()}
    callbacks = read_json(home.path / "callbacks.json").get("events", [])
    return {"installed": record.get("status") == "installed", "release": release,
            "registeredEntrypointMatches": server.get("args") == [record.get("entrypoint")],
            "ownedFragmentsMatch": fragments, "ownedHooksMatch": hook_matches,
            "observedHookEvents": sorted({v["event"] for v in callbacks if isinstance(v.get("event"), str)}),
            "hookTrust": "not_inspected_or_modified", "halted": home.halted(),
            "desktopConnection": "verify_actual_evidence_status_loadedRelease",
            "liveAccess": "not_tested_by_doctor", "effectiveness": "not_inferred"}
