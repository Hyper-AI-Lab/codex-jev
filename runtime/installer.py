"""Conservative, reversible native user-global Codex registration."""

from __future__ import annotations

import copy
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

from common import atomic_write, encoded, git_root, no_symlinks, now
from common import (
    MAX_SESSIONS,
    private_directory,
    read_bytes,
    read_json,
    sha,
    write_transaction,
)

CHECKOUT = Path(__file__).resolve().parent.parent
MANAGE = CHECKOUT / "runtime" / "manage.py"
SERVER = "jev_context"
EVENTS = (
    "SessionStart",
    "SessionEnd",
    "PreCompact",
    "PostCompact",
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "SubagentStop",
    "Stop",
    "Interrupt",
)
DEFAULTS = {
    "schema_version": 1,
    "enabled": False,
    "live_validated": False,
    "model": "jev-1.13.0",
    "validation_budget_usd": 0,
    "monthly_budget_usd": 0,
    "total_budget_usd": 0,
    "max_requests_per_day": 100,
    "additional_exclusions": [],
    "redaction_literals": [],
    "cache_enabled": True,
}


def block(label, body, markdown=False):
    begin, end = (
        (f"<!-- BEGIN jev-context:{label} -->", f"<!-- END jev-context:{label} -->")
        if markdown
        else (f"# BEGIN jev-context:{label}", f"# END jev-context:{label}")
    )
    return begin + "\n" + body.rstrip() + "\n" + end + "\n"


def guidance(home, manage=MANAGE):
    command = shlex.join([str(Path(sys.executable).resolve()), str(manage)])
    location = shlex.quote(str(home.codex))
    return block(
        "guidance",
        f"""Preserve the owner's selected coding model, reasoning effort and all explicit overrides.
Preserve native worker delegation policies; do not change models, providers or authentication. Use the Jev evidence tools by default
for broad workspace investigation and large logs; keep precise reads, edits and tests native.
Check evidence_status and report Jev, cache, bypass or fallback honestly. Recover unscored and
omitted ranges when needed; verify hashes. Never send secrets or full conversations. Paid selection
needs owner authorization, approved caps and retention validation; enablement does not prove savings.
Before substantive work, checkpoint objective, progress, next step, checks and owned jobs with
`{command} checkpoint --codex-home {location} --workspace <root> --task <session-id> --state <private-json>`.
Honor the shared halt at {home.path / "halt.json"}; stop new work on quota failure.
Inspect with `{command} status --codex-home {location}`. Run
`{command} resume --codex-home {location} --acknowledge` only after explicit owner authorization. Never replay saved
patches/external effects or kill unrelated jobs. Hooks require native trust; coverage is partial.
""",
        markdown=True,
    )


def validate_config(value):
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported Jev config schema")
    if any(type(value.get(key)) is not bool for key in ("enabled", "live_validated")):
        raise ValueError("Invalid enable/validation flags")
    for key in ("validation_budget_usd", "monthly_budget_usd", "total_budget_usd"):
        number = value.get(key)
        if type(number) not in (int, float) or not 0 <= number < float("inf"):
            raise ValueError("Invalid budget")
    if value.get("max_requests_per_day") is not None and (
        type(value.get("max_requests_per_day")) is not int
        or not 1 <= value["max_requests_per_day"] <= 10000
    ):
        raise ValueError("Invalid daily request cap")
    if value.get("model") != "jev-1.13.0":
        raise ValueError("Invalid Jev model")
    roots = value.get("allowed_roots")
    if (
        not isinstance(roots, list)
        or len(roots) > MAX_SESSIONS
        or any(
            not isinstance(root, str)
            or len(root) > 4096
            or not Path(root).is_absolute()
            or Path(root).resolve() in {Path("/"), Path("/root"), Path.home().resolve()}
            for root in roots
        )
    ):
        raise ValueError("Invalid allowed roots")


def node_version(node):
    node = Path(node)
    if not node.is_absolute() or not node.is_file() or not os.access(node, os.X_OK):
        raise ValueError("--node must be an absolute executable path")
    result = subprocess.run(
        [str(node), "--version"], capture_output=True, timeout=5, check=True
    )
    match = re.fullmatch(rb"v(\d+)\.(\d+)\.(\d+)\s*", result.stdout)
    if not match or tuple(map(int, match.groups())) < (22, 13, 0):
        raise ValueError("Node 22.13 or newer is required")
    return node.resolve(), result.stdout.decode().strip()


def parse_hooks(raw):
    hooks = json.loads(raw) if raw else {}
    if not isinstance(hooks, dict) or not isinstance(hooks.get("hooks", {}), dict):
        raise ValueError("Invalid native hooks file")
    if any(not isinstance(value, list) for value in hooks.get("hooks", {}).values()):
        raise ValueError("Invalid hook matcher groups")
    return hooks


def same_owned(text, record):
    owned = record["text"]
    return sha(owned.encode()) == record["sha256"] and text.count(owned) == 1


def reconcile_pending(manifest, raw, agents, hooks):
    """Select only exact old/new owned fragments after an interrupted upgrade."""
    value = copy.deepcopy(manifest)
    old = value.get("previous_owned") if value.get("status") == "pending" else None
    if not old:
        return value
    for name, record in value["blocks"].items():
        text = agents if name == "guidance" else raw
        prior = old["blocks"].get(name)
        if not same_owned(text, record) and prior and same_owned(text, prior):
            value["blocks"][name] = prior
    for event, record in value["hooks"].items():
        groups = hooks.get("hooks", {}).get(event, [])
        prior = old["hooks"].get(event)
        if groups.count(record["group"]) != 1 and prior and groups.count(prior["group"]) == 1:
            if sha(encoded(prior["group"])) != prior["sha256"]:
                raise ValueError("Corrupt prior hook ownership; preserved")
            value["hooks"][event] = prior
    return value


def install(home, node, workspace, entrypoint="dist", preserve_guidance_edits=False):
    if entrypoint != "dist":
        raise ValueError("Immutable installation requires the bundled dist entrypoint; run npm run build")
    root = git_root(workspace)
    node, version = node_version(node)
    server = CHECKOUT / "dist/server.mjs"
    if not server.is_file():
        raise ValueError("Requested MCP entrypoint is missing")
    home.ensure()
    if home.path.is_relative_to(root):
        raise ValueError("State home is inside workspace")
    with home.lock():
        manifest_path = home.path / "installation.json"
        previous = read_json(manifest_path)
        if previous and previous.get("version") != 1:
            raise ValueError("Unknown installer ownership schema")
        raw = read_bytes(home.codex / "config.toml").decode()
        config = tomllib.loads(raw)
        hooks_raw = read_bytes(home.codex / "hooks.json")
        hooks = parse_hooks(hooks_raw)
        agents = read_bytes(home.codex / "AGENTS.md").decode()
        previous = reconcile_pending(previous, raw, agents, hooks)
        warnings = []
        project_path = root / ".codex" / "config.toml"
        project = tomllib.loads(read_bytes(project_path).decode())
        overrides = {
            key: project[key]
            for key in ("model", "model_reasoning_effort", "model_provider")
            if key in project
        }
        worker_model = project.get("agents", {}).get("default_subagent_model")
        if worker_model:
            overrides["default_subagent_model"] = worker_model
        if overrides:
            warnings.append(
                "Project model/effort/provider overrides detected and preserved; review project_overrides."
            )
        if any(
            parse_hooks(read_bytes(root / ".codex" / "hooks.json"))
            .get("hooks", {})
            .values()
        ):
            warnings.append(
                "Project hook file exists; global and project hooks may both run. Verify before removing duplicates."
            )
        manifest = copy.deepcopy(previous) or {
            "version": 1,
            "blocks": {},
            "hooks": {},
            "created_at": now(),
        }
        if previous.get("status") == "conflicts":
            raise ValueError("Resolve uninstall conflicts before reinstalling")
        preserved_guidance = None
        for name, record in manifest["blocks"].items():
            target = agents if name == "guidance" else raw
            if not same_owned(target, record):
                if name == "guidance" and preserve_guidance_edits:
                    begin, end = "<!-- BEGIN jev-context:guidance -->", "<!-- END jev-context:guidance -->"
                    if target.count(begin) != 1 or target.count(end) != 1 or target.index(end) < target.index(begin):
                        raise ValueError("Ambiguous guidance markers; preserved")
                    preserved_guidance = target[target.index(begin):target.index(end) + len(end)]
                    if target[target.index(end) + len(end):].startswith("\n"):
                        preserved_guidance += "\n"
                    manifest["blocks"][name] = {"text": preserved_guidance, "sha256": sha(preserved_guidance.encode())}
                    previous["blocks"][name] = copy.deepcopy(manifest["blocks"][name])
                    continue
                if previous.get("status") != "pending" or record["text"] in target:
                    raise ValueError("Owner edited a managed block; preserved")
        from releases import materialize

        release = materialize(home, CHECKOUT)
        server = Path(release["root"]) / "dist/server.mjs"
        manage = Path(release["root"]) / "runtime/manage.py"
        expected = copy.deepcopy(config)
        additions = []
        # An absent model is also an owner choice: native defaults remain native.
        mcp = {
            "command": str(node),
            "args": [str(server)],
            "startup_timeout_sec": 20,
            "tool_timeout_sec": 60,
            "env": {
                "JEV_CONTEXT_HOME": str(home.path),
                "CODEX_HOME": str(home.codex),
                "JEV_PYTHON": str(Path(sys.executable).resolve()),
                "JEV_RELEASE_ID": release["id"],
            },
        }
        servers = config.get("mcp_servers", {})
        if not isinstance(servers, dict):
            raise ValueError("Invalid MCP configuration")
        mcp_body = (
            f"[mcp_servers.{SERVER}]\ncommand = {json.dumps(str(node))}\n"
            f"args = [{json.dumps(str(server))}]\nstartup_timeout_sec = 20\ntool_timeout_sec = 60\n"
            f"[mcp_servers.{SERVER}.env]\nJEV_CONTEXT_HOME = {json.dumps(str(home.path))}\n"
            f"CODEX_HOME = {json.dumps(str(home.codex))}\n"
            f"JEV_PYTHON = {json.dumps(str(Path(sys.executable).resolve()))}\n"
            f"JEV_RELEASE_ID = {json.dumps(release['id'])}\n"
        )
        if SERVER in servers:
            if "mcp" not in manifest["blocks"]:
                raise ValueError("Existing MCP entry differs; owner settings preserved")
            if servers[SERVER] != mcp:
                prior = manifest["blocks"]["mcp"]
                if not same_owned(raw, prior):
                    raise ValueError("Owner edited managed MCP entry; preserved")
                content = ("\n" if prior["text"].startswith("\n") else "") + block("mcp", mcp_body)
                raw = raw.replace(prior["text"], content, 1)
                manifest["blocks"]["mcp"] = {"text": content, "sha256": sha(content.encode())}
                expected["mcp_servers"][SERVER] = mcp
        else:
            additions.append(("mcp", block("mcp", mcp_body), "append"))
            expected.setdefault("mcp_servers", {})[SERVER] = mcp
        for name, content, position in additions:
            if f"BEGIN jev-context:{name}" in raw:
                raise ValueError("Unowned managed marker conflict")
            if position == "prepend":
                raw = content + raw
            else:
                content = ("\n" if raw and not raw.endswith("\n") else "") + content
                raw += content
            manifest["blocks"][name] = {
                "text": content,
                "sha256": sha(content.encode()),
            }
        if tomllib.loads(raw) != expected:
            raise ValueError("TOML merge changed unrelated settings")
        command = shlex.join(
            [
                str(Path(sys.executable).resolve()),
                str(manage),
                "hook",
                "--codex-home",
                str(home.codex),
            ]
        )
        for event in EVENTS:
            handler = {
                "type": "command",
                "command": command,
                "timeout": 3 if event == "Interrupt" else 30,
            }
            if event == "SessionStart":
                handler["additionalContextLimit"] = 400
            group = {"hooks": [handler]}
            groups = hooks.setdefault("hooks", {}).setdefault(event, [])
            owned = manifest["hooks"].get(event)
            if not owned and group in groups:
                raise ValueError("Pre-existing unowned hook; preserved without adoption")
            if owned:
                old_group = owned["group"]
                if owned["sha256"] != sha(encoded(old_group)):
                    raise ValueError("Corrupt managed hook ownership; preserved")
                if groups.count(old_group) == 1:
                    if old_group != group:
                        if group in groups:
                            raise ValueError("Duplicate replacement hook; preserved")
                        groups[groups.index(old_group)] = group
                elif previous.get("status") != "pending" or groups.count(old_group) != 0:
                    raise ValueError("Owner edited managed hook; preserved")
            if group not in groups:
                groups.append(group)
            manifest["hooks"][event] = {"group": group, "sha256": sha(encoded(group))}
        content = guidance(home, manage)
        if preserved_guidance is not None or previous.get("preserve_guidance_edits"):
            content = preserved_guidance or manifest["blocks"]["guidance"]["text"]
            old_paths = set()
            for record in previous.get("hooks", {}).values():
                for handler in record.get("group", {}).get("hooks", []):
                    args = shlex.split(handler.get("command", ""))
                    if len(args) >= 3 and args[2] == "hook" and Path(args[1]).name == "manage.py":
                        old_paths.add(args[1])
            if len(old_paths) != 1:
                raise ValueError("Ambiguous prior recovery command; guidance preserved")
            content = content.replace(next(iter(old_paths)), str(manage))
            manifest["preserve_guidance_edits"] = True
            warnings.append("Custom guidance preserved; only the previously owned recovery-helper path was updated.")
        if manifest["blocks"].get("guidance", {}).get("text", "").startswith("\n"):
            content = "\n" + content
        if "guidance" not in manifest["blocks"]:
            if "BEGIN jev-context:guidance" in agents:
                raise ValueError("Unowned AGENTS managed block conflict")
            content = ("\n" if agents and not agents.endswith("\n") else "") + content
            agents += content
            manifest["blocks"]["guidance"] = {
                "text": content,
                "sha256": sha(content.encode()),
            }
        elif previous.get("status") == "pending" and not same_owned(
            agents, manifest["blocks"]["guidance"]
        ):
            agents += manifest["blocks"]["guidance"]["text"]
        elif manifest["blocks"]["guidance"]["text"] != content:
            record = manifest["blocks"]["guidance"]
            agents = agents.replace(record["text"], content, 1)
            manifest["blocks"]["guidance"] = {"text": content, "sha256": sha(content.encode())}
        config_path = home.path / "config.json"
        local = read_json(config_path)
        for key, value in DEFAULTS.items():
            local.setdefault(key, value)
        roots = local.setdefault("allowed_roots", [])
        validate_config(local)
        if str(root) not in roots:
            roots.append(str(root))
        validate_config(local)
        if (
            config.get("features", {}).get("hooks") is False
            or config.get("features", {}).get("codex_hooks") is False
        ):
            warnings.append(
                "Owner disabled hooks; left disabled. Native trust/activation remains pending."
            )
        if config.get("hooks"):
            warnings.append("Inline hooks preserved; matching sources run together.")
        secrets = home.path / "secrets"
        private_directory(secrets)
        key_path = no_symlinks(secrets / "typesafe_api_key")
        if key_path.exists() and not key_path.is_file():
            raise ValueError("Key path is not a regular file")
        manifest.update(
            status="pending",
            node=str(node),
            node_version=version,
            entrypoint=str(server),
            release_id=release["id"],
            release_root=release["root"],
            launch_cwd="inherit_client_workspace",
            updated_at=now(),
        )
        if previous.get("blocks") or previous.get("hooks"):
            manifest["previous_owned"] = {
                "blocks": previous["blocks"], "hooks": previous["hooks"]
            }
        # Write ownership intent first so a crash leaves removals inspectable.
        # Backups contain only added non-secret entries and preimage hashes, never raw auth/config.
        backup = {
            "version": 1,
            "preimage_hashes": {
                name: sha(read_bytes(home.codex / name))
                for name in ("config.toml", "hooks.json", "AGENTS.md")
            },
            "owned_additions": manifest["blocks"],
            "hooks": manifest["hooks"],
        }
        private_directory(home.path / "install-backups")
        atomic_write(
            home.path / "install-backups" / (sha(encoded(backup)) + ".json"),
            encoded(backup),
        )
        backups = sorted(
            (
                p
                for p in (home.path / "install-backups").iterdir()
                if re.fullmatch(r"[0-9a-f]{64}\.json", p.name)
            ),
            key=lambda p: p.stat().st_mtime_ns,
            reverse=True,
        )
        for old in backups[8:]:
            if sha(read_bytes(old)) != old.stem:
                raise ValueError("Corrupt installation backup; preserved")
            old.unlink()
        atomic_write(manifest_path, encoded(manifest))
        manifest["status"] = "installed"
        manifest.pop("previous_owned", None)
        changes = {
            home.codex / "config.toml": raw.encode(),
            home.codex / "hooks.json": encoded(hooks),
            home.codex / "AGENTS.md": agents.encode(),
            config_path: encoded(local),
        }
        # Never read an existing credential, including for rollback bookkeeping.
        if not key_path.exists():
            changes[key_path] = b""
        changes[manifest_path] = encoded(manifest)
        write_transaction(changes)
        key_path.chmod(0o600)
    return {
        "installed": True,
        "release_id": release["id"],
        "release_root": release["root"],
        "state_home": str(home.path),
        "mcp_server": SERVER,
        "launch_cwd": "inherit_client_workspace",
        "hooks_trust": "owner_review_required",
        "warnings": warnings,
        "project_overrides": overrides,
        "enabled": local["enabled"],
        "live_validated": local["live_validated"],
    }


def uninstall(home):
    home.ensure()
    with home.lock():
        path = home.path / "installation.json"
        manifest = read_json(path)
        if not manifest:
            return {
                "uninstalled": True,
                "conflicts": [],
                "retained": "private state and secrets",
            }
        if manifest.get("version") != 1:
            raise ValueError("Unknown ownership schema")
        conflicts = []
        raw = read_bytes(home.codex / "config.toml").decode()
        manifest = reconcile_pending(
            manifest, raw, read_bytes(home.codex / "AGENTS.md").decode(),
            parse_hooks(read_bytes(home.codex / "hooks.json")),
        )
        for name in ("mcp", "model"):
            record = manifest["blocks"].get(name)
            if not record:
                continue
            if not same_owned(raw, record):
                if manifest.get("status") == "pending" and record["text"] not in raw:
                    native = tomllib.loads(raw)
                    absent = (
                        SERVER not in native.get("mcp_servers", {})
                        if name == "mcp"
                        else "model" not in native
                    )
                    if absent and f"BEGIN jev-context:{name}" not in raw:
                        del manifest["blocks"][name]
                        continue
                conflicts.append("config.toml:" + name)
                continue
            candidate = raw.replace(record["text"], "", 1)
            before, after = tomllib.loads(raw), tomllib.loads(candidate)
            expected = copy.deepcopy(before)
            if name == "mcp":
                expected["mcp_servers"].pop(SERVER, None)
                if not expected["mcp_servers"]:
                    expected.pop("mcp_servers")
                if after.get("mcp_servers") == {}:
                    after.pop("mcp_servers")
            else:
                expected.pop("model", None)
            if after != expected:
                conflicts.append("config.toml:" + name)
                continue
            raw = candidate
            del manifest["blocks"][name]
        hooks = parse_hooks(read_bytes(home.codex / "hooks.json"))
        for event, record in list(manifest["hooks"].items()):
            groups = hooks.get("hooks", {}).get(event, [])
            group = record["group"]
            if sha(encoded(group)) != record["sha256"] or groups.count(group) != 1:
                if (
                    manifest.get("status") == "pending"
                    and not groups
                    and sha(encoded(group)) == record["sha256"]
                ):
                    del manifest["hooks"][event]
                    continue
                conflicts.append("hooks.json:" + event)
                continue
            groups.remove(group)
            if not groups:
                hooks["hooks"].pop(event)
            del manifest["hooks"][event]
        agents = read_bytes(home.codex / "AGENTS.md").decode()
        record = manifest["blocks"].get("guidance")
        if record:
            if same_owned(agents, record):
                agents = agents.replace(record["text"], "", 1)
                del manifest["blocks"]["guidance"]
            else:
                if (
                    manifest.get("status") == "pending"
                    and "BEGIN jev-context:guidance" not in agents
                ):
                    del manifest["blocks"]["guidance"]
                else:
                    conflicts.append("AGENTS.md:guidance")
        manifest.update(
            status="conflicts" if conflicts else "uninstalled", updated_at=now()
        )
        if not conflicts:
            manifest.pop("previous_owned", None)
        write_transaction(
            {
                home.codex / "config.toml": raw.encode(),
                home.codex / "hooks.json": encoded(hooks),
                home.codex / "AGENTS.md": agents.encode(),
                path: encoded(manifest),
            }
        )
    return {
        "uninstalled": not conflicts,
        "conflicts": conflicts,
        "retained": "private recovery, halt, registry, budgets, ledger, backups and key file",
    }


def status(home):
    manifest = read_json(home.path / "installation.json")
    config = read_json(home.path / "config.json")
    native = tomllib.loads(read_bytes(home.codex / "config.toml").decode())
    server = native.get("mcp_servers", {}).get(SERVER)
    registry = home.registry()
    callbacks = read_json(home.path / "callbacks.json").get("events", [])
    return {
        "state_home": str(home.path),
        "installation": manifest.get("status", "not_installed"),
        "halted": home.halted(),
        "mcp_registered": server is not None,
        "mcp_launch_cwd": server.get("cwd", "inherit_client_workspace")
        if server
        else None,
        "mcp_actual_launch_cwd": "not_observed_by_runtime; verify MCP diagnostics in client",
        "configured_roots": config.get("allowed_roots", []),
        "hook_observed_roots": registry["roots"],
        "hooks_observed": sorted({event["event"] for event in callbacks}),
        "hooks_trust": "not_modified_or_inferred",
        "model_default": native.get("model"),
        "enabled": config.get("enabled", False),
        "live_validated": config.get("live_validated", False),
        "default_authorization": config.get("default_authorization"),
        "max_requests_per_day": config.get("max_requests_per_day"),
        "trial": {
            key: config["trial"].get(key)
            for key in ("id", "starts_at", "expires_at", "policy")
        }
        if isinstance(config.get("trial"), dict)
        else None,
        "measurement_enabled": config.get("measurement_enabled", False),
    }
