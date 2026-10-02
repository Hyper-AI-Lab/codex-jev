"""Optional OTel/service registration. Install never starts or enables a daemon."""

from __future__ import annotations

import copy
import json
import os
import plistlib
import shlex
import sys
import tomllib
from pathlib import Path

from common import atomic_write, encoded, locked, no_symlinks, now
from common import private_directory, read_bytes, read_json, sha, write_transaction
from installer import MANAGE, block, same_owned


def service_definition(home, port, platform, service_root):
    root = no_symlinks(Path(service_root or Path.home()).expanduser())
    suffix = sha(str(home.codex).encode())[:12]
    args = [
        str(Path(sys.executable).resolve()),
        "-B",
        str(MANAGE),
        "telemetry",
        "--codex-home",
        str(home.codex),
        "--port",
        str(port),
    ]
    if any(any(ord(char) < 32 for char in arg) for arg in args + [str(root)]):
        raise ValueError("Control characters in service paths")
    if platform == "linux":
        name = f"jev-context-observer-{suffix}.service"
        path = root / ".config" / "systemd" / "user" / name

        # systemd parses ExecStart itself, not as a shell command.
        def quote(value):
            return (
                json.dumps(value, ensure_ascii=False)
                .replace("%", "%%")
                .replace("$", "$$")
            )

        content = (
            "[Unit]\nDescription=Jev local quota observer\nStartLimitIntervalSec=60\nStartLimitBurst=3\n"
            "[Service]\nType=simple\nExecStart=" + " ".join(map(quote, args)) + "\n"
            "Restart=on-failure\nRestartSec=5\nUMask=0077\n"
            "StandardOutput=null\nStandardError=null\n"
            "[Install]\nWantedBy=default.target\n"
        ).encode()
        start = [
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "start", name],
        ]
        stop = [["systemctl", "--user", "disable", "--now", name]]
    elif platform == "darwin":
        name = f"com.openai.jev-context.{suffix}"
        path = root / "Library" / "LaunchAgents" / (name + ".plist")
        content = plistlib.dumps(
            {
                "Label": name,
                "ProgramArguments": args,
                "RunAtLoad": True,
                "KeepAlive": {"SuccessfulExit": False},
                "ThrottleInterval": 30,
                "ProcessType": "Background",
                "Umask": 0o077,
                "StandardOutPath": "/dev/null",
                "StandardErrorPath": "/dev/null",
            }
        )
        start = [["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)]]
        stop = [["launchctl", "bootout", f"gui/{os.getuid()}/{name}"]]
    else:
        raise ValueError("Observer services support Linux and macOS only")
    return path, content, start, stop


def service_idle(home):
    return locked(home.path / "observer.lock", timeout=0.1)


def install_observer(home, port=43181, platform=sys.platform, service_root=None):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Invalid observer port")
    home.ensure()
    with home.lock(), service_idle(home):
        path = home.path / "observer-installation.json"
        previous = read_json(path)
        if previous and previous.get("version") != 1:
            raise ValueError("Unknown observer ownership schema")
        service_path, service, start, stop = service_definition(
            home, port, platform, service_root
        )
        no_symlinks(service_path)
        raw = read_bytes(home.codex / "config.toml").decode()
        native = tomllib.loads(raw)
        env_conflicts = sorted(key for key in os.environ if key.startswith("OTEL_"))
        profile_conflict = any(
            isinstance(value, dict) and "otel" in value
            for value in native.get("profiles", {}).values()
        )
        if env_conflicts or profile_conflict:
            return {
                "installed": False,
                "started": False,
                "conflicts": [
                    "existing profile/environment OTel configuration; preserved"
                ],
            }
        body = (
            "[otel]\nlog_user_prompt = false\n"
            f'exporter = {{ otlp-http = {{ endpoint = "http://127.0.0.1:{port}/v1/logs", protocol = "json" }} }}\n'
        )
        addition = block("observer-otel", body)
        record = previous.get("otel")
        if previous.get("status") not in {None, "uninstalled", "pending", "installed"}:
            raise ValueError("Resolve observer ownership conflicts before reinstalling")
        if record:
            if (
                previous.get("service_path") != str(service_path)
                or previous.get("port") != port
            ):
                raise ValueError(
                    "Uninstall existing observer before changing port or service location"
                )
            if same_owned(raw, record):
                addition = record["text"]
            elif not (
                previous.get("status") == "pending"
                and "otel" not in native
                and "BEGIN jev-context:observer-otel" not in raw
            ):
                return {
                    "installed": False,
                    "started": False,
                    "conflicts": ["config.toml:otel; preserved"],
                }
            else:
                raw += record["text"]
                addition = record["text"]
        elif "otel" in native or "BEGIN jev-context:observer-otel" in raw:
            return {
                "installed": False,
                "started": False,
                "conflicts": ["existing config.toml OTel configuration; preserved"],
            }
        else:
            addition = ("\n" if raw and not raw.endswith("\n") else "") + addition
            raw += addition
        parsed = tomllib.loads(raw)
        expected = copy.deepcopy(native)
        expected["otel"] = tomllib.loads(body)["otel"]
        if parsed != expected:
            raise ValueError("Observer TOML merge changed unrelated configuration")
        existing_service = read_bytes(service_path)
        if service_path.exists() and not (
            previous.get("service_sha256") == sha(existing_service)
            and existing_service == service
        ):
            return {
                "installed": False,
                "started": False,
                "conflicts": ["existing service definition; preserved"],
            }
        private_directory(service_path.parent)
        manifest = {
            "version": 1,
            "status": "pending",
            "platform": platform,
            "port": port,
            "service_path": str(service_path),
            "service_sha256": sha(service),
            "otel": {"text": addition, "sha256": sha(addition.encode())},
            "start_commands": start,
            "stop_commands": stop,
            "updated_at": now(),
        }
        atomic_write(path, encoded(manifest))
        manifest["status"] = "installed"
        write_transaction(
            {
                home.codex / "config.toml": raw.encode(),
                service_path: service,
                path: encoded(manifest),
            }
        )
    return {
        "installed": True,
        "started": False,
        "enabled": False,
        "service_path": str(service_path),
        "endpoint": f"http://127.0.0.1:{port}/v1/logs",
        "log_user_prompt": False,
        "start_commands": [shlex.join(command) for command in start],
        "stop_commands": [shlex.join(command) for command in stop],
        "native_coverage": "unverified; profile/client overrides and native hook trust require owner validation",
    }


def uninstall_observer(home):
    home.ensure()
    with home.lock(), service_idle(home):
        path = home.path / "observer-installation.json"
        manifest = read_json(path)
        if not manifest or manifest.get("status") == "uninstalled":
            return {"uninstalled": True, "conflicts": []}
        if manifest.get("version") != 1:
            raise ValueError("Unknown observer ownership schema")
        service_path = no_symlinks(manifest["service_path"])
        raw = read_bytes(home.codex / "config.toml").decode()
        record = manifest["otel"]
        conflicts = []
        candidate = raw
        if same_owned(raw, record):
            candidate = raw.replace(record["text"], "", 1)
            expected = tomllib.loads(raw)
            expected.pop("otel")
            if tomllib.loads(candidate) != expected:
                conflicts.append("config.toml:otel")
        elif not (
            manifest.get("status") == "pending"
            and "otel" not in tomllib.loads(raw)
            and "BEGIN jev-context:observer-otel" not in raw
        ):
            conflicts.append("config.toml:otel")
        if (
            service_path.exists()
            and sha(read_bytes(service_path)) != manifest["service_sha256"]
        ):
            conflicts.append("service definition")
        if conflicts:
            return {"uninstalled": False, "conflicts": conflicts}
        # All preflight checks precede any removal. Keep intent on interruption.
        manifest["status"] = "pending"
        atomic_write(path, encoded(manifest))
        write_transaction({home.codex / "config.toml": candidate.encode()})
        service_path.unlink(missing_ok=True)
        manifest.update(status="uninstalled", otel=None, updated_at=now())
        atomic_write(path, encoded(manifest))
    return {
        "uninstalled": True,
        "conflicts": [],
        "retained": "private recovery and telemetry timestamps",
        "service_manager_reload_required": True,
    }


def observer_status(home):
    from telemetry import diagnostic_status

    home.ensure()
    manifest = read_json(home.path / "observer-installation.json")
    try:
        with service_idle(home):
            running = False
    except TimeoutError:
        running = True
    return {
        "installation": manifest.get("status", "not_installed"),
        "running_lock_observed": running,
        "service_path": manifest.get("service_path"),
        "port": manifest.get("port"),
        "last_received": read_json(home.path / "telemetry-status.json").get(
            "last_received"
        ),
        "service_manager_state": "not_queried",
        "native_coverage": "not_inferred",
        "compatibility": diagnostic_status(home),
    }
