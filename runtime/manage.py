#!/usr/bin/env python3
"""Local installation, checkpoint and recovery CLI. No model calls or auth access."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from pathlib import Path

from common import Home, atomic_write, encoded, git_root, now, read_json
from installer import install, status, uninstall
from recovery import Guard, halt, resume

READ_ONLY_EVIDENCE_TOOLS = {
    f"mcp__jev_context__{name}" for name in (
        "evidence_status", "search_workspace_evidence", "read_large_text_evidence",
        "read_selected_evidence", "list_evidence")
}


def recovery_command(payload, home):
    if payload.get("tool_name") in {"close_agent", "multi_agent_v1__close_agent"}:
        return True
    value = payload.get("tool_input", {})
    if payload.get("tool_name") not in {"Bash", "exec_command"} or not isinstance(
        value, dict
    ):
        return False
    command = value.get("command", value.get("cmd", ""))
    try:
        args = shlex.split(command)
    except (ValueError, TypeError):
        return False
    # Exact read-only status command only; no compound shell commands or arbitrary args.
    base = [
        str(Path(sys.executable).resolve()),
        str(Path(__file__).resolve()),
        "status",
    ]
    return command == shlex.join(args) and args in (
        base,
        base + ["--codex-home", str(home.codex)],
    )


def deny(reason="Jev recovery failed; inspect local status before further changes."):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def hook(home, payload):
    if not isinstance(payload, dict):
        raise ValueError("Expected hook object")
    started = time.perf_counter()
    try:
        return run_hook(home, payload)
    except Exception:
        if payload.get("hook_event_name") == "PreToolUse":
            return deny()
        if payload.get("hook_event_name") in {"Interrupt", "SessionEnd"}:
            return {
                "systemMessage": "Recovery failed during interruption; inspect last verified checkpoint."
            }
        if payload.get("hook_event_name") in {
            "Stop",
            "SubagentStop",
            "SessionStart",
            "PreCompact",
            "PostCompact",
            "PostToolUse",
        }:
            return {
                "continue": False,
                "stopReason": "Recovery failed; owner inspection required.",
                "systemMessage": "No automatic retry or continuation was requested.",
            }
        raise
    finally:
        # Measurement failures must not weaken or become a new recovery gate.
        try:
            from measurements import record
            from history_usage import observe_hook

            observed = observe_hook(home, payload)
            if observed["state"] not in {"not_a_collection_boundary", "history_not_provided"}:
                with home.lock():
                    atomic_write(home.path / "usage-history-status.json", encoded({
                        "at": now(), "state": observed["state"],
                        "recorded": observed.get("recorded"),
                        "invalid_records": observed.get("invalid_records"),
                    }))

            record(home, kind="hook", values={"duration_ms": (time.perf_counter() - started) * 1000},
                   session=payload.get("session_id"), turn=payload.get("turn_id"))
        except Exception:
            pass


def run_hook(home, payload):
    event = payload.get("hook_event_name")
    session = payload.get("session_id", "")
    allowed = {
        "SessionStart",
        "PreCompact",
        "PostCompact",
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SubagentStop",
        "Stop",
        "Interrupt",
        "SessionEnd",
    }
    if event not in allowed:
        return {}
    if event == "PreToolUse" and recovery_command(payload, home):
        return {}
    home.ensure()
    if event == "PreToolUse" and home.halted():
        if recovery_command(payload, home):
            return {}
        home.log_callback(event, session, "halted")
        return deny(
            "Quota halt active. Inspect recovery and obtain explicit owner-authorized resume."
        )
    try:
        cwd = payload.get("cwd")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            raise ValueError("Expected absolute workspace")
        root = git_root(cwd)
    except (ValueError, OSError) as error:
        if (
            isinstance(error, ValueError)
            and str(error) == "Workspace is not a Git worktree"
        ):
            home.log_callback(event, session, "not_git_workspace")
            return {
                "systemMessage": "Git recovery is unavailable in this directory; native work remains permitted. Initialize Git to enable checkpoints."
            }
        if event == "PreToolUse":
            return deny(
                "Jev recovery cannot verify this workspace; inspect local status before changes."
            )
        home.log_callback(event, session, "not_git_workspace")
        return (
            {
                "systemMessage": "Jev recovery not attached: current directory is not an eligible Git workspace."
            }
            if event == "SessionStart"
            else {}
        )
    if event == "SessionStart":
        home.register(root, session)
    try:
        from measurements import bind_session

        bind_session(home, session, str(root))
    except Exception:
        pass
    guard = Guard(home, root, session)
    previous = read_json(guard.runtime / "latest.json")
    if event == "SessionStart":
        # Do not overwrite the last recovery checkpoint before reconciling it.
        if not previous:
            guard.checkpoint("session_start")
        else:
            guard.status()
    elif event == "SessionEnd":
        guard.checkpoint("session_end")
        guard.close_session()
    elif event in {"PreToolUse", "PostToolUse"} and payload.get("tool_name") in READ_ONLY_EVIDENCE_TOOLS and previous:
        with guard.locked():
            guard.verify_latest()
    elif event in {
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SubagentStop",
        "PreCompact",
        "PostCompact",
        "Stop",
        "Interrupt",
    }:
        guard.checkpoint(event)
    home.log_callback(event, session, "verified")
    if event == "SessionStart":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": f"Codex Jev recovery: {guard.runtime / 'state_checkpoint.md'}. "
                "Reconcile current files and latest owner request before resuming. No patches or external effects are replayed. "
                f"Quota halt: {home.halted()}. Jev selection and hook trust are independently verified states.",
            }
        }
    if event in {"PreCompact", "PostCompact", "UserPromptSubmit"}:
        return {
            "systemMessage": f"Recovery pointer: {guard.runtime / 'state_checkpoint.md'}. Reconcile files before continuation; never replay patches or external effects."
        }
    return {}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="action", required=True)
    for name in (
        "install",
        "uninstall",
        "status",
        "checkpoint",
        "resume",
        "halt",
        "hook",
        "telemetry",
        "observer-install",
        "observer-uninstall",
        "observer-status",
        "metrics-report",
        "usage-register",
        "usage-collect",
        "recovery-verify",
    ):
        cmd = sub.add_parser(name)
        cmd.add_argument("--codex-home")
        if name == "metrics-report":
            cmd.add_argument("--format", choices=("json", "markdown"), default="json")
        if name in {"usage-register", "usage-collect"}:
            cmd.add_argument("--history", type=Path, required=True)
            cmd.add_argument("--task", required=True)
        if name == "install":
            cmd.add_argument("--node", required=True)
            cmd.add_argument("--workspace", required=True)
            cmd.add_argument("--entrypoint", choices=("source", "dist"), default="dist")
        if name in {"checkpoint", "status", "recovery-verify"}:
            cmd.add_argument("--workspace")
            cmd.add_argument("--task")
        if name == "checkpoint":
            cmd.add_argument("--state", type=Path)
        if name == "resume":
            cmd.add_argument("--acknowledge", action="store_true")
        if name == "halt":
            cmd.add_argument(
                "--provider", choices=("codex", "typesafe"), default="codex"
            )
        if name in {"telemetry", "observer-install"}:
            cmd.add_argument("--port", type=int, default=43181)
        if name == "observer-install":
            cmd.add_argument(
                "--platform", choices=("linux", "darwin"), default=sys.platform
            )
            cmd.add_argument(
                "--service-root",
                type=Path,
                help="Explicit user home for service definitions",
            )
    return result


def main():
    args = parser().parse_args()
    try:
        home = Home(args.codex_home)
        if args.action == "install":
            value = install(home, args.node, args.workspace, args.entrypoint)
        elif args.action == "uninstall":
            value = uninstall(home)
        elif args.action == "status":
            value = status(home)
            if args.workspace and args.task:
                value["checkpoint"] = Guard(home, args.workspace, args.task).status()
        elif args.action == "checkpoint":
            if not args.workspace or not args.task:
                raise ValueError("Checkpoint needs workspace and task")
            value = Guard(home, args.workspace, args.task).checkpoint(
                state=read_json(args.state) if args.state else None
            )
        elif args.action == "recovery-verify":
            if not args.workspace or not args.task:
                raise ValueError("Recovery verification needs workspace and task")
            value = Guard(home, args.workspace, args.task).status()
        elif args.action == "resume":
            value = resume(home, args.acknowledge)
        elif args.action in {"usage-register", "usage-collect"}:
            from history_usage import collect_history, installed_version, register_history

            value = (register_history(home, args.history, args.task, client_version=installed_version())
                     if args.action == "usage-register" else collect_history(home, args.history, args.task))
        elif args.action == "metrics-report":
            from measurements import report

            value = report(home)
            if args.format == "markdown":
                print("# Jev Runtime Measurements\n\nNumeric local observations only; not billing or savings proof.\n")
                print("| Kind | Origin | Month | Revision | Metric | Samples | Value |\n| --- | --- | --- | --- | --- | --- | --- |")
                for row in value["groups"]:
                    print(f"| {row['kind']} | {row['origin']} | {row['month']} | {row['revision'][:12]} | {row['metric']} | {row['samples']} | {row['value']} |")
                return
        elif args.action == "halt":
            value = halt(home, args.provider, "owner_or_agent_reported_quota")
        elif args.action == "hook":
            raw = sys.stdin.buffer.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Hook payload too large")
            value = hook(home, json.loads(raw))
        elif args.action.startswith("observer-"):
            from observer import install_observer, observer_status, uninstall_observer

            if args.action == "observer-install":
                value = install_observer(
                    home, args.port, args.platform, args.service_root
                )
            elif args.action == "observer-uninstall":
                value = uninstall_observer(home)
            else:
                value = observer_status(home)
        else:
            from telemetry import serve

            serve(home, args.port)
            return
        sys.stdout.buffer.write(encoded(value))
    except Exception as error:
        # Provider/tool payloads, subprocess stderr and credentials never enter errors.
        if args.action == "hook":
            sys.stdout.buffer.write(encoded(deny()))
            sys.stderr.write(
                "Jev recovery failed; blocking hook until local state is inspected.\n"
            )
            raise SystemExit(2) from None
        else:
            sys.stderr.write(
                f"Jev runtime failed ({type(error).__name__}); configuration/state preserved.\n"
            )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
