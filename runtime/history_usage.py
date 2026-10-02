"""Incremental, local-only numeric usage from explicitly registered Codex histories.

Registration starts at the current file boundary, not at the beginning of a
conversation. Legacy cumulative counters establish a baseline before differences
are recorded. Missing observations are never reported as zero-cost work.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from common import JSON_LIMIT, atomic_write, encoded, identifier, locked, no_symlinks, read_json, sha
from measurements import bind_session, record

MAX_LINE = 1024 * 1024
MAX_BATCH = 8 * 1024 * 1024
MAX_HISTORIES = 128
KEYS = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens")


def schema(version):
    if not isinstance(version, str) or not re.fullmatch(r"0\.(130|156|157)\.\d+", version):
        raise ValueError("Unsupported Codex history version; compatibility review required")
    return "response_records" if version.split(".")[1] == "157" else "cumulative"


def location(home, path):
    path = no_symlinks(path)
    relative = path.relative_to(home.codex)
    if (relative.parts[0] not in {"sessions", "archived_sessions"}
            or not path.name.startswith("rollout-") or path.suffix != ".jsonl"):
        raise ValueError("Only registered native session histories are allowed")
    return path, relative.as_posix(), sha(relative.as_posix().encode())


@contextmanager
def open_history(path):
    # Walk directory descriptors so replacing a parent with a symlink cannot
    # redirect the read between path validation and opening the final file.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError("Unsafe session history file")
            yield stream, info
    finally:
        os.close(directory)


def registry(home):
    value = read_json(home.path / "usage-histories.json")
    if not value:
        return {"version": 1, "histories": {}}
    if (set(value) != {"version", "histories"} or value.get("version") != 1
            or not isinstance(value.get("histories"), dict) or len(value["histories"]) > MAX_HISTORIES):
        raise ValueError("Invalid usage registry; preserve and reconcile")
    for key, item in value["histories"].items():
        if (not isinstance(key, str) or not re.fullmatch("[a-f0-9]{64}", key)
                or not isinstance(item, dict) or not identifier(item.get("session"))
                or set(item) != {"session", "path", "root", "client_version", "format", "offset", "device",
                                 "inode", "invalid_records", "counter_resets", "header", "anchor", "counters"}
                or not isinstance(item.get("path"), str) or not 1 <= len(item["path"]) <= 4096
                or not isinstance(item.get("root"), str) or not 1 <= len(item["root"]) <= 4096
                or item.get("format") not in {"response_records", "cumulative"}
                or not all(type(item.get(k)) is int and item[k] >= 0 for k in
                           ("offset", "device", "inode", "invalid_records", "counter_resets"))
                or not all(isinstance(item.get(k), str) and re.fullmatch("[a-f0-9]{64}", item[k])
                           for k in ("header", "anchor"))):
            raise ValueError("Invalid usage cursor; preserve and reconcile")
        if schema(item.get("client_version")) != item["format"]:
            raise ValueError("History version/schema mismatch")
        if item.get("counters") is not None:
            validated = counters(item["counters"])
            if validated != item["counters"]:
                raise ValueError("Invalid usage baseline")
    return value


def store_registry(home, state):
    data = encoded(state)
    if len(data) > JSON_LIMIT:
        raise ValueError("Usage registry exceeds storage budget")
    atomic_write(home.path / "usage-histories.json", data)


def authorization(home, session):
    entry = home.registry()["sessions"].get(session)
    if not entry:
        raise ValueError("History session is not registered to an authorized workspace")
    return entry["root"]


def header(stream, session, root):
    stream.seek(0)
    raw = stream.readline(MAX_LINE + 1)
    if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
        raise ValueError("Incomplete or oversized history header")
    value = json.loads(raw)
    payload = value.get("payload") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("type") != "session_meta" or not isinstance(payload, dict)
            or payload.get("id", payload.get("session_id")) != session
            or payload.get("cwd") != root):
        raise ValueError("History identity does not match registered workspace/task")
    schema(payload.get("cli_version"))
    return sha(raw)


def anchor(stream, offset):
    stream.seek(max(0, offset - 4096))
    return sha(stream.read(min(offset, 4096)))


def register_history(home, path, session, *, client_version):
    home.ensure()
    format_name = schema(client_version)
    root = authorization(home, session)
    path, relative, key = location(home, path)
    with locked(home.path / "usage-history.lock"):
        state = registry(home)
        prior = state["histories"].get(key)
        if prior:
            if (prior["session"], prior["root"], prior["client_version"]) != (session, root, client_version):
                raise ValueError("History registration changed; explicit reconciliation required")
            return {"state": "already_registered", "history": key, "format": prior["format"]}
        if len(state["histories"]) >= MAX_HISTORIES:
            raise ValueError("Usage history registry capacity reached")
        with open_history(path) as (stream, info):
            header_hash = header(stream, session, root)
            # Resume from the final complete line, retaining any partial record.
            stream.seek(max(0, info.st_size - MAX_LINE))
            tail = stream.read(MAX_LINE)
            last_newline = tail.rfind(b"\n")
            if last_newline < 0:
                raise ValueError("No bounded complete history boundary")
            offset = max(0, info.st_size - MAX_LINE) + last_newline + 1
            state["histories"][key] = dict(path=relative, session=session, root=root,
                client_version=client_version, format=format_name, offset=offset,
                device=info.st_dev, inode=info.st_ino, header=header_hash, anchor=anchor(stream, offset),
                counters=None, invalid_records=0, counter_resets=0)
        bind_session(home, session, root)
        store_registry(home, state)
    return {"state": "registered", "history": key, "format": format_name,
            "coverage": "From registration only; cumulative format first sample establishes baseline."}


def counters(value):
    if not isinstance(value, dict):
        raise ValueError("Missing numeric usage")
    result = {key: value.get("reasoning_output_tokens", value.get(key)) if key == "reasoning_tokens" else value.get(key)
              for key in KEYS}
    if any(type(v) is not int or not 0 <= v <= 10**15 for v in result.values()):
        raise ValueError("Unsupported numeric usage")
    if result["cached_input_tokens"] > result["input_tokens"] or result["reasoning_tokens"] > result["output_tokens"]:
        raise ValueError("Invalid usage subsets")
    return result


def stamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Missing usage timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Usage timestamp has no timezone")
    return parsed.timestamp()


def process(home, item, cursor, key, offset):
    if not isinstance(item, dict):
        raise ValueError("Unknown history record")
    kind, payload = item.get("type"), item.get("payload")
    if kind == "token_usage_record":
        if cursor["format"] != "response_records" or not isinstance(payload, dict):
            raise ValueError("History usage schema changed; review compatibility")
        if payload.get("thread_id") != cursor["session"] or not identifier(payload.get("response_id")):
            raise ValueError("Usage response identity mismatch")
        values = counters(payload.get("usage"))
        return record(home, kind="native_usage", values=values, session=cursor["session"],
                      turn=payload.get("turn_id"), event_id=payload["response_id"],
                      observed_at=stamp(item.get("timestamp")), source="history")
    if kind != "event_msg" or not isinstance(payload, dict) or payload.get("type") != "token_count":
        return False
    if cursor["format"] == "response_records":
        return False  # The same usage also appears as cumulative UI snapshots.
    info = payload.get("info")
    if info is None:
        return False  # Rate-limit-only UI update, not zero usage.
    if not isinstance(info, dict):
        raise ValueError("Unknown cumulative usage schema")
    current = counters(info.get("total_token_usage"))
    previous = cursor["counters"]
    if previous is None:
        cursor["counters"] = current
        return False
    delta = {key: current[key] - previous[key] for key in KEYS}
    if any(value < 0 for value in delta.values()):
        cursor["counter_resets"] += 1
        cursor["counters"] = current
        return False  # A reset is a new baseline, not additional historical usage.
    if not any(delta.values()):
        return False
    # Include cursor and previous/current counters so a crash before cursor commit
    # replays the same receipt, without adding a cumulative snapshot a second time.
    receipt = "history:" + sha(encoded([key, offset, previous, current]))
    accepted = record(home, kind="native_usage", values=delta, session=cursor["session"],
                      event_id=receipt,
                      observed_at=stamp(item.get("timestamp")), source="history")
    cursor["counters"] = current
    return accepted


def collect_history(home, path, session):
    home.ensure()
    root = authorization(home, session)
    path, relative, key = location(home, path)
    with locked(home.path / "usage-history.lock"):
        state = registry(home)
        cursor = state["histories"].get(key)
        if not cursor or (cursor["session"], cursor["root"], cursor["path"]) != (session, root, relative):
            raise ValueError("Unregistered history; do not infer task identity")
        recorded, scanned, result = 0, 0, "caught_up"
        with open_history(path) as (stream, info):
            if ((info.st_dev, info.st_ino) != (cursor["device"], cursor["inode"])
                    or info.st_size < cursor["offset"] or header(stream, session, root) != cursor["header"]
                    or anchor(stream, cursor["offset"]) != cursor["anchor"]):
                raise ValueError("History changed; preserve cursor and reconcile before resuming")
            stream.seek(cursor["offset"])
            while scanned < MAX_BATCH:
                start = stream.tell()
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    result = "oversized_record"
                    break
                if not raw.endswith(b"\n"):
                    result = "partial_record"
                    break
                scanned += len(raw)
                try:
                    item = json.loads(raw)
                except (ValueError, UnicodeError):
                    cursor["invalid_records"] += 1
                else:
                    try:
                        recorded += process(home, item, cursor, key, start)
                    except (ValueError, TypeError, OverflowError):
                        cursor["invalid_records"] += 1
                cursor["offset"] = stream.tell()
            if scanned >= MAX_BATCH:
                result = "scan_limit"
            cursor["anchor"] = anchor(stream, cursor["offset"])
        if cursor["invalid_records"] and result == "caught_up":
            result = "incomplete"
        store_registry(home, state)
        return {"state": result, "history": key, "recorded": recorded, "scanned_bytes": scanned,
                "invalid_records": cursor["invalid_records"], "counter_resets": cursor["counter_resets"],
                "format": cursor["format"], "coverage": "Registered interval only; resets establish a new baseline."}


def installed_version():
    result = subprocess.run(["codex", "--version"], check=True, capture_output=True, timeout=2)
    text = result.stdout.decode("ascii").strip()
    if len(text) > 100 or not text.startswith("codex-cli "):
        raise ValueError("Unsupported installed client version response")
    version = text.removeprefix("codex-cli ")
    schema(version)
    return version


def observe_hook(home, payload):
    """Best-effort numeric observation; never changes recovery or approval gates."""
    if payload.get("hook_event_name") not in {
        "SessionStart", "PostToolUse", "PostCompact", "UserPromptSubmit", "Stop", "SessionEnd"
    }:
        return {"state": "not_a_collection_boundary"}
    path, session = payload.get("transcript_path"), payload.get("session_id")
    if not isinstance(path, str) or not identifier(session):
        return {"state": "history_not_provided"}
    try:
        _, _, key = location(home, path)
        with locked(home.path / "usage-history.lock"):
            existing = registry(home)["histories"].get(key)
        if existing is None:
            return register_history(home, path, session, client_version=installed_version())
        return collect_history(home, path, session)
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        # No exception strings, payloads, paths, or source text enter diagnostics.
        return {"state": "history_unavailable_or_requires_reconciliation"}
