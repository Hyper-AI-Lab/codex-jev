"""Exact native pre/post hook receipts. Never infer identity from timing alone."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from common import identifier, no_symlinks, sha

OPERATIONS = {"search_workspace_evidence", "read_large_text_evidence", "read_selected_evidence", "list_evidence", "evidence_status", "judge_evidence"}
METRICS = {"responseBytes", "durationMs", "jevRequests", "jevInputTokens", "jevOutputTokens", "retrievalMs",
           "selectionMs", "evidenceBytes", "followupBytes", "followupReads", "cacheHits", "localBypasses", "localFallbacks"}
TTL = 600_000
RETENTION = 30 * 86400_000
MAX_ROWS = 10000


def milliseconds():
    return int(time.time() * 1000)


def canonical_digest(value):
    def validate(item, depth=0):
        if depth > 16:
            raise ValueError("Invocation arguments exceed depth limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= 2**53 - 1:
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) <= 65536:
                return
        if isinstance(item, list) and len(item) <= 4096:
            for child in item:
                validate(child, depth + 1)
            return
        if isinstance(item, dict) and len(item) <= 4096:
            for key, child in item.items():
                if not isinstance(key, str) or not re.fullmatch(r"[\x20-\x7e]{1,200}", key):
                    raise ValueError("Unsupported argument key")
                validate(child, depth + 1)
            return
        raise ValueError("Unsupported invocation arguments")

    validate(value)
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > 65536:
        raise ValueError("Invocation arguments exceed size limit")
    return sha(data)


@contextmanager
def database(home):
    home.ensure()
    path = no_symlinks(home.path / "invocations.sqlite3")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("Unsafe invocation ledger")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_nlink != 1:
            raise ValueError("Invalid invocation ledger owner")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        db.executescript(Path(__file__).with_name("invocations.sql").read_text())
        if [r[0] for r in db.execute("SELECT version FROM invocation_schema")] != [1]:
            raise ValueError("Unknown invocation schema")
        yield db
    finally:
        db.close()


def identity(home, payload, workspace):
    operation = payload.get("tool_name", "").removeprefix("mcp__jev_context__") if isinstance(payload.get("tool_name"), str) else ""
    if operation not in OPERATIONS or not payload.get("tool_name", "").startswith("mcp__jev_context__"):
        return None, "not_covered"
    native = [payload.get(k) for k in ("session_id", "turn_id", "tool_use_id")]
    if not all(identifier(item) for item in native):
        return None, "missing_native_identity"
    session, turn, call = native
    registered = home.registry()["sessions"].get(session)
    if not registered or registered["root"] != str(workspace):
        return None, "workspace_mismatch"
    if not isinstance(payload.get("tool_input"), dict):
        return None, "invalid_arguments"
    return dict(session_hash=sha(session.encode()), turn_hash=sha(turn.encode()),
                call_hash=canonical_digest(native), workspace_hash=sha(str(workspace).encode()),
                operation=operation, arguments_hash=canonical_digest(payload["tool_input"])), None


def pre_tool(home, payload, workspace):
    fields, error = identity(home, payload, workspace)
    if error:
        return {"state": error}
    now = milliseconds()
    with database(home) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM invocation_receipts WHERE created_at < ?", (now - RETENTION,))
        existing = db.execute("SELECT * FROM invocation_receipts WHERE call_hash=?", (fields["call_hash"],)).fetchone()
        if existing:
            return {"state": "receipt_exists" if all(existing[k] == v for k, v in fields.items()) else "mismatch"}
        if db.execute("SELECT COUNT(*) FROM invocation_receipts").fetchone()[0] >= MAX_ROWS:
            return {"state": "receipt_capacity"}
        db.execute("""INSERT INTO invocation_receipts
            (call_hash,session_hash,turn_hash,workspace_hash,operation,arguments_hash,created_at,expires_at)
            VALUES(:call_hash,:session_hash,:turn_hash,:workspace_hash,:operation,:arguments_hash,:created_at,:expires_at)""",
                   {**fields, "created_at": now, "expires_at": now + TTL})
    return {"state": "receipt_created"}


def result_identity(response):
    if not isinstance(response, dict):
        return None
    found = []
    if isinstance(response.get("structuredContent"), dict):
        found.append(response["structuredContent"].get("measurementId"))
    content = response.get("content", [])
    if not isinstance(content, list) or len(content) > 8:
        return None
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            if len(item["text"]) > 131072:
                return None
            try:
                parsed = json.loads(item["text"])
            except ValueError:
                continue
            if isinstance(parsed, dict):
                found.append(parsed.get("measurementId"))
    found = [item for item in found if item is not None]
    if not found or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", item) for item in found):
        return None
    return found[0] if len(set(found)) == 1 else None


def post_tool(home, payload, workspace):
    fields, error = identity(home, payload, workspace)
    if error:
        return {"state": error}
    operation_id = result_identity(payload.get("tool_response"))
    if operation_id is None:
        return {"state": "missing_result_identity"}
    with database(home) as db, db:
        db.execute("BEGIN IMMEDIATE")
        receipt = db.execute("SELECT * FROM invocation_receipts WHERE call_hash=?", (fields["call_hash"],)).fetchone()
        if not receipt:
            return {"state": "missing_receipt"}
        if any(receipt[k] != v for k, v in fields.items()):
            return {"state": "mismatch"}
        operation = db.execute("SELECT * FROM invocations WHERE id=?", (operation_id,)).fetchone()
        if not operation:
            return {"state": "missing_operation"}
        if any(operation[k] != fields[k] for k in ("workspace_hash", "operation", "arguments_hash")):
            return {"state": "mismatch"}
        if receipt["invocation_id"]:
            return {"state": "already_verified" if receipt["invocation_id"] == operation_id
                    and operation["call_hash"] == fields["call_hash"] else "consumed"}
        if operation["call_hash"] is not None:
            return {"state": "operation_already_attributed"}
        if milliseconds() > receipt["expires_at"]:
            return {"state": "expired"}
        if operation["result_status"] == "started" or operation["completed_at"] is None:
            return {"state": "unfinished"}
        if (not receipt["created_at"] <= operation["started_at"] <= operation["completed_at"] <= receipt["expires_at"]
                or operation["completed_at"] > milliseconds()):
            return {"state": "invalid_interval"}
        db.execute("UPDATE invocations SET session_hash=?,turn_hash=?,call_hash=? WHERE id=?",
                   (fields["session_hash"], fields["turn_hash"], fields["call_hash"], operation_id))
        db.execute("UPDATE invocation_receipts SET invocation_id=? WHERE call_hash=?", (operation_id, fields["call_hash"]))
    return {"state": "verified"}


def usage_report(home, session):
    if not identifier(session):
        raise ValueError("Task identity is required")
    path = no_symlinks(home.path / "invocations.sqlite3")
    rows = []
    if path.exists():
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("Unsafe invocation ledger")
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM invocations WHERE session_hash=? ORDER BY started_at LIMIT ?",
                              (sha(session.encode()), MAX_ROWS)).fetchall()
    metrics = {}
    timeline = []
    for row in rows:
        raw = json.loads(row["metrics"])
        values = {k: v for k, v in raw.items() if k in METRICS and type(v) in (int, float) and math.isfinite(v) and 0 <= v <= 1e15}
        for key, value in values.items():
            metrics[key] = metrics.get(key, 0) + value
        timeline.append({"measurementId": row["id"], "operation": row["operation"], "revision": row["revision"],
                         "startedAt": row["started_at"], "completedAt": row["completed_at"],
                         "status": row["result_status"], "turnHash": row["turn_hash"], "metrics": values})
    return {"verifiedOperations": len(rows), "failedOperations": sum(r["result_status"] == "error" for r in rows),
            "metrics": metrics, "timeline": timeline, "accountSavingsMeasured": False,
            "coverage": "Verified native receipts only. Missing hooks and ambiguous operations are excluded, not zero-cost."}
