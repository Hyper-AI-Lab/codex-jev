"""Bounded, local numeric measurements. Never store telemetry bodies or source."""

import math
import os
import sqlite3
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from common import encoded, identifier, no_symlinks, read_bytes, sha

MAX_RECORDS = 10000
RETENTION_DAYS = 30
ORIGINS = {"ordinary", "synthetic", "comparison", "unattributed"}
KINDS = {"native_usage", "native_tool", "hook", "checkpoint"}
FIELDS = {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens",
          "duration_ms", "tool_calls", "success", "collector_errors"}


@lru_cache(maxsize=1)
def revision():
    return sha(b"".join(read_bytes(Path(__file__).with_name(name))
                        for name in ("measurements.py", "telemetry.py", "manage.py", "recovery.py")))


def identity(value):
    return sha(value.encode()) if identifier(value) else None


@contextmanager
def database(home):
    home.ensure()
    path = no_symlinks(home.path / "measurements.sqlite3")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("Unsafe measurements database")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(descriptor)
    path.chmod(0o600)
    connection = sqlite3.connect(path, timeout=2)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript("""
          CREATE TABLE IF NOT EXISTS events(
            id TEXT PRIMARY KEY, at REAL NOT NULL, revision TEXT NOT NULL,
            kind TEXT NOT NULL, session_hash TEXT, turn_hash TEXT, origin TEXT NOT NULL,
            metrics TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS bindings(
            session_hash TEXT PRIMARY KEY, workspace_hash TEXT NOT NULL,
            origin TEXT NOT NULL, at REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS totals(
            month TEXT NOT NULL, revision TEXT NOT NULL, kind TEXT NOT NULL,
            origin TEXT NOT NULL, metric TEXT NOT NULL, samples INTEGER NOT NULL,
            value REAL NOT NULL, PRIMARY KEY(month,revision,kind,origin,metric));
        """)
        yield connection
    finally:
        connection.close()


def bind_session(home, session, workspace, origin="ordinary"):
    session_hash = identity(session)
    if session_hash is None or origin not in ORIGINS or not isinstance(workspace, str):
        raise ValueError("Invalid measurement binding")
    with database(home) as db, db:
        db.execute("DELETE FROM bindings WHERE at < ?", (time.time() - RETENTION_DAYS * 86400,))
        prior = db.execute("SELECT * FROM bindings WHERE session_hash=?", (session_hash,)).fetchone()
        workspace_hash = sha(workspace.encode())
        if prior and (prior["workspace_hash"] != workspace_hash or prior["origin"] != origin):
            raise ValueError("Conflicting measurement binding; do not guess attribution")
        db.execute("INSERT OR REPLACE INTO bindings VALUES(?,?,?,?)", (session_hash, workspace_hash, origin, time.time()))
        db.execute("DELETE FROM bindings WHERE session_hash NOT IN (SELECT session_hash FROM bindings ORDER BY at DESC LIMIT 256)")


def record(home, *, kind, values, session=None, turn=None, event_id=None,
           origin="unattributed", observed_at=None):
    if kind not in KINDS or origin not in ORIGINS or not isinstance(values, dict):
        raise ValueError("Invalid measurement")
    clean = {key: value for key, value in values.items() if key in FIELDS
             and type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1e15}
    if not clean:
        return False
    for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "tool_calls", "success", "collector_errors"):
        if key in clean and (not float(clean[key]).is_integer() or (key == "success" and clean[key] > 1)):
            raise ValueError("Invalid numeric measurement")
    if (clean.get("cached_input_tokens", 0) > clean.get("input_tokens", float("inf"))
            or clean.get("reasoning_tokens", 0) > clean.get("output_tokens", float("inf"))):
        raise ValueError("Token subsets exceed totals")
    timestamp = time.time() if observed_at is None else observed_at
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0 or timestamp > time.time() + 300:
        raise ValueError("Invalid measurement timestamp")
    session_hash, turn_hash = identity(session), identity(turn)
    row = {"kind": kind, "session": session_hash, "turn": turn_hash, "values": clean,
           "event": identity(event_id), "at": timestamp, "revision": revision()}
    key = sha(encoded({k: row[k] for k in ("kind", "session", "turn", "event", "at")}))
    with database(home) as db, db:
        if session_hash:
            binding = db.execute("SELECT origin FROM bindings WHERE session_hash=?", (session_hash,)).fetchone()
            if binding:
                origin = binding["origin"]
        inserted = db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?)",
                              (key, timestamp, revision(), kind, session_hash, turn_hash, origin, encoded(clean).decode())).rowcount
        if inserted:
            month = time.strftime("%Y-%m", time.gmtime(timestamp))
            for name, value in clean.items():
                db.execute("""INSERT INTO totals VALUES(?,?,?,?,?,1,?)
                    ON CONFLICT(month,revision,kind,origin,metric) DO UPDATE
                    SET samples=samples+1,value=value+excluded.value""",
                           (month, revision(), kind, origin, name, value))
        db.execute("DELETE FROM events WHERE at < ?", (time.time() - RETENTION_DAYS * 86400,))
        db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY at DESC LIMIT ?)", (MAX_RECORDS,))
    return bool(inserted)


def report(home):
    path = no_symlinks(home.path / "measurements.sqlite3")
    if not path.exists():
        return {"state": "no_observations", "nativeTokensMeasured": False,
                "accountSavingsMeasured": False, "groups": []}
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("Unsafe measurements database")
    # Report is read-only, including when the collector is stopped.
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2) as db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute("SELECT * FROM totals ORDER BY month,revision,kind,origin,metric")]
        details = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        native = any(row["kind"] == "native_usage" and row["metric"] == "input_tokens" for row in rows)
        return {"state": "observed" if rows else "no_observations", "nativeTokensMeasured": native,
                "accountSavingsMeasured": False, "retentionDays": RETENTION_DAYS,
                "detailRecords": details, "maxDetailRecords": MAX_RECORDS, "groups": rows,
                "attribution": "session binding only; no time-window inference",
                "note": "Cached input and reasoning are subsets, not additional tokens. Usage is not an invoice."}
