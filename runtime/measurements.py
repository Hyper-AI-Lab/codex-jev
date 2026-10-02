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
MAX_NATIVE_RECEIPTS = 100000
RETENTION_DAYS = 30
ORIGINS = {"ordinary", "synthetic", "comparison", "unattributed"}
KINDS = {"native_usage", "native_tool", "hook", "checkpoint"}
FIELDS = {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens",
          "duration_ms", "tool_calls", "success", "collector_errors"}


@lru_cache(maxsize=1)
def revision():
    return sha(b"".join(read_bytes(Path(__file__).with_name(name))
                        for name in ("measurements.py", "telemetry.py", "history_usage.py", "manage.py", "recovery.py")))


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
          CREATE TABLE IF NOT EXISTS native_sources(
            session_hash TEXT PRIMARY KEY, source TEXT NOT NULL, at REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS native_receipts(
            id TEXT PRIMARY KEY, metrics_hash TEXT NOT NULL, at REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS measurement_metadata(
            key TEXT PRIMARY KEY, value REAL NOT NULL);
        """)
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM measurement_metadata WHERE key='source_election_boundary'").fetchone():
                legacy = connection.execute("""SELECT EXISTS(SELECT 1 FROM events e WHERE e.kind='native_usage'
                    AND NOT EXISTS(SELECT 1 FROM native_receipts r WHERE r.id=e.id))""").fetchone()[0]
                unknown_legacy = (not connection.execute("SELECT 1 FROM native_sources LIMIT 1").fetchone()
                                  and connection.execute("SELECT 1 FROM totals WHERE kind='native_usage' LIMIT 1").fetchone())
                # Preserve known legacy ownership; pruned/sessionless aggregates
                # stay explicitly unverified and cannot be backfilled over.
                connection.execute("""INSERT OR IGNORE INTO native_sources
                    SELECT DISTINCT e.session_hash,'otlp',? FROM events e
                    WHERE e.kind='native_usage' AND e.session_hash IS NOT NULL
                    AND NOT EXISTS(SELECT 1 FROM native_receipts r WHERE r.id=e.id)""", (time.time(),))
                connection.execute("INSERT INTO measurement_metadata VALUES('source_election_boundary',?)",
                                   (time.time() if legacy or unknown_legacy else 0,))
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
           origin="unattributed", observed_at=None, source="otlp"):
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
    if source not in {"otlp", "history"}:
        raise ValueError("Unknown native measurement source")
    session_hash, turn_hash = identity(session), identity(turn)
    row = {"kind": kind, "session": session_hash, "turn": turn_hash, "values": clean,
           "event": identity(event_id), "at": timestamp, "revision": revision()}
    stable_native = kind == "native_usage" and session_hash and identity(event_id)
    key = sha(encoded({k: row[k] for k in
                      (("kind", "session", "event") if stable_native else
                       ("kind", "session", "turn", "event", "at"))}))
    with database(home) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if kind == "native_usage":
            cutoff = time.time() - RETENTION_DAYS * 86400
            boundary = db.execute("SELECT value FROM measurement_metadata WHERE key='source_election_boundary'").fetchone()[0]
            if timestamp < max(cutoff, boundary) or "input_tokens" not in clean or not session_hash:
                return False
            db.execute("DELETE FROM native_receipts WHERE at < ?", (cutoff,))
            db.execute("DELETE FROM native_sources WHERE at < ?", (cutoff,))
            # Elect one source for each registered task. Never add a transcript
            # counter to OTLP totals for the same task, even without response IDs.
            if session_hash:
                prior_source = db.execute("SELECT source FROM native_sources WHERE session_hash=?", (session_hash,)).fetchone()
                if prior_source and prior_source["source"] != source:
                    return False
                if not prior_source and db.execute("SELECT COUNT(*) FROM native_sources").fetchone()[0] >= MAX_RECORDS:
                    raise ValueError("Native source capacity reached; usage coverage incomplete")
                db.execute("INSERT INTO native_sources VALUES(?,?,?) ON CONFLICT(session_hash) DO UPDATE SET at=excluded.at",
                           (session_hash, source, time.time()))
            elif source == "history":
                raise ValueError("History usage requires a verified session")
            if stable_native:
                metrics_hash = sha(encoded(clean))
                receipt = db.execute("SELECT metrics_hash FROM native_receipts WHERE id=?", (key,)).fetchone()
                if receipt:
                    if receipt["metrics_hash"] != metrics_hash:
                        raise ValueError("Conflicting native response usage")
                    return False
                if db.execute("SELECT COUNT(*) FROM native_receipts").fetchone()[0] >= MAX_NATIVE_RECEIPTS:
                    raise ValueError("Native receipt capacity reached; usage coverage incomplete")
                db.execute("INSERT INTO native_receipts VALUES(?,?,?)", (key, metrics_hash, timestamp))
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
        sources = [dict(row) for row in db.execute("SELECT session_hash,source,at FROM native_sources")] if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='native_sources'").fetchone() else []
        return {"state": "observed" if rows else "no_observations", "nativeTokensMeasured": native,
                "accountSavingsMeasured": False, "retentionDays": RETENTION_DAYS,
                "detailRecords": details, "maxDetailRecords": MAX_RECORDS, "groups": rows,
                "attribution": "session binding only; no time-window inference", "nativeSources": sources,
                "sourcePolicy": "First validated source per task; alternate source excluded, not summed. Historical aggregates remain unverified.",
                "note": "Cached input and reasoning are subsets, not additional tokens. Usage is not an invoice."}
