"""Read-only task measurements. Missing coverage is not zero usage or savings."""

import json
import math
import sqlite3
import time

from common import identifier, no_symlinks, sha
from invocations import usage_report
from measurements import FIELDS, KINDS, MAX_RECORDS, RETENTION_DAYS


def report(home, task):
    if not identifier(task):
        raise ValueError("Task identity required")
    path = no_symlinks(home.path / "measurements.sqlite3")
    rows = []
    if path.exists():
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("Unsafe measurements database")
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM events WHERE session_hash=? AND at>=? ORDER BY at LIMIT ?",
                              (sha(task.encode()), time.time() - RETENTION_DAYS * 86400, MAX_RECORDS)).fetchall()
    groups = {}
    for row in rows:
        if row["kind"] not in KINDS:
            continue
        key = (row["kind"], row["revision"], row["origin"])
        group = groups.setdefault(key, {"kind": key[0], "revision": key[1], "origin": key[2],
                                       "observations": 0, "metrics": {}, "coverage": {}})
        group["observations"] += 1
        for name, value in json.loads(row["metrics"]).items():
            if name not in FIELDS or type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1e15:
                continue
            group["metrics"][name] = group["metrics"].get(name, 0) + value
            group["coverage"][name] = group["coverage"].get(name, 0) + 1
    return {"taskHash": sha(task.encode()), "nativeTokensMeasured": any(k[0] == "native_usage" for k in groups),
            "accountSavingsMeasured": False, "runtime": list(groups.values()), "retrieval": usage_report(home, task),
            "scope": {"retentionDays": RETENTION_DAYS, "maxDetailRecords": MAX_RECORDS,
                      "retainedTaskRecords": len(rows), "wholeTaskCoverageVerified": False},
            "notes": ["No observations means unknown, not zero usage.",
                      "Cached input is part of input; reasoning is part of output. Do not add subsets twice.",
                      "Checkpoint, hook and retrieval timings overlap; do not add them as wall-clock duration.",
                      "Routing observations include denied attempts, not unique successful executions.",
                      "Only receipt-verified MCP operations appear in retrieval; declared CLI scopes are excluded.",
                      "Provider charges, cached-input discounts and account-quota savings are not inferred from bytes."]}


def markdown(value):
    lines = ["# Task Measurements", "", "Retained local observations only; not a savings or billing statement.", "",
             "| Category | Revision | Origin | Metric | Observations | Value |",
             "| --- | --- | --- | --- | --- | --- |"]
    for group in value["runtime"]:
        for key, total in sorted(group["metrics"].items()):
            lines.append(f"| {group['kind']} | {group['revision'][:12]} | {group['origin']} | {key} | {group['coverage'][key]} | {total} |")
    lines += ["", f"Verified retrieval operations: {value['retrieval']['verifiedOperations']}",
              f"Native token observations: {'present' if value['nativeTokensMeasured'] else 'missing'}", ""]
    lines.extend("- " + note for note in value["notes"])
    return "\n".join(lines) + "\n"
