"""Read-only version probe. Unknown availability never authorizes maintenance."""

import json
import re
import subprocess
import time


def classify(result):
    if result.returncode:
        return {"status": "unavailable", "reason": "version_query_failed"}
    try:
        if not isinstance(result.stdout, str) or len(result.stdout) > 8192:
            raise ValueError()
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
    except (ValueError, TypeError):
        return {"status": "unknown", "reason": "invalid_version_response"}
    status = value.get("status")
    if status not in {"running", "stopped"}:
        return {"status": "unknown", "reason": "unsupported_server_state"}
    versions = {}
    for key in ("cliVersion", "appServerVersion", "managedCodexVersion"):
        version = value.get(key)
        if version is not None and (not isinstance(version, str) or
                not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version)):
            return {"status": "unknown", "reason": "invalid_version_response"}
        versions[key] = version
    if status == "running" and versions["appServerVersion"] is None:
        return {"status": "unknown", "reason": "missing_server_version"}
    return {"status": status, **versions}


def probe(query, *, attempts=3, sleep=time.sleep):
    """Retry only read-only availability queries, never starts or shutdowns."""
    if type(attempts) is not int or not 1 <= attempts <= 3:
        raise ValueError("Version query attempts must be bounded")
    for attempt in range(attempts):
        try:
            result = classify(query())
        except (OSError, subprocess.TimeoutExpired):
            result = {"status": "unavailable", "reason": "version_query_failed"}
        result["attempts"] = attempt + 1
        if result["status"] != "unavailable" or attempt + 1 == attempts:
            return result
        sleep(0.2)


def require_known(result):
    if result.get("status") not in {"running", "stopped"}:
        raise RuntimeError("server_availability_unverified_no_action")
    return result
