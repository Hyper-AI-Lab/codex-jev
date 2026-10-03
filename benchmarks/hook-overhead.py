"""Offline dirty-worktree hook timing; no native model or hosted requests."""

import json
from pathlib import Path
import statistics
import sys
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from manage import hook
from test_support import RuntimeCase


def main():
    fixture = RuntimeCase()
    fixture.setUp()
    try:
        for index in range(40):
            fixture.write(f"file-{index}.txt", "before\n" * 128)
        fixture.git("add", ".")
        fixture.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "timing fixture")
        for index in range(40):
            fixture.write(f"file-{index}.txt", "after\n" * 128)
        fixture.git("add", "file-0.txt")
        fixture.write("file-0.txt", "additional unstaged change\n")
        fixture.write("untracked.txt", "untracked fixture\n")
        payload = {"hook_event_name": "SessionStart", "session_id": "offline-timing",
                   "cwd": str(fixture.root), "tool_name": "exec_command",
                   "tool_input": {"cmd": "cat source.txt"}}
        hook(fixture.home, payload)
        payload["hook_event_name"] = "PreToolUse"
        samples = {"capture": [], "verified_read": []}
        for index in range(14):
            for mode in (list(samples) if index % 2 == 0 else list(reversed(samples))):
                started = time.perf_counter()
                if mode == "capture":
                    with patch("retrieval.routing_decision", return_value={"state": "unclassified", "reason": "timing_baseline"}):
                        result = hook(fixture.home, payload)
                else:
                    result = hook(fixture.home, payload)
                if result:
                    raise ValueError("Offline hook did not pass verification")
                if index >= 2:
                    samples[mode].append((time.perf_counter() - started) * 1000)
        medians = {key: statistics.median(value) for key, value in samples.items()}
        print(json.dumps({"scope": "offline_in_process_hooks_not_codex_wall_time", "pairs": 12,
                          "median_ms": medians, "reduction_percent": 100 * (1 - medians["verified_read"] / medians["capture"])}))
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    main()
