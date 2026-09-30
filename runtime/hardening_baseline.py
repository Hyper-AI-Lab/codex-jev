"""Freeze non-secret installation evidence and an offline capture benchmark."""

import argparse
import hashlib
import json
import statistics
import tempfile
import time
from pathlib import Path

from common import Home, atomic_write, encoded, git, private_directory, read_json, sha
from recovery import Guard
from manage import hook


def dirty_fixture(root):
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Offline fixture")
    git(root, "config", "user.email", "offline@example.invalid")
    for index in range(24):
        (root / f"module_{index:02}.txt").write_text("base\n" * 20)
    git(root, "add", ".")
    git(root, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
    for index in range(24):
        (root / f"module_{index:02}.txt").write_text(f"changed {index}\n" * 20)
    git(root, "add", "module_00.txt", "module_01.txt")
    (root / "module_00.txt").write_text("staged plus unstaged\n")
    for index in range(8):
        (root / f"new_{index:02}.txt").write_text(f"new {index}\n")
    return sha(encoded({p.name: sha(p.read_bytes()) for p in sorted(root.glob("*.txt"))}))


def capture_benchmark(samples=7):
    with tempfile.TemporaryDirectory(prefix="jev-capture-baseline-") as directory:
        base = Path(directory)
        fixture_hash = dirty_fixture(base / "workspace")
        guard = Guard(Home(base / "codex"), base / "workspace", "capture-benchmark")
        guard.checkpoint("warmup")
        elapsed = []
        for _ in range(samples):
            start = time.perf_counter()
            guard.checkpoint("benchmark")
            elapsed.append(round((time.perf_counter() - start) * 1000, 3))
        hook_elapsed = []
        for _ in range(samples):
            start = time.perf_counter()
            value = hook(guard.home, {"hook_event_name": "PreToolUse", "session_id": "capture-benchmark",
                                     "cwd": str(guard.root), "tool_name": "mcp__jev_context__read_selected_evidence"})
            if value:
                raise ValueError("Read-only hook benchmark did not succeed")
            hook_elapsed.append(round((time.perf_counter() - start) * 1000, 3))
        return {"fixture_sha256": fixture_hash, "samples_ms": elapsed,
                "median_ms": statistics.median(elapsed), "p95_ms": max(elapsed),
                "samples": samples, "read_hook_samples_ms": hook_elapsed, "read_hook_p95_ms": max(hook_elapsed),
                "statistic_note": "empirical p95; seven samples uses maximum"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--compare-to")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise ValueError("Baseline already exists; never overwrite it")
    root = Path(__file__).resolve().parents[1]
    home = Home(args.codex_home)
    config = read_json(home.path / "config.json")
    files = [root / "dist/server.mjs", root / "benchmarks/confirmation-v4-tasks.mjs",
             root / "benchmarks/confirmation-v4-semantic-review.mjs",
             home.codex / "config.toml", home.codex / "hooks.json"]
    report = {"version": 1, "head": git(root, "rev-parse", "HEAD").decode().strip(),
              "hashes": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()},
              "selection": {k: config.get(k) for k in ["enabled", "live_validated", "default_authorization",
                 "validation_budget_usd", "monthly_budget_usd", "total_budget_usd"]},
              "hook_trust": "not_inferred; runtime callback observations recorded separately",
              "native_runs_launched": 0, "capture": capture_benchmark()}
    if args.compare_to:
        baseline = read_json(Path(args.compare_to))["capture"]
        current = report["capture"]
        if baseline["fixture_sha256"] != current["fixture_sha256"]:
            raise ValueError("Capture fixture drift")
        report["comparison"] = {"median_reduction": 1 - current["median_ms"] / baseline["median_ms"],
                                "p95_reduction": 1 - current["p95_ms"] / baseline["p95_ms"],
                                "native_savings_measured": False}
        report["comparison"]["passed"] = min(report["comparison"]["median_reduction"], report["comparison"]["p95_reduction"]) >= 0.5
    private_directory(output.parent)
    atomic_write(output, encoded(report))
    print(json.dumps({"evidence": str(output), "head": report["head"], "capture": report["capture"]}))


if __name__ == "__main__":
    main()
