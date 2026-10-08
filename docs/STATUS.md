# Verification and Measurement Status

Initial public release: `0.4.0-beta.1`. This is a tested beta, not a claim of
universal production certification or guaranteed savings.

Current development rollout (2026-10-08): 253 Node and 164 Python tests pass.
The protected judgment tool and global skill are installed; live protocol
acceptance passes. Actual desktop tests exposed and led to repair of an exact-read
context-expansion defect. The corrected release now passes actual desktop reads,
fresh startup/prompt/tool hooks and same-turn receipt verification. Two ordinary-work
observations remain open. See [current rollout evidence](SELECTIVE_ADOPTION_RESULTS.md)
for the distinction between installed, connected, trusted and effective.

The curated Linux export passed 204 Node tests and 71 Python tests, plus
ESLint, scoped Ruff, compile checks and a Gitleaks directory scan. Packaging
assertions include synthetic fixtures and attribution, not just runtime modules.
GitHub CI repeats the offline checks and scans the entire published history.
An additional public-artifact scan regression brings the Node suite to 205 tests.
The first clean GitHub runner exposed an accidental `codex --version` dependency
in a mocked comparison test; version probing is now injected in that test, so
the offline suite does not require Codex or its credentials to be installed.

| Dimension | Evidence and limits |
| --- | --- |
| Linux runtime | Offline Node/Python suites; isolated package install/upgrade/rollback/uninstall |
| Actual desktop connection | Existing Linux deployment used from macOS desktop; loaded build observed through MCP |
| Public installer | Portable, model-neutral export; live private installation is not automatically replaced |
| Mac-local / Windows | Mac-local unverified; Windows unsupported |
| Jev access | Prior live requests succeeded on the private deployment; public users supply their own key/caps |
| Native hooks | Generated and tested; each user grants native trust independently |
| Native ordinary-work token telemetry | Automatic history collection observed; 419 numeric observations and seven explicit gaps at verification; six validation receipts verified, not ordinary-task savings evidence |
| Net cost, token and speed improvement | Not established; no generalized percentage claim |

## What the interrupted comparison does and does not show

A frozen multi-file native configuration investigation passed all nine required
facts, recording 37,668 input tokens, including 23,808 cached, and 465 output
tokens. The corresponding Jev-assisted arm hit native quota before final usage
and correctness could be recorded. The second task pair was not launched.

This is an **incomplete comparison**, not a negative or positive savings result.
The owner chose to publish a tested beta without retrying it. Private reports,
session identifiers and operational logs are not included in this repository.

Separate synthetic dirty-worktree measurements found checkpoint median latency
decreased from 1,853.672 ms to 640.780 ms after batching (seven measurements per
version). This is checkpoint overhead only, not coding-task speed or quota savings.
`runtime/hardening_baseline.py` retains the offline fixture methodology.

## How to report useful evidence

Compare identical tasks, source snapshots, model and reasoning effort. Count
follow-up reads, hook/checkpoint time, cache behavior and correctness alongside
native input/cached/output/reasoning tokens where the client reports them.
Cached input and reasoning are subsets, not extra tokens to sum twice.
Separate ordinary work, synthetic validation and comparisons by build revision.

Use `evidence_status`, `node scripts/retrieval-trial.mjs report`, and
`python3 runtime/manage.py metrics-report --format markdown`. These expose
different measurement scopes; neither turns excerpt bytes into an invoice.
Do not share raw private configuration, query text, source excerpts or checkpoints.

Four native runs is the explicit comparison ceiling, not a completion guarantee.
Missing usage or quota ends that campaign; no automatic failed-arm retries.
The package never starts an inference benchmark during install or CI.
