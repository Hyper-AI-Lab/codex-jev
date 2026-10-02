# Native Usage Collection

Native usage is not an invoice, a subscription-quota meter, or proof of savings.
Cached input is part of input tokens; reasoning is part of output tokens. Neither
subset is added to its parent total. Historical aggregates from older releases
retain their original revision and are not retroactively validated.

## Sources

OTLP completion events and registered local histories use one shared numeric
ledger. The first validated source for a task is authoritative for that task;
alternate-source observations are excluded, not added. Response identifiers are
deduplicated independently of delivery timestamps. A changed payload for the same
identifier is rejected. Separate bounded receipts preserve deduplication even
after detailed measurement rows expire.

Native events without a usable task identity remain diagnostic observations and
are excluded from additive usage. On upgrade, known legacy task ownership is
preserved as OTLP; a migration boundary prevents historical backfill over older
aggregates whose response receipts are unavailable. This does not repair or
retroactively qualify legacy totals.

The collector stores fixed numeric compatibility counters to distinguish a live
transport from recognized completion events and missing token categories. Raw
OTLP attributes, prompts, response bodies, exception strings, and source text are
discarded. The quota halt is recorded before optional diagnostics are written.

## Local History Fallback

Supported hooks use `transcript_path` only after native workspace registration.
The path must identify a regular, owner-owned file under the current Codex home's
`sessions` or `archived_sessions` directory. Header task/workspace identities must
match. Symlinks, hardlinks, changed file identities, rewritten cursor boundaries,
and unregistered tasks are rejected. Parent-directory traversal uses directory
descriptors with no-follow checks.

Registration starts at the last complete line at registration time. It does not
import an entire old conversation or attribute past work to a new integration
revision. Each pass reads at most a bounded batch, retains partial lines, and
reports scan limits or invalid records. A crash after numeric recording but before
cursor persistence replays the same receipt, not the charge. Nothing is uploaded.

- Codex 0.157: response-identified `token_usage_record` observations. Accompanying
  cumulative UI snapshots are ignored to avoid counting the same usage twice.
- Codex 0.130 / 0.156: cumulative `token_count` snapshots. First observations and
  counter resets establish baselines. Only subsequent valid differences count.
  These differences have no inferred turn identity; coverage across a reset is
  explicitly incomplete.
- Other client/history versions: unsupported until compatibility is verified.
  Transcript formats are not a stable public API; see the official
  [hook documentation](https://learn.chatgpt.com/docs/hooks).

Subagent-stop hooks use the parent's session identifier. They are deliberately not
used to infer worker usage from an unrelated transcript. Worker attribution needs
its own verified registration and remains part of the invocation-attribution work.

For an already registered task, explicit commands are available:

```sh
python3 runtime/manage.py usage-register --codex-home "$CODEX_HOME" \
  --task "$TASK_ID" --history "$TRANSCRIPT_PATH"
python3 runtime/manage.py usage-collect --codex-home "$CODEX_HOME" \
  --task "$TASK_ID" --history "$TRANSCRIPT_PATH"
python3 runtime/manage.py metrics-report --codex-home "$CODEX_HOME"
```

Registration checks the installed CLI version. It never automatically resets a
changed cursor. Diagnose and preserve corrupt state before any explicit
re-registration; never erase accounting to force a successful measurement.

## Bounds and Coverage

Numeric details expire after 30 days and have a 10,000-row limit. Native response
receipts retain 30 days with a 100,000-entry cap; reaching capacity refuses further
observations rather than evicting deduplication protection. Compact totals retain
historical accounting. Up to 128 explicitly registered history segments are
supported; the registry never recursively scans every conversation.

First-source selection prevents double counting, but cannot fill gaps in an
already-elected source. Reports must identify missing intervals instead of claiming
complete accounting. These source changes are not live merely because their tests
pass; installation and desktop reconnection remain separate release checks.
