# Task-Scoped CLI Evidence

MCP stays bound to the workspace that launched its connection. For a separately
authorized checkout, run the packaged CLI with that checkout as its working
directory. `--root` must resolve to that same directory; it cannot redirect a
running connection to an arbitrary workspace.

```bash
codex-jev search --task "$CODEX_THREAD_ID" --query "How is cache invalidation handled?" --local
codex-jev list --task "$CODEX_THREAD_ID" --session SESSION_ID
codex-jev read --task "$CODEX_THREAD_ID" --session SESSION_ID --evidence e1 --start-line 10 --end-line 40
```

The task must already exist in the trusted-hook workspace registry. Secondary
roots need explicit owner authorization in `allowed_roots`; knowledge of an
evidence reference or another active workspace is not sufficient. A supplied task
must match `CODEX_THREAD_ID` when that host variable is present. Task registration
must be fresh (within 30 days); closing the task revokes its CLI scope.

Search, list and read share a stable task/workspace scope across CLI processes.
Evidence sessions remain bounded to the existing 30-minute lifetime and 128
stored sessions. A different task/root cannot reuse references. MCP references
remain connection-scoped and are not interchangeable with CLI references.

Every follow-up rechecks workspace authorization, local exclusions, links and
source hashes. Changed or now-private files require a new permitted search; the
CLI never silently reads old cached text. Listing references and exact reads do
not contact Jev. Search uses the same sanitization, key file, spending ledger,
cache and shared quota halt as MCP. Old one-shot CLI search remains compatible,
but persistent follow-ups require `--task`.

## Measurement Boundary

CLI scope is declared local identity, not verified native hook-to-MCP attribution.
Responses explicitly report `taskAttribution: cli_declared_not_native_verified`.
This is protection against accidental cross-task reuse within the trusted local
runtime, not an isolation boundary against an owner-level process that can modify
private state or environment. No model, provider, authentication or budget is
changed. Mac-local execution still requires its own verification.
