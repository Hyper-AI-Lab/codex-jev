# Verified Invocation Receipts

Jev does not infer task attribution from request timing, the latest active task,
or model-supplied session identifiers. Its MCP connection can serve calls whose
native task metadata is not exposed to the server.

The supported native pre-tool hook creates a private receipt bound to the native
task, turn, tool-call ID, workspace, operation, and canonical arguments digest.
The server independently assigns each operation a random measurement ID and
records numeric results locally. The native post-tool hook joins that ID from
the actual tool result to the exact pre-tool receipt. Attribution succeeds only
when operation, arguments, workspace, bounded lifetime, and one-time consumption
all match. It is not a permission grant and cannot weaken recovery, privacy, or
provider budget gates.

Missing hooks, unsupported paths, malformed output, expired receipts, conflicts,
and replay attempts remain explicitly unattributed. Covered post-tool hook calls
can be repeated idempotently for the same already verified operation. A receipt
cannot be consumed by a second operation or another task.

## Cross-Runtime Contract

- `runtime/invocations.sql` is shared by Python hooks and the Node entrypoint.
- Private database: `invocations.sqlite3`; no prompt, source, tool arguments,
  transcript, credential, or raw error is stored.
- IDs and workspace/arguments identities are SHA-256 digests; operation IDs are
  random UUIDs. Native identifiers are hashed before storage.
- Canonical input is recursively sorted-key UTF-8 JSON with no whitespace.
  JSON integers, booleans, nulls, strings, arrays and objects are accepted; floats,
  non-finite values, invalid Unicode, and oversized inputs are rejected.
- Operations are the five existing Jev MCP names, without their server prefix.
- Receipts expire after 10 minutes. Private detail has a 30-day retention bound
  and a 10,000-row cap per table; capacity failure is visible, not silent eviction
  of an unconsumed live receipt.
- Only fixed non-negative numeric fields enter metrics. Result status is one of
  `started`, `success`, or `error`. Interrupted operations stay `started`, not
  falsely completed.
- The MCP result adds a `measurementId` when recording succeeded. The response
  itself cannot claim native verification, which happens in the post-tool hook.

This is an implementation contract, not a claim that the currently loaded desktop
connection has been updated. Actual hook coverage is verified during release.
