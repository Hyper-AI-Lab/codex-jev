# Native Retrieval Preference

The pre-tool hook recognizes a bounded subset of simple `rg`, `grep`, `cat`,
`head`, `tail`, and `sed` reads. Broad searches and reads over 48 KiB receive a
denial with a short instruction to use the protected evidence tool. No command
is rewritten, executed, or sent to a provider by the classifier.

Exact identifier searches, filename/count queries, small reads, and explicit
ranges of at most 240 lines remain native. Unknown tools, compound commands,
substitutions, unsupported options, edits, tests and structured queries are
unclassified, not redirected. Hooks cover only supported native tool boundaries;
this is a retrieval preference, not a universal shell or security policy.

The classifier reads file metadata and Git exclusions, never file content.
Private, ignored, linked, outside-workspace, oversized and missing paths remain
explicit native exceptions. The evidence service independently revalidates every
read. A source changing after classification cannot authorize an evidence read.

`RetrievalRouting` callbacks retain only hashed task IDs and fixed state/reason
codes. No command, query, path, error body, or owner instruction is stored in
these records. The bounded callback history is diagnostic, not a complete
execution count. Broader task metrics are documented separately.

## Owner Overrides

Routing is enabled for an enabled integration by default. An owner can opt out
using the private `jev-context/retrieval-policy.json` under their Codex home:

```json
{"enabled": false}
```

Exact, expiring exceptions are also supported in `native_exceptions`. Each entry
has `digest` (SHA-256 of canonical absolute command working directory, a newline,
and the exact command), `expires_at` (Unix seconds, within seven days), and
`reason: "owner_requested"`. They must be created only for an explicit owner
instruction. They neither clear a quota halt nor bypass native permissions or
recovery verification. Changing the command or working directory invalidates
the exception. A model-supplied shell comment is not an exception.

If classification is unavailable or the evidence workspace is unregistered,
the native exception is recorded; no alternate provider or arbitrary root is
enabled. Recovery corruption and quota halts still block execution first.

Source implementation and passing fixtures do not establish live deployment.
Actual connection and native hook trust are checked in the rollout step.
