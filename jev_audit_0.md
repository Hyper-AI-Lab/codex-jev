# Jev Integration Closure and Verified Efficiency

Saved as `jev_audit_0` on 2026-10-01 at the owner's request. Status: deferred for later execution. Saving this plan does not authorize implementation, benchmark restarts, model changes, or deployment. The enforcement and measurement choices below remain the recommended defaults from the proposed plan, not separately confirmed choices.

Execution authorized on 2026-10-02. The original saved copy is retained privately.
Host-specific paths below are made portable for publication. The owner's later
native Astra/Luna/Sol delegation policy supersedes the Astra-only wording; Jev
preserves all explicit model/effort choices. See `docs/INTEGRATION_CLOSURE.md`
for the execution ledger. The ten implementation steps remain unchanged in scope.

## Summary

Finish the original Astra-only integration: reliable default retrieval, preserved evidence, truthful task-linked measurements, safe quota recovery, and a verified Mac-to-Linux rollout.

Jev remains an evidence reranker, not a model router or conversation-compression proxy. TypeSafe describes ranking a locally retrieved shortlist; the integration must provide discovery, selection, and delivery. [TypeSafe retrieval guidance](https://docs.typesafe.ai/cookbooks/rerank_typesafe)

Implementation proceeds in order. Every step appends changes, checks, results, evidence, and next action to the existing progress log. Necessary deviations are documented before execution.

## Implementation Steps

1. **Freeze the requirements and audit baseline.** Reconcile the original plans, owner clarifications, private implementation, public beta, installed artifacts, hooks, and recorded usage. Create one closure matrix with verified, defective, incomplete, and intentionally unsupported states. Preserve existing work, recovery evidence, accounting, and configuration.

2. **Establish one maintained implementation.** Develop in this public `codex-jev` checkout on `codex/integration-closure`. Audit every supported CLI, MCP, installer, recovery, telemetry, and evaluation entrypoint. Convert confirmed findings into regression tests before fixes. Retain the private checkout as rollback evidence; stop maintaining divergent runtime behavior.

3. **Repair native usage collection.** Diagnose the actual exporter/service/parser mismatch using numeric compatibility diagnostics, never raw event logging. Add an incremental, version-checked reader for registered local Codex task histories as a fallback. Handle partial records, reconnects, compaction, counter resets, repeated events, and resumed transcript segments. Report unsupported formats explicitly. Never add cumulative snapshots together or double-count OTLP and transcript observations.

4. **Add verified operation attribution.** Use supported hooks to associate native task, turn, and tool-call identifiers with retrieval operations through private, short-lived invocation receipts. Validate workspace, operation, arguments digest, expiry, and receipt consumption. Keep missing or ambiguous associations unattributed. Add task-scoped records for provider requests, cache hits, bypasses, exact reads, hook latency, and native exceptions.

5. **Make broad retrieval the operational default.** Introduce one bounded hook classifier for recognized broad searches and large-file reads. Redirect by denying the recognized native read with a concise retrieval instruction, not by silently rewriting shell commands. Exact identifier searches, bounded source reads, edits, tests, structured queries, and recovery remain native. Unknown commands are reported as unclassified, not automatically executed through another path. Hooks remain partial guards, as documented by Codex. [Hook capabilities and limitations](https://learn.chatgpt.com/docs/hooks)

6. **Resolve workspace and follow-up usability.** Preserve strict MCP workspace binding. Provide a protected workspace-scoped CLI path for explicitly authorized secondary checkouts, with search/list/exact-read operations and task-bound references that survive separate CLI invocations. Reject cross-task references, unapproved roots, symlink escapes, changed exclusions, and stale hashes. Never fix usability by allowing arbitrary filesystem access.

7. **Improve selection without hiding evidence.** Default broad retrieval to concise previews with addressable exact ranges; preserve explicit full-detail requests. Audit candidate diversity, scoring, protection rules, and conservative retention against frozen fixtures. Maintain contradiction, exception-chain, uncertainty, and critical-diagnostic coverage. Make omitted and unscanned evidence visibly recoverable. Keep the 20-candidate, eight-block, and 48-KiB outbound limits.

8. **Measure total overhead and harden recovery.** Measure full serialized responses, follow-up bytes, Jev usage, cache behavior, discovery time, hooks, checkpoints, and native token categories separately. Extend supported quota detection to worker failures without matching arbitrary document text. Halt covered operations, retain uncertain charges and original recovery evidence, and require acknowledged reconciliation. Deduplicate checkpoints for verified reads; unknown commands retain conservative protection.

9. **Deploy a verifiable, reversible release.** Generate one manifest covering Node/Python runtime, bundle, policy, schemas, and dependencies. Install immutable artifacts rather than executing from a mutable checkout. Migrate only integration-owned configuration and preserve authentication, model/effort, permissions, trust, keys, budgets, and accounting. Verify loaded hashes and behavior through the actual desktop connection in Cyber-Team and a second authorized workspace. Request reconnect or native hook trust only when necessary.

10. **Observe real work and publish honest closure.** Collect data during two ordinary development tasks containing broad retrieval and exact follow-ups; do not manufacture extra work to fill a sample. Report task-level usage, retrieval adoption, correctness, latency, overhead, and missing coverage. Publish verified fixes and sanitized documentation through a reviewed GitHub checkpoint. Keep engineering readiness and demonstrated efficiency as separate outcomes.

## Interfaces and Verification

- Extend `evidence_status` with workspace binding, loaded-component versions, invocation coverage, collector health, adoption counts, access proof, and effectiveness status. Preserve existing fields; stop deriving access and effectiveness from the same flag.
- Add `doctor`, task-scoped JSON/Markdown usage reports, a timeline, and CLI list/read operations. Preserve existing MCP tool names. Store numeric metadata and opaque identifiers, not prompts, source text, credentials, or full conversations.
- Test actual sanitized client event shapes, duplicate delivery, restarted counters, missing IDs, concurrent tasks, worker quota failures, checkpoint corruption, disk exhaustion, uncertain charges, and rollback without accounting reset.
- Test native-read classification against safe exact reads, broad searches, quoted arguments, compound commands, unsupported paths, and owner exceptions. No false blocking of edits, tests, or recovery in the acceptance suite.
- Test evidence retention, malicious instructions, redaction, stale references, workspace isolation, changed ignores, pagination, reconnects, and CLI follow-up reads.
- Run complete Node/Python suites, lint/static checks, package lifecycle tests, dependency/license/secret scans, and public CI. Live acceptance must prove retrieval, cache reuse, exact reads, native usage capture, and verified task attribution.

## Acceptance and Boundaries

- Every confirmed defect has a regression test; no known high-severity integrity finding remains unresolved.
- Every recognized eligible broad retrieval in acceptance tests uses the protected path or records an explicit native exception. Unclassified paths remain visible.
- Native usage reconciles with verified local counters for completed acceptance intervals; missing measurements never become zeros.
- All annotated necessary evidence remains accessible, with explicit omissions and complete recovery paths.
- Preserve the existing overlapping $10 ceilings, one concurrent Jev request, no daily request-count cap, and no quota retries or provider switching.
- Do not restart the interrupted native benchmark campaign. A new capped comparison requires separate authorization; ordinary-work observations alone do not establish causal savings.
- Cyber-Team services, business logic, Google credentials, billing, and local inference remain untouched. Mac-local execution remains unverified until tested separately.
- Completion establishes a correctly integrated, tested, observable system. Significant quota or speed improvement is claimed only when measurements support it; negative or inconclusive results are reported plainly.
