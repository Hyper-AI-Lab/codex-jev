# Advisory Evidence Judgments

`judge_evidence` classifies, checks or scores exact authorized source ranges.
It does not search for missing evidence, execute commands, certify a completed
task, approve changes or switch models. Keep deterministic verification native.

Supply `workspaceRoot`, `items` and either `kind`/`question`/`criteria` or `preset`.
Items are `{path,startLine,endLine,hash?}` or `{sessionId,evidenceId}` from this
connection. Paths are workspace-relative. Hashes and exclusions are revalidated
before dispatch and disclosure. Results contain exact references, not raw source.

- `check`: one concrete `question`; optional `criteria` with `true`/`false` descriptions.
- `classification`: `question` and 2-20 label/description entries in `criteria`.
  Include an uncertain/no-match label where appropriate.
- `score`: `question` and 2-10 ordered descriptions in `criteria`.
- Preset `diagnostic_triage`: failure, constraint, informational, uncertain.
- Preset `completion_claim`: requires the individual claim as `question`.

Question text is limited to 1,000 characters; each criterion to 512. One call
accepts 1-20 items, each up to 200 lines and 8 KiB after redaction. The integration
packs one page within the 48-KiB request and bounded response budgets. If
`nextOffset` is present, repeat the same batch with that `offset`; nothing is
automatically dispatched. A single oversized range must be narrowed explicitly.
`remainingCount` counts inputs after this page; `unevaluatedCount` includes items
not judged by this call. A local-only or failed provider path returns no invented
judgments. Missing evidence is not a negative finding.

Results preserve yes probabilities or complete choice/score distributions and
confidence. These are model outputs, not measured correctness. Only a validated
typed answer is accepted. Source text is untrusted; no answer can acquire authority.

The CLI uses an eligible workspace JSON specification, not raw text passthrough:

```sh
codex-jev judge --spec review-claims.json --jev --allow-network
```

```json
{
  "preset": "completion_claim",
  "question": "This test checks rejection of expired sessions.",
  "items": [{"path": "tests/auth.test.mjs", "startLine": 10, "endLine": 30}]
}
```

Flags cannot enable billing. Existing protected keys, approved caps, one concurrent
request and quota halts apply. A quota failure is a stop condition, never a retry.
`--local` returns unavailable rather than pretending to classify. References
created by separate CLI calls additionally need the same registered `--task`.

Cache identity includes capability/policy, workspace, privacy settings, source
hashes, exact ranges and sanitized questions. Cache hits incur no provider usage.
Numeric `judgment-*` cohorts and `judge_evidence` invocation receipts are separate
from retrieval, validation and native Codex tokens. No text enters usage ledgers.
