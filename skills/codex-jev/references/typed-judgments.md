# Typed Judgment Inputs

Call `judge_evidence` with `workspaceRoot`, 1-20 `items` and a single operation.
Each item is `{path,startLine,endLine,hash?}` or `{sessionId,evidenceId}` from the
current connection. Paths are relative. Use exact source evidence, not a summary
of what you hope it says. Each range is at most 200 lines / 8 KiB sanitized text.

`kind: check` asks one concrete `question`. Optional `criteria` describes `true`
and `false`. The answer is a probability of yes, not separate confidence.

`kind: classification` uses `question` and `criteria: {label: description, ...}`
with 2-20 labels. Include an uncertain/no-match label when needed. It returns
the chosen label, every label's probability and distribution confidence.

`kind: score` uses `question` and `criteria: [low-description, ..., high-description]`
with 2-10 levels. Describe observable situations, not vague numbers. The result
is probability-weighted across levels; it need not be an integer.

Alternatively use `preset: diagnostic_triage` (question optional) or
`preset: completion_claim` (the individual claim is the required question).
Presets cannot be combined with `kind` or custom `criteria`.

Questions are limited to 1,000 characters and criterion descriptions to 512.
`nextOffset` requires another explicit call with the same batch and that offset.
There is no automatic pagination or unlimited batching. Larger inputs must be
split explicitly; an oversized individual range must be narrowed. Model answers
do not certify completeness, correctness, approval or executed test outcomes.
Missing key, disabled authorization or service failure yields no fabricated
local judgment. A quota halt is not a fallback opportunity.

MCP is preferred. The equivalent `codex-jev judge --spec relative-spec.json`
loads a bounded eligible JSON specification locally through the same controls.
No `.env`, raw conversation, key, provider override or arbitrary HTTP input is
supported. Source references created in prior CLI calls need the registered task.
