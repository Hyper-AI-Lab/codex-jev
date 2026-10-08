# Preview-First Retrieval

Broad search and large-text retrieval now default to concise previews for
noncritical blocks. `detailLevel: "full"` (CLI `--detail full`) preserves explicit
full-detail requests. Preview results retain the original hash, evidence ID and
`sourceLines`, so `read_selected_evidence` can recover exactly what was omitted.
With only `sessionId` and `evidenceId`, a read returns that reference's original
range, not a 120-line context window. Explicit line bounds and `complete: true`
remain available under existing size/privacy limits. Retained, omitted and
unscored references use the same hash-verified read behavior.
Critical diagnostics, constraints, uncertainty and exception chains remain full
until the response budget requires an explicit reference with exact-read guidance.

The shortlist keeps query-related protected evidence first, then represents
different source kinds and paths before adding more ranges from one file. Rank
order is preserved within the chosen set. Remaining scanned ranges are unscored,
not erased, and can be paginated with `list_evidence`. Whitespace-only blocks do
not occupy slots. The existing 20-candidate, eight-result and 48-KiB request caps
are unchanged; scoring questions have not been retuned against held-out answers.

All scan, storage and pagination limits remain visible. If protected evidence
exceeds the shortlist or response bound, the overflow notice requires follow-up;
a preview never proves a fact absent. Skipped files may need a narrower search.
This reduces some result bytes, not the already-loaded conversation. Actual
speed, native usage and total follow-up overhead must be measured separately.
