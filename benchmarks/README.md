# Offline Fixtures and Regression Helpers

These synthetic fixtures deliberately contain application defects to test whether
retrieval and grading preserve the evidence needed to identify them. They are
not runtime integrations, real customer records or recommended application code.

Historical campaign mains are disabled. Their helper exports and frozen manifest
support offline regression tests only; historical model names and campaign caps
do not configure the MCP server or authorize inference. The copied manifest's
machine-specific executable path is replaced with a synthetic path.

The current explicitly gated comparison lives in `scripts/hardening-comparison.mjs`.
It is not an installation step, background job or CI command. Prior private
results and recovery records are intentionally not included.
