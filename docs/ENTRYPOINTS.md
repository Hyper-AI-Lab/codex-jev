# Supported Entrypoints

All maintained changes belong to this repository. Older private checkouts are
rollback evidence, not an alternate development target.

| Surface | Implementation | Protection / regression evidence |
| --- | --- | --- |
| MCP stdio | `src/mcp-server.mjs` -> `EvidenceService` | MCP, protected entrypoint, policy/store tests |
| Search CLI | `scripts/investigate.mjs` -> `EvidenceService` | Protected entrypoint tests; follow-up persistence pending step 6 |
| Live validation | `scripts/validate-hardened.mjs` | Shared service/caps; no automatic retry |
| Evaluation preflight | `scripts/evaluation-preflight.mjs` | Explicit manifest, shared service/caps, fixture scope |
| Native comparison | `scripts/hardening-comparison.mjs` | Explicit authorization, run cap, quota stop; not restarted |
| Legacy transport | `src/investigator.mjs` | Direct Jev transport throws; historical pure utilities remain |
| Installer / recovery | `runtime/manage.py`, `installer.py`, `recovery.py` | Offline Python and isolated package lifecycle tests |
| Numeric collector | `runtime/telemetry.py`, `measurements.py` | Telemetry/measurement tests; stable-response regression added before fix |

The source and dist surfaces share the same service. The baseline installer API
and CLI choose different entrypoint defaults, and both still execute mutable
checkout paths. Step 9 will resolve both as one immutable-release change, with
dedicated installer regressions before the fix. Preview-first changes belong to
step 7; persistent CLI receipts belong to step 6. Do not hide incomplete steps
with skipped tests or claims that existing baseline suites cover new behavior.
