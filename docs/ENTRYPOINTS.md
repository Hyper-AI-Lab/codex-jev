# Supported Entrypoints

All maintained changes belong to this repository. Older private checkouts are
rollback evidence, not an alternate development target.

| Surface | Implementation | Protection / regression evidence |
| --- | --- | --- |
| MCP stdio | `src/mcp-server.mjs` -> `EvidenceService` | MCP, protected entrypoint, policy/store tests |
| Search/list/read CLI | `scripts/investigate.mjs` -> `EvidenceService` | Task-bound process continuity, source hashes and protected entrypoint tests |
| Live validation | `scripts/validate-hardened.mjs` | Shared service/caps; no automatic retry |
| Evaluation preflight | `scripts/evaluation-preflight.mjs` | Explicit manifest, shared service/caps, fixture scope |
| Native comparison | `scripts/hardening-comparison.mjs` | Explicit authorization, run cap, quota stop; not restarted |
| Legacy transport | `src/investigator.mjs` | Direct Jev transport throws; historical pure utilities remain |
| Installer / recovery | `runtime/manage.py`, `installer.py`, `recovery.py` | Offline Python and isolated package lifecycle tests |
| Numeric collector | `runtime/telemetry.py`, `measurements.py` | Telemetry/measurement tests; stable-response regression added before fix |

Source and dist share the service. Installer API and CLI now default to the
bundled `dist` entrypoint; mutable source installation is rejected. The manifest
covers Node/Python code, the bundled dependencies, policy, schema and dependency
lock. Runtime files are copied into a private content-addressed directory and
made read-only. See `IMMUTABLE_RELEASES.md`; implementation and actual desktop
activation remain separate items in the closure ledger.
