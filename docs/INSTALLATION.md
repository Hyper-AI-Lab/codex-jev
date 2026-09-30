# Installation

## Choose the execution host

Install on the Linux host that runs Codex and has the project files. A macOS app
connected to that host does not imply a second Mac installation is required.
For Mac-local projects the code has portable paths, but this release does not
claim a tested Mac-local deployment. Native `fcntl`/process behavior means Windows
is not currently supported; use a Linux environment instead.

Use Node 22.13+ (CI pins a tested version), Python 3.11+, Git and ripgrep on PATH.
Run `node --version`, `python3 --version`, `git --version`, and `rg --version`.
The source checkout and development dependencies are required for source-mode
MCP or development/evaluation scripts. The default bundled `dist` MCP and Python
installer work from the release tarball without npm runtime dependencies.

Follow the README commands. The workspace argument is an existing Git worktree,
not your home or filesystem root. Install once per Codex home; repeat the same
install command with another workspace to authorize it. Trusted startup hooks
also register the workspace from the native session. Authorization is local,
and each MCP connection remains bound to its current workspace.

### Files and ownership

- `~/.codex/config.toml`: owned `mcp_servers.jev_context` registration.
- `~/.codex/AGENTS.md`: owned retrieval/recovery guidance block.
- `~/.codex/hooks.json`: owned lifecycle handlers, requiring native trust.
- `~/.codex/jev-context/`: private config, key, accounting and recovery state.

`--codex-home` overrides these paths. The installer does not read authentication
files, force a coding model, set reasoning effort, manufacture hook trust, or
start a telemetry service. Keep the install directory and interpreter paths
stable; use the installer to change versions, not a move of installed files.

## Verify local-only operation

```bash
python3 runtime/manage.py status --codex-home "${CODEX_HOME:-$HOME/.codex}"
node scripts/retrieval-trial.mjs report
```

For Node commands use the same `CODEX_HOME` environment variable if not default.
`JEV_CONTEXT_HOME` is an advanced override and must match its `jev-context`
subdirectory. A long JSON status is normal. Check `halted`, installed paths and
configuration; do not paste full private status or configuration into public issues.
Use the actual Codex `evidence_status` tool to verify the loaded build. Disk state
alone does not establish that a still-running MCP process reloaded.

## Optional paid Jev ranking

Hosted Jev processes selected evidence under its own retention and billing
terms. Review [TypeSafe models](https://docs.typesafe.ai/models) and
[privacy](https://typesafe.ai/legal/privacy-policy) first. Local accounting uses
the pinned model's published rate, not a provider invoice; pricing changes need
review. Never infer that a timed-out request was free.

1. Open the installer-created private file
   `~/.codex/jev-context/secrets/typesafe_api_key` in a local editor. Put only the
   API token there, no quotes, variable assignment or `Bearer` prefix. Never put
   it in chat, command arguments, Git, application `.env` files or issue reports.
2. Open `~/.codex/jev-context/config.json` locally. Keep its existing fields and
   set `validation_budget_usd`, `monthly_budget_usd`, and `total_budget_usd` to
   your authorized positive USD ceilings. Set `enabled: true` for validation.
   Ordinary paid selection is still blocked without retention proof/authorization.
3. Keep `max_requests_per_day` as a positive integer, or deliberately set it to
   `null` for no daily count cap. Enabling persistent selection never changes it.
   Spending ceilings still apply; total and validation caps do not reset monthly.
4. Confirm both private files are mode 0600 and directories 0700. The installer
   creates safe permissions; do not weaken them when editing.
5. Run the explicitly paid **synthetic retention check** below. It uses up to
   four Jev selections plus local checks, no native Codex comparison runs:

```bash
node scripts/evaluation-preflight.mjs --live --acknowledge-cost
```

Only after `retention_passed`, opt into persistent paid ranking:

```bash
node scripts/retrieval-trial.mjs enable-default --acknowledge-cost
node scripts/retrieval-trial.mjs report
```

This validation proves the fixed fixtures retain necessary evidence, not general
task savings. Keep `live_validated` false: it is an effectiveness status, not a
shortcut around validation. No key rotation or automatic retry follows quota
failure. To return to local-only selection without deleting accounting:

```bash
node scripts/retrieval-trial.mjs stop
```

## Optional numeric telemetry

Recovery and MCP work without the telemetry daemon. For supported clients,
`runtime/manage.py observer-install` can install the local loopback collector;
inspect `--help` and its proposed configuration first. This separately changes
the owned OpenTelemetry configuration and service definition. Prompt logging
is disabled; only allowlisted numeric fields are retained. Never expose the
collector publicly. Native token export is client-dependent and may remain
unobserved. `metrics-report` prints coverage honestly.

## Troubleshooting

| State | Action |
| --- | --- |
| `workspace_denied` | Check the exact authorized root and MCP connection working directory |
| `local_only` | Expected before paid opt-in; no key is required |
| `key_missing` / invalid key | Inspect the private key file locally; never share its value |
| `preflight_required` | Run the authorized retention check; do not forge a report |
| `budget_blocked` | Review count/spending caps and uncertain reservations; no automatic reset |
| `busy` | Inspect the live or crashed reservation using Recovery instructions |
| `halted` | Reconcile before an explicit terminal resume; do not delete halt state |
| Old `loadedBuild` | Reload/reconnect the execution host and check the actual MCP tool again |
| Hook awaiting review | Inspect the generated command in native Hooks UI and authorize there |

Managed Codex policy can override user settings. Client hooks do not cover every
tool path. See [official MCP configuration](https://learn.chatgpt.com/docs/extend/mcp)
and [hook coverage](https://learn.chatgpt.com/docs/hooks).
