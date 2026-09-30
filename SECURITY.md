# Security Policy

## Supported release

The latest `0.4.x` beta receives security fixes. This tool handles potentially
sensitive local source code; use it only within your organization's data policy.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/Hyper-AI-Lab/codex-jev/security/advisories/new).
Do not open a public issue containing keys, source from a private project,
conversation logs, authorization headers or recovery artifacts. Provide a minimal
synthetic reproduction, affected version and sanitized environment details.
No response-time SLA or bug bounty is promised.

## Threat model and limitations

The adapter defends against accidental cross-workspace reads, common credential
disclosure, stale evidence, misleading omissions, duplicate spending and unsafe
recovery. It does not defend against a compromised host or an attacker with the
same user's filesystem privileges. Private state/configuration is owner-controlled,
not a tamper-proof boundary against that owner.

Regex redaction cannot detect every secret or confidential fact. Selected sanitized
excerpts, queries and requirements may be sent to TypeSafe only after opt-in.
Never authorize hosted selection when third-party processing is forbidden.
Provider retention and invoices remain outside this tool's control.

Recovery diffs and eligible untracked artifacts can still contain proprietary
source. Keep the private Codex state directory outside Git and backups with public
access. Do not attach it to reports. Uninstall preserves this state and the key;
review and delete manually only after accounting/recovery needs are resolved.

Hooks are partial enforcement. Tool aliases, direct terminal commands, already
running jobs and hard failures may not be intercepted. They never substitute
for Codex sandbox permissions, native approvals, least-privilege OS access or
independent review of external side effects.

Dependencies are locked and releases include attribution. CI does not need a
TypeSafe or OpenAI key, and should never be given one. Fork pull requests run
unprivileged tests; no `pull_request_target` workflow is used.
