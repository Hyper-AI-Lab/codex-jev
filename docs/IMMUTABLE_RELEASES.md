# Verified Release Installation

`npm run build` creates bundles, a dependency-lock copy and
`release-manifest.json`. Installation verifies every declared component before
copying it to `$CODEX_HOME/jev-context/releases/<manifest-sha256>/`. The release
contains no keys, accounting, task state, application files or mutable settings.
Files are read-only; source edits cannot change a deployed release. Both the MCP
startup and installed Python entrypoint check integrity. Hashes detect changes;
they are not publisher signatures or protection against an owner-level attacker.

The API and CLI default to `dist`. Installing a mutable source entrypoint is no
longer supported. Node 22.13+ and Python 3.11+ remain external prerequisites.
The release manifest covers locked bundled dependencies, not the host executables.

```bash
python3 runtime/manage.py doctor --codex-home "${CODEX_HOME:-$HOME/.codex}"
```

Doctor is local and read-only. It distinguishes configuration, owned fragments,
integrity and observed callbacks. It does not grant hook trust, make live calls,
or infer the desktop's loaded release. Verify `loadedRelease.id` using the actual
connected `evidence_status`, not a separately launched test process. Historical
successful provider requests are access evidence, not current-key or effectiveness
proof. Configuration changes may require reconnect and native hook review.

Owner edits normally block installation. An audited guidance-only migration can
use `install --preserve-guidance-edits` with the normal install arguments. It
preserves the owner's current guidance and only replaces the one previously owned
recovery-helper path. Duplicate markers or ambiguous paths still fail. Other
configuration and native worker policies are never adopted or overwritten.

Keep the previous release/checkout. Roll back by running that version's installer
with the same Codex home, node and workspace. Never reset accounting or recovery
state. Reload and verify the loaded release; revised hooks require native trust.
The observer has its own ownership record and must be stopped before changing its
definition. Reinstall the observer through the selected release's runtime, then
restart only that service and verify its lock/status.

At most eight release directories (including interrupted staging directories) are
accepted. No release is silently pruned: review running processes and rollback
needs before removing an unused version. Uninstall retains releases and private
state. Linux package lifecycle tests cover install, upgrade, interruption,
rollback and uninstall; actual Mac-local execution remains unverified.
