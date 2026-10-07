# Recovery, Upgrade and Rollback

## Quota or interruption

On an identifiable quota failure, stop new work. Covered hooks and protected
retrieval paths honor a shared halt. A hard cutoff can prevent a final capture;
the last verified operation boundary is the recovery point, not an exact line
of model execution.

```bash
python3 runtime/manage.py status --codex-home "${CODEX_HOME:-$HOME/.codex}"
python3 runtime/manage.py recovery-verify \
  --workspace /absolute/path/to/project --task ACTUAL_SESSION_ID \
  --codex-home "${CODEX_HOME:-$HOME/.codex}"
```

Review the reconciliation report, current Git state, unfinished jobs and external
effects. Do not reapply saved patches or rerun deployments/emails because they
appear in a checkpoint. Corrupt snapshots must retain their evidence and halt.
Only after the owner acknowledges the reconciliation, run in an **owner terminal**:

```bash
python3 runtime/manage.py resume \
  --codex-home "${CODEX_HOME:-$HOME/.codex}" --acknowledge
```

The updated hook permits its exact absolute status command and exact resume
command with `--acknowledge` during a halt. Owner acknowledgment is still required;
the exception only lets the verified recovery procedure run, it does not clear the
halt itself. Other commands and compound shell syntax remain blocked. Older
installed hooks may still require an owner terminal. Never bypass trust or delete
`halt.json`. JSON output with no remaining halt indicates successful recovery, not
automatic replay of work.

Covered native `wait_agent` results also halt work when an identified worker has
a structured quota error or the observed native usage-limit error envelope.
Completed worker text, documents and arbitrary command output do not trigger this
detector. Unsolicited worker notifications without that supported hook envelope
remain uncovered: the coordinator must stop and record the halt explicitly.

Known bounded native reads and protected evidence reads verify the previous
checkpoint without recapturing unchanged files. Unknown commands retain full
capture. This avoids repeated Git work, not corruption checks or before/after
mutation boundaries.

## Uncertain Jev charges

```bash
node scripts/reservations.mjs status
node scripts/reservations.mjs reconcile REQUEST_ID --acknowledge-uncertain-charge
```

Inspect the request identity first. A running process cannot be released. Legacy
or unverifiable identities also need `--confirm-unidentified-process-stopped`
after independent inspection. Reconciliation retains the conservative charge;
it does not clear quota halts, retry a request or assert that a timeout was free.

## Upgrade and rollback

Keep the previous checkout at its existing path. Build a new pinned release in
a second stable directory and run its installer with the same Codex home and
workspace. The ownership journal updates only unchanged owned fragments and
rejects owner-edit conflicts. Reload Codex; inspect any changed hook definitions
in the native trust UI before authorizing them.

To roll back between skill-aware releases, run the previous checkout's installer
with the same arguments. For a release predating skill ownership, first use the
current installer to uninstall its owned integration and skill files, then run
the previous installer. Stop on owner-edit conflicts; never delete those files
manually or copy an old ownership journal over them.
Reload and verify `evidence_status`. This restores owned paths/configuration,
not accounting, keys, halts or recovery history. Do not reset the ledger.

The bounded history reader upgrades its cursor registry to version 2. Older
readers reject that registry. A code rollback therefore leaves history collection
unavailable until compatible code is restored; it must not rewind cursors or
reimport usage to manufacture compatibility. Keep the original evidence and
report that coverage gap. Existing read-only recovery history remains intact.

## Uninstall

```bash
python3 runtime/manage.py observer-uninstall --codex-home "${CODEX_HOME:-$HOME/.codex}"
python3 runtime/manage.py uninstall --codex-home "${CODEX_HOME:-$HOME/.codex}"
```

The observer command applies only if the optional collector was installed.
Uninstall removes owned unchanged configuration, guidance and hooks. Conflicting
owner edits are preserved and reported. **Private keys, accounting and recovery
artifacts remain on disk intentionally.** Review them locally and decide retention
separately; uninstall does not silently destroy recovery evidence or reset spend.
