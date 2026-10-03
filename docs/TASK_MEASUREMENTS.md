# Task Measurements and Overhead

Use the actual native task identifier, not a title or a guessed session:

```bash
python3 runtime/manage.py task-report --task ACTUAL_SESSION_ID --format markdown
python3 runtime/manage.py task-report --task ACTUAL_SESSION_ID --format json
```

The read-only report separates native usage, hooks, checkpoints, routing decisions
and exact-receipt retrieval operations. Numeric measurements are grouped by
implementation revision and origin. Missing measurements mean unknown, not zero.
Thirty-day detail is bounded to 10,000 records; it is not guaranteed whole-task
coverage. Native cached input and reasoning output are subsets, not additional
tokens. Checkpoint, hook and retrieval durations overlap and cannot be summed as
end-to-end latency. Failed/denied routing attempts are observations, not completed
tool calls. CLI-declared task scope is not native receipt verification.

Provider tokens are recorded only for new Jev requests. Cache responses may carry
historical selection metadata but do not create additional billable token totals.
Local fallbacks are distinguished from intentionally small-result bypasses.
Conservative request reservations remain the accounting authority; the report
does not infer dollars or subscription-quota savings from evidence bytes.

`python3 benchmarks/hook-overhead.py` measures 12 counterbalanced, warmed offline
hook pairs on a fixed synthetic dirty Git tree. It compares full capture with
verified read handling. It uses no Codex inference or Jev requests and does not
claim whole-session speedups. Run it with the same Python and host conditions
when comparing releases.
