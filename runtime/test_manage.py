import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from installer import MANAGE
from manage import hook
from recovery import Guard, halt
from test_support import RuntimeCase


class ManageTests(RuntimeCase):
    def test_broad_retrieval_redirect_has_no_rewrite_and_preserves_native_commands(self):
        hook(self.home, self.payload("SessionStart"))
        self.state("config.json", {"enabled": True, "allowed_roots": [str(self.root)]})
        payload = self.payload()
        payload["tool_input"]["cmd"] = 'rg "broad discovery" .'
        response = hook(self.home, payload)
        self.denied(response)
        self.assertIn("search_workspace_evidence", json.dumps(response))
        self.assertNotIn("updatedInput", json.dumps(response))
        for command in ('rg source_hash .', 'cat source.txt', 'npm test', 'git diff', 'rg pattern . | head'):
            payload["tool_input"]["cmd"] = command
            self.assertEqual(hook(self.home, payload), {})
        callbacks = self.read_state("callbacks.json")["events"]
        self.assertTrue(any(e["result"] == "unclassified:unsupported_shell" for e in callbacks))
        self.assertNotIn("broad discovery", json.dumps(callbacks))

    def test_owner_native_exception_is_exact_and_expiring(self):
        from common import sha
        from time import time

        hook(self.home, self.payload("SessionStart"))
        self.state("config.json", {"enabled": True})
        payload = self.payload()
        payload["tool_input"]["cmd"] = 'rg pattern .'
        entry = {"digest": sha((str(self.root) + "\nrg pattern .").encode()),
                 "expires_at": time() + 300, "reason": "owner_requested"}
        self.state("retrieval-policy.json", {"native_exceptions": [entry]})
        self.assertEqual(hook(self.home, payload), {})
        payload["tool_input"]["cmd"] = 'rg different .'
        self.denied(hook(self.home, payload))
        payload["tool_input"]["cmd"] = 'rg pattern .'
        entry["expires_at"] = time() - 1
        self.state("retrieval-policy.json", {"native_exceptions": [entry]})
        self.denied(hook(self.home, payload))

    def test_routing_failure_does_not_weaken_quota_or_recovery(self):
        hook(self.home, self.payload("SessionStart"))
        with patch("retrieval.routing_decision", side_effect=ValueError("private synthetic")):
            self.assertEqual(hook(self.home, self.payload()), {})
            halt(self.home, "codex", "test_limit")
            self.denied(hook(self.home, self.payload()))

    def test_concurrent_hook_processes_preserve_a_verifiable_checkpoint(self):
        hook(self.home, self.payload("SessionStart"))
        self.write("source.txt", "dirty state remains local\n")

        def invoke(_):
            return self.cli(["hook"], json.dumps(self.payload()).encode())

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(invoke, range(2)))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("deny", result.stdout.decode())
        guard = Guard(self.home, self.root, "session-one")
        self.assertTrue(guard.status()["latest"]["snapshot"])
        self.assertEqual((self.root / "source.txt").read_text(), "dirty state remains local\n")

    def test_known_evidence_read_verifies_without_capture_unknown_tools_capture(self):
        hook(self.home, self.payload("SessionStart"))
        payload = self.payload()
        payload["tool_name"] = "mcp__jev_context__read_selected_evidence"
        with patch.object(Guard, "collect", side_effect=AssertionError("read should not capture")):
            self.assertEqual(hook(self.home, payload), {})
        payload["tool_name"] = "untrusted__read_file"
        with patch.object(Guard, "checkpoint") as capture:
            hook(self.home, payload)
            capture.assert_called_once()

    def test_lightweight_read_still_blocks_corrupt_checkpoint(self):
        hook(self.home, self.payload("SessionStart"))
        guard = Guard(self.home, self.root, "session-one")
        snapshot = guard.status()["latest"]["snapshot"]
        (guard.snapshots / snapshot / "staged.patch").write_bytes(b"corrupt")
        payload = self.payload()
        payload["tool_name"] = "mcp__jev_context__evidence_status"
        self.denied(hook(self.home, payload))

    def test_verified_hook_creates_receipt_but_halted_hook_does_not(self):
        from invocations import database

        hook(self.home, self.payload("SessionStart"))
        payload = {**self.payload(), "tool_name": "mcp__jev_context__search_workspace_evidence",
                   "turn_id": "turn", "tool_use_id": "call-one",
                   "tool_input": {"workspaceRoot": str(self.root), "query": "evidence"}}
        self.assertEqual(hook(self.home, payload), {})
        with database(self.home) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM invocation_receipts").fetchone()[0], 1)
        halt(self.home, "codex", "test_limit")
        payload["tool_use_id"] = "call-two"
        self.denied(hook(self.home, payload))
        with database(self.home) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM invocation_receipts").fetchone()[0], 1)

    def test_invocation_measurement_failure_does_not_weaken_recovery_or_deny_read(self):
        hook(self.home, self.payload("SessionStart"))
        payload = {**self.payload(), "tool_name": "mcp__jev_context__evidence_status"}
        with patch("invocations.pre_tool", side_effect=OSError("synthetic ledger failure")):
            self.assertEqual(hook(self.home, payload), {})

    def test_session_end_releases_registries_and_preserves_history(self):
        hook(self.home, self.payload("SessionStart"))
        guard = Guard(self.home, self.root, "session-one")
        before = guard.status()["latest"]["snapshot"]
        self.assertEqual(hook(self.home, self.payload("SessionEnd")), {})
        self.assertTrue((guard.snapshots / before / "manifest.json").is_file())
        self.assertEqual(self.read_state("active-tasks.json")["tasks"], {})
        self.assertEqual(self.home.registry()["sessions"], {})
        self.assertTrue((guard.runtime / "closed.json").is_file())

    def test_session_end_collects_usage_before_revoking_history_registration(self):
        history = self.home.codex / "sessions" / "rollout-offline.jsonl"
        history.parent.mkdir()
        history.write_text(json.dumps({"type": "session_meta", "payload": {
            "id": "session-one", "cwd": str(self.root), "cli_version": "0.157.1"}}) + "\n")
        start = {**self.payload("SessionStart"), "transcript_path": str(history)}
        with patch("history_usage.installed_version", return_value="0.157.1"):
            hook(self.home, start)
        with history.open("a") as stream:
            stream.write(json.dumps({"type": "token_usage_record", "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {"thread_id": "session-one", "turn_id": "turn", "response_id": "last-response", "usage": {
                    "input_tokens": 100, "cached_input_tokens": 80, "output_tokens": 10, "reasoning_output_tokens": 2}}}) + "\n")
        hook(self.home, {**start, "hook_event_name": "SessionEnd"})
        from measurements import report

        self.assertTrue(report(self.home)["nativeTokensMeasured"])
        self.assertEqual(self.home.registry()["sessions"], {})

    def payload(self, event="PreToolUse"):
        return {
            "hook_event_name": event,
            "session_id": "session-one",
            "cwd": str(self.root),
            "tool_name": "exec_command",
            "tool_input": {"cmd": "echo test"},
        }

    def denied(self, result):
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def cli(self, command, data=None):
        return subprocess.run(
            [
                sys.executable,
                str(MANAGE),
                *command,
                "--codex-home",
                str(self.home.codex),
            ],
            input=data,
            capture_output=True,
            timeout=20,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_pretool_errors_deny_closed(self):
        for method in ("ensure", "halted", "log_callback"):
            with (
                self.subTest(method=method),
                patch.object(self.home, method, side_effect=ValueError("synthetic")),
            ):
                self.denied(hook(self.home, self.payload()))
        with patch("manage.Guard", side_effect=ValueError("synthetic")):
            self.denied(hook(self.home, self.payload()))
        payload = self.payload()
        payload.pop("cwd")
        self.denied(hook(self.home, payload))

    def test_halt_denies_all_except_exact_readonly_status(self):
        halt(self.home, "codex", "test_limit")
        self.denied(hook(self.home, self.payload()))
        payload = self.payload()
        command = shlex.join(
            [
                str(Path(sys.executable).resolve()),
                str(MANAGE),
                "status",
                "--codex-home",
                str(self.home.codex),
            ]
        )
        payload["tool_input"]["cmd"] = command
        self.assertEqual(hook(self.home, payload), {})
        for suffix in ("; echo escaped", " && true", " --workspace /tmp", "\ntrue"):
            payload["tool_input"]["cmd"] = command + suffix
            self.denied(hook(self.home, payload))
        self.state("halt.json", {})
        self.denied(hook(self.home, self.payload()))

    def test_cli_malformed_payload_blocks_with_exit_two(self):
        for data in (b"{bad", b"[]", b"x" * (1024 * 1024 + 1)):
            result = self.cli(["hook"], data)
            self.assertEqual(result.returncode, 2)
            self.denied(json.loads(result.stdout))
            self.assertNotIn(data[:20], result.stderr)

    def test_session_start_reconciles_without_overwriting_previous(self):
        result = hook(self.home, self.payload("SessionStart"))
        self.assertIn("additionalContext", result["hookSpecificOutput"])
        guard = Guard(self.home, self.root, "session-one")
        before = (guard.runtime / "latest.json").read_bytes()
        self.write("source.txt", "changed after checkpoint\n")
        hook(self.home, self.payload("SessionStart"))
        self.assertEqual((guard.runtime / "latest.json").read_bytes(), before)
        self.assertIn(str(self.root), self.home.registry()["roots"])

    def test_cli_checkpoint_status_halt_resume_and_preexisting_node_marker(self):
        result = self.cli(
            ["checkpoint", "--workspace", str(self.root), "--task", "cli-task"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.state(
            "halt.json",
            {"provider": "typesafe", "reason": "quota_exhausted", "at": "synthetic"},
        )
        marker = (self.home.path / "halt.json").read_bytes()
        result = self.cli(["halt", "--provider", "typesafe"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["tasks"][0]["checkpointed"])
        self.assertEqual((self.home.path / "halt.json").read_bytes(), marker)
        self.assertEqual(self.cli(["resume"]).returncode, 1)
        self.assertEqual(
            self.cli(
                ["status", "--workspace", str(self.root), "--task", "cli-task"]
            ).returncode,
            0,
        )
        self.assertEqual(self.cli(["resume", "--acknowledge"]).returncode, 0)

    def test_hooks_do_not_save_tool_inputs_or_prompts(self):
        payload = self.payload()
        payload["tool_input"]["cmd"] = "PRIVATE-SYNTHETIC-TOOL-CANARY"
        payload["prompt"] = "PRIVATE-SYNTHETIC-PROMPT-CANARY"
        hook(self.home, payload)
        for file in self.home.path.rglob("*"):
            if file.is_file():
                self.assertNotIn(b"PRIVATE-SYNTHETIC", file.read_bytes())

    def test_non_git_directory_does_not_disable_unrelated_native_work(self):
        root = self.root.parent / "new-project"
        root.mkdir()
        payload = self.payload()
        payload["cwd"] = str(root)
        result = hook(self.home, payload)
        self.assertNotIn("hookSpecificOutput", result)
        self.assertIn("unavailable", result["systemMessage"])
        halt(self.home, "codex", "test_limit")
        self.denied(hook(self.home, payload))

    def test_stop_failure_never_requests_automatic_continuation(self):
        for event in (
            "Stop",
            "SubagentStop",
            "SessionStart",
            "PostToolUse",
            "PreCompact",
            "PostCompact",
        ):
            with patch.object(self.home, "ensure", side_effect=OSError("disk full")):
                value = hook(self.home, self.payload(event))
            self.assertIs(value["continue"], False)
            self.assertNotIn("decision", value)

    def test_prompt_and_worker_boundaries_do_not_persist_prompt_or_transcript(self):
        for event in ("UserPromptSubmit", "SubagentStop"):
            payload = self.payload(event)
            payload.update(
                prompt="PROMPT-CANARY",
                last_assistant_message="ASSISTANT-CANARY",
                agent_transcript_path="/unreadable",
            )
            hook(self.home, payload)
        for path in self.home.path.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"CANARY", path.read_bytes())
