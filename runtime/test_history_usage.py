"""Synthetic histories only. No user prompts or real Codex home in tests."""

import json
import os
import time
from datetime import datetime, timezone
from unittest.mock import patch

from common import encoded
from history_usage import collect_history, observe_hook, register_history
from measurements import record, report
from test_support import RuntimeCase


class HistoryUsageTests(RuntimeCase):
    def setUp(self):
        super().setUp()
        self.home.register(self.root, "session-one")
        self.folder = self.home.codex / "sessions" / "2026" / "10" / "02"
        self.folder.mkdir(parents=True)
        self.path = self.folder / "rollout-fixture.jsonl"
        self.lines = [dict(type="session_meta", payload={"id": "session-one", "cwd": str(self.root),
                      "cli_version": "0.157.1", "base_instructions": "NEVER-STORE-CONTENT"})]
        self.flush()

    def flush(self):
        self.path.write_bytes(b"".join(json.dumps(line).encode() + b"\n" for line in self.lines))

    def response(self, identity="response-one", amount=100):
        return dict(type="token_usage_record", timestamp=datetime.now(timezone.utc).isoformat(),
                    payload={"thread_id": "session-one", "turn_id": "turn-one", "response_id": identity,
                             "usage": {"input_tokens": amount, "cached_input_tokens": 40,
                                       "output_tokens": 10, "reasoning_output_tokens": 3}})

    def register(self, **kwargs):
        return register_history(self.home, self.path, "session-one", client_version="0.157.1", **kwargs)

    def collect(self):
        return collect_history(self.home, self.path, "session-one")

    def tokens(self):
        return sum(r["value"] for r in report(self.home)["groups"] if r["metric"] == "input_tokens")

    def test_incremental_response_usage_replay_and_numeric_privacy(self):
        self.register()
        self.lines += [self.response(), self.response(), dict(type="response_item", payload={"text": "NEVER-STORE-CONTENT"})]
        self.flush()
        self.assertEqual(self.collect()["recorded"], 1)
        self.assertEqual(self.collect()["recorded"], 0)
        self.assertEqual(self.tokens(), 100)
        for path in self.home.path.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"NEVER-STORE-CONTENT", path.read_bytes())

    def test_registration_does_not_import_historical_costs(self):
        self.lines.append(self.response("historical"))
        self.flush()
        self.register()
        self.assertEqual(self.collect()["recorded"], 0)
        self.assertEqual(self.tokens(), 0)
        self.lines.append(self.response("new"))
        self.flush()
        self.assertEqual(self.collect()["recorded"], 1)

    def test_partial_line_waits_then_records_once(self):
        self.register()
        data = json.dumps(self.response()).encode()
        with self.path.open("ab") as stream:
            stream.write(data[:35])
        self.assertEqual(self.collect()["state"], "partial_record")
        with self.path.open("ab") as stream:
            stream.write(data[35:] + b"\n")
        self.assertEqual(self.collect()["recorded"], 1)

    def test_unregistered_wrong_session_and_unknown_version_are_rejected(self):
        with self.assertRaises(ValueError):
            self.collect()
        with self.assertRaises(ValueError):
            register_history(self.home, self.path, "other", client_version="0.157.1")
        with self.assertRaises(ValueError):
            register_history(self.home, self.path, "session-one", client_version="9.0.0")
        self.lines[0]["payload"]["cwd"] = "/unapproved"
        self.flush()
        with self.assertRaises(ValueError):
            self.register()

    def test_symlink_hardlink_and_outside_histories_rejected(self):
        alias = self.folder / "rollout-link.jsonl"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            register_history(self.home, alias, "session-one", client_version="0.157.1")
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.register()

    def test_changed_prefix_truncation_and_rotation_require_reconciliation(self):
        self.register()
        self.path.write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            self.collect()
        self.flush()
        self.path.rename(self.folder / "old.jsonl")
        self.flush()
        with self.assertRaises(ValueError):
            self.collect()

    def test_transcript_and_otlp_never_sum_for_same_session(self):
        self.register()
        self.lines.append(self.response())
        self.flush()
        self.collect()
        self.assertFalse(record(self.home, kind="native_usage", session="session-one",
                                values={"input_tokens": 100}, event_id="otlp-one", observed_at=time.time()))
        self.assertEqual(self.tokens(), 100)

    def test_existing_otlp_is_not_duplicated_by_fallback(self):
        record(self.home, kind="native_usage", session="session-one", event_id="otlp-first", values={"input_tokens": 90})
        self.register()
        self.lines.append(self.response())
        self.flush()
        self.assertEqual(self.collect()["recorded"], 0)
        self.assertEqual(self.tokens(), 90)

    def test_legacy_counters_baseline_reset_duplicate_and_compaction(self):
        self.lines[0]["payload"]["cli_version"] = "0.156.1"
        self.flush()
        register_history(self.home, self.path, "session-one", client_version="0.156.1")

        def counter(amount):
            return dict(type="event_msg", timestamp=datetime.now(timezone.utc).isoformat(), payload={
                "type": "token_count", "info": {"total_token_usage": {
                    "input_tokens": amount, "cached_input_tokens": 0, "output_tokens": 0,
                    "reasoning_output_tokens": 0}}})

        self.lines += [counter(1000), counter(1100), counter(1100), dict(type="compacted", payload={}),
                       counter(10), counter(30)]
        self.flush()
        result = self.collect()
        self.assertEqual(result["recorded"], 2)
        self.assertEqual(result["counter_resets"], 1)
        self.assertEqual(self.tokens(), 120)

    def test_oversized_or_malformed_record_is_visible_not_silently_complete(self):
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b"not-json\n")
        result = self.collect()
        self.assertEqual(result["invalid_records"], 1)
        self.assertEqual(result["state"], "incomplete")

    def test_registry_corruption_never_replaces_original_state(self):
        self.register()
        state = self.home.path / "usage-histories.json"
        state.write_bytes(encoded({"version": 100}))
        before = state.read_bytes()
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(state.read_bytes(), before)

    def test_cursor_write_failure_can_retry_without_duplicate_usage(self):
        self.register()
        self.lines.append(self.response())
        self.flush()
        with patch("history_usage.atomic_write", side_effect=OSError("synthetic disk full")):
            with self.assertRaises(OSError):
                self.collect()
        self.assertEqual(self.tokens(), 100)
        self.assertEqual(self.collect()["recorded"], 0)
        self.assertEqual(self.tokens(), 100)

    def test_resumed_segment_response_identity_deduplicates_across_files(self):
        self.register()
        other = self.folder / "rollout-resumed.jsonl"
        other.write_bytes(self.path.read_bytes())
        register_history(self.home, other, "session-one", client_version="0.157.1")
        self.lines.append(self.response())
        self.flush()
        other.write_bytes(self.path.read_bytes())
        self.assertEqual(self.collect()["recorded"], 1)
        self.assertEqual(collect_history(self.home, other, "session-one")["recorded"], 0)
        self.assertEqual(self.tokens(), 100)

    def test_oversize_budget_does_not_advance_into_unread_record(self):
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b"x" * 2049 + b"\n")
        with patch("history_usage.MAX_LINE", 2048):
            self.assertEqual(self.collect()["state"], "oversized_record")

    def test_parent_directory_symlink_swap_is_rejected(self):
        self.register()
        moved = self.folder.with_name("moved")
        self.folder.rename(moved)
        self.folder.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.collect()

    def test_hook_registers_once_then_collects_without_reprobing_client(self):
        payload = dict(hook_event_name="SessionStart", session_id="session-one", transcript_path=str(self.path))
        with patch("history_usage.installed_version", return_value="0.157.1") as version:
            self.assertEqual(observe_hook(self.home, payload)["state"], "registered")
            self.lines.append(self.response())
            self.flush()
            payload["hook_event_name"] = "PostToolUse"
            self.assertEqual(observe_hook(self.home, payload)["recorded"], 1)
            version.assert_called_once()

    def test_worker_parent_ids_are_not_misattributed_or_implicitly_registered(self):
        with patch("history_usage.installed_version") as version:
            result = observe_hook(self.home, dict(hook_event_name="SubagentStop", session_id="session-one",
                                                 agent_transcript_path=str(self.path)))
        version.assert_not_called()
        self.assertEqual(result["state"], "not_a_collection_boundary")
