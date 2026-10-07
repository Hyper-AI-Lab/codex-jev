"""Synthetic histories only. No user prompts or real Codex home in tests."""

import json
import os
import time
from datetime import datetime, timezone
from unittest.mock import patch

from common import encoded
from history_usage import MAX_LINE, collect_history, coverage, observe_hook, register_history
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

    def test_coverage_reports_numeric_gaps_without_paths_or_false_completeness(self):
        self.assertEqual(coverage(self.home, "session-one")["state"], "unregistered")
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b"x" * (MAX_LINE + 1) + b"\n")
        self.collect()
        summary = coverage(self.home, "session-one")
        self.assertEqual(summary["state"], "gaps_observed")
        self.assertEqual(summary["skippedRecords"], 1)
        self.assertFalse(summary["wholeTaskCoverageVerified"])
        self.assertNotIn(str(self.root), json.dumps(summary))
        self.assertEqual(coverage(self.home, "other-task")["state"], "unregistered")

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

    def test_current_client_registers_new_and_resumed_response_histories(self):
        for original_version in ("0.160.0", "0.157.1", "0.130.0"):
            with self.subTest(original_version=original_version):
                path = self.folder / f"rollout-origin-{original_version}.jsonl"
                head = dict(type="session_meta", payload={"id": "session-one", "cwd": str(self.root),
                            "cli_version": original_version})
                path.write_bytes(json.dumps(head).encode() + b"\n")
                registered = register_history(self.home, path, "session-one", client_version="0.160.0")
                self.assertEqual(registered["format"], "response_records")
                with path.open("ab") as stream:
                    stream.write(json.dumps(self.response(f"response-{original_version}")).encode() + b"\n")
                self.assertEqual(collect_history(self.home, path, "session-one")["recorded"], 1)
        self.assertEqual(self.tokens(), 300)

    def test_oversized_record_advances_without_hiding_coverage_gap(self):
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b'{"type":"response_item","payload":"' + b"x" * (MAX_LINE * 2) + b'"}\n')
            stream.write(json.dumps(self.response()).encode() + b"\n")
        result = self.collect()
        self.assertEqual(result["recorded"], 1)
        self.assertEqual(result["state"], "incomplete")
        self.assertEqual(result["skipped_records"], 1)
        self.assertGreater(result["skipped_bytes"], MAX_LINE * 2)
        self.assertFalse(result["discarding_oversized"])
        self.assertEqual(self.collect()["skipped_records"], 1)
        self.assertEqual(self.tokens(), 100)

    def test_oversized_partial_record_resumes_after_restart_with_bounded_scan(self):
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b"x" * (MAX_LINE * 3))
        with patch("history_usage.MAX_BATCH", MAX_LINE + 100):
            first = self.collect()
            self.assertLessEqual(first["scanned_bytes"], MAX_LINE + 100)
            self.assertTrue(first["discarding_oversized"])
            self.assertEqual(first["skipped_records"], 1)
            second = self.collect()
            self.assertLessEqual(second["scanned_bytes"], MAX_LINE + 100)
            self.assertEqual(second["skipped_records"], 1)
        waiting = self.collect()
        self.assertEqual(waiting["state"], "partial_oversized_record")
        with self.path.open("ab") as stream:
            stream.write(b"\n" + json.dumps(self.response()).encode() + b"\n")
        done = self.collect()
        self.assertEqual(done["recorded"], 1)
        self.assertEqual(done["skipped_records"], 1)
        self.assertFalse(done["discarding_oversized"])
        self.assertEqual(self.tokens(), 100)

    def test_v1_cursor_migrates_only_on_successful_collection(self):
        self.register()
        state = self.read_state("usage-histories.json")
        state["version"] = 1
        for cursor in state["histories"].values():
            for key in ("skipped_records", "skipped_bytes", "discarding_oversized"):
                cursor.pop(key, None)
        self.state("usage-histories.json", state)
        self.collect()
        migrated = self.read_state("usage-histories.json")
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(next(iter(migrated["histories"].values()))["skipped_records"], 0)

    def test_oversize_cursor_write_failure_and_truncation_preserve_truth(self):
        self.register()
        before = (self.home.path / "usage-histories.json").read_bytes()
        with self.path.open("ab") as stream:
            stream.write(b"x" * (MAX_LINE + 10) + b"\n" + json.dumps(self.response()).encode() + b"\n")
        with patch("history_usage.atomic_write", side_effect=OSError("synthetic disk full")):
            with self.assertRaises(OSError):
                self.collect()
        self.assertEqual((self.home.path / "usage-histories.json").read_bytes(), before)
        self.assertEqual(self.collect()["skipped_records"], 1)
        self.assertEqual(self.tokens(), 100)
        cursor_before = (self.home.path / "usage-histories.json").read_bytes()
        self.path.write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual((self.home.path / "usage-histories.json").read_bytes(), cursor_before)

    def test_invalid_discard_state_is_not_replaced(self):
        self.register()
        state = self.read_state("usage-histories.json")
        cursor = next(iter(state["histories"].values()))
        cursor["discarding_oversized"] = "true"
        self.state("usage-histories.json", state)
        before = (self.home.path / "usage-histories.json").read_bytes()
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual((self.home.path / "usage-histories.json").read_bytes(), before)

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

    def test_oversize_budget_discards_only_the_complete_oversized_record(self):
        self.register()
        with self.path.open("ab") as stream:
            stream.write(b"x" * 2049 + b"\n")
        with patch("history_usage.MAX_LINE", 2048):
            result = self.collect()
            self.assertEqual(result["state"], "incomplete")
            self.assertEqual(result["skipped_records"], 1)
            self.assertEqual(result["skipped_bytes"], 2050)

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
