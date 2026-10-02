"""Offline native-hook receipt tests; no real Codex task or provider calls."""

import json
import time
import uuid
from unittest.mock import patch

from common import sha
from invocations import canonical_digest, database, pre_tool, post_tool, usage_report
from test_support import RuntimeCase


class InvocationTests(RuntimeCase):
    def setUp(self):
        super().setUp()
        self.home.register(self.root, "native-session")
        self.payload = {"session_id": "native-session", "turn_id": "native-turn", "tool_use_id": "native-call",
                        "tool_name": "mcp__jev_context__search_workspace_evidence", "tool_input": {
                            "workspaceRoot": str(self.root), "query": "NEVER-STORE-QUERY", "resultLimit": 4}}

    def operation(self, *, workspace=None, arguments=None, status="success", identity=None):
        identity = identity or str(uuid.uuid4())
        now = int(time.time() * 1000)
        with database(self.home) as db, db:
            db.execute("INSERT INTO invocations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                identity, sha(str(workspace or self.root).encode()), "search_workspace_evidence",
                canonical_digest(arguments or self.payload["tool_input"]), "a" * 64, "ordinary", now, now,
                status, '{"responseBytes":50,"jevRequests":1}', None, None, None))
        return identity

    def post(self, identity):
        response = {"measurementId": identity}
        payload = {**self.payload, "tool_response": {"structuredContent": response,
                       "content": [{"type": "text", "text": json.dumps(response)}]}}
        return post_tool(self.home, payload, self.root)

    def test_exact_pre_and_post_bind_once_without_storing_arguments(self):
        self.assertEqual(pre_tool(self.home, self.payload, self.root)["state"], "receipt_created")
        identity = self.operation()
        self.assertEqual(self.post(identity)["state"], "verified")
        self.assertEqual(self.post(identity)["state"], "already_verified")
        summary = usage_report(self.home, "native-session")
        self.assertEqual(summary["verifiedOperations"], 1)
        self.assertEqual(summary["metrics"]["jevRequests"], 1)
        content = (self.home.path / "invocations.sqlite3").read_bytes()
        for secret in (b"NEVER-STORE-QUERY", b"native-session", b"native-turn", b"native-call"):
            self.assertNotIn(secret, content)

    def test_missing_pre_receipt_stays_unattributed(self):
        self.assertEqual(self.post(self.operation())["state"], "missing_receipt")
        self.assertEqual(usage_report(self.home, "native-session")["verifiedOperations"], 0)

    def test_changed_arguments_and_workspace_do_not_bind(self):
        pre_tool(self.home, self.payload, self.root)
        self.assertEqual(self.post(self.operation(arguments={"query": "other"}))["state"], "mismatch")
        self.assertEqual(self.post(self.operation(workspace="/other"))["state"], "mismatch")

    def test_other_task_cannot_consume_a_valid_receipt(self):
        pre_tool(self.home, self.payload, self.root)
        identity = self.operation()
        self.home.register(self.root, "other-session")
        self.payload["session_id"] = "other-session"
        self.assertEqual(self.post(identity)["state"], "missing_receipt")

    def test_expiry_and_result_replay_are_explicit(self):
        pre_tool(self.home, self.payload, self.root)
        identity = self.operation()
        with patch("invocations.milliseconds", return_value=int(time.time() * 1000) + 601_000):
            self.assertEqual(self.post(identity)["state"], "expired")
        self.assertEqual(self.post(identity)["state"], "verified")
        self.assertEqual(self.post(self.operation())["state"], "consumed")

    def test_duplicate_pre_is_idempotent_and_conflicting_pre_is_rejected(self):
        pre_tool(self.home, self.payload, self.root)
        self.assertEqual(pre_tool(self.home, self.payload, self.root)["state"], "receipt_exists")
        self.payload["tool_input"]["query"] = "changed"
        self.assertEqual(pre_tool(self.home, self.payload, self.root)["state"], "mismatch")

    def test_missing_turn_or_unknown_tool_is_not_guessed(self):
        for key in ("turn_id", "tool_use_id", "session_id"):
            value = {k: v for k, v in self.payload.items() if k != key}
            self.assertEqual(pre_tool(self.home, value, self.root)["state"], "missing_native_identity")
        self.assertEqual(pre_tool(self.home, {**self.payload, "tool_name": "exec_command"}, self.root)["state"], "not_covered")

    def test_conflicting_result_ids_and_started_operations_are_not_verified(self):
        pre_tool(self.home, self.payload, self.root)
        identity = self.operation(status="started")
        self.assertEqual(self.post(identity)["state"], "unfinished")
        payload = {**self.payload, "tool_response": {"structuredContent": {"measurementId": identity},
                   "content": [{"type": "text", "text": json.dumps({"measurementId": str(uuid.uuid4())})}]}}
        self.assertEqual(post_tool(self.home, payload, self.root)["state"], "missing_result_identity")

    def test_error_outcome_can_be_verified_without_raw_error(self):
        pre_tool(self.home, self.payload, self.root)
        self.assertEqual(self.post(self.operation(status="error"))["state"], "verified")
        self.assertEqual(usage_report(self.home, "native-session")["failedOperations"], 1)

    def test_canonical_digest_is_order_independent_but_strict(self):
        self.assertEqual(canonical_digest({"b": [True, None, 3], "a": "line\nvalue"}),
                         canonical_digest({"a": "line\nvalue", "b": [True, None, 3]}))
        for value in ({"x": 1.5}, {"x": float("nan")}, {"x": "\ud800"}, {"non-ascii-\u00e9": 1}, {"x": "a" * 66000}):
            with self.assertRaises(ValueError):
                canonical_digest(value)
