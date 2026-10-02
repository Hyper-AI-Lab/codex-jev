import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from measurements import bind_session, record, report
from test_support import RuntimeCase


class MeasurementTests(RuntimeCase):
    def test_numeric_only_deduplication_and_binding(self):
        bind_session(self.home, "private-session-canary", str(self.root))
        event = dict(kind="native_usage", values={"input_tokens": 100, "cached_input_tokens": 40,
                     "output_tokens": 12, "reasoning_tokens": 5, "prompt": "NEVER-STORE-ME"},
                     session="private-session-canary", turn="private-turn", event_id="response-one", observed_at=time.time())
        self.assertTrue(record(self.home, **event))
        self.assertFalse(record(self.home, **event))
        result = report(self.home)
        self.assertTrue(result["nativeTokensMeasured"])
        self.assertFalse(result["accountSavingsMeasured"])
        self.assertTrue(all(row["origin"] == "ordinary" for row in result["groups"]))
        self.assertEqual(result["detailRecords"], 1)
        data = (self.home.path / "measurements.sqlite3").read_bytes()
        for secret in (b"NEVER-STORE-ME", b"private-session-canary", b"private-turn"):
            self.assertNotIn(secret, data)

    def test_unattributed_and_synthetic_are_not_ordinary(self):
        record(self.home, kind="native_tool", values={"tool_calls": 1})
        record(self.home, kind="hook", values={"duration_ms": 3}, origin="synthetic")
        self.assertEqual({r["origin"] for r in report(self.home)["groups"]}, {"unattributed", "synthetic"})
        self.assertFalse(report(self.home)["nativeTokensMeasured"])

    def test_native_response_identity_survives_replayed_timestamp(self):
        event = dict(kind="native_usage", values={"input_tokens": 100},
                     session="session", turn="turn", event_id="response-one")
        self.assertTrue(record(self.home, **event, observed_at=time.time() - 1))
        self.assertFalse(record(self.home, **event, observed_at=time.time()))

    def test_same_response_id_with_conflicting_usage_is_not_silently_accepted(self):
        event = dict(kind="native_usage", session="session", event_id="response-one")
        record(self.home, **event, values={"input_tokens": 100})
        with self.assertRaises(ValueError):
            record(self.home, **event, values={"input_tokens": 101})

    def test_native_receipts_survive_detail_pruning(self):
        with patch("measurements.MAX_RECORDS", 2):
            for index in range(4):
                record(self.home, kind="native_usage", session="one", values={"input_tokens": 10}, event_id=str(index))
        self.assertFalse(record(self.home, kind="native_usage", session="one", values={"input_tokens": 10}, event_id="0"))
        self.assertEqual(sum(r["value"] for r in report(self.home)["groups"] if r["metric"] == "input_tokens"), 40)

    def test_incomplete_telemetry_does_not_claim_the_native_source(self):
        self.assertFalse(record(self.home, kind="native_usage", session="one", values={"duration_ms": 10}))
        self.assertTrue(record(self.home, kind="native_usage", session="one", source="history",
                               values={"input_tokens": 100}, event_id="history"))

    def test_concurrent_delivery_inserts_one_native_response(self):
        def deliver(_index):
            return record(self.home, kind="native_usage", session="one", values={"input_tokens": 100}, event_id="response")
        with ThreadPoolExecutor(max_workers=3) as pool:
            self.assertEqual(sum(pool.map(deliver, range(6))), 1)
        self.assertEqual(sum(r["value"] for r in report(self.home)["groups"] if r["metric"] == "input_tokens"), 100)

    def test_sessionless_native_usage_is_diagnostic_not_additive_usage(self):
        self.assertFalse(record(self.home, kind="native_usage", values={"input_tokens": 100}, event_id="no-session"))
        self.assertTrue(record(self.home, kind="native_usage", session="one", source="history",
                               values={"input_tokens": 100}, event_id="response"))
        self.assertEqual(sum(r["value"] for r in report(self.home)["groups"] if r["metric"] == "input_tokens"), 100)

    def test_legacy_native_usage_claims_otlp_before_history_election(self):
        record(self.home, kind="native_usage", session="one", event_id="old", values={"input_tokens": 100})
        with sqlite3.connect(self.home.path / "measurements.sqlite3") as db:
            db.execute("DELETE FROM native_sources")
            db.execute("DELETE FROM native_receipts")
            db.execute("DROP TABLE IF EXISTS measurement_metadata")
        self.assertFalse(record(self.home, kind="native_usage", session="one", source="history",
                                event_id="new-history", values={"input_tokens": 100}))
        self.assertTrue(record(self.home, kind="native_usage", session="one", event_id="new-otlp",
                               values={"input_tokens": 25}))
        self.assertEqual(sum(r["value"] for r in report(self.home)["groups"] if r["metric"] == "input_tokens"), 125)

    def test_bounded_detail_preserves_aggregates(self):
        with patch("measurements.MAX_RECORDS", 2):
            for index in range(4):
                record(self.home, kind="hook", values={"duration_ms": index + 1}, origin="synthetic")
        result = report(self.home)
        self.assertEqual(result["detailRecords"], 2)
        self.assertEqual(result["groups"][0]["value"], 10)
        self.assertEqual(result["groups"][0]["samples"], 4)

    def test_conflicts_and_invalid_numbers(self):
        bind_session(self.home, "one", str(self.root))
        with self.assertRaises(ValueError):
            bind_session(self.home, "one", "/other-workspace")
        for values in ({"input_tokens": 1, "cached_input_tokens": 2},
                       {"output_tokens": 0, "reasoning_tokens": 1},
                       {"tool_calls": 0.5}):
            with self.assertRaises(ValueError):
                record(self.home, kind="native_usage", values=values)
        self.assertFalse(record(self.home, kind="hook", values={"duration_ms": float("nan")}))
        self.assertFalse(record(self.home, kind="hook", values={"duration_ms": True}))

    def test_readonly_report_and_private_modes(self):
        self.assertEqual(report(self.home)["state"], "no_observations")
        self.assertFalse((self.home.path / "measurements.sqlite3").exists())
        record(self.home, kind="checkpoint", values={"duration_ms": 2})
        path = self.home.path / "measurements.sqlite3"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        json.dumps(report(self.home))
        self.assertEqual(path.read_bytes(), before)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
