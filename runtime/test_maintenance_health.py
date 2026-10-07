import json
import subprocess
import unittest
from unittest.mock import Mock

from maintenance_health import classify, probe, require_known


def response(status="running", version="0.160.0", **extra):
    return subprocess.CompletedProcess([], 0, json.dumps({
        "status": status, "appServerVersion": version, **extra,
    }), "not_retained")


class MaintenanceHealthTests(unittest.TestCase):
    def test_transient_failure_then_running_is_not_stopped(self):
        query = Mock(side_effect=[subprocess.TimeoutExpired("metadata", 1), response()])
        sleep = Mock()
        result = probe(query, sleep=sleep)
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["attempts"], 2)
        sleep.assert_called_once_with(0.2)

    def test_nonzero_failure_retries_only_three_queries(self):
        query = Mock(return_value=subprocess.CompletedProcess([], 1, "private", "private"))
        result = probe(query, sleep=Mock())
        self.assertEqual(query.call_count, 3)
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("private", json.dumps(result))
        with self.assertRaisesRegex(RuntimeError, "unverified"):
            require_known(result)

    def test_stopped_requires_explicit_successful_status(self):
        result = probe(Mock(return_value=response("stopped", None)))
        self.assertEqual(require_known(result)["status"], "stopped")
        for raw in ["{}", "[]", "private", "x" * 8193,
                    '{"status":"future-state"}', '{"status":"running"}',
                    '{"status":"running","appServerVersion":"private"}']:
            query = Mock(return_value=subprocess.CompletedProcess([], 0, raw))
            result = probe(query)
            self.assertEqual(query.call_count, 1)
            self.assertEqual(result["status"], "unknown")
            with self.assertRaises(RuntimeError):
                require_known(result)

    def test_filters_unknown_fields_and_validates_bounds(self):
        result = classify(response(secret="not_retained"))
        self.assertNotIn("secret", result)
        for attempts in [0, 4, True]:
            query = Mock()
            with self.assertRaises(ValueError):
                probe(query, attempts=attempts)
            query.assert_not_called()
