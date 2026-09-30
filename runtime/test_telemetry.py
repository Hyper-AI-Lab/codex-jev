import contextlib
import http.client
import io
import json
import threading
import time

from telemetry import make_server, quota_event, receive
from test_support import RuntimeCase
from measurements import bind_session, report


def event(name="codex.api_request", status="429", service="codex", error=None):
    attributes = [
        {"key": "event.name", "value": {"stringValue": name}},
        {"key": "status_code", "value": {"intValue": status}},
    ]
    if error:
        attributes.append({"key": "error.code", "value": {"stringValue": error}})
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}}
                    ]
                },
                "scopeLogs": [{"logRecords": [{"attributes": attributes}]}],
            }
        ]
    }


class TelemetryTests(RuntimeCase):
    def usage_event(self):
        payload = event("codex.sse_event", status="200")
        record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        record["timeUnixNano"] = str(time.time_ns())
        record["attributes"] += [{"key": key, "value": {"stringValue": value}} for key, value in {
            "kind": "response.completed", "conversation.id": "test-session", "turn_id": "test-turn",
            "input_tokens": "120", "cached_input_tokens": "100", "output_tokens": "15",
            "reasoning_tokens": "5", "prompt": "DO-NOT-STORE", "error": "DO-NOT-STORE",
        }.items()]
        return payload

    def test_usage_is_numeric_bound_and_idempotent(self):
        bind_session(self.home, "test-session", str(self.root))
        payload = self.usage_event()
        self.assertEqual(receive(self.home, payload)["measurements"], 1)
        self.assertEqual(receive(self.home, payload)["measurements"], 0)
        result = report(self.home)
        self.assertTrue(result["nativeTokensMeasured"])
        self.assertEqual({row["origin"] for row in result["groups"]}, {"ordinary"})
        self.assertNotIn(b"DO-NOT-STORE", (self.home.path / "measurements.sqlite3").read_bytes())

    def test_unknown_schema_or_missing_timestamp_does_not_invent_usage(self):
        payload = self.usage_event()
        record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        del record["timeUnixNano"]
        self.assertEqual(receive(self.home, payload)["measurements"], 0)
        self.assertFalse(report(self.home)["nativeTokensMeasured"])

    def test_installed_event_aliases_and_body_name(self):
        payload = self.usage_event()
        item = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        item["body"] = {"stringValue": "codex.sse_event"}
        item["attributes"] = [row for row in item["attributes"] if row["key"] != "event.name"]
        for row in item["attributes"]:
            if row["key"] == "kind":
                row["key"] = "event_kind"
                row["value"]["stringValue"] = "response_completed"
            if row["key"] == "input_tokens":
                row["key"] = "input_token_count"
        self.assertEqual(receive(self.home, payload)["measurements"], 1)
        self.assertTrue(report(self.home)["nativeTokensMeasured"])

    def test_native_quota_names_and_codes(self):
        for name in (
            "codex.api_request",
            "codex.sse_event",
            "codex.websocket_request",
            "codex.websocket_event",
        ):
            with self.subTest(name=name):
                self.assertTrue(quota_event(event(name)))
        for code in (
            "insufficient_quota",
            "usage_limit_reached",
            "rate_limit_exceeded",
            "out_of_usage",
        ):
            self.assertTrue(quota_event(event(status="200", error=code)))
        payload = event()
        record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        record["eventName"] = record["attributes"].pop(0)["value"]["stringValue"]
        self.assertTrue(quota_event(payload))

    def test_tool_429_and_prompt_mentions_never_trigger_halt(self):
        for name in (
            "codex.tool_result",
            "codex.tool_decision",
            "codex.user_prompt",
            "jev.api_request",
        ):
            payload = event(name)
            self.assertFalse(quota_event(payload))
            self.assertFalse(receive(self.home, payload)["halted"])
        self.assertFalse(quota_event(event(service="typesafe")))
        self.assertFalse(
            quota_event(
                event(status="200", error="tool output mentions 429 insufficient_quota")
            )
        )
        self.assertFalse(self.home.halted())

    def test_malformed_shapes_are_not_false_native_events(self):
        for payload in ([], None, "429", {"resourceLogs": {}}):
            with self.assertRaises(ValueError):
                quota_event(payload)
        for payload in (
            {},
            {"resourceLogs": [None, {}, {"resource": None}]},
            {"resourceLogs": [{"resource": {"attributes": [None]}}]},
        ):
            self.assertFalse(quota_event(payload))

    def test_receive_stores_no_raw_event_and_retains_halt(self):
        payload = event()
        payload["prompt"] = "PRIVATE-PROMPT-CANARY"
        self.assertTrue(receive(self.home, payload)["halted"])
        self.assertTrue(receive(self.home, event("codex.tool_result"))["halted"])
        for file in self.home.path.rglob("*"):
            if file.is_file():
                self.assertNotIn(b"PRIVATE-PROMPT-CANARY", file.read_bytes())

    def test_loopback_http_validation_no_raw_logs_and_bounded_body(self):
        server = make_server(self.home, 0)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        # A temporary in-process test listener, never an installed/background daemon.
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.start()
        output = io.StringIO()

        def request(payload, path="/v1/logs", headers=None):
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=5
            )
            try:
                connection.request(
                    "POST",
                    path,
                    payload,
                    headers=headers or {"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                body = response.read()
                return response.status, body
            finally:
                connection.close()

        try:
            with contextlib.redirect_stderr(output):
                self.assertEqual(
                    request(json.dumps(event("codex.tool_result")))[0], 200
                )
                self.assertFalse(self.home.halted())
                self.assertEqual(request(b"[]")[0], 400)
                self.assertEqual(request(b"{}", path="/wrong")[0], 400)
                self.assertEqual(
                    request(b"{}", headers={"Content-Type": "text/plain"})[0], 415
                )
                self.assertEqual(
                    request(
                        b"{}",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": "http://hostile.invalid",
                        },
                    )[0],
                    400,
                )
                self.assertEqual(
                    request(
                        b"{}",
                        headers={
                            "Content-Type": "application/json",
                            "Host": "attacker.invalid",
                        },
                    )[0],
                    400,
                )
                self.assertEqual(
                    request(
                        b"{}",
                        headers={
                            "Content-Type": "application/json",
                            "Content-Length": str(1024 * 1024 + 1),
                        },
                    )[0],
                    400,
                )
                payload = event()
                payload["prompt"] = "SYNTHETIC-PRIVATE-HTTP-PROMPT"
                self.assertEqual(request(json.dumps(payload)), (200, b"{}"))
                self.assertTrue(self.home.halted())
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(output.getvalue(), "")
        for file in self.home.path.rglob("*"):
            if file.is_file():
                self.assertNotIn(b"SYNTHETIC-PRIVATE-HTTP-PROMPT", file.read_bytes())

    def test_invalid_ports_rejected(self):
        for port in (True, -1, 1, 65536):
            with self.assertRaises(ValueError):
                make_server(self.home, port)
