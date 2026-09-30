"""Loopback OTLP/HTTP JSON quota observer; never forwards or stores raw events."""

from __future__ import annotations

import json
import math
from http.server import BaseHTTPRequestHandler, HTTPServer

from common import atomic_write, encoded, locked, now
from recovery import halt
from measurements import record as record_measurement


def objects(value):
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def attributes(value):
    return {
        a["key"]: a["value"]
        for a in objects(value)
        if isinstance(a.get("key"), str) and isinstance(a.get("value"), dict)
    }


def quota_event(payload):
    if not isinstance(payload, dict) or not isinstance(
        payload.get("resourceLogs", []), list
    ):
        raise ValueError("Expected OTLP JSON object")
    for resource in objects(payload.get("resourceLogs")):
        descriptor = resource.get("resource")
        attrs = (
            attributes(descriptor.get("attributes"))
            if isinstance(descriptor, dict)
            else {}
        )
        service = attrs.get("service.name", {}).get("stringValue", "")
        if service not in ("codex", "codex-cli", "codex-app-server", "codex_cli_rs"):
            continue
        for scope in objects(resource.get("scopeLogs")):
            for record in objects(scope.get("logRecords")):
                values = attributes(record.get("attributes"))
                body = record.get("body")
                fallback = body.get("stringValue", "") if isinstance(body, dict) else ""
                name = values.get("event.name", {}).get(
                    "stringValue", record.get("eventName", fallback)
                )
                if name not in (
                    "codex.api_request",
                    "codex.sse_event",
                    "codex.websocket_event",
                    "codex.websocket_request",
                ):
                    continue
                code = values.get(
                    "http.response.status_code",
                    values.get("status_code", values.get("status", {})),
                )
                error = values.get("error.code", values.get("error", {})).get(
                    "stringValue", ""
                )
                if str(
                    code.get("intValue", code.get("stringValue", ""))
                ) == "429" or error in (
                    "insufficient_quota",
                    "usage_limit_reached",
                    "rate_limit_exceeded",
                    "out_of_usage",
                ):
                    return True
    return False


def scalar(value):
    if not isinstance(value, dict):
        return None
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    return None


def numeric(value):
    if type(value) not in (str, int, float):
        return None
    try:
        number = float(value)
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and 0 <= number <= 1e15 else None


def measure_native(home, payload):
    count = 0
    aliases = {
        "input_tokens": ("input_tokens", "input_token_count"),
        "cached_input_tokens": ("cached_input_tokens", "cached_input_token_count", "cached_token_count", "cached_tokens"),
        "output_tokens": ("output_tokens", "output_token_count"),
        "reasoning_tokens": ("reasoning_tokens", "reasoning_output_tokens", "reasoning_token_count"),
        "duration_ms": ("duration_ms",),
    }
    for resource in objects(payload.get("resourceLogs")):
        descriptor = resource.get("resource")
        context = attributes(descriptor.get("attributes")) if isinstance(descriptor, dict) else {}
        if scalar(context.get("service.name")) not in ("codex", "codex-cli", "codex-app-server", "codex_cli_rs"):
            continue
        for scope in objects(resource.get("scopeLogs")):
            for item in objects(scope.get("logRecords")):
                values = {key: scalar(value) for key, value in {**context, **attributes(item.get("attributes"))}.items()}
                name = values.get("event.name", item.get("eventName", scalar(item.get("body"))))
                kind = values.get("event.kind", values.get("kind", values.get("event_kind")))
                if name == "codex.tool_result":
                    category, metrics = "native_tool", {"tool_calls": 1}
                elif name in ("codex.sse_event", "codex.websocket_event") and kind in ("response.completed", "response_completed", "response.done"):
                    category, metrics = "native_usage", {}
                else:
                    continue
                for target, sources in aliases.items():
                    for source in sources:
                        number = numeric(values.get(source))
                        if number is not None:
                            metrics[target] = number
                            break
                # Native telemetry, not prompt text, supplies these explicit IDs.
                session = next((values[k] for k in ("conversation.id", "conversation_id", "session_id", "thread.id", "thread_id") if values.get(k)), None)
                turn = next((values[k] for k in ("turn.id", "turn_id") if values.get(k)), None)
                # Nanoseconds exceed the ordinary numeric metric limit.
                try:
                    stamp = int(item.get("timeUnixNano", "")) / 1e9
                    if not math.isfinite(stamp) or stamp <= 0:
                        continue
                except (ValueError, TypeError, OverflowError):
                    continue
                event_id = values.get("response.id", values.get("tool_use_id"))
                if not metrics:
                    continue
                try:
                    count += record_measurement(home, kind=category, values=metrics, session=session, turn=turn,
                                    event_id=event_id, observed_at=stamp)
                except ValueError:
                    # Reject malformed usage without retaining offending attributes.
                    continue
    return count


def receive(home, payload):
    if quota_event(payload):
        result = halt(home, "codex", "native_quota_event")
        return {
            "halted": True,
            "checkpointed": sum(item["checkpointed"] for item in result["tasks"]),
        }
    measured = measure_native(home, payload)
    return {"halted": home.halted(), "measurements": measured}


def make_server(home, port):
    if type(port) is not int or not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("Invalid local telemetry port")
    home.ensure()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            # Not a public ingestion service. Ignore all raw logs after classification.
            try:
                size = int(self.headers.get("Content-Length", "0"))
                host = self.headers.get("Host", "")
                expected_host = f"127.0.0.1:{self.server.server_port}"
                if (
                    self.path != "/v1/logs"
                    or self.headers.get("Origin")
                    or not 0 < size <= 1024 * 1024
                    or host != expected_host
                    or self.headers.get("Transfer-Encoding")
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get("Content-Encoding")
                ):
                    self.send_error(400)
                    return
                if self.headers.get_content_type() != "application/json":
                    self.send_error(415)
                    return
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("Incomplete telemetry body")
                receive(home, json.loads(raw))
                with home.lock():
                    atomic_write(
                        home.path / "telemetry-status.json",
                        encoded(
                            {"last_received": now(), "transport": "otlp-http-json"}
                        ),
                    )
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                self.send_error(400)

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

    return HTTPServer(("127.0.0.1", port), Handler)


def serve(home, port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Invalid local telemetry port")
    home.ensure()
    with (
        locked(home.path / "observer.lock", timeout=0.1),
        make_server(home, port) as server,
    ):
        server.serve_forever()
