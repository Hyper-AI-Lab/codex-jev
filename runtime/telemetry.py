"""Loopback OTLP/HTTP JSON quota observer; never forwards or stores raw events."""

from __future__ import annotations

import json
import math
from http.server import BaseHTTPRequestHandler, HTTPServer

from common import atomic_write, encoded, locked, now, read_json
from recovery import halt
from measurements import record as record_measurement

DIAGNOSTIC_KEYS = (
    "transport_seen",
    "resources_seen",
    "events_seen",
    "recognized_services",
    "unsupported_service_resources",
    "completed_usage_candidates",
    "supported_token_events",
    "missing_session_ids",
    "missing_turn_ids",
    "missing_timestamps",
    "missing_input_tokens",
    "missing_cached_input_tokens",
    "missing_output_tokens",
    "missing_reasoning_tokens",
    "invalid_usage",
    "unsupported_shapes",
)
MAX_DIAGNOSTIC_COUNT = 1_000_000_000
SERVICES = ("codex", "codex-cli", "codex-app-server", "codex_cli_rs")
TOKEN_ALIASES = {
    "input_tokens": ("input_tokens", "input_token_count"),
    "cached_input_tokens": (
        "cached_input_tokens", "cached_input_token_count", "cached_token_count", "cached_tokens",
    ),
    "output_tokens": ("output_tokens", "output_token_count"),
    "reasoning_tokens": (
        "reasoning_tokens", "reasoning_output_tokens", "reasoning_token_count",
    ),
    "duration_ms": ("duration_ms",),
}


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


def measure_native(home, payload, *, record=True):
    count = 0
    diagnostics = dict.fromkeys(DIAGNOSTIC_KEYS, 0)
    resources = payload.get("resourceLogs", [])
    diagnostics["resources_seen"] = len(resources)
    for resource in resources:
        if not isinstance(resource, dict):
            diagnostics["unsupported_shapes"] += 1
            continue
        descriptor = resource.get("resource")
        if descriptor is not None and not isinstance(descriptor, dict):
            diagnostics["unsupported_shapes"] += 1
        raw_context = descriptor.get("attributes", []) if isinstance(descriptor, dict) else []
        if not isinstance(raw_context, list):
            diagnostics["unsupported_shapes"] += 1
        else:
            diagnostics["unsupported_shapes"] += sum(
                not isinstance(entry, dict)
                or not isinstance(entry.get("key"), str)
                or not isinstance(entry.get("value"), dict)
                for entry in raw_context
            )
        context = attributes(raw_context)
        service = scalar(context.get("service.name"))
        recognized = service in SERVICES
        if recognized:
            diagnostics["recognized_services"] += 1
        elif isinstance(service, str) and service:
            diagnostics["unsupported_service_resources"] += 1
        raw_scopes = resource.get("scopeLogs", [])
        if not isinstance(raw_scopes, list):
            diagnostics["unsupported_shapes"] += 1
            continue
        for scope in raw_scopes:
            if not isinstance(scope, dict):
                diagnostics["unsupported_shapes"] += 1
                continue
            raw_items = scope.get("logRecords", [])
            if not isinstance(raw_items, list):
                diagnostics["unsupported_shapes"] += 1
                continue
            diagnostics["events_seen"] += len(raw_items)
            for item in raw_items:
                if not isinstance(item, dict):
                    diagnostics["unsupported_shapes"] += 1
                    continue
                raw_attrs = item.get("attributes", [])
                if not isinstance(raw_attrs, list):
                    diagnostics["unsupported_shapes"] += 1
                    raw_attrs = []
                else:
                    diagnostics["unsupported_shapes"] += sum(
                        not isinstance(entry, dict)
                        or not isinstance(entry.get("key"), str)
                        or not isinstance(entry.get("value"), dict)
                        for entry in raw_attrs
                    )
                if not recognized:
                    continue
                values = {key: scalar(value) for key, value in {**context, **attributes(item.get("attributes"))}.items()}
                name = values.get("event.name", item.get("eventName", scalar(item.get("body"))))
                kind = values.get("event.kind", values.get("kind", values.get("event_kind")))
                if name == "codex.tool_result":
                    category, metrics = "native_tool", {"tool_calls": 1}
                elif name in ("codex.sse_event", "codex.websocket_event") and kind in ("response.completed", "response_completed", "response.done"):
                    category, metrics = "native_usage", {}
                    diagnostics["completed_usage_candidates"] += 1
                else:
                    continue
                for target, sources in TOKEN_ALIASES.items():
                    for source in sources:
                        number = numeric(values.get(source))
                        if number is not None:
                            metrics[target] = number
                            break
                if category == "native_usage":
                    session_value = next((values[k] for k in ("conversation.id", "conversation_id", "session_id", "thread.id", "thread_id") if values.get(k)), None)
                    turn_value = next((values[k] for k in ("turn.id", "turn_id") if values.get(k)), None)
                    if not session_value:
                        diagnostics["missing_session_ids"] += 1
                    if not turn_value:
                        diagnostics["missing_turn_ids"] += 1
                    for target in (
                        "input_tokens",
                        "cached_input_tokens",
                        "output_tokens",
                        "reasoning_tokens",
                    ):
                        sources = TOKEN_ALIASES[target]
                        present = any(source in values for source in sources)
                        if not present:
                            diagnostics[f"missing_{target}"] += 1
                    invalid_metrics = any(
                        any(source in values for source in sources)
                        and not any(numeric(values.get(source)) is not None for source in sources)
                        for sources in TOKEN_ALIASES.values()
                    )
                # Native telemetry, not prompt text, supplies these explicit IDs.
                session = next((values[k] for k in ("conversation.id", "conversation_id", "session_id", "thread.id", "thread_id") if values.get(k)), None)
                turn = next((values[k] for k in ("turn.id", "turn_id") if values.get(k)), None)
                # Nanoseconds exceed the ordinary numeric metric limit.
                timestamp_present = "timeUnixNano" in item
                try:
                    stamp = int(item.get("timeUnixNano", "")) / 1e9
                    if not math.isfinite(stamp) or stamp <= 0:
                        raise ValueError("Invalid timestamp")
                except (ValueError, TypeError, OverflowError):
                    stamp = None
                if category == "native_usage" and stamp is None and not timestamp_present:
                    diagnostics["missing_timestamps"] += 1
                if category == "native_usage" and (
                    invalid_metrics or (timestamp_present and stamp is None)
                ):
                    diagnostics["invalid_usage"] += 1
                    continue
                event_id = values.get("response.id", values.get("tool_use_id"))
                if not metrics or stamp is None or not record:
                    continue
                try:
                    inserted = record_measurement(
                        home,
                        kind=category,
                        values=metrics,
                        session=session,
                        turn=turn,
                        event_id=event_id,
                        observed_at=stamp,
                    )
                    count += inserted
                except ValueError:
                    # Reject malformed usage without retaining offending attributes.
                    if category == "native_usage":
                        diagnostics["invalid_usage"] += 1
                    continue
                if (
                    category == "native_usage"
                    and inserted
                    and "input_tokens" in metrics
                    and "output_tokens" in metrics
                ):
                    diagnostics["supported_token_events"] += 1
    for key in DIAGNOSTIC_KEYS:
        diagnostics[key] = min(MAX_DIAGNOSTIC_COUNT, diagnostics[key])
    return count, diagnostics


def persist_diagnostics(home, counters):
    home.ensure()
    path = home.path / "telemetry-diagnostics.json"
    with locked(home.path / "telemetry-diagnostics.lock"):
        stored = read_json(path)
        if stored:
            existing = stored.get("counters")
            if (
                stored.get("version") != 1
                or not isinstance(existing, dict)
                or set(existing) != set(DIAGNOSTIC_KEYS)
                or any(
                    type(value) is not int
                    or not 0 <= value <= MAX_DIAGNOSTIC_COUNT
                    for value in existing.values()
                )
                or set(stored) != {"version", "counters"}
            ):
                raise ValueError("Invalid telemetry diagnostics state")
            totals = existing.copy()
        else:
            totals = dict.fromkeys(DIAGNOSTIC_KEYS, 0)
        for key in DIAGNOSTIC_KEYS:
            value = counters.get(key, 0)
            if type(value) is not int or value < 0:
                raise ValueError("Invalid telemetry diagnostic counter")
            totals[key] = min(MAX_DIAGNOSTIC_COUNT, totals[key] + value)
        atomic_write(path, encoded({"version": 1, "counters": totals}))
    return counters


def diagnostic_status(home):
    value = read_json(home.path / "telemetry-diagnostics.json")
    if not value:
        return {"state": "not_observed", "tokenCoverage": "unknown"}
    counters = value.get("counters")
    if (value.get("version") != 1 or not isinstance(counters, dict)
            or set(counters) != set(DIAGNOSTIC_KEYS)
            or any(type(v) is not int or not 0 <= v <= MAX_DIAGNOSTIC_COUNT for v in counters.values())):
        return {"state": "invalid_diagnostics", "tokenCoverage": "unknown"}
    return {"state": "observed", "counters": counters,
            "tokenCoverage": "some_events_observed" if counters["supported_token_events"] else "not_observed",
            "completeCoverageVerified": False}


def receive(home, payload):
    if quota_event(payload):
        # Quota protection must not depend on optional measurement storage.
        result = halt(home, "codex", "native_quota_event")
        _, diagnostics = measure_native(home, payload, record=False)
        diagnostics["transport_seen"] = 1
        try:
            persist_diagnostics(home, diagnostics)
        except (OSError, ValueError, TimeoutError):
            pass
        return {
            "halted": True,
            "checkpointed": sum(item["checkpointed"] for item in result["tasks"]),
            "diagnostics": diagnostics,
        }
    measured, diagnostics = measure_native(home, payload)
    diagnostics["transport_seen"] = 1
    persist_diagnostics(home, diagnostics)
    return {"halted": home.halted(), "measurements": measured, "diagnostics": diagnostics}


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
