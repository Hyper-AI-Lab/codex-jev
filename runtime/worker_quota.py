"""Quota signals only from known native worker status envelopes, never prose."""

import json

from common import identifier

TOOLS = {"wait_agent", "multi_agent_v1__wait_agent", "functions.wait_agent"}
CODES = {"insufficient_quota", "usage_limit_reached", "rate_limit_exceeded", "out_of_usage"}


def detected(payload):
    if (payload.get("hook_event_name") != "PostToolUse" or payload.get("tool_name") not in TOOLS
            or not all(identifier(payload.get(k)) for k in ("session_id", "turn_id", "tool_use_id"))):
        return False
    response = payload.get("tool_response")
    if isinstance(response, str) and len(response) <= 65536:
        try:
            response = json.loads(response)
        except ValueError:
            return False
    states = response.get("status") if isinstance(response, dict) else None
    if not isinstance(states, dict) or len(states) > 64:
        return False
    for agent, state in states.items():
        if not identifier(agent) or not isinstance(state, dict) or set(state) != {"errored"}:
            continue
        error = state["errored"]
        if isinstance(error, dict):
            code = error.get("code")
            if (isinstance(code, str) and code in CODES) or error.get("status_code") == 429:
                return True
        elif isinstance(error, str) and len(error) <= 8192:
            if error.startswith(("You've hit your usage limit.", "You\u2019ve hit your usage limit.")):
                return True
    return False
