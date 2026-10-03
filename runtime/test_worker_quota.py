from common import encoded
from manage import hook
from test_support import RuntimeCase
from worker_quota import detected


class WorkerQuotaTests(RuntimeCase):
    def payload(self, status):
        return {"hook_event_name": "PostToolUse", "session_id": "task", "turn_id": "turn",
                "tool_use_id": "call", "cwd": str(self.root), "tool_name": "multi_agent_v1__wait_agent",
                "tool_response": {"status": {"worker": status}, "timed_out": False}}

    def test_native_worker_error_codes_and_observed_limit_prefix_are_detected(self):
        for error in ("You've hit your usage limit. Try again later.",
                      "You\u2019ve hit your usage limit. PRIVATE-MARKER",
                      {"code": "insufficient_quota"}, {"status_code": 429}):
            self.assertTrue(detected(self.payload({"errored": error})))

    def test_documents_prompts_completed_workers_and_unrelated_errors_do_not_halt(self):
        for status in ({"completed": "You've hit your usage limit."}, {"errored": "unit test quota text"}, "running"):
            self.assertFalse(detected(self.payload(status)))
        original = self.payload({"errored": "You've hit your usage limit."})
        for tool in ("exec_command", "mcp__jev_context__read_selected_evidence", "unknown_wait_agent"):
            self.assertFalse(detected({**original, "tool_name": tool}))
        self.assertFalse(detected({**original, "hook_event_name": "UserPromptSubmit"}))
        self.assertFalse(detected({**original, "tool_response": {"content": [{"text": "You've hit your usage limit."}]}}))

    def test_hook_halts_and_checkpoints_without_persisting_worker_text(self):
        self.home.register(self.root, "task")
        hook(self.home, {"hook_event_name": "SessionStart", "session_id": "task", "cwd": str(self.root)})
        output = hook(self.home, self.payload({"errored": "You've hit your usage limit. PRIVATE-MARKER"}))
        self.assertTrue(self.home.halted())
        self.assertFalse(output["continue"])
        self.assertNotIn(b"PRIVATE-MARKER", encoded(self.read_state("halt.json")))
        self.assertTrue(self.read_state("halt-checkpoint.json"))
