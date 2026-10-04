from measurements import bind_session, record
from task_report import markdown, report
from test_support import RuntimeCase


class TaskReportTests(RuntimeCase):
    def test_empty_report_does_not_claim_zero_usage_or_savings(self):
        value = report(self.home, "task")
        self.assertFalse(value["nativeTokensMeasured"])
        self.assertFalse(value["scope"]["wholeTaskCoverageVerified"])
        self.assertEqual(value["runtime"], [])
        self.assertIn("missing", markdown(value))

    def test_reports_isolate_tasks_revisions_and_overlapping_categories(self):
        bind_session(self.home, "task", str(self.root))
        record(self.home, kind="native_usage", session="task", event_id="response", values={
            "input_tokens": 100, "cached_input_tokens": 80, "output_tokens": 10, "reasoning_tokens": 3})
        record(self.home, kind="hook", session="task", values={"duration_ms": 50})
        record(self.home, kind="checkpoint", session="task", values={"duration_ms": 35, "success": 1})
        record(self.home, kind="retrieval_routing", session="task", values={"routing_redirect": 1})
        record(self.home, kind="native_usage", session="other", event_id="response", values={"input_tokens": 999})
        value = report(self.home, "task")
        groups = {g["kind"]: g for g in value["runtime"]}
        self.assertEqual(groups["native_usage"]["metrics"]["input_tokens"], 100)
        self.assertEqual(groups["hook"]["metrics"]["duration_ms"], 50)
        self.assertEqual(groups["checkpoint"]["metrics"]["duration_ms"], 35)
        self.assertTrue(value["nativeTokensMeasured"])
        self.assertFalse(value["accountSavingsMeasured"])
        self.assertEqual(value["scope"]["retainedTaskRecords"], 4)
        self.assertEqual(len(value["timeline"]), 4)
        self.assertEqual(value["timelineOmittedRecords"], 0)
        self.assertNotIn("other", markdown(value))
