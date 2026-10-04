import tempfile
import unittest
import os
from pathlib import Path

from deskpilot.app import AuditLog, Planner, PolicyEngine, Step, Tools, LLMClient


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.audit = AuditLog(self.tmp / "audit.db")
        import threading
        self.policy = PolicyEngine([self.tmp])
        self.tools = Tools(self.policy, self.audit, threading.Event())
        self.planner = Planner(self.tools, LLMClient())

    def test_list_downloads_plan_is_read_only(self):
        plan = self.planner.rule_plan("list my downloads")
        self.assertEqual(plan.steps[0].tool, "filesystem.list")
        step = Step("filesystem.list", {"path": str(self.tmp)}, "List test directory", 0)
        self.assertEqual(self.policy.evaluate(step)["decision"], "allow")

    def test_command_requires_confirmation(self):
        step = Step("process.start", {"command": "python3 --version"}, "Run command", 2, True)
        decision = self.policy.evaluate(step)
        self.assertEqual(decision["decision"], "require_confirmation")

    def test_path_outside_allowlist_is_denied(self):
        step = Step("filesystem.read_text", {"path": "/etc/passwd"}, "Read system file", 0)
        decision = self.policy.evaluate(step)
        self.assertEqual(decision["decision"], "deny")

    def test_search_plan(self):
        plan = self.planner.rule_plan("find quarterly report in Downloads")
        self.assertEqual(plan.steps[0].tool, "filesystem.search")
        self.assertIn("quarterly report", plan.steps[0].arguments["query"])

    def test_system_status_executes(self):
        step = Step("system.status", {}, "System status", 0)
        output = self.tools.run(step)
        self.assertIn("Platform:", output)

    def test_power_actions_require_confirmation(self):
        plan = self.planner.rule_plan("restart computer")
        self.assertEqual(plan.steps[0].tool, "system.shutdown")
        self.assertEqual(self.policy.evaluate(plan.steps[0])["decision"], "require_confirmation")

    def test_window_and_audio_commands_are_planned(self):
        self.assertEqual(self.planner.rule_plan("list windows").steps[0].tool, "window.list")
        self.assertEqual(self.planner.rule_plan("mute sound").steps[0].tool, "system.mute")

    def test_offline_only_flag_is_understood(self):
        old = os.environ.get("DESKPILOT_OFFLINE_ONLY")
        os.environ["DESKPILOT_OFFLINE_ONLY"] = "1"
        try:
            from deskpilot.app import LLMClient
            self.assertTrue(LLMClient().offline_only)
        finally:
            if old is None:
                os.environ.pop("DESKPILOT_OFFLINE_ONLY", None)
            else:
                os.environ["DESKPILOT_OFFLINE_ONLY"] = old


if __name__ == "__main__":
    unittest.main()
