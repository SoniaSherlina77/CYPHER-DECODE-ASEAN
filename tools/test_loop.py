"""Focused tests for the agentic loop in loop/loop.py.

All model calls are faked: no network, no META_API_KEY, no helper server.
Run: PYTHONPATH=src python -m unittest discover -s tools
"""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("agent_loop", REPO / "loop" / "loop.py")
loop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loop)

SCAM_TEXT = "This is the police. Transfer your money to a safe account immediately."
FINAL_RED = (
    "This looks like a scam. The police never ask you to move money to a safe account. "
    "Stop. Do not click or pay. Check with your bank. Report and block."
)
CALM_TEXT = "Everything looks fine. You can go ahead."


def scripted(*responses):
    """Fake complete(): play each response in order, repeat the last one."""
    state = {"n": 0}

    def _complete(messages, tools):
        resp = responses[min(state["n"], len(responses) - 1)]
        state["n"] += 1
        return copy.deepcopy(resp)

    _complete.state = state
    return _complete


def tool_call(name, args):
    return {"content": "", "tool_calls": [{"name": name, "args": args}]}


def final_answer(content):
    return {"content": content, "tool_calls": []}


class LayoutTests(unittest.TestCase):
    def test_paths_point_at_repo_layout(self):
        self.assertTrue(loop.SYSTEM_PATH.is_file())
        self.assertTrue(loop.OBJECTIVE_PATH.is_file())
        self.assertTrue(loop.DATA_DIR.is_dir())
        self.assertEqual(loop.MEMO_PATH.parent, loop.BASE_DIR)
        self.assertEqual(loop.MEMO_PATH.name, "memo.md")

    def test_placeholders_all_filled_from_data(self):
        ctx = loop.load_runtime_context("MY")
        self.assertEqual(
            set(ctx), {"assistant_name", "official_contacts", "scam_blocklist", "trusted_contact", "hotline"}
        )
        filled = loop.fill_placeholders(loop.read_text(loop.SYSTEM_PATH), ctx)
        for key in ctx:
            self.assertNotIn("{{" + key + "}}", filled)
        self.assertIn("[unverified]", filled)  # draft data stays marked

    def test_build_tools_match_specs(self):
        tools = loop.build_tools()
        self.assertEqual(
            set(tools),
            {"check_url", "check_number", "check_file_name", "match_scam_pattern", "get_reporting_channel"},
        )
        self.assertEqual(set(tools), set(loop.TOOL_SPECS))
        result = json.loads(tools["match_scam_pattern"]({"text": SCAM_TEXT}))
        self.assertEqual(result["label"], "RED")


class TurnTests(unittest.TestCase):
    def test_final_answer_ends_turn(self):
        messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        done, text = loop.run_turn(messages, scripted(final_answer(FINAL_RED)), loop.build_tools())
        self.assertTrue(done)
        self.assertEqual(text, FINAL_RED)

    def test_unknown_tool_is_reported_not_raised(self):
        messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        done, _ = loop.run_turn(
            messages, scripted(tool_call("nope", {})), loop.build_tools()
        )
        self.assertFalse(done)
        self.assertIn("Unknown tool: nope", messages[-1]["content"])

    def test_tool_then_final(self):
        findings, trace = loop.run_loop_with_trace(
            "s",
            SCAM_TEXT,
            scripted(
                tool_call("match_scam_pattern", {"text": SCAM_TEXT}),
                final_answer(FINAL_RED),
            ),
            loop.build_tools(),
        )
        self.assertEqual(findings, FINAL_RED)
        self.assertEqual(trace.stop_reason, "final")
        self.assertEqual(trace.turns_used, 2)
        self.assertIn("match_scam_pattern: label=RED", trace.tool_summaries)


class StopTests(unittest.TestCase):
    def test_repeat_calls_stop(self):
        same = tool_call("match_scam_pattern", {"text": SCAM_TEXT})
        findings, trace = loop.run_loop_with_trace("s", SCAM_TEXT, scripted(same), loop.build_tools())
        self.assertEqual(trace.stop_reason, "repeat_calls")
        self.assertEqual(trace.turns_used, 3)
        self.assertIn("repeated", findings)

    def test_max_turns_stop(self):
        calls = scripted(
            tool_call("match_scam_pattern", {"text": "a"}),
            tool_call("match_scam_pattern", {"text": "b"}),
            tool_call("match_scam_pattern", {"text": "c"}),
        )
        _, trace = loop.run_loop_with_trace("s", SCAM_TEXT, calls, loop.build_tools(), max_turns=3)
        self.assertEqual(trace.stop_reason, "max_turns")
        self.assertEqual(trace.turns_used, 3)
        self.assertEqual(calls.state["n"], 3)


class CheckTests(unittest.TestCase):
    def test_offline_baseline_red(self):
        result = loop.check(SCAM_TEXT)
        self.assertEqual(result["label"], "RED")
        self.assertEqual(result["stop_reason"], "baseline")
        self.assertIn("Stop", result["reply"])
        self.assertIn("997", result["reply"])

    def test_emergency_short_circuits_without_model(self):
        def bomb(messages, tools):
            raise AssertionError("model must not be called for emergencies")

        result = loop.check("I already transferred RM500 to them", complete=bomb)
        self.assertEqual(result["intent"], "emergency")
        self.assertIn("Call your bank", result["reply"])

    def test_safety_net_overrules_uncautious_model(self):
        result = loop.check(SCAM_TEXT, complete=scripted(final_answer(CALM_TEXT)))
        self.assertIsNotNone(result["disagreement"])
        self.assertTrue(result["reply"].startswith("This looks like a scam."))

    def test_cautious_model_answer_is_kept(self):
        result = loop.check(SCAM_TEXT, complete=scripted(final_answer(FINAL_RED)))
        self.assertIsNone(result["disagreement"])
        self.assertEqual(result["reply"], FINAL_RED)

    def test_otp_is_redacted_before_model(self):
        seen = {}

        def capture(messages, tools):
            seen["user"] = messages[1]["content"]
            return final_answer(FINAL_RED)

        result = loop.check("My OTP 482913, the caller asked me to share it", complete=capture)
        self.assertNotIn("482913", seen["user"])
        self.assertIn("[CODE]", seen["user"])
        self.assertEqual(result["redacted"].get("code"), 1)

    def test_guardrails(self):
        text, corrections = loop.apply_guardrails("This is 100% safe, trust me.")
        self.assertNotIn("100% safe", text)
        self.assertTrue(corrections)
        text, _ = loop.apply_guardrails("This is 100% a scam.", confirmed=False)
        self.assertNotIn("100%", text)
        text, corrections = loop.apply_guardrails("This is 100% a scam.", confirmed=True)
        self.assertIn("100%", text)
        self.assertFalse(corrections)


class MemoTests(unittest.TestCase):
    def test_run_agent_files_memo(self):
        with tempfile.TemporaryDirectory() as tmp:
            memo_path = str(Path(tmp) / "memo.md")
            findings, memo = loop.run_agent(
                "s", SCAM_TEXT, scripted(final_answer(FINAL_RED)), {}, memo_path=memo_path
            )
            self.assertEqual(memo, memo_path)
            body = Path(memo).read_text(encoding="utf-8")
            self.assertIn("# Findings memo", body)
            self.assertIn(FINAL_RED, body)
            self.assertIn("stop_reason: final", body)
            self.assertNotIn(SCAM_TEXT, body)  # trace carries summaries, not user text


if __name__ == "__main__":
    unittest.main()
