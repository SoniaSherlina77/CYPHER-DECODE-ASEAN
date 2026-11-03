import unittest

from scamhelper import tools
from scamhelper.intents import detect_intent


class FileNameTests(unittest.TestCase):
    def test_apk_is_high(self):
        r = tools.check_file_name("update.apk")
        self.assertEqual(r["risk"], "high")
        self.assertIn("apk", r["codes"])

    def test_double_extension_is_high(self):
        r = tools.check_file_name("Invoice.PDF.apk")
        self.assertEqual(r["risk"], "high")
        self.assertIn("double_extension", r["codes"])

    def test_exe_is_medium(self):
        self.assertEqual(tools.check_file_name("setup.exe")["risk"], "medium")

    def test_pdf_is_low_and_notes_limits(self):
        r = tools.check_file_name("statement.pdf")
        self.assertEqual(r["risk"], "low")
        self.assertIn("not malware analysis", r["note"])


class OtherToolTests(unittest.TestCase):
    def test_number_not_listed_is_never_called_safe(self):
        r = tools.check_number("+60 19-876 5432")
        self.assertFalse(r["confirmed_scam"])
        self.assertEqual(r["label"], "UNSURE")
        self.assertIn("does not mean it is safe", r["note"])

    def test_short_number_is_unsure(self):
        self.assertEqual(tools.check_number("123")["label"], "UNSURE")

    def test_url_lookalike_without_scheme(self):
        r = tools.check_url("maybank2u-secure-login.xyz/verify")
        self.assertIn(r["label"], ("AMBER", "RED"))

    def test_reporting_channel(self):
        r = tools.get_reporting_channel("my")
        self.assertTrue(r["found"])
        self.assertIn("name", r)
        self.assertFalse(tools.get_reporting_channel("ZZ")["found"])

    def test_notify_trusted_contact_is_disabled(self):
        self.assertFalse(tools.notify_trusted_contact("hi", consent=True)["ok"])

    def test_call_tool_dispatch_and_errors(self):
        self.assertEqual(tools.call_tool("check_file_name", {"name": "a.apk"})["risk"], "high")
        self.assertIn("error", tools.call_tool("nope", {}))
        self.assertIn("error", tools.call_tool("check_url", {"wrong": 1}))

    def test_schemas_cover_callable_tools(self):
        for schema in tools.TOOL_SCHEMAS:
            self.assertIn(schema["name"], tools._FUNCTIONS)
            self.assertEqual(schema["input_schema"]["type"], "object")


class IntentTests(unittest.TestCase):
    def test_greeting(self):
        for text in ("hi", "Hello!", "bantuan", "你好"):
            self.assertEqual(detect_intent(text), "greeting", text)

    def test_emergency(self):
        for text in (
            "I already transferred RM5000 to them",
            "I shared my OTP with the caller",
            "saya dah transfer duit tadi",
            "我已经转账了",
            "kena tipu la",
        ):
            self.assertEqual(detect_intent(text), "emergency", text)

    def test_check_not_emergency(self):
        for text in (
            "They say I must transfer money to a safe account",
            "Should I share my OTP?",
            "Polis suruh transfer duit",
        ):
            self.assertEqual(detect_intent(text), "check", text)


if __name__ == "__main__":
    unittest.main()
