import json
import tempfile
import unittest
from pathlib import Path

from scamhelper.triage import AMBER, GREENISH, RED, UNSURE, Blocklist, analyse
from scamhelper.messages import render

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL = {"maybank": ["maybank2u.com.my", "maybank.com"]}
EMPTY = Blocklist()


def check(text, **kw):
    return analyse(text, blocklist=kw.get("blocklist", EMPTY), official=kw.get("official", OFFICIAL))


class TriageTests(unittest.TestCase):
    def test_empty_is_unsure(self):
        self.assertEqual(check("  ").label, UNSURE)

    def test_safe_account_is_red(self):
        r = check("Transfer your money to a safe account now")
        self.assertEqual(r.label, RED)
        self.assertIn("safe_account", r.codes)

    def test_otp_request_flagged_but_real_otp_notice_not(self):
        self.assertIn("otp_request", check("Please send me your OTP").codes)
        self.assertNotIn("otp_request", check("Your OTP is 123456. Do not share it.").codes)

    def test_pinjam_does_not_trigger_pin(self):
        self.assertNotIn("otp_request", check("Boleh saya pinjam buku awak? tolong bagi esok").codes)

    def test_lookalike_domain(self):
        r = check("Login at http://maybank2u-secure-login.xyz/verify")
        self.assertIn("lookalike", r.codes)
        self.assertEqual(r.label, RED)

    def test_official_domain_not_lookalike(self):
        r = check("Visit https://www.maybank2u.com.my for your statement")
        self.assertNotIn("lookalike", r.codes)
        self.assertEqual(r.label, GREENISH)

    def test_apk_flagged(self):
        self.assertIn("apk", check("Install this app: update.apk").codes)

    def test_blocklist_number_is_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blocklist.txt"
            path.write_text("# fictional\n+60 12-345 6789\nbad-example.invalid\n", encoding="utf-8")
            bl = Blocklist.load(path)
        r = check("Call me on 012-345 6789 about your parcel", blocklist=bl)
        self.assertTrue(r.confirmed)
        self.assertEqual(r.label, RED)
        r = check("Go to http://login.bad-example.invalid/x", blocklist=bl)
        self.assertTrue(r.confirmed)

    def test_no_confirmed_flag_without_blocklist_hit(self):
        self.assertFalse(check("Transfer to safe account now").confirmed)

    def test_greenish_never_says_safe(self):
        text = render(check("See you at tea time tomorrow"), "en")
        self.assertNotIn("safe", text.lower())
        self.assertIn("cannot be 100% sure", text)


class RenderTests(unittest.TestCase):
    def test_all_languages_render_red(self):
        r = check("Transfer your money to a safe account now")
        for lang in ("en", "ms", "zh", "manglish"):
            out = render(r, lang, {"name": "Hotline", "phone": "000"})
            self.assertIn("Hotline", out)
            self.assertGreater(len(out.splitlines()), 3)

    def test_voice_mode_has_no_numbering_or_newlines(self):
        out = render(check("Transfer your money to a safe account now"), "en", voice=True)
        self.assertNotIn("\n", out)
        self.assertNotIn("1.", out)


class SampleSetTests(unittest.TestCase):
    def test_sample_cases(self):
        path = ROOT / "data" / "samples" / "test_cases.jsonl"
        official = json.loads((ROOT / "data" / "official_domains.json").read_text(encoding="utf-8"))
        official = {k: v for k, v in official.items() if not k.startswith("_")}
        for line in path.read_text(encoding="utf-8").splitlines():
            case = json.loads(line)
            r = analyse(case["text"], blocklist=EMPTY, official=official)
            with self.subTest(case=case["id"]):
                if case["label"] == "scam":
                    self.assertIn(r.label, (AMBER, RED))
                else:
                    self.assertEqual(r.label, GREENISH)


if __name__ == "__main__":
    unittest.main()
