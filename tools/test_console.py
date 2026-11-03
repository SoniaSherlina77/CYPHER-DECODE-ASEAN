import importlib.util
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("console_ui", REPO / "ui" / "ui.py")
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)


class ConsoleTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / "data"
        shutil.copytree(REPO / "data", self.data)
        self.c = ui.Console(self.tmp, self.data, "tok")
        self.addCleanup(self.c.shutdown)

    def call(self, method, path, body=None, query=None):
        return self.c.handle(method, path, query or {}, body or {})

    def wait_job(self, job_id, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            code, job = self.call("GET", f"/api/jobs/{job_id}")
            if job["status"] != "running":
                return job
            time.sleep(0.05)
        self.fail("job did not finish")


class CheckAndSteerTests(ConsoleTestCase):
    def test_check_returns_verdict_reply_and_reasons(self):
        code, r = self.call("POST", "/api/check", {"text": "Transfer to a safe account now", "lang": "en"})
        self.assertEqual(code, 200)
        self.assertEqual(r["label"], "RED")
        self.assertIn("scam", r["reply"].lower())
        self.assertTrue(r["reasons"])
        self.assertEqual(r["thresholds"], [5, 2])

    def test_threshold_validation(self):
        for red, amber in ((1, 1), (11, 2), (5, 5), (5, 0), ("x", 2)):
            code, r = self.call("POST", "/api/config", {"red_threshold": red, "amber_threshold": amber, "default_country": "MY"})
            self.assertEqual(code, 400, (red, amber))

    def test_saved_thresholds_change_verdicts(self):
        text = "Please pay the courier parcel fee at https://bit.ly/abc"
        self.assertEqual(self.call("POST", "/api/check", {"text": text})[1]["label"], "RED")
        code, _ = self.call("POST", "/api/config", {"red_threshold": 9, "amber_threshold": 3, "default_country": "SG"})
        self.assertEqual(code, 200)
        self.assertEqual(self.call("POST", "/api/check", {"text": text})[1]["label"], "AMBER")
        self.assertEqual(self.c.config()["default_country"], "SG")

    def test_simulate_does_not_save(self):
        code, r = self.call("POST", "/api/simulate", {"red_threshold": 3, "amber_threshold": 1})
        self.assertEqual(code, 200)
        self.assertEqual(r["current"]["red"], 5)
        self.assertEqual(r["proposed"]["red"], 3)
        self.assertEqual(self.c.config()["red_threshold"], 5)
        self.assertGreaterEqual(r["proposed"]["recall"], r["current"]["recall"])

    def test_data_file_validation_and_backup(self):
        code, r = self.call("PUT", "/api/data/contacts", {"content": "{not json"})
        self.assertEqual(code, 400)
        code, r = self.call("PUT", "/api/data/contacts", {"content": json.dumps({"MY": {"name": "X"}})})
        self.assertEqual(code, 400)
        good = json.dumps({"MY": {"name": "NSRC", "phone": "997", "verified": True}})
        self.assertEqual(self.call("PUT", "/api/data/contacts", {"content": good})[0], 200)
        self.assertTrue((self.data / "contacts.json.bak").exists())
        self.assertEqual(self.call("PUT", "/api/data/nope", {"content": "x"})[0], 404)

    def test_blocklist_edit_takes_effect(self):
        self.call("PUT", "/api/data/blocklist", {"content": "+60 12-345 6789\n"})
        code, r = self.call("POST", "/api/check", {"text": "Call me on 012-345 6789 now"})
        self.assertTrue(r["confirmed"])
        self.assertEqual(r["label"], "RED")


class ReviewTests(ConsoleTestCase):
    def test_review_roundtrip_and_disagreements(self):
        code, r = self.call("POST", "/api/review", {"text": "Hi mak, see you at six", "expected": "benign"})
        self.assertEqual((code, r["id"]), (200, "review-0001"))
        self.call("POST", "/api/review", {"text": "Congratulations, we have a gift for you, send your details", "expected": "scam"})
        code, r = self.call("GET", "/api/review")
        self.assertEqual((r["count"], r["scam"], r["benign"]), (2, 1, 1))
        self.assertEqual([d["id"] for d in r["disagreements"]], ["review-0002"])  # a miss: rules said not flagged

    def test_review_validation(self):
        self.assertEqual(self.call("POST", "/api/review", {"text": "hello there", "expected": "maybe"})[0], 400)
        self.assertEqual(self.call("POST", "/api/review", {"text": "x", "expected": "scam"})[0], 400)

    def test_audit_never_contains_message_text(self):
        secret = "my-private-message-text"
        self.call("POST", "/api/review", {"text": secret, "expected": "benign"})
        self.assertNotIn(secret, "\n".join(self.c.audit_lines))
        self.assertNotIn(secret, (self.tmp / "ui" / ".console-audit.log").read_text())


class JobTests(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.c.catalog["echo"] = {"label": "Echo", "desc": "t", "cmd": [sys.executable, "-c", "print('hello'); print('world')"]}
        self.c.catalog["slow"] = {"label": "Slow", "desc": "t", "cmd": [sys.executable, "-c", "import time; print('start', flush=True); time.sleep(30)"], "long_running": True}
        self.c.catalog["needs"] = {"label": "Needs", "desc": "t", "cmd": [sys.executable, "-c", "pass"], "needs_env": ["SCAMHELPER_TEST_MISSING_VAR"]}

    def test_job_runs_and_streams_lines(self):
        code, job = self.call("POST", "/api/jobs", {"name": "echo"})
        self.assertEqual(code, 200)
        done = self.wait_job(job["id"])
        self.assertEqual(done["status"], "done")
        code, r = self.call("GET", f"/api/jobs/{job['id']}", query={"since": ["1"]})
        self.assertEqual(r["lines"], ["world"])
        self.assertEqual(r["next"], 2)

    def test_unknown_job_and_missing_env(self):
        self.assertEqual(self.call("POST", "/api/jobs", {"name": "rm -rf"})[0], 404)
        code, r = self.call("POST", "/api/jobs", {"name": "needs"})
        self.assertEqual(code, 400)
        self.assertIn("SCAMHELPER_TEST_MISSING_VAR", r["error"])

    def test_stop_and_no_double_start(self):
        code, job = self.call("POST", "/api/jobs", {"name": "slow"})
        self.assertEqual(self.call("POST", "/api/jobs", {"name": "slow"})[0], 409)
        self.call("POST", f"/api/jobs/{job['id']}/stop")
        self.assertEqual(self.wait_job(job["id"])["status"], "stopped")

    def test_evaluate_result_is_parsed_into_readiness(self):
        (self.tmp / "scripts").mkdir()
        shutil.copy(REPO / "scripts" / "evaluate.py", self.tmp / "scripts" / "evaluate.py")
        shutil.copytree(REPO / "src", self.tmp / "src")
        self.c.catalog["evaluate"]["cmd"] = [sys.executable, "scripts/evaluate.py", str(self.data / "samples" / "test_cases.jsonl")]
        code, job = self.call("POST", "/api/jobs", {"name": "evaluate"})
        self.wait_job(job["id"])
        time.sleep(0.2)
        item = next(i for i in self.c.readiness() if i["key"] == "evaluation")
        self.assertTrue(item["ok"], item)

    def test_readiness_reflects_unverified_data_and_manual_items(self):
        ready = {i["key"]: i for i in self.c.readiness()}
        self.assertFalse(ready["hotlines"]["ok"])
        self.assertFalse(ready["native_review"]["ok"])
        self.call("POST", "/api/manual", {"key": "native_review", "value": True})
        self.assertTrue({i["key"]: i for i in self.c.readiness()}["native_review"]["ok"])
        self.assertEqual(self.call("POST", "/api/manual", {"key": "bogus", "value": True})[0], 404)


class HttpTests(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ui.make_handler(self.c))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def req(self, path, token=None, data=None, method=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Console-Token"] = token
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def test_page_is_served_without_token_and_has_security_headers(self):
        status, body, headers = self.req("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Scam Helper", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_api_requires_the_token(self):
        self.assertEqual(self.req("/api/state")[0], 401)
        self.assertEqual(self.req("/api/state", token="wrong")[0], 401)
        self.assertEqual(self.req("/api/state", token="tok")[0], 200)
        self.assertEqual(self.req("/api/check", token="bad", data={"text": "x"}, method="POST")[0], 401)

    def test_check_over_http_and_bad_json(self):
        status, body, _ = self.req("/api/check", token="tok", data={"text": "safe account transfer now"}, method="POST")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["label"], "RED")
        request = urllib.request.Request(
            self.base + "/api/check", data=b"[1,2]", method="POST",
            headers={"X-Console-Token": "tok", "Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
