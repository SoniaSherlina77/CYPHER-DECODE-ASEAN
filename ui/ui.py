#!/usr/bin/env python3
"""Scam Helper agent console: start, watch and steer the project from a browser.

    python3 ui/ui.py            # then open the URL it prints

What it is: a small local web app (standard library only) that serves one prebuilt page.
  START  run the unit tests, the sample evaluation, or the WhatsApp webhook as managed jobs
  WATCH  live job log, status pills, and a readiness checklist for the project
  STEER  check a message, tune the RED/AMBER thresholds with a before/after preview, edit the
         blocklist / hotline / official-domain files, and label cases to grow a review set

What it is NOT: it does not run an AI agent. The project has no LLM agent yet; this console
drives the rule-based triage, the tests and the WhatsApp webhook that exist today.

Security: binds to 127.0.0.1 by default. Every /api call needs the token printed at start-up.
Only the fixed jobs in CATALOG can run (no arbitrary commands). Message text is never written
to the audit log. Secrets from .env go only to the WhatsApp child process and are never shown.
"""

from __future__ import annotations

import argparse
import atexit
import datetime as dt
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scamhelper import triage  # noqa: E402
from scamhelper.lang import detect_language  # noqa: E402
from scamhelper.messages import LANGS, REASONS, render  # noqa: E402

VERSION = "0.1.0"
MAX_BODY = 1_000_000
MAX_LOG_LINES = 5000
WHATSAPP_ENV = ["WHATSAPP_VERIFY_TOKEN", "WHATSAPP_APP_SECRET", "WHATSAPP_ACCESS_TOKEN", "WHATSAPP_PHONE_NUMBER_ID"]

PY = sys.executable
CATALOG = {
    "tests": {
        "label": "Run tests",
        "desc": "Runs the unit tests. They should all pass.",
        "cmd": [PY, "-m", "unittest", "discover", "-s", "tests", "-v"],
    },
    "evaluate": {
        "label": "Evaluate samples",
        "desc": "Scores the synthetic sample cases: scam recall and false alarms. A smoke test, not an accuracy claim.",
        "cmd": [PY, "scripts/evaluate.py"],
    },
    "evaluate_reviewed": {
        "label": "Evaluate samples + review set",
        "desc": "Scores the samples plus the cases you labelled in this console.",
        "cmd": [PY, "scripts/evaluate.py", "data/samples/test_cases.jsonl", "data/samples/reviewed.jsonl"],
    },
    "whatsapp": {
        "label": "WhatsApp bot",
        "desc": "Starts the WhatsApp webhook. Needs the credentials in .env and a public HTTPS URL that Meta can reach. Not yet tested against a live account.",
        "cmd": [PY, "-m", "scamhelper.whatsapp"],
        "long_running": True,
        "needs_env": WHATSAPP_ENV,
    },
}

DATA_FILES = {
    "blocklist": ("blocklist.txt", "Confirmed scam numbers and domains, one per line. Official sources only."),
    "contacts": ("contacts.json", "Hotlines by country. Set \"verified\": true only after checking the official source."),
    "official_domains": ("official_domains.json", "Brand to official domains, used to catch lookalike links. Add \"_verified\": true after you check every entry."),
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip().strip("'\"")
    return env


class ApiError(Exception):
    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code


class Job:
    def __init__(self, job_id: int, name: str, proc: subprocess.Popen):
        self.id, self.name, self.proc = job_id, name, proc
        self.status = "running"
        self.started = now()
        self.ended: str | None = None
        self.returncode: int | None = None
        self.stop_requested = False
        self.lines: list[str] = []
        self.base = 0  # how many old lines were dropped from the front
        self.lock = threading.Lock()

    def add(self, line: str) -> None:
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > MAX_LOG_LINES:
                del self.lines[:1000]
                self.base += 1000

    def since(self, index: int) -> tuple[list[str], int]:
        with self.lock:
            start = max(index - self.base, 0)
            return self.lines[start:], self.base + len(self.lines)

    def summary(self) -> dict:
        return {
            "id": self.id, "name": self.name, "status": self.status,
            "started": self.started, "ended": self.ended, "returncode": self.returncode,
        }


class Console:
    """All console logic, independent of HTTP so it can be tested directly."""

    def __init__(self, root: Path, data: Path, token: str):
        self.root, self.data, self.token = root, data, token
        self.catalog = {k: dict(v) for k, v in CATALOG.items()}
        self.jobs: dict[int, Job] = {}
        self.next_id = 1
        self.last: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.state_file = root / "ui" / ".console-state.json"
        self.audit_file = root / "ui" / ".console-audit.log"
        self.audit_lines: list[str] = []

    # ---- small helpers ----------------------------------------------------------------

    def audit(self, action: str, detail: str = "") -> None:
        line = f"{now()} | {action} | {detail}".rstrip(" |")
        self.audit_lines.append(line)
        del self.audit_lines[:-200]
        try:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def config(self) -> dict:
        return triage.load_config(self.data / "config.json")

    def contacts(self) -> dict:
        path = self.data / "contacts.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)}

    def official(self) -> dict:
        return triage.load_official_domains(self.data / "official_domains.json")

    def blocklist(self) -> triage.Blocklist:
        return triage.Blocklist.load(self.data / "blocklist.txt")

    def reviewed_path(self) -> Path:
        return self.data / "samples" / "reviewed.jsonl"

    def read_jsonl(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def manual(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8")).get("manual", {})
        except (OSError, ValueError):
            return {}

    def child_env(self) -> dict:
        env = dict(os.environ)
        env.update(load_env_file(self.root / ".env"))
        env["PYTHONPATH"] = str(self.root / "src")
        env["PYTHONUNBUFFERED"] = "1"
        env["SCAMHELPER_DATA"] = str(self.data)
        return env

    def missing_env(self, name: str) -> list[str]:
        env = self.child_env()
        return [k for k in self.catalog[name].get("needs_env", []) if not env.get(k)]

    # ---- checking and steering --------------------------------------------------------

    def api_check(self, body: dict) -> dict:
        text = str(body.get("text", ""))[:2000]
        cfg = self.config()
        result = triage.analyse(
            text, blocklist=self.blocklist(), official=self.official(),
            thresholds=(cfg["red_threshold"], cfg["amber_threshold"]),
        )
        lang = body.get("lang", "auto")
        lang = detect_language(text) if lang == "auto" else lang
        if lang not in LANGS:
            raise ApiError("unknown language")
        contact = self.contacts().get(cfg["default_country"])
        reply = render(result, lang, contact, voice=bool(body.get("voice")))
        return {
            **result.to_dict(), "lang": lang, "reply": reply,
            "reasons": [REASONS[c]["en"] for c in result.codes if c in REASONS],
            "thresholds": [cfg["red_threshold"], cfg["amber_threshold"]],
        }

    def all_cases(self) -> list[dict]:
        return self.read_jsonl(self.data / "samples" / "test_cases.jsonl") + self.read_jsonl(self.reviewed_path())

    def metrics(self, red: int, amber: int) -> dict:
        cases = self.all_cases()
        blocklist, official = self.blocklist(), self.official()
        scams = benign = caught = red_on_scam = false_alarms = 0
        for case in cases:
            label = triage.analyse(case["text"], blocklist=blocklist, official=official, thresholds=(red, amber)).label
            flagged = label in (triage.AMBER, triage.RED)
            if case.get("label") == "scam":
                scams += 1
                caught += flagged
                red_on_scam += label == triage.RED
            elif case.get("label") == "benign":
                benign += 1
                false_alarms += flagged
        return {
            "red": red, "amber": amber, "cases": len(cases), "scams": scams, "benign": benign,
            "recall": caught / scams if scams else None,
            "red_on_scam": red_on_scam / scams if scams else None,
            "false_alarm": false_alarms / benign if benign else None,
        }

    @staticmethod
    def validate_thresholds(red, amber) -> tuple[int, int]:
        try:
            red, amber = int(red), int(amber)
        except (TypeError, ValueError):
            raise ApiError("thresholds must be whole numbers")
        if not (2 <= red <= 10):
            raise ApiError("RED threshold must be between 2 and 10")
        if not (1 <= amber < red):
            raise ApiError("AMBER threshold must be at least 1 and below the RED threshold")
        return red, amber

    def api_simulate(self, body: dict) -> dict:
        red, amber = self.validate_thresholds(body.get("red_threshold"), body.get("amber_threshold"))
        cfg = self.config()
        return {
            "current": self.metrics(cfg["red_threshold"], cfg["amber_threshold"]),
            "proposed": self.metrics(red, amber),
        }

    def api_config_post(self, body: dict) -> dict:
        red, amber = self.validate_thresholds(body.get("red_threshold"), body.get("amber_threshold"))
        country = str(body.get("default_country", "")).upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise ApiError("country must be a two-letter code, for example MY")
        cfg = {"red_threshold": red, "amber_threshold": amber, "default_country": country}
        self.write_atomic(self.data / "config.json", json.dumps(cfg, indent=2) + "\n")
        self.audit("config.update", f"red={red} amber={amber} country={country}")
        return cfg

    # ---- data files -------------------------------------------------------------------

    @staticmethod
    def write_atomic(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)

    def api_data_get(self, name: str) -> dict:
        if name not in DATA_FILES:
            raise ApiError("unknown file", 404)
        filename, hint = DATA_FILES[name]
        path = self.data / filename
        return {"name": name, "filename": filename, "hint": hint,
                "content": path.read_text(encoding="utf-8") if path.exists() else ""}

    def api_data_put(self, name: str, body: dict) -> dict:
        if name not in DATA_FILES:
            raise ApiError("unknown file", 404)
        content = body.get("content")
        if not isinstance(content, str) or len(content) > 200_000:
            raise ApiError("content must be text under 200 KB")
        filename = DATA_FILES[name][0]
        if name == "blocklist":
            lines = content.splitlines()
            if len(lines) > 5000 or any(len(line) > 200 for line in lines):
                raise ApiError("blocklist: at most 5000 lines of 200 characters")
        else:
            try:
                parsed = json.loads(content)
            except ValueError as exc:
                raise ApiError(f"not valid JSON: {exc}")
            if not isinstance(parsed, dict):
                raise ApiError("top level must be a JSON object")
            entries = {k: v for k, v in parsed.items() if not k.startswith("_")}
            if name == "contacts":
                for country, entry in entries.items():
                    if not (isinstance(entry, dict) and isinstance(entry.get("name"), str) and isinstance(entry.get("phone"), str)):
                        raise ApiError(f"contacts.{country} needs text fields \"name\" and \"phone\"")
            else:
                for brand, domains in entries.items():
                    if not (isinstance(domains, list) and all(isinstance(d, str) for d in domains)):
                        raise ApiError(f"official_domains.{brand} must be a list of domain strings")
        path = self.data / filename
        if path.exists():
            path.with_suffix(path.suffix + ".bak").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        self.write_atomic(path, content if content.endswith("\n") else content + "\n")
        self.audit("data.save", filename)
        return {"saved": filename}

    # ---- review set -------------------------------------------------------------------

    def api_review_post(self, body: dict) -> dict:
        text = str(body.get("text", "")).strip()
        expected = body.get("expected")
        if expected not in ("scam", "benign"):
            raise ApiError("expected must be \"scam\" or \"benign\"")
        if not (3 <= len(text) <= 2000):
            raise ApiError("text must be 3 to 2000 characters")
        cfg = self.config()
        predicted = triage.analyse(
            text, blocklist=self.blocklist(), official=self.official(),
            thresholds=(cfg["red_threshold"], cfg["amber_threshold"]),
        ).label
        existing = self.read_jsonl(self.reviewed_path())
        case_id = f"review-{len(existing) + 1:04d}"
        record = {
            "id": case_id, "lang": detect_language(text), "label": expected, "text": text,
            "note": str(body.get("note", ""))[:200], "predicted": predicted, "added": now(),
        }
        path = self.reviewed_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.audit("review.add", f"{case_id} ({expected})")  # never log the text itself
        return {"id": case_id, "count": len(existing) + 1}

    def api_review_get(self) -> dict:
        cases = self.read_jsonl(self.reviewed_path())
        flagged = (triage.AMBER, triage.RED)
        disagreements = [
            {"id": c["id"], "label": c["label"], "predicted": c.get("predicted"), "text": c["text"][:140]}
            for c in cases
            if (c["label"] == "scam" and c.get("predicted") not in flagged)
            or (c["label"] == "benign" and c.get("predicted") in flagged)
        ]
        return {
            "count": len(cases),
            "scam": sum(c["label"] == "scam" for c in cases),
            "benign": sum(c["label"] == "benign" for c in cases),
            "disagreements": disagreements[-20:],
            "recent": [{"id": c["id"], "label": c["label"], "predicted": c.get("predicted"), "text": c["text"][:140]}
                       for c in cases[-10:]][::-1],
        }

    # ---- jobs -------------------------------------------------------------------------

    def api_job_start(self, body: dict) -> dict:
        name = body.get("name")
        if name not in self.catalog:
            raise ApiError("unknown job", 404)
        spec = self.catalog[name]
        with self.lock:
            if any(j.name == name and j.status == "running" for j in self.jobs.values()):
                raise ApiError(f"{spec['label']} is already running", 409)
            missing = self.missing_env(name)
            if missing:
                raise ApiError("Missing in .env: " + ", ".join(missing))
            if name == "evaluate_reviewed" and not self.reviewed_path().exists():
                raise ApiError("No review set yet. Label some cases first.")
            proc = subprocess.Popen(
                spec["cmd"], cwd=self.root, env=self.child_env(), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8", errors="replace",
            )
            job = Job(self.next_id, name, proc)
            self.jobs[job.id] = job
            self.next_id += 1
            for old in sorted(self.jobs)[:-20]:
                if self.jobs[old].status != "running":
                    del self.jobs[old]
        threading.Thread(target=self._watch, args=(job,), daemon=True).start()
        self.audit("job.start", f"{name} #{job.id}")
        return job.summary()

    def _watch(self, job: Job) -> None:
        assert job.proc.stdout is not None
        for line in job.proc.stdout:
            job.add(line.rstrip("\n"))
        job.proc.stdout.close()
        job.returncode = job.proc.wait()
        job.ended = now()
        job.status = "stopped" if job.stop_requested else ("done" if job.returncode == 0 else "failed")
        self._record_result(job)

    def _record_result(self, job: Job) -> None:
        if job.status == "stopped":
            return
        entry: dict = {"at": job.ended, "ok": job.returncode == 0, "job": job.id}
        if job.name.startswith("evaluate"):
            text = "\n".join(job.since(0)[0])
            recall = re.search(r"scam recall:\s+(\d+)%\s+missed: (.*)", text)
            fa = re.search(r"false-alarm rate:\s+(\d+)%", text)
            if recall and fa:
                entry.update(recall=int(recall.group(1)), missed=recall.group(2).strip(), false_alarm=int(fa.group(1)))
        self.last[job.name] = entry

    def api_job_get(self, job_id: int, since: int) -> dict:
        job = self.jobs.get(job_id)
        if not job:
            raise ApiError("no such job", 404)
        lines, nxt = job.since(since)
        return {**job.summary(), "lines": lines, "next": nxt}

    def api_job_stop(self, job_id: int) -> dict:
        job = self.jobs.get(job_id)
        if not job:
            raise ApiError("no such job", 404)
        if job.status == "running":
            job.stop_requested = True
            job.proc.terminate()
            self.audit("job.stop", f"{job.name} #{job.id}")
        return job.summary()

    def shutdown(self) -> None:
        for job in self.jobs.values():
            if job.status == "running":
                job.stop_requested = True
                job.proc.terminate()

    # ---- state and readiness ----------------------------------------------------------

    def api_manual(self, body: dict) -> dict:
        key, value = body.get("key"), bool(body.get("value"))
        if key not in MANUAL_ITEMS:
            raise ApiError("unknown item", 404)
        manual = self.manual()
        manual[key] = value
        self.write_atomic(self.state_file, json.dumps({"manual": manual}, indent=2) + "\n")
        self.audit("manual.set", f"{key}={value}")
        return {"manual": manual}

    def readiness(self) -> list[dict]:
        contacts = self.contacts()
        unverified = [c for c, e in contacts.items() if not e.get("verified")]
        try:
            domains_ok = bool(json.loads((self.data / "official_domains.json").read_text(encoding="utf-8")).get("_verified"))
        except (OSError, ValueError):
            domains_ok = False
        tests, ev = self.last.get("tests"), self.last.get("evaluate_reviewed") or self.last.get("evaluate")
        missing = self.missing_env("whatsapp")
        items = [
            {"key": "tests", "label": "Unit tests pass", "ok": bool(tests and tests["ok"]),
             "detail": "Not run yet" if not tests else ("Passed" if tests["ok"] else "Last run failed")},
            {"key": "evaluation", "label": "Evaluation clean (no misses, no false alarms)",
             "ok": bool(ev and ev["ok"] and ev.get("missed") == "none" and ev.get("false_alarm") == 0),
             "detail": "Not run yet" if not ev else
             f"Recall {ev.get('recall', '?')}%, false alarms {ev.get('false_alarm', '?')}%, missed {ev.get('missed', '?')}"},
            {"key": "hotlines", "label": "Hotlines verified against official sources", "ok": bool(contacts) and not unverified,
             "detail": "All verified" if contacts and not unverified else "Unverified: " + (", ".join(unverified) or "none loaded")},
            {"key": "domains", "label": "Official domains verified", "ok": domains_ok,
             "detail": "Marked verified" if domains_ok else "Add \"_verified\": true to official_domains.json after checking"},
            {"key": "whatsapp_env", "label": "WhatsApp credentials present in .env", "ok": not missing,
             "detail": "All set" if not missing else "Missing: " + ", ".join(missing)},
        ]
        manual = self.manual()
        for key, label in MANUAL_ITEMS.items():
            items.append({"key": key, "label": label, "ok": bool(manual.get(key)), "manual": True,
                          "detail": "Confirmed by you" if manual.get(key) else "Needs a human"})
        return items

    def api_state(self) -> dict:
        running = {j.name: j.id for j in self.jobs.values() if j.status == "running"}
        catalog = []
        for name, spec in self.catalog.items():
            catalog.append({
                "name": name, "label": spec["label"], "desc": spec["desc"],
                "long_running": bool(spec.get("long_running")), "running_job": running.get(name),
                "missing_env": self.missing_env(name), "last": self.last.get(name),
            })
        return {
            "version": VERSION, "repo": self.root.name, "config": self.config(),
            "countries": sorted(self.contacts()), "catalog": catalog,
            "jobs": [j.summary() for j in sorted(self.jobs.values(), key=lambda j: -j.id)],
            "readiness": self.readiness(), "review": {"count": len(self.read_jsonl(self.reviewed_path()))},
            "audit": self.audit_lines[-30:][::-1],
        }

    # ---- routing ----------------------------------------------------------------------

    def handle(self, method: str, path: str, query: dict, body: dict) -> tuple[int, dict]:
        try:
            if method == "GET" and path == "/api/state":
                return 200, self.api_state()
            if method == "POST" and path == "/api/check":
                return 200, self.api_check(body)
            if method == "POST" and path == "/api/simulate":
                return 200, self.api_simulate(body)
            if method == "POST" and path == "/api/config":
                return 200, self.api_config_post(body)
            if method == "GET" and path == "/api/review":
                return 200, self.api_review_get()
            if method == "POST" and path == "/api/review":
                return 200, self.api_review_post(body)
            if method == "POST" and path == "/api/jobs":
                return 200, self.api_job_start(body)
            if method == "POST" and path == "/api/manual":
                return 200, self.api_manual(body)
            m = re.fullmatch(r"/api/data/([a-z_]+)", path)
            if m and method == "GET":
                return 200, self.api_data_get(m.group(1))
            if m and method == "PUT":
                return 200, self.api_data_put(m.group(1), body)
            m = re.fullmatch(r"/api/jobs/(\d+)", path)
            if m and method == "GET":
                return 200, self.api_job_get(int(m.group(1)), int(query.get("since", ["0"])[0] or 0))
            m = re.fullmatch(r"/api/jobs/(\d+)/stop", path)
            if m and method == "POST":
                return 200, self.api_job_stop(int(m.group(1)))
            return 404, {"error": "not found"}
        except ApiError as exc:
            return exc.code, {"error": str(exc)}


MANUAL_ITEMS = {
    "native_review": "Native speakers reviewed the Malay, Chinese and Manglish wording",
    "live_whatsapp": "Tested with a live WhatsApp test number",
    "meta_terms": "Read Meta's current WhatsApp Business terms (including AI chatbot rules)",
    "ethics": "Consent and ethics review done before testing with real elders",
    "readability": "Readability test with the target group done",
}


def make_handler(console: Console):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ScamHelperConsole"

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if ctype.startswith("text/html"):
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
                )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: dict) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _route(self, method: str) -> None:
            parsed = urlparse(self.path)
            if method == "GET" and parsed.path == "/":
                return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
            if method == "GET" and parsed.path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if not parsed.path.startswith("/api/"):
                return self._json(404, {"error": "not found"})
            supplied = self.headers.get("X-Console-Token", "")
            if not hmac.compare_digest(supplied.encode(), console.token.encode()):
                return self._json(401, {"error": "Missing or wrong token. Open the full URL printed in the terminal."})
            body: dict = {}
            if method in ("POST", "PUT"):
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._json(413, {"error": "request too large"})
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    return self._json(400, {"error": "body must be a JSON object"})
            try:
                code, obj = console.handle(method, parsed.path, parse_qs(parsed.query), body)
            except Exception as exc:  # keep the console alive; never echo request content
                console.audit("error", type(exc).__name__)
                code, obj = 500, {"error": f"internal error: {type(exc).__name__}"}
            self._json(code, obj)

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_PUT(self):
            self._route("PUT")

        def log_message(self, *args):
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scam Helper agent console")
    parser.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (this computer only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.environ.get("CONSOLE_TOKEN"), help="fixed token (default: random each run)")
    parser.add_argument("--open", action="store_true", help="open the URL in your browser")
    args = parser.parse_args(argv)

    token = args.token or secrets.token_urlsafe(16)
    console = Console(ROOT, triage.data_dir(), token)
    atexit.register(console.shutdown)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(console))
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{shown_host}:{args.port}/?token={token}"
    print("Scam Helper agent console")
    print(f"  Open this URL: {url}")
    print("  Stop with Ctrl+C. The token changes every run unless you pass --token.")
    if args.host not in ("127.0.0.1", "localhost"):
        print("  WARNING: listening beyond this computer. Anyone who can reach this port AND has the token")
        print("  can run the project's jobs and edit its data files. Use a trusted network or add HTTPS and your own login.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        console.shutdown()
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scam Helper Console</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1b1f24;--muted:#5b6571;--border:#d9dee5;--accent:#1f6feb;--accent-ink:#fff;
--red:#c8281d;--red-bg:#fdecea;--amber:#9a5b00;--amber-bg:#fff3dc;--green:#1a7f37;--green-bg:#e6f6ea;--grey:#57606a;--grey-bg:#eef0f3;--log-bg:#0f1720;--log-text:#d6e2f0;--radius:10px}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--panel:#161b22;--text:#e6edf3;--muted:#9aa7b4;--border:#2d3540;--accent:#4c8dff;--accent-ink:#06101f;
--red:#ff7b72;--red-bg:#3a1618;--amber:#e3b341;--amber-bg:#3a2b0a;--green:#56d364;--green-bg:#0f2e1a;--grey:#9aa7b4;--grey-bg:#222a33;--log-bg:#0a0e13}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding-bottom:260px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 16px;background:var(--panel);border-bottom:1px solid var(--border)}
.brand{font-weight:700;font-size:17px}.brand small{color:var(--muted);font-weight:500;margin-left:6px}
.pills{display:flex;flex-wrap:wrap;gap:8px}
.pill{border:1px solid var(--border);border-radius:999px;padding:3px 10px;font-size:13px;background:var(--grey-bg);color:var(--grey)}
.pill.ok{background:var(--green-bg);color:var(--green);border-color:transparent}.pill.bad{background:var(--red-bg);color:var(--red);border-color:transparent}.pill.warn{background:var(--amber-bg);color:var(--amber);border-color:transparent}
nav{display:flex;gap:4px;padding:8px 12px 0;overflow-x:auto;border-bottom:1px solid var(--border);background:var(--panel)}
nav button{background:none;border:0;border-bottom:3px solid transparent;color:var(--muted);padding:10px 14px;font:inherit;cursor:pointer;white-space:nowrap}
nav button[aria-selected=true]{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
main{max-width:1000px;margin:0 auto;padding:16px}
section{display:none}section.active{display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:14px}
.card h2{margin:0 0 4px;font-size:16px}.card p.hint{margin:0 0 12px;color:var(--muted);font-size:13.5px}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
textarea,input,select{font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px;max-width:100%}
textarea{width:100%;min-height:96px;resize:vertical}textarea.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;min-height:220px}
input[type=number]{width:84px}
button.btn{font:inherit;border:1px solid var(--border);background:var(--panel);color:var(--text);padding:8px 14px;border-radius:8px;cursor:pointer}
button.btn:hover{border-color:var(--accent)}button.btn.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent);font-weight:600}
button.btn:disabled{opacity:.5;cursor:not-allowed}
.banner{background:var(--amber-bg);color:var(--amber);border-radius:8px;padding:8px 12px;font-size:13.5px;margin-bottom:12px}
.verdict{display:inline-flex;gap:8px;align-items:center;padding:6px 12px;border-radius:8px;font-weight:700}
.verdict.RED{background:var(--red-bg);color:var(--red)}.verdict.AMBER{background:var(--amber-bg);color:var(--amber)}.verdict.GREENISH{background:var(--green-bg);color:var(--green)}.verdict.UNSURE{background:var(--grey-bg);color:var(--grey)}
pre.reply{white-space:pre-wrap;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;margin:10px 0;font:inherit}
ul.plain{margin:6px 0;padding-left:20px}.muted{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted);font-weight:600}
.job{display:flex;flex-direction:column;gap:8px}.status{font-size:12.5px;padding:2px 8px;border-radius:6px;background:var(--grey-bg);color:var(--grey)}
.status.running{background:var(--amber-bg);color:var(--amber)}.status.done{background:var(--green-bg);color:var(--green)}.status.failed{background:var(--red-bg);color:var(--red)}
.check{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}.check:last-child{border-bottom:0}.mark{width:22px;text-align:center;font-weight:700}
.mark.ok{color:var(--green)}.mark.no{color:var(--red)}
.dock{position:fixed;left:0;right:0;bottom:0;background:var(--log-bg);color:var(--log-text);border-top:2px solid var(--accent);height:240px;display:flex;flex-direction:column;z-index:5}
.dock.min{height:40px}.dock .bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:6px 12px;background:#0006;font-size:13px}
.dock select,.dock .btn{background:#ffffff14;color:var(--log-text);border:1px solid #ffffff30;padding:3px 8px;font-size:13px;border-radius:6px}
pre#log{margin:0;flex:1;overflow:auto;padding:8px 12px;font:12.5px/1.45 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
pre#log .e{color:#ff8b82}pre#log .g{color:#6fe58a}pre#log .w{color:#f1c453}
#toast{position:fixed;top:14px;right:14px;max-width:min(420px,90vw);padding:10px 14px;border-radius:8px;background:var(--text);color:var(--bg);z-index:9;display:none}
#toast.err{background:var(--red);color:#fff}
@media (max-width:600px){main{padding:10px}.dock{height:200px}body{padding-bottom:220px}}
</style>
</head>
<body>
<div id="toast" role="status"></div>
<header>
  <div class="brand">🛡️ Scam Helper<small>Agent Console</small></div>
  <div class="pills" id="pills" aria-live="polite"></div>
</header>
<nav role="tablist" id="tabs">
  <button role="tab" data-tab="check">Check</button>
  <button role="tab" data-tab="run">Run</button>
  <button role="tab" data-tab="steer">Steer</button>
  <button role="tab" data-tab="review">Review set</button>
  <button role="tab" data-tab="ready">Readiness</button>
</nav>
<main>
<div id="authbanner" class="banner" style="display:none">This page needs the token. Open the full URL printed in the terminal where you ran <code>python3 ui/ui.py</code>.</div>

<section id="tab-check">
  <div class="card">
    <h2>Try the helper</h2>
    <p class="hint">Paste a message, a call story, a link or a file name. It never opens links or files.</p>
    <div class="banner">Use synthetic or public examples only. Do not paste real victims' messages, numbers or passwords.</div>
    <textarea id="msg" placeholder="e.g. Ada orang call kata dari polis, suruh transfer duit ke akaun selamat." aria-label="Message to check"></textarea>
    <div class="row" style="margin-top:10px">
      <label>Reply language <select id="lang"><option value="auto">Auto-detect</option><option value="en">English</option><option value="ms">Bahasa Malaysia</option><option value="zh">中文</option><option value="manglish">Manglish</option></select></label>
      <label><input type="checkbox" id="voice"> Voice style</label>
      <button class="btn primary" id="checkBtn">Check it</button>
    </div>
  </div>
  <div class="card" id="result" style="display:none">
    <div class="row"><span class="verdict" id="vchip"></span><span class="muted" id="vmeta"></span></div>
    <pre class="reply" id="reply"></pre>
    <div><strong>Why</strong> <span class="muted">(signals found)</span><ul class="plain" id="why"></ul></div>
    <hr style="border:0;border-top:1px solid var(--border);margin:14px 0">
    <h2>Steer: what should it have said?</h2>
    <p class="hint">Your label is saved to the review set. It shows where the rules disagree with you and feeds the threshold preview.</p>
    <div class="row">
      <label><input type="radio" name="exp" value="scam" checked> It is a scam</label>
      <label><input type="radio" name="exp" value="benign"> It is not a scam</label>
      <input id="note" placeholder="Optional note" maxlength="200" style="flex:1;min-width:160px">
      <button class="btn" id="saveCase">Save to review set</button>
    </div>
  </div>
</section>

<section id="tab-run">
  <div class="card"><h2>Start and stop</h2><p class="hint">Fixed jobs only. Output streams into the log at the bottom of the page.</p></div>
  <div class="grid" id="jobs"></div>
</section>

<section id="tab-steer">
  <div class="card">
    <h2>Verdict thresholds</h2>
    <p class="hint">Each warning sign adds points. Score at or above RED shows RED; at or above AMBER shows AMBER; below that shows GREEN-ish. Lower numbers flag more messages, so you catch more scams and risk more false alarms.</p>
    <div class="row">
      <label>RED at <input type="number" id="red" min="2" max="10"></label>
      <label>AMBER at <input type="number" id="amber" min="1" max="9"></label>
      <label>Hotline country <select id="country"></select></label>
      <button class="btn" id="previewBtn">Preview effect</button>
      <button class="btn primary" id="saveCfg">Save</button>
    </div>
    <div id="preview" style="margin-top:12px"></div>
  </div>
  <div class="card">
    <h2>Data files</h2>
    <p class="hint" id="dataHint"></p>
    <div class="row" style="margin-bottom:10px">
      <select id="dataSel" aria-label="Data file"><option value="blocklist">blocklist.txt</option><option value="contacts">contacts.json</option><option value="official_domains">official_domains.json</option></select>
      <button class="btn" id="reloadData">Reload</button>
      <button class="btn primary" id="saveData">Save file</button>
    </div>
    <textarea class="mono" id="dataText" spellcheck="false" aria-label="File contents"></textarea>
    <p class="muted">Saving keeps a .bak copy and checks the format first. The WhatsApp bot reads these files when it starts, so restart it after changes.</p>
  </div>
  <div class="card"><h2>Activity</h2><p class="hint">What was started or changed from this console. Message text is never recorded here.</p><ul class="plain" id="audit"></ul></div>
</section>

<section id="tab-review">
  <div class="card">
    <div class="row" style="justify-content:space-between"><div><h2>Review set</h2><p class="hint" style="margin:0" id="revSummary"></p></div><button class="btn primary" id="evalRev">Evaluate samples + review set</button></div>
  </div>
  <div class="card"><h2>Where the rules disagree with you</h2><p class="hint">Missed scams and false alarms, using the verdict at the time you labelled. These are the cases to learn from.</p><div id="disagree"></div></div>
  <div class="card"><h2>Latest labelled</h2><div id="recent"></div></div>
</section>

<section id="tab-ready">
  <div class="card"><h2>Project readiness</h2><p class="hint">Computed from the last runs and your data files. Items marked "you" need a person to confirm; tick them only when it is true.</p><div id="ready"></div></div>
</section>
</main>

<div class="dock" id="dock">
  <div class="bar">
    <strong>Live log</strong>
    <select id="logSel" aria-label="Job log"></select>
    <span id="logStatus"></span>
    <button class="btn" id="stopLog">Stop this job</button>
    <label><input type="checkbox" id="follow" checked> follow</label>
    <button class="btn" id="minDock" style="margin-left:auto">Hide</button>
  </div>
  <pre id="log" aria-live="off">No job selected. Start one in the Run tab.</pre>
</div>

<script>
const $ = (s, r) => (r || document).querySelector(s);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) { if (kid == null) continue; el.append(kid.nodeType ? kid : document.createTextNode(String(kid))); }
  return el;
}
function tryGet(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }
function trySet(k, v) { try { sessionStorage.setItem(k, v); } catch (e) {} }

let TOKEN = new URLSearchParams(location.search).get('token') || tryGet('sh_token') || '';
if (TOKEN) { trySet('sh_token', TOKEN); history.replaceState(null, '', location.pathname); }

async function api(method, path, body) {
  const r = await fetch('/api' + path, { method, headers: { 'X-Console-Token': TOKEN, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await r.json(); } catch (e) {}
  if (r.status === 401) $('#authbanner').style.display = 'block';
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
let toastTimer;
function toast(msg, isErr) {
  const t = $('#toast'); t.textContent = msg; t.className = isErr ? 'err' : ''; t.style.display = 'block';
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.style.display = 'none'; }, isErr ? 6000 : 2500);
}
async function act(fn) { try { return await fn(); } catch (e) { toast(e.message, true); } }
function ago(iso) {
  if (!iso) return ''; const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + ' min ago'; if (s < 86400) return Math.floor(s / 3600) + ' h ago'; return Math.floor(s / 86400) + ' d ago';
}
const pct = v => v == null ? 'n/a' : Math.round(v * 100) + '%';

/* tabs */
function showTab(name) {
  document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  document.querySelectorAll('main section').forEach(s => s.classList.toggle('active', s.id === 'tab-' + name));
  trySet('sh_tab', name);
  if (name === 'review') loadReview(); if (name === 'steer') loadData();
}
document.querySelectorAll('#tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));

/* check */
const VERDICT = { RED: ['🔴', 'RED · Looks like a scam'], AMBER: ['🟠', 'AMBER · Be careful'], GREENISH: ['🟢', 'GREEN-ish · No warning signs seen (not a guarantee)'], UNSURE: ['⚪', 'UNSURE · Cannot check this'] };
let lastText = '';
$('#checkBtn').addEventListener('click', () => act(async () => {
  const text = $('#msg').value;
  const r = await api('POST', '/check', { text, lang: $('#lang').value, voice: $('#voice').checked });
  lastText = text;
  const [icon, label] = VERDICT[r.label];
  const chip = $('#vchip'); chip.className = 'verdict ' + r.label; chip.textContent = icon + ' ' + label;
  $('#vmeta').textContent = 'language: ' + r.lang + ' · score ' + r.score + ' (RED at ' + r.thresholds[0] + ', AMBER at ' + r.thresholds[1] + ')' + (r.confirmed ? ' · on confirmed blocklist' : '');
  $('#reply').textContent = r.reply;
  const why = $('#why'); why.replaceChildren();
  if (!r.reasons.length) why.append(h('li', {}, 'No warning signs found.'));
  r.reasons.forEach(x => why.append(h('li', {}, x)));
  $('#result').style.display = 'block';
}));
$('#saveCase').addEventListener('click', () => act(async () => {
  const expected = document.querySelector('input[name=exp]:checked').value;
  const r = await api('POST', '/review', { text: lastText, expected, note: $('#note').value });
  toast('Saved as ' + r.id + ' (' + r.count + ' in review set)'); $('#note').value = ''; refresh();
}));

/* run */
function renderJobs(state) {
  const box = $('#jobs'); box.replaceChildren();
  state.catalog.forEach(c => {
    const last = c.last, running = c.running_job != null;
    const stat = running ? h('span', { class: 'status running' }, 'running') : last ? h('span', { class: 'status ' + (last.ok ? 'done' : 'failed') }, (last.ok ? 'last: ok ' : 'last: failed ') + ago(last.at)) : h('span', { class: 'status' }, 'not run');
    const lines = [h('div', { class: 'row', style: 'justify-content:space-between' }, h('strong', {}, c.label), stat), h('div', { class: 'muted' }, c.desc)];
    if (c.missing_env.length) lines.push(h('div', { class: 'banner' }, 'Missing in .env: ' + c.missing_env.join(', ')));
    if (last && last.recall != null) lines.push(h('div', { class: 'muted' }, 'recall ' + last.recall + '% · false alarms ' + last.false_alarm + '% · missed: ' + last.missed));
    const btns = h('div', { class: 'row' },
      h('button', { class: 'btn primary', onclick: () => startJob(c.name), ...(running || c.missing_env.length ? { disabled: '' } : {}) }, 'Start'),
      running ? h('button', { class: 'btn', onclick: () => act(() => api('POST', '/jobs/' + c.running_job + '/stop').then(refresh)) }, 'Stop') : null,
      running ? h('button', { class: 'btn', onclick: () => selectJob(c.running_job) }, 'Watch log') : null);
    box.append(h('div', { class: 'card job' }, lines, btns));
  });
}
function startJob(name) { return act(async () => { const j = await api('POST', '/jobs', { name }); await refresh(); selectJob(j.id); }); }

/* log dock */
let curJob = null, nextLine = 0;
function selectJob(id) { curJob = id; nextLine = 0; $('#log').replaceChildren(); $('#dock').classList.remove('min'); $('#minDock').textContent = 'Hide'; if ($('#logSel').value != id) $('#logSel').value = id; pollLog(); }
$('#logSel').addEventListener('change', e => selectJob(Number(e.target.value)));
$('#stopLog').addEventListener('click', () => curJob && act(() => api('POST', '/jobs/' + curJob + '/stop').then(refresh)));
$('#minDock').addEventListener('click', () => { const d = $('#dock'); d.classList.toggle('min'); $('#minDock').textContent = d.classList.contains('min') ? 'Show' : 'Hide'; });
function addLogLine(text) {
  const cls = /error|traceback|fail|✗/i.test(text) ? 'e' : /\bok\b|passed|100%/i.test(text) ? 'g' : /warn/i.test(text) ? 'w' : '';
  const span = h('span', cls ? { class: cls } : {}, text + '\n'); $('#log').append(span);
}
let polling = false;
async function pollLog() {
  if (curJob == null || polling) return; polling = true;
  try {
    const r = await api('GET', '/jobs/' + curJob + '?since=' + nextLine);
    r.lines.forEach(addLogLine); nextLine = r.next;
    if (r.lines.length && $('#follow').checked) { const l = $('#log'); l.scrollTop = l.scrollHeight; }
    $('#logStatus').textContent = r.name + ' #' + r.id + ' · ' + r.status + (r.returncode != null ? ' (exit ' + r.returncode + ')' : '');
    $('#stopLog').disabled = r.status !== 'running';
  } catch (e) {} finally { polling = false; }
}
setInterval(pollLog, 1000);

/* steer */
let CFG = null;
function fillConfig(cfg, countries) {
  CFG = cfg;
  if (document.activeElement !== $('#red')) $('#red').value = cfg.red_threshold;
  if (document.activeElement !== $('#amber')) $('#amber').value = cfg.amber_threshold;
  const sel = $('#country'); if (!sel.options.length || sel.dataset.n !== String(countries.length)) { sel.replaceChildren(...countries.map(c => h('option', { value: c }, c))); sel.dataset.n = countries.length; }
  if (document.activeElement !== sel) sel.value = cfg.default_country;
}
function metricsTable(cur, prop) {
  const row = (name, m) => h('tr', {}, h('td', {}, name), h('td', {}, 'RED ≥ ' + m.red + ', AMBER ≥ ' + m.amber), h('td', {}, pct(m.recall)), h('td', {}, pct(m.red_on_scam)), h('td', {}, pct(m.false_alarm)));
  return h('div', {}, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, ''), h('th', {}, 'Thresholds'), h('th', {}, 'Scams flagged'), h('th', {}, 'Scams shown RED'), h('th', {}, 'False alarms'))), h('tbody', {}, row('Current', cur), row('Proposed', prop))),
    h('p', { class: 'muted' }, 'Based on ' + cur.cases + ' labelled cases (' + cur.scams + ' scam, ' + cur.benign + ' not scam). Small sets can mislead: treat this as a guide, not proof.'));
}
$('#previewBtn').addEventListener('click', () => act(async () => {
  const r = await api('POST', '/simulate', { red_threshold: $('#red').value, amber_threshold: $('#amber').value });
  $('#preview').replaceChildren(metricsTable(r.current, r.proposed));
}));
$('#saveCfg').addEventListener('click', () => act(async () => {
  await api('POST', '/config', { red_threshold: $('#red').value, amber_threshold: $('#amber').value, default_country: $('#country').value });
  toast('Saved. New checks use these thresholds.'); refresh();
}));
async function loadData() {
  const r = await act(() => api('GET', '/data/' + $('#dataSel').value)); if (!r) return;
  $('#dataText').value = r.content; $('#dataHint').textContent = r.filename + ': ' + r.hint;
}
$('#dataSel').addEventListener('change', loadData); $('#reloadData').addEventListener('click', loadData);
$('#saveData').addEventListener('click', () => act(async () => { const r = await api('PUT', '/data/' + $('#dataSel').value, { content: $('#dataText').value }); toast('Saved ' + r.saved); refresh(); }));

/* review */
function caseTable(rows, empty) {
  if (!rows.length) return h('p', { class: 'muted' }, empty);
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'ID'), h('th', {}, 'You said'), h('th', {}, 'It said'), h('th', {}, 'Text'))),
    h('tbody', {}, rows.map(c => h('tr', {}, h('td', {}, c.id), h('td', {}, c.label === 'scam' ? 'scam' : 'not scam'), h('td', {}, c.predicted || ''), h('td', {}, c.text)))));
}
async function loadReview() {
  const r = await act(() => api('GET', '/review')); if (!r) return;
  $('#revSummary').textContent = r.count + ' cases: ' + r.scam + ' scam, ' + r.benign + ' not scam. Stored locally in data/samples/reviewed.jsonl (not committed to git).';
  $('#disagree').replaceChildren(caseTable(r.disagreements, 'No disagreements yet. Label some cases from the Check tab.'));
  $('#recent').replaceChildren(caseTable(r.recent, 'Nothing labelled yet.'));
}
$('#evalRev').addEventListener('click', () => startJob('evaluate_reviewed'));

/* readiness + pills + state */
function renderReady(items) {
  const box = $('#ready'); box.replaceChildren();
  items.forEach(i => {
    const mark = h('span', { class: 'mark ' + (i.ok ? 'ok' : 'no') }, i.ok ? '✓' : '✗');
    const body = h('div', { style: 'flex:1' }, h('div', {}, i.label, i.manual ? h('span', { class: 'muted' }, ' (you)') : ''), h('div', { class: 'muted' }, i.detail));
    const row = h('div', { class: 'check' }, mark, body);
    if (i.manual) row.append(h('input', { type: 'checkbox', 'aria-label': 'Confirm: ' + i.label, ...(i.ok ? { checked: '' } : {}), onchange: e => act(() => api('POST', '/manual', { key: i.key, value: e.target.checked }).then(refresh)) }));
    box.append(row);
  });
}
function renderPills(s) {
  const get = n => s.catalog.find(c => c.name === n);
  const t = get('tests').last, e = (get('evaluate_reviewed').last || get('evaluate').last), bot = get('whatsapp');
  const done = s.readiness.filter(r => r.ok).length;
  const pills = $('#pills'); pills.replaceChildren(
    h('span', { class: 'pill ' + (t ? (t.ok ? 'ok' : 'bad') : '') }, 'Tests: ' + (t ? (t.ok ? 'passed' : 'failed') : 'not run')),
    h('span', { class: 'pill ' + (e ? (e.recall === 100 && e.false_alarm === 0 ? 'ok' : 'warn') : '') }, 'Eval: ' + (e && e.recall != null ? 'recall ' + e.recall + '%, false alarms ' + e.false_alarm + '%' : 'not run')),
    h('span', { class: 'pill ' + (bot.running_job ? 'ok' : '') }, 'WhatsApp bot: ' + (bot.running_job ? 'running' : 'stopped')),
    h('span', { class: 'pill ' + (done === s.readiness.length ? 'ok' : 'warn') }, 'Ready: ' + done + '/' + s.readiness.length));
}
function renderLogSelect(jobs) {
  const sel = $('#logSel'), cur = sel.value;
  sel.replaceChildren(...jobs.map(j => h('option', { value: j.id }, '#' + j.id + ' ' + j.name + ' · ' + j.status)));
  if (curJob != null) sel.value = curJob; else if (cur) sel.value = cur;
  if (curJob == null && jobs.length) { curJob = jobs[0].id; sel.value = curJob; pollLog(); }
}
async function refresh() {
  const s = await act(() => api('GET', '/state')); if (!s) return;
  renderPills(s); renderJobs(s); renderReady(s.readiness); renderLogSelect(s.jobs); fillConfig(s.config, s.countries);
  $('#audit').replaceChildren(...(s.audit.length ? s.audit.map(a => h('li', {}, a)) : [h('li', { class: 'muted' }, 'Nothing yet.')]));
}
showTab(tryGet('sh_tab') || 'check'); refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
