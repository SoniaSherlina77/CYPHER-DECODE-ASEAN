"""WhatsApp Cloud API webhook for Scam Helper.

Receives WhatsApp messages, runs the triage and tool layer, and replies in the user's language.

SCOPE NOTE: WhatsApp is an over-the-top (OTT) app. The ASEAN Guide covers telco calls and SMS
only and excludes OTT apps (p.10). This module is an extension beyond the Guide's scope.

Design notes
- Standard library only. Replies are fixed templates, so scam text can never talk the bot
  into saying something else, and the user's message is never echoed back (no link previews).
- Webhook calls must be signed (X-Hub-Signature-256) unless ALLOW_UNSIGNED=1 for local tests.
- Message text is never logged. Logs hold a short hash of the sender, the message type and the
  label only. Duplicate deliveries (Meta retries) are ignored by message id.
- Voice notes and pictures are not read yet; the bot asks the user to type instead.

Run: python -m scamhelper.whatsapp   (configuration comes from environment variables, see
docs/whatsapp-integration.md and .env.example)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterable
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import parse_qs, urlparse

from . import tools
from .intents import detect_intent
from .lang import detect_language
from .messages import EMERGENCY, HOTLINE, UNSUPPORTED, WELCOME, render
from .triage import AMBER, GREENISH, RED, UNSURE, CODE_PRIORITY, Result, analyse, load_config

log = logging.getLogger("scamhelper.whatsapp")

MAX_CHARS = 2000          # analyse at most this much text per message
MAX_BODY_BYTES = 1_000_000
DEFAULT_API_VERSION = "v21.0"  # [VERIFY] use a currently supported Graph API version

# --- security helpers -------------------------------------------------------------------


def verify_signature(app_secret: str, body: bytes, header: str | None) -> bool:
    """Check Meta's X-Hub-Signature-256 header: 'sha256=' + HMAC-SHA256(app_secret, raw body)."""
    if not app_secret or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256="):])


def verify_challenge(params: dict[str, list[str]], verify_token: str) -> str | None:
    """Answer Meta's webhook verification (GET). Returns the challenge to echo, or None."""
    mode = params.get("hub.mode", [""])[0]
    token = params.get("hub.verify_token", [""])[0]
    challenge = params.get("hub.challenge", [""])[0]
    if mode == "subscribe" and verify_token and hmac.compare_digest(token, verify_token):
        return challenge
    return None


# --- incoming messages ------------------------------------------------------------------


@dataclass
class IncomingMessage:
    id: str
    sender: str
    type: str
    text: str = ""
    filename: str = ""
    caption: str = ""


def extract_messages(payload: dict) -> Iterable[IncomingMessage]:
    """Pull user messages out of a WhatsApp Cloud API webhook payload."""
    for entry in payload.get("entry", []) or []:
        for change in entry.get("changes", []) or []:
            value = change.get("value", {}) or {}
            for m in value.get("messages", []) or []:
                kind = m.get("type", "")
                text = (m.get("text") or {}).get("body", "") if kind == "text" else ""
                document = m.get("document") or {}
                image = m.get("image") or {}
                yield IncomingMessage(
                    id=m.get("id", ""),
                    sender=m.get("from", ""),
                    type=kind,
                    text=text,
                    filename=document.get("filename", ""),
                    caption=document.get("caption", "") or image.get("caption", ""),
                )


# --- building replies -------------------------------------------------------------------

_SEVERITY = {UNSURE: 0, GREENISH: 1, AMBER: 2, RED: 3}


def _merge(a: Result, b: Result) -> Result:
    worse = a if _SEVERITY[a.label] >= _SEVERITY[b.label] else b
    codes = sorted(set(a.codes) | set(b.codes), key=lambda c: CODE_PRIORITY.index(c) if c in CODE_PRIORITY else 99)
    return Result(
        label=worse.label, score=a.score + b.score, codes=codes,
        confirmed=a.confirmed or b.confirmed, hosts=a.hosts + b.hosts,
    )


def _contact(country: str) -> dict | None:
    channel = tools.get_reporting_channel(country)
    return channel if channel.get("found") else None


def build_reply(msg: IncomingMessage, country: str = "MY", last_lang: str | None = None) -> tuple[str, str]:
    """Return (reply_text, language). Pure function: no network, no logging."""
    text = (msg.text or msg.caption or "")[:MAX_CHARS]
    lang = detect_language(text) if text.strip() else (last_lang or "en")
    contact = _contact(country)

    # Document with a file name: check the name and type first.
    if msg.type == "document" and msg.filename:
        file_check = tools.check_file_name(msg.filename)
        if file_check["risk"] == "high":
            result = Result(RED, score=5, codes=file_check["codes"])
        elif file_check["risk"] == "medium":
            result = Result(AMBER, score=3, codes=file_check["codes"])
        else:
            result = Result(GREENISH)
        if text.strip():
            result = _merge(result, analyse(text))
        return render(result, lang, contact), lang

    if msg.type == "text" or (msg.type == "image" and text.strip()):
        intent = detect_intent(text)
        if intent == "greeting":
            return WELCOME, lang
        if intent == "emergency":
            body = EMERGENCY[lang]
            if contact:
                body += "\n" + HOTLINE[lang].format(name=contact["name"], phone=contact["phone"])
            return body, lang
        return render(analyse(text), lang, contact), lang

    # Voice notes, pictures without text, video, stickers, and so on.
    return UNSUPPORTED, lang


# --- sending ----------------------------------------------------------------------------

Transport = Callable[[str, dict, bytes], tuple[int, bytes]]


def _urllib_transport(url: str, headers: dict, data: bytes) -> tuple[int, bytes]:
    req = urlrequest.Request(url, data=data, headers=headers, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:  # noqa: S310 (fixed https URL)
            return resp.status, resp.read()
    except urlerror.HTTPError as exc:
        return exc.code, exc.read()


class WhatsAppClient:
    def __init__(
        self, access_token: str, phone_number_id: str,
        api_version: str = DEFAULT_API_VERSION, transport: Transport | None = None,
    ):
        self.url = f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages"
        self.headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        self.transport = transport or _urllib_transport

    def send_text(self, to: str, body: str) -> int:
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": {"preview_url": False, "body": body[:4096]},
        }
        status, _ = self.transport(self.url, self.headers, json.dumps(payload).encode())
        return status


class Bot:
    """Handles webhook payloads: dedupes, builds replies, sends them."""

    def __init__(self, client: WhatsAppClient, country: str = "MY", memory_size: int = 5000):
        self.client = client
        self.country = country
        self.memory_size = memory_size
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lang: OrderedDict[str, str] = OrderedDict()  # sender -> last language (memory only)
        self._lock = threading.Lock()

    def _remember(self, store: OrderedDict, key: str, value) -> None:
        store[key] = value
        store.move_to_end(key)
        while len(store) > self.memory_size:
            store.popitem(last=False)

    def handle_payload(self, payload: dict) -> int:
        sent = 0
        for msg in extract_messages(payload):
            with self._lock:
                if msg.id in self._seen:
                    continue
                self._remember(self._seen, msg.id, None)
                last_lang = self._lang.get(msg.sender)
            try:
                reply, lang = build_reply(msg, self.country, last_lang)
                status = self.client.send_text(msg.sender, reply)
                with self._lock:
                    self._remember(self._lang, msg.sender, lang)
                sent += 1
                who = hashlib.sha256(msg.sender.encode()).hexdigest()[:8]
                log.info("replied user=%s type=%s lang=%s http=%s", who, msg.type, lang, status)
            except Exception:  # keep the webhook alive; never log message content
                log.exception("failed to handle a %s message", msg.type)
        return sent


# --- HTTP server ------------------------------------------------------------------------


def make_handler(bot: Bot, verify_token: str, app_secret: str, allow_unsigned: bool = False):
    class Webhook(BaseHTTPRequestHandler):
        def _reply(self, code: int, body: bytes = b"", ctype: str = "text/plain") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # Meta webhook verification
            parsed = urlparse(self.path)
            if parsed.path != "/webhook":
                return self._reply(404)
            challenge = verify_challenge(parse_qs(parsed.query), verify_token)
            if challenge is None:
                return self._reply(403)
            self._reply(200, challenge.encode())

        def do_POST(self):
            if urlparse(self.path).path != "/webhook":
                return self._reply(404)
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY_BYTES:
                return self._reply(400)
            body = self.rfile.read(length)
            if not allow_unsigned and not verify_signature(app_secret, body, self.headers.get("X-Hub-Signature-256")):
                return self._reply(403)
            try:
                payload = json.loads(body)
            except ValueError:
                return self._reply(400)
            self._reply(200)  # answer Meta quickly, then work in the background
            threading.Thread(target=bot.handle_payload, args=(payload,), daemon=True).start()

        def log_message(self, *args):  # no access log: it would record client addresses
            pass

    return Webhook


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    env = os.environ
    missing = [k for k in ("WHATSAPP_VERIFY_TOKEN", "WHATSAPP_ACCESS_TOKEN", "WHATSAPP_PHONE_NUMBER_ID") if not env.get(k)]
    allow_unsigned = env.get("ALLOW_UNSIGNED") == "1"
    if not env.get("WHATSAPP_APP_SECRET") and not allow_unsigned:
        missing.append("WHATSAPP_APP_SECRET")
    if missing:
        print("Missing environment variables: " + ", ".join(missing))
        return 2
    if allow_unsigned:
        log.warning("ALLOW_UNSIGNED=1: webhook signatures are NOT checked. Local testing only.")

    client = WhatsAppClient(
        env["WHATSAPP_ACCESS_TOKEN"], env["WHATSAPP_PHONE_NUMBER_ID"],
        env.get("WHATSAPP_API_VERSION", DEFAULT_API_VERSION),
    )
    bot = Bot(client, env.get("SCAMHELPER_COUNTRY") or load_config()["default_country"])
    handler = make_handler(bot, env["WHATSAPP_VERIFY_TOKEN"], env.get("WHATSAPP_APP_SECRET", ""), allow_unsigned)
    port = int(env.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    log.info("Scam Helper WhatsApp webhook listening on :%s/webhook", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
