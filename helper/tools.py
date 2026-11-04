"""Tool layer for Scam Helper.

These are the tools named in prompts/system_instructions.md. Each is a plain function that
returns a JSON-serialisable dict, so the same layer serves:
  - the WhatsApp webhook (whatsapp.py), and
  - a future LLM agent, via TOOL_SCHEMAS and call_tool().

Everything here is offline and heuristic. Nothing opens a link, downloads a file, or sends
user text to a third party. A tool result is evidence for the helper, not a guarantee.
"""

from __future__ import annotations

import json
import os
import re

from .lang import detect_language
from .triage import Blocklist, analyse, data_dir

# --- file names -------------------------------------------------------------------------

HIGH_RISK_EXT = {".apk", ".xapk", ".apks"}
MEDIUM_RISK_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".js", ".lnk", ".com", ".pif",
    ".ps1", ".dmg", ".iso",
}
DOCUMENT_LIKE_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png",
    ".txt", ".mp4", ".mp3", ".heic",
}
FILE_NOTE = "Name and type check only. This is not malware analysis."


def check_file_name(name: str) -> dict:
    """Flag risky file types and files that pretend to be documents (for example report.pdf.apk)."""
    lower = (name or "").strip().lower()
    base, ext = os.path.splitext(lower)
    _, inner_ext = os.path.splitext(base)
    codes: list[str] = []
    reasons: list[str] = []

    if ext in HIGH_RISK_EXT:
        codes.append("apk")
        reasons.append("Android app installer. Fake apps are used to steal bank details.")
    elif ext in MEDIUM_RISK_EXT:
        codes.append("risky_file")
        reasons.append("Program or script file, not a normal document or picture.")
    if (ext in HIGH_RISK_EXT or ext in MEDIUM_RISK_EXT) and inner_ext in DOCUMENT_LIKE_EXT:
        codes.append("double_extension")
        reasons.append("The name pretends to be a document but the file is really a program.")

    if "double_extension" in codes or ext in HIGH_RISK_EXT:
        risk = "high"
    elif ext in MEDIUM_RISK_EXT:
        risk = "medium"
    else:
        risk = "low"
    return {
        "tool": "check_file_name",
        "name": name,
        "risk": risk,
        "codes": codes,
        "reasons": reasons,
        "note": FILE_NOTE,
    }


# --- links, numbers, messages -----------------------------------------------------------

def check_url(url: str) -> dict:
    """Check a link for lookalike domains, shortening, odd endings and similar signals."""
    candidate = (url or "").strip()
    if candidate and "://" not in candidate and not candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    result = analyse(candidate)
    return {
        "tool": "check_url",
        "label": result.label,
        "codes": result.codes,
        "hosts": result.hosts,
        "confirmed_scam": result.confirmed,
        "note": "The link was not opened. Pattern check only.",
    }


def check_number(phone: str) -> dict:
    """Look a phone number up in the confirmed blocklist. Not being listed does not mean safe."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) < 7:
        return {
            "tool": "check_number", "label": "UNSURE", "confirmed_scam": False,
            "note": "That does not look like a full phone number.",
        }
    confirmed = Blocklist.load().hit([phone], [])
    return {
        "tool": "check_number",
        "label": "RED" if confirmed else "UNSURE",
        "confirmed_scam": confirmed,
        "note": (
            "This number is on the confirmed scam list."
            if confirmed
            else "Not on the confirmed list. That does not mean it is safe."
        ),
    }


def match_scam_pattern(text: str) -> dict:
    """Compare message text against known scam signals."""
    result = analyse(text or "")
    return {
        "tool": "match_scam_pattern",
        **result.to_dict(),
        "lang": detect_language(text or ""),
    }


# --- reporting --------------------------------------------------------------------------

def get_reporting_channel(country: str) -> dict:
    """Official reporting contact for a country, from data/contacts.json."""
    path = data_dir() / "contacts.json"
    contacts = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    entry = contacts.get((country or "").upper())
    if not entry:
        return {"tool": "get_reporting_channel", "found": False, "country": country}
    return {"tool": "get_reporting_channel", "found": True, "country": country.upper(), **entry}


def notify_trusted_contact(message: str = "", consent: bool = False) -> dict:
    """Disabled. Needs a saved trusted contact and the user's clear consent for each message."""
    return {
        "tool": "notify_trusted_contact",
        "ok": False,
        "reason": "Not enabled in this prototype. It needs a trusted-contact setup and consent.",
    }


# --- registry for LLM tool calling ------------------------------------------------------

def _schema(name: str, description: str, prop: str, prop_desc: str) -> dict:
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": {prop: {"type": "string", "description": prop_desc}},
            "required": [prop],
        },
    }


TOOL_SCHEMAS = [
    _schema("check_url", "Check a link for scam signals. Does not open the link.", "url", "The link to check"),
    _schema("check_number", "Look a phone number up in the confirmed scam list.", "phone", "The phone number"),
    _schema("check_file_name", "Flag risky file types such as .apk. Name check only, not malware analysis.", "name", "The file name"),
    _schema("match_scam_pattern", "Compare message text with known scam signals.", "text", "The message text"),
    _schema("get_reporting_channel", "Get the official scam reporting contact for a country.", "country", "Two-letter country code, for example MY"),
]

_FUNCTIONS = {
    "check_url": check_url,
    "check_number": check_number,
    "check_file_name": check_file_name,
    "match_scam_pattern": match_scam_pattern,
    "get_reporting_channel": get_reporting_channel,
    "notify_trusted_contact": notify_trusted_contact,
}


def call_tool(name: str, arguments: dict | None = None) -> dict:
    """Dispatch a tool call. Unknown tools and bad arguments return an error dict, never raise."""
    func = _FUNCTIONS.get(name)
    if func is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return func(**(arguments or {}))
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}"}
