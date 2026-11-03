"""Decide whether a message is a greeting, an "I already got scammed" emergency, or a check request."""

from __future__ import annotations

import re

GREETING = re.compile(
    r"^\s*(?:hi|hello|hey|hai|helo|start|help|menu|salam|assalamualaikum|bantuan|tolong|"
    r"你好|您好|帮助|开始)\W*$",
    re.I,
)

EMERGENCY = re.compile(
    # English: "I already transferred ...", "I shared my OTP", "I clicked the link"
    r"\b(?:i|we)\s+(?:(?:have|had|already|just)\s+)*"
    r"(?:paid|transferred|sent (?:the )?money|shared|gave|clicked|installed|lost)\b"
    r"|\b(?:i|we)\s+(?:already|just)\s+(?:pay|transfer|give|share|click|install)\b"
    # Malay: "dah transfer", "sudah bagi OTP", "kena tipu"
    r"|\b(?:dah|sudah|telah)\s+(?:\w+\s+){0,2}?(?:bayar|transfer|pindah|bagi|beri|klik|pasang|kongsi)\b"
    r"|\bkena tipu\b"
    # Chinese: "已经转账", "我给了验证码", "被骗了"
    r"|已经(?:转|付|给|点|装|汇)|我(?:转了|付了|给了|点了|装了|汇了)|被骗了",
    re.I,
)


def detect_intent(text: str) -> str:
    """Return "greeting", "emergency" or "check"."""
    if GREETING.match(text or ""):
        return "greeting"
    if EMERGENCY.search(text or ""):
        return "emergency"
    return "check"
