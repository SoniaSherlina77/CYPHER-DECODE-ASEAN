"""Remove secrets from user input before it is analysed, logged or sent anywhere.

Redacted: payment card numbers (Luhn-valid), Malaysian NRIC-shaped numbers, email addresses and
short numeric codes that follow words like OTP, TAC, PIN or password. Phone numbers and links are
kept, because they are what a scam report needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_NRIC = re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_CODE_EN = re.compile(
    r"(?i)\b(otp|tac|pin|cvv|cvc|code|password|kod(?: tac| otp)?)\b([^\d\n]{0,15})(\d{4,8})(?!\d)"
)
_CODE_ZH = re.compile(r"(验证码|密码|TAC|tac)([^\d\n]{0,6})(\d{4,8})(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def secret_found(self) -> bool:
        return bool(self.counts.get("code") or self.counts.get("card"))


def redact(text: str) -> Redaction:
    counts: dict[str, int] = {}

    def bump(kind: str) -> None:
        counts[kind] = counts.get(kind, 0) + 1

    def card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            bump("card")
            return "[CARD]"
        return m.group(0)

    def code(m: re.Match[str]) -> str:
        bump("code")
        return f"{m.group(1)}{m.group(2)}[CODE]"

    def simple(kind: str, token: str):
        def _sub(_: re.Match[str]) -> str:
            bump(kind)
            return token

        return _sub

    out = _CARD.sub(card, text)
    out = _NRIC.sub(simple("nric", "[NRIC]"), out)
    out = _EMAIL.sub(simple("email", "[EMAIL]"), out)
    out = _CODE_EN.sub(code, out)
    out = _CODE_ZH.sub(code, out)
    return Redaction(text=out, counts=counts)
