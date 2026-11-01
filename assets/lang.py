"""Tiny rule-based language detector for the four supported reply styles.

Returns one of: "zh" (Chinese), "ms" (Bahasa Malaysia), "en" (English),
"manglish" (mixed English with Malay/Chinese words or particles like "lah").

This is a baseline. A production version should use a proper language-ID model
and be tested on real elder speech and typing, which is often mixed and misspelt.
"""

from __future__ import annotations

import re

CJK = re.compile(r"[一-鿿]")
WORD = re.compile(r"[a-z']+")

MALAY = {
    "saya", "awak", "anda", "kamu", "tak", "tidak", "yang", "dan", "untuk", "dengan",
    "ada", "kata", "suruh", "duit", "akaun", "polis", "boleh", "sila", "jangan",
    "segera", "sekarang", "ini", "itu", "dari", "telah", "pautan", "nombor", "orang",
    "mahkamah", "bayar", "pindah", "hadiah", "tahniah", "menang", "ke", "kat", "nanti",
}
ENGLISH = {
    "the", "is", "are", "you", "your", "and", "to", "from", "this", "please", "will",
    "account", "click", "now", "have", "has", "with", "for", "not", "be", "they", "say",
    "got", "must", "money", "me", "my", "we", "it", "of", "in", "on",
}
PARTICLES = {"lah", "leh", "lor", "meh", "wor", "hor"}


def detect_language(text: str) -> str:
    if CJK.search(text):
        return "zh"
    words = WORD.findall(text.lower())
    malay = sum(w in MALAY for w in words)
    english = sum(w in ENGLISH for w in words)
    particles = sum(w in PARTICLES for w in words)
    # One borrowed English word in a Malay sentence ("call", "transfer") stays Malay.
    if malay and english >= 2:
        return "manglish"
    if particles and (english or not malay):
        return "manglish"
    if malay:
        return "ms"
    return "en"
