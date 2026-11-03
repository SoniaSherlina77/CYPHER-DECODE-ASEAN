"""Rule-based scam and malicious-link triage (baseline).

This is a transparent heuristic baseline, not a machine-learning model and not malware
analysis. It looks for scam *signals* in text and links, adds up weights, and returns a
label. It never opens links or inspects file contents.

Labels: RED, AMBER, GREENISH, UNSURE. GREENISH means "no warning signs seen", never "safe".
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

RED, AMBER, GREENISH, UNSURE = "RED", "AMBER", "GREENISH", "UNSURE"


def data_dir() -> Path:
    env = os.environ.get("SCAMHELPER_DATA")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data"


def _rx(words: list[str] = (), cjk: list[str] = ()) -> re.Pattern:
    parts = []
    if words:
        parts.append(r"\b(?:" + "|".join(words) + r")\b")
    if cjk:
        parts.append("|".join(cjk))
    return re.compile("|".join(parts), re.I)


OTP_TERMS = r"(?:\b(?:otp|tac|pin|cvv|password|kata laluan)\b|验证码|校验码|密码)"
OTP_VERBS = (
    r"(?:\b(?:share|send|give|provide|tell|reply|bagi|beri|berikan|hantar|kongsi|sebut)\b"
    r"|告诉|提供|发送|给我)"
)
OTP_REQUEST = re.compile(
    rf"{OTP_VERBS}.{{0,40}}{OTP_TERMS}|{OTP_TERMS}.{{0,40}}{OTP_VERBS}", re.I
)
NEGATION = re.compile(
    r"do not share|don't share|never share|jangan kongsi|jangan beri|jangan share|请勿|不要告诉|切勿",
    re.I,
)

# (code, pattern, weight)
TEXT_RULES: list[tuple[str, re.Pattern, int]] = [
    ("safe_account", _rx(["safe account", "akaun selamat", "akaun keselamatan"], ["安全账户", "安全账号"]), 5),
    ("authority", _rx(
        ["police", "polis", "pdrm", "court", "mahkamah", "bank negara", "bnm", "lhdn",
         "inland revenue", "customs", "kastam", "immigration", "imigresen", "interpol", "mcmc"],
        ["警察", "警方", "法院", "法庭", "海关", "税务局", "移民局", "国家银行"]), 2),
    ("money_transfer", _rx(
        ["transfer", "remit", "pay", "payment", "deposit", "pindah", "bayar", "bayaran"],
        ["转账", "汇款", "付款", "汇钱"]), 2),
    ("urgency", _rx(
        ["urgent", "immediately", "right now", r"within \d+ (?:hours|hrs)", "within 24 hours",
         "last warning", "segera", "dengan segera", "serta-merta", r"dalam masa \d+ jam"],
        ["紧急", "立即", "马上", "限时"]), 1),
    ("prize", _rx(
        ["won", "winner", "prize", "lottery", "lucky draw", "menang", "hadiah",
         "cabutan bertuah", "tahniah"], ["中奖", "奖金", "抽奖", "恭喜"]), 2),
    ("parcel", _rx(
        ["parcel", "package", "delivery", "courier", "poslaju", r"j&t", "bungkusan", "penghantaran"],
        ["包裹", "快递", "派送"]), 1),
    ("apk", re.compile(r"\.apk\b|\bapk\b", re.I), 4),
    ("investment", _rx(
        [r"guaranteed (?:returns?|profits?)", "double your money", "pulangan terjamin",
         "untung berganda", "jamin untung"], ["稳赚", "保证回报", "日赚", "高回报"]), 3),
    ("job", _rx(
        [r"part[- ]time job", "work from home", "kerja sambilan", "kerja dari rumah"],
        ["兼职", "在家工作", "日结"]), 2),
]

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.ly|s\.id|shorturl\.at|rb\.gy|cutt\.ly)/\S+",
    re.I,
)
PHONE_RE = re.compile(r"\+?\d[\d\s\-]{7,}\d")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "s.id", "shorturl.at", "rb.gy", "cutt.ly"}
ODD_TLDS = (".xyz", ".top", ".click", ".icu", ".cfd", ".sbs", ".vip", ".link")
LEET = str.maketrans("0135", "oles")

# Order used when choosing which reasons to show first.
CODE_PRIORITY = [
    "blocklist", "safe_account", "otp_request", "lookalike", "apk", "double_extension", "risky_file",
    "authority", "money_transfer",
    "investment", "prize", "punycode", "ip_link", "shortener", "odd_tld", "job", "urgency",
    "parcel", "link",
]


@dataclass
class Result:
    label: str
    score: int = 0
    codes: list[str] = field(default_factory=list)
    confirmed: bool = False  # True only when a number/domain is on the confirmed blocklist
    hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label, "score": self.score, "codes": self.codes,
            "confirmed": self.confirmed, "hosts": self.hosts,
        }


class Blocklist:
    """Confirmed scam numbers and domains. Load from official sources only."""

    def __init__(self, numbers: set[str] | None = None, domains: set[str] | None = None):
        self.numbers = numbers or set()
        self.domains = domains or set()

    @classmethod
    def load(cls, path: Path | None = None) -> "Blocklist":
        path = path or data_dir() / "blocklist.txt"
        numbers, domains = set(), set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                digits = re.sub(r"\D", "", line)
                if digits and re.fullmatch(r"[\d+\s\-]+", line):
                    numbers.add(digits[-8:])
                else:
                    domains.add(line)
        return cls(numbers, domains)

    def hit(self, phones: list[str], hosts: list[str]) -> bool:
        if any(re.sub(r"\D", "", p)[-8:] in self.numbers for p in phones):
            return True
        return any(h == d or h.endswith("." + d) for h in hosts for d in self.domains)


def load_official_domains(path: Path | None = None) -> dict[str, list[str]]:
    path = path or data_dir() / "official_domains.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


DEFAULT_CONFIG = {"red_threshold": 5, "amber_threshold": 2, "default_country": "MY"}


def load_config(path: Path | None = None) -> dict:
    """Thresholds and defaults from data/config.json, falling back to safe defaults."""
    cfg = dict(DEFAULT_CONFIG)
    path = path or data_dir() / "config.json"
    try:
        cfg.update(json.loads(path.read_text(encoding="utf-8")))
        cfg["red_threshold"] = int(cfg["red_threshold"])
        cfg["amber_threshold"] = int(cfg["amber_threshold"])
    except (OSError, ValueError, TypeError):
        return dict(DEFAULT_CONFIG)
    return cfg


def analyse(
    text: str,
    blocklist: Blocklist | None = None,
    official: dict[str, list[str]] | None = None,
    thresholds: tuple[int, int] | None = None,
) -> Result:
    """Score a message. `thresholds` is (red, amber); default comes from data/config.json."""
    if len(re.sub(r"\s", "", text or "")) < 3:
        return Result(UNSURE)
    blocklist = blocklist if blocklist is not None else Blocklist.load()
    official = official if official is not None else load_official_domains()

    weights: dict[str, int] = {}
    for code, pattern, weight in TEXT_RULES:
        if pattern.search(text):
            weights[code] = weight
    if OTP_REQUEST.search(text) and not NEGATION.search(text):
        weights["otp_request"] = 4

    urls = URL_RE.findall(text)
    hosts = [h for h in (_host(u) for u in urls) if h]
    if urls:
        weights["link"] = 1
    for host in hosts:
        if "xn--" in host:
            weights["punycode"] = 3
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            weights["ip_link"] = 3
        if host in SHORTENERS:
            weights["shortener"] = 2
        if host.endswith(ODD_TLDS):
            weights["odd_tld"] = 2
        normalised = host.translate(LEET).replace("rn", "m")
        for brand, domains in official.items():
            is_official = any(host == d or host.endswith("." + d) for d in domains)
            if brand in normalised and not is_official:
                weights["lookalike"] = 4

    score = sum(weights.values())
    if "authority" in weights and "money_transfer" in weights:
        score += 2  # authority asking for money is the classic impersonation pattern

    phones = PHONE_RE.findall(text)
    confirmed = blocklist.hit(phones, hosts)
    if confirmed:
        weights["blocklist"] = 10
        score += 10

    codes = sorted(weights, key=lambda c: CODE_PRIORITY.index(c) if c in CODE_PRIORITY else 99)
    if thresholds is None:
        cfg = load_config()
        thresholds = (cfg["red_threshold"], cfg["amber_threshold"])
    red_at, amber_at = thresholds
    label = RED if score >= red_at else AMBER if score >= amber_at else GREENISH
    return Result(label=label, score=score, codes=codes, confirmed=confirmed, hosts=hosts)
