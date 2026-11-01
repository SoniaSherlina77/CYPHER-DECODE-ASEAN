"""Compute recall and false-alarm rate on the labelled sample set.

Usage: python scripts/evaluate.py [path/to/cases.jsonl]

The bundled set is tiny and synthetic: it is a smoke test, NOT evidence of real-world
accuracy. Objective O1/O2 targets (docs/objectives.md) need a larger, reviewed test set.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scamhelper.triage import AMBER, RED, Blocklist, analyse, load_official_domains  # noqa: E402


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "samples" / "test_cases.jsonl"
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    official, blocklist = load_official_domains(), Blocklist()
    scams = [c for c in cases if c["label"] == "scam"]
    benign = [c for c in cases if c["label"] == "benign"]

    def flagged(c) -> bool:
        return analyse(c["text"], blocklist=blocklist, official=official).label in (AMBER, RED)

    missed = [c["id"] for c in scams if not flagged(c)]
    false_alarms = [c["id"] for c in benign if flagged(c)]
    recall = 1 - len(missed) / len(scams) if scams else float("nan")
    fa_rate = len(false_alarms) / len(benign) if benign else float("nan")

    print(f"cases: {len(cases)} ({len(scams)} scam, {len(benign)} benign)")
    print(f"scam recall:      {recall:.0%}   missed: {missed or 'none'}")
    print(f"false-alarm rate: {fa_rate:.0%}   wrongly flagged: {false_alarms or 'none'}")
    print("Note: tiny synthetic set. Smoke test only, not a performance claim.")
    return 1 if missed or false_alarms else 0


if __name__ == "__main__":
    raise SystemExit(main())
