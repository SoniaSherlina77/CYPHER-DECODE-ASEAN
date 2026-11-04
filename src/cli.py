"""Command-line demo: `scamhelper check "message text"`."""

from __future__ import annotations

import argparse
import json
import sys

from .lang import detect_language
from .messages import LANGS, render
from .triage import analyse, data_dir


def load_contact(country: str) -> dict | None:
    path = data_dir() / "contacts.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get(country.upper())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamhelper", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="Check a message, number or link")
    check.add_argument("text", nargs="?", help="Text to check (reads stdin if omitted)")
    check.add_argument("--lang", choices=("auto",) + LANGS, default="auto")
    check.add_argument("--country", default="MY", help="Country code for the hotline (default MY)")
    check.add_argument("--voice", action="store_true", help="Voice-style output (no numbering)")
    check.add_argument("--json", action="store_true", help="Print the raw result as JSON")
    args = parser.parse_args(argv)

    text = args.text if args.text is not None else sys.stdin.read()
    result = analyse(text)
    lang = detect_language(text) if args.lang == "auto" else args.lang

    if args.json:
        print(json.dumps({**result.to_dict(), "lang": lang}, ensure_ascii=False, indent=2))
    else:
        print(render(result, lang, load_contact(args.country), voice=args.voice))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
