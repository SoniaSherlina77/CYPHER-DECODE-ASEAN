# Full test findings (2026-11-04)

Command: `PYTHONPATH=src python -m unittest discover -s tools -v`
Result: 86 tests, 80 pass, 2 failures + 4 errors (all in `test_console`).
Raw log: `tools/test-output.txt`.

## Per-suite results

| Suite | Tests | Pass | Fail/Error |
|---|---|---|---|
| test_loop (loop/) | 21 | 21 | — |
| test_lang (src/) | 5 | 5 | — |
| test_tools (src/) | 14 | 14 | — |
| test_triage (src/) | 13 | 13 | — |
| test_whatsapp (app integration) | 16 | 16 | — |
| test_console (ui/) | 17 | 11 | 2 FAIL + 4 ERROR |

## Pre-existing console issues (not touched; outside loop scope)

1. `HttpTests` x3 — `PermissionError WinError 10013` binding `127.0.0.1:0`
   in this sandbox. No product change; retry outside sandbox.
2. `test_evaluate_result_is_parsed_into_readiness` — looks for
   `scripts/evaluate.py`; real file is `tools/evaluate.py` (also in
   `ui.py` catalog). Stale path.
3. `test_readiness_reflects_unverified_data` — expects unverified hotlines,
   but `data/contacts.json` is now verified (2026-11-03). Stale expectation.
4. `test_review_roundtrip_and_disagreements` — expects `review-0001` but
   `data/samples/reviewed.jsonl` already holds 5 rows, so the next id is
   `review-0006`. Test-isolation issue.

## Folder mapping

- `loop/` verified by test_loop; memos in `loop/memo*.md`.
- `src/` verified by test_lang/test_tools/test_triage.
- `app integration/` verified by test_whatsapp.
- `data/` smoke test: see `data/samples/findings.md`.
