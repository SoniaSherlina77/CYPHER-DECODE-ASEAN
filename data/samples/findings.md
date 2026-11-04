# Sample evaluation findings (2026-11-04)

Command: `PYTHONPATH=src python tools/evaluate.py`
Raw log: `data/samples/evaluate-output.txt`

- cases: 16 (10 scam, 6 benign)
- scam recall: 100%, missed: none
- false-alarm rate: 0%, wrongly flagged: none

Note: tiny synthetic set. Smoke test only, not a performance claim
(O1/O2 targets in `docs/objectives.md` need a larger reviewed set).
