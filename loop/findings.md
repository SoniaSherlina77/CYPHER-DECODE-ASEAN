# Loop findings (2026-11-04)

Focused suite: `tools.test_loop` — 21 tests, OK (exit 0).
Raw log: `loop/test-output.txt`.

## Turn and stop verification

- Turn: model call with no tool calls ends the turn with that text; otherwise up
  to 4 tool calls run and their results return as tool messages.
- Stops observed: `final` (answered), `max_turns` (budget spent),
  `repeat_calls` (same call a 3rd time, not executed).
- `check()` adds: `baseline` (no model), `intent` (greeting/emergency
  short-circuit), `no_helpers`, plus `turns_used` on every path.

## Safety checks in this run

- Verified MY hotline carries no `[unverified]` marker; unverified entries
  still do; unknown country reports no verified hotline.
- OTP redacted before the model (`[CODE]`); safety net overrules uncautious
  model answers; guardrails strip `100% safe` and unconfirmed `100% scam`.
- Turn budgets share `MAX_TURNS_DEFAULT`; `.env` loader never overrides
  existing vars and never logs values.

## Memos filed (offline baseline, `--offline`)

- `loop/memo.md` — RED police safe-account scam (EN).
- `loop/memo-prize-apk.md` — RED prize + `.apk` link (MS).
- `loop/memo-benign.md` — GREENISH family message (MS).

Each memo carries a loop trace and no user text in the trace.
Env: root `.env` copied from `ui/.env` (same 7 keys); loop loads root first,
`ui/.env` as fallback.
