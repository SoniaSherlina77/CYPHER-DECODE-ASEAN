# Agent Console

A browser console to **start, watch and steer** the project. One file: `ui/ui.py`. Standard library only.

```bash
python3 ui/ui.py            # prints a URL like http://127.0.0.1:8765/?token=...
python3 ui/ui.py --open     # also opens it in your browser
python3 ui/ui.py --port 9000 --token mysecret    # fixed port and token
```

Open the printed URL. The token is part of it; the page removes it from the address bar and keeps it in memory for the session. The token changes on every run unless you pass `--token` (or set `CONSOLE_TOKEN`).

> **What this is not.** The project has no LLM agent yet. The console drives what exists today: the rule-based triage, the tests, the evaluation, and the WhatsApp webhook. When an LLM agent is added, it can be added to the job catalog in `ui/ui.py`.

## What you can do

| Tab | Start | Watch | Steer |
|---|---|---|---|
| **Check** | Paste a message, pick a reply language, voice style on or off | Verdict, easy-language reply, the signals found | Label the result "scam" or "not a scam" to save it to the review set |
| **Run** | Run tests · Evaluate samples · Evaluate samples + review set · WhatsApp bot (stop any time) | Live log at the bottom of every page, job status, pills in the header | |
| **Steer** | | Before/after table: scams flagged, scams shown RED, false alarms | RED and AMBER thresholds, hotline country, and the blocklist, hotline and official-domain files (format-checked, `.bak` kept) |
| **Review set** | Start an evaluation that includes your labelled cases | Where the rules disagree with you: missed scams and false alarms | |
| **Readiness** | | Checklist from the last runs and your data files | Tick the items only a person can confirm (native-speaker review, live WhatsApp test, Meta terms, ethics review, readability test) |

The header pills show the last test and evaluation results, whether the WhatsApp bot is running, and how many readiness items are done.

## How steering works

- **Thresholds** live in `data/config.json`. Each warning sign adds points; a score at or above RED shows RED, at or above AMBER shows AMBER. The **Preview effect** button re-scores all labelled cases at the proposed numbers without saving, so you can see the trade-off first. Save applies it to new checks (and to the WhatsApp bot after it restarts).
- **Review set**: every case you label is appended to `data/samples/reviewed.jsonl` with the verdict at the time. This is a human-in-the-loop labelling loop: look at disagreements, adjust thresholds or rules, re-evaluate.
- **Data files**: the blocklist should only contain numbers and domains from official sources. Contacts have a `verified` flag per country; official domains have a single `_verified` flag. Readiness stays red until you set them after checking.

## Safety

- Binds to `127.0.0.1` only by default. Every `/api` call needs the token.
- Only the four fixed jobs in the catalog can run. There is no way to run an arbitrary command from the page.
- Secrets in `.env` go only to the WhatsApp child process. The page shows the names of missing variables, never values.
- Message text is never written to the activity log (`ui/.console-audit.log`). Review-set cases are stored locally and are git-ignored, because pasted text could be real.
- Using `--host 0.0.0.0` exposes the console to your network. Anyone with the port and token can run jobs and edit data files. Use it only on a trusted network, or put HTTPS and your own login in front of it.
- The page sends a strict Content-Security-Policy and cannot be framed.

## URL

The console is a local web app, so its URL is `http://127.0.0.1:<port>/?token=...` on the computer that runs it. A public link needs hosting: either a tunnel to that computer, or a server with HTTPS and a login in front. I have not set either up.

## Tested

`tests/test_console.py` covers checking, threshold validation and effect, data-file validation, the review set, job start/stream/stop, readiness, token enforcement and security headers. The page was also driven in a real headless browser: checking a message, running the test job and watching the live log, previewing thresholds, loading the data editor, the readiness list, and a 390px-wide phone layout. No browser console errors.

Dark mode was checked by eye on the Check tab. Not tested: running the WhatsApp job against a live account.
