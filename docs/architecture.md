# Architecture

## Components

| Component | File | Role |
|---|---|---|
| Language detection | `src/scamhelper/lang.py` | Picks zh, ms, en or manglish for the reply. Rule-based baseline. |
| Triage | `src/scamhelper/triage.py` | Finds scam signals in text and links, scores them, returns a label and reason codes. |
| Replies | `src/scamhelper/messages.py` | Easy-language templates in four languages; voice mode drops numbering. |
| CLI | `src/scamhelper/cli.py` | Demo entry point. |
| Data | `data/` | Official-domain list, confirmed blocklist, hotline contacts, sample cases. |
| Agent prompt | `prompts/system_instructions.md` | Runtime prompt for the LLM helper (planned layer). |

## Data flow

1. Input arrives as text (typed, or transcribed from voice).
2. Language is detected, or taken from the user's setting.
3. Triage extracts links, phone numbers and keywords; adds weights; checks the confirmed blocklist.
4. Label rule: score 5 or more is RED, 2 to 4 is AMBER, below 2 is GREENISH, input that is too short is UNSURE. A blocklist hit forces RED and sets `confirmed`.
5. The reply is built from the label, the top two reasons, the three steps and the country hotline.

## Design choices

- **Transparent rules first.** Each flag has a code and a reason in plain words, so a reviewer can see why an answer was given.
- **Honest labels.** There is no "safe" label. GREENISH always carries "cannot be 100% sure".
- **Confirmed vs suspected.** Only the official blocklist can set `confirmed`; everything else is a suspicion.
- **No network calls.** The prototype never opens links or uploads user text.

## Planned LLM layer

An agent follows `prompts/system_instructions.md` and may call tools: `check_url`, `check_number`, `check_file_name`, `match_scam_pattern`, `get_reporting_channel`, `notify_trusted_contact`. The rule-based triage stays in the loop as a baseline and a safety net: if the agent says GREEN-ish while the baseline says RED, show the more cautious one and log the disagreement for review.

## Limits

Rules are brittle against new wording, misspellings and voice transcription errors. The language detector is a keyword baseline and will misjudge short or mixed input.
