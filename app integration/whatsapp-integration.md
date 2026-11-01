# WhatsApp Integration

`src/scamhelper/whatsapp.py` connects Scam Helper to the WhatsApp Cloud API. A user messages your WhatsApp number; the webhook runs the triage and tool layer and replies in their language.

> **Scope note.** WhatsApp is an over-the-top (OTT) app. The ASEAN Guide covers telco calls and SMS only and excludes OTT apps (p.10). This integration is an extension beyond the Guide's scope. Many elders use WhatsApp, which is why it is worth building, but do not present it as something the Guide recommends.

> **Tested vs untested.** Tested here: signature and handshake checks, payload parsing, reply building, de-duplication, and the HTTP server (local probes with a fake sender). **Not tested against the live WhatsApp API**: this build environment cannot reach `graph.facebook.com`. Expect to fix small things on first contact with a real account.

## What the bot does

| User sends | Bot replies |
|---|---|
| "hi", "bantuan", "你好" | Welcome in English, Malay and Chinese, plus "never share your OTP" |
| A message, number or link | Verdict, up to two reasons, Stop / Check / Report and block, and the country hotline |
| "I already transferred...", "dah transfer", "我已经转账了" | Emergency steps: call the bank first, then the hotline |
| A file (document) | File name and type check, for example `Invoice.pdf.apk` is flagged high risk |
| Voice note, picture without text, video | Asks the user to type the message, number or link |

Replies are fixed templates in the user's language (detected from the message; the last language is remembered in memory for follow-ups such as a file with no caption). The bot never echoes the user's message back, and sends with link previews off.

## Tools used

The webhook calls the same tool layer (`src/scamhelper/tools.py`) that a future LLM agent will call through `TOOL_SCHEMAS` and `call_tool()`.

| Tool | Used by WhatsApp today | What it does |
|---|---|---|
| `check_file_name` | Yes (documents) | Risky types (`.apk`, `.exe` and others) and fake double extensions. Not malware analysis. |
| `get_reporting_channel` | Yes (hotline line) | Reads `data/contacts.json` (numbers unverified) |
| `match_scam_pattern` | Via triage | Scam signals in text |
| `check_url` | Via triage | Lookalike, shortened, odd-ending links; never opened |
| `check_number` | Planned | Confirmed blocklist only; "not listed" is reported as unsure, never safe |
| `notify_trusted_contact` | Disabled | Needs a trusted-contact setup and consent |

## Setup

Menu names on Meta's side change often. Follow Meta's current WhatsApp Cloud API documentation for the exact clicks; the values you need are below.

1. **Create a Meta developer app** and add the WhatsApp product. Note the **phone number ID**, an **access token** (the temporary test token expires; production needs a permanent token) and the **app secret**.
2. **Configure the environment.** Copy `.env.example` to `.env` and fill it in, or export the variables. Never commit real values.
3. **Run the webhook** where Meta can reach it over HTTPS (a small server, or a tunnel for testing):
   ```bash
   export PYTHONPATH=src
   set -a; . ./.env; set +a
   python -m scamhelper.whatsapp          # or: scamhelper-whatsapp after pip install .
   ```
4. **Register the webhook** in the app settings: callback URL `https://<your-host>/webhook`, verify token = `WHATSAPP_VERIFY_TOKEN`, and subscribe to the `messages` field.
5. **Test** by messaging the test number from a phone that is added as a test recipient.

Docker:

```bash
docker build -t scam-helper .
docker run --rm -p 8080:8080 --env-file .env --entrypoint scamhelper-whatsapp scam-helper
```

### Local test without Meta

```bash
export PYTHONPATH=src ALLOW_UNSIGNED=1 WHATSAPP_VERIFY_TOKEN=vt WHATSAPP_ACCESS_TOKEN=x WHATSAPP_PHONE_NUMBER_ID=1
python -m scamhelper.whatsapp &
curl "http://127.0.0.1:8080/webhook?hub.mode=subscribe&hub.verify_token=vt&hub.challenge=42"   # prints 42
```

`ALLOW_UNSIGNED=1` skips signature checks. Never set it in a real deployment.

## Safety and privacy built in

- Webhook posts must carry a valid `X-Hub-Signature-256`, otherwise they get 403.
- Message text is never logged. Logs hold a short hash of the sender, the message type, the language and the HTTP status.
- Duplicate deliveries are ignored by message id.
- Replies are templates, so instructions hidden inside a scam message cannot change what the bot says.
- No message is stored on disk. De-duplication and language memory are in memory only and are lost on restart.

## Before a real pilot

1. **Read Meta's current WhatsApp Business terms and policies**, including any rules on AI-powered chatbots, and check that a narrow scam-checking service fits them. I have not verified the current terms.
2. **Check the messaging rules and pricing**. This bot only replies to messages users send first, but confirm the current customer-service-window rules.
3. **Personal data law.** Users will paste phone numbers and messages. Check the data-protection rules that apply to you and state clearly in the welcome message what is and is not kept.
4. **Verify hotlines** in `data/contacts.json` and the domains in `data/official_domains.json`.
5. **Native-speaker review** of every reply template.
6. **Consent and ethics review** before testing with real elders (see `ethics-and-safety.md`).

## Known limits

- The prototype server is single-process and uses a thread per request. For real traffic, run it behind a proper WSGI/ASGI server or a queue, and keep de-duplication in shared storage.
- Voice notes and images are not read yet. Planned: speech-to-text for voice notes, and OCR for screenshots (the user must be told that an image is being read).
- Language detection is a keyword baseline; short or mixed messages can be misjudged.
- Group chats, buttons and templates are not handled.
