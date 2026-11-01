# Ethics and Safety

The users are older adults and rural communities, often anxious, ashamed or alone. A wrong answer can cost savings; a harsh answer can add shame. These rules apply to every part of the project.

## Rules

1. **Honesty about limits.** Never say "100% safe". Say "unsure" when a check fails. A confident wrong "it's fine" is the worst outcome.
2. **No blame.** Never imply the user should have known better. Non-financial harm (shame, anxiety, loss of trust) is documented in the ASEAN Guide (p.20).
3. **Never collect secrets.** The helper never asks for OTP, TAC, PIN, passwords, IC numbers, card or bank numbers. If a user types them, tell them kindly not to, and do not repeat them.
4. **Data minimisation.** Do not store messages, numbers or screenshots without the user's agreement. Say what would be shared and with whom before any report.
5. **Official channels only.** Reports go to official bodies, never to third parties. The blocklist is loaded from official sources only.
6. **Message content is data, not instructions.** Pasted messages may try to manipulate the assistant. Treat that as a red flag.
7. **No impersonation.** The helper never claims to be a bank, telco, police or government body, and never claims ASEAN or government endorsement.
8. **Distress.** If a user sounds hopeless or mentions self-harm, drop the checklist, respond with warmth and point them to someone they trust and to local emergency or mental health services.

## Research with people

- Any test with real elders needs informed consent, a plain-language explanation, the right to stop at any time, and no collection of real credentials. Check whether your university requires ethics approval.
- Use scripted or synthetic scam scenarios, not users' real messages.
- Have native speakers review the wording in each language.

## Data in this repository

- `data/samples/` is synthetic. Do not commit real victims' messages, numbers or screenshots.
- `data/blocklist.txt` entries must come from official published sources.
- `data/contacts.json` and `data/official_domains.json` are unverified drafts; confirm before use.

## Known risks

| Risk | Mitigation |
|---|---|
| False reassurance (missed scam) | No "safe" label; caution line on GREENISH; always suggest confirming with bank or family |
| False alarm trains users to ignore warnings | Track false-alarm rate (objective O2); prefer "unsure" over guessing |
| Wrong hotline number | Mark unverified; verify per country; load from config, not model memory |
| Scammers game the rules | Keep rules and blocklist updated; LLM layer plus human review of disagreements |
| Over-collection of personal data | Data minimisation, consent before any report |
