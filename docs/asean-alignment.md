# Alignment with the ASEAN Guide on Anti-Scam Policies and Best Practices (January 2026)

Case file pages read so far: 1-21 and 70-97. Chapters 3-6 (pp.22-69: SIM controls, network measures in detail, information sharing, international coordination) are **not yet read**; rows that depend on them are marked *to verify*.

## Scope fit

| Guide position | Page | What it means here |
|---|---|---|
| Covers scams over telephone calls and SMS only; excludes social media and OTT apps (WhatsApp, iMessage, RCS) | 10 | Core design targets calls and SMS. WhatsApp or Telegram handling is a labelled extension outside the Guide. |
| Audience: governments, telco regulators, telcos | 10, 13 | The helper is a user-side tool. Alignment means mapping to principles, typology and public-education measures, not claiming telco controls. |
| Nothing in the Guide changes legal obligations | 93 | Do not present the helper as compliance with any law. |

## Principles (p.7, p.91)

| Principle | How the project applies it | Status |
|---|---|---|
| Prioritise baseline harmonisation | Same Stop, Check, Report routine in all four languages; same verdict labels | Prototype |
| Cultivate adaptive interventions at source | Rule baseline now; LLM agent and pattern updates planned so new scam types can be handled | Planned |
| Embrace collaborative defence | Report route to official hotlines; confirmed blocklist loaded from official sources only | Prototype (hotlines unverified) |

## Scam typology (Figure 3, p.17; pp.10-11, 16)

| Guide scam type | Detection signal in the prototype |
|---|---|
| Bank impersonation | OTP request, lookalike bank domain, authority + money |
| Impersonation of government | Authority terms + money transfer, safe account |
| E-commerce / parcel | Parcel terms + shortened or odd link, payment request |
| Prize / lottery | Prize terms, odd link, `.apk` |
| Phishing | Lookalike, odd TLD, punycode, IP link, shortener |
| Malware / smishing | `.apk` and risky links (name and pattern check only, no file analysis) |
| Investment | Guaranteed-return phrases |
| Job offers | Work-from-home and part-time phrases |
| Romance, loans | Not yet covered (planned) |

## Three stages of a scam (Figure 1, p.12)

| Stage | Guide intervention | Project role |
|---|---|---|
| Accessing telco services | SIM and equipment controls | Out of scope (telco) |
| Initial contact | Network blocking, preventing impersonation | Out of scope (telco). The helper acts after contact reaches the user. |
| **Call to action** | Block reply calls, consumer warnings | **Core.** Interrupt before the user clicks, replies, or pays. |
| Transaction | Banks disrupt transfers | Emergency flow tells the user to call the bank immediately. |

## Recommendations (Figure 17, pp.76-87)

| Ref | Guide recommendation | Tier | Project position |
|---|---|---|---|
| A1, A2 | SIM registration and limits, SIM box licensing | 1 | Out of scope |
| A3 | Block scam calls; analytics; AI/ML detection | 1-3 | Out of scope at network level. User-side analogue: call description triage. |
| A4 | Prevent caller ID impersonation | 1, 3 | Out of scope. Tell the user not to trust caller ID alone. |
| A5 | Block or divert reply calls to a consumer warning | 2-3 | The helper's verdict acts as a user-side warning. Guide says warnings need high confidence to keep public trust (p.83), so the helper says "unsure" rather than guess. |
| A6 | SMS firewalls (known scam URLs, numbers, requests for bank details) | 1-3 | Out of scope at network level. The prototype's link and content rules mirror the same indicators on-device. |
| A7 | Sender ID checks and registries | 1-2 | Out of scope. Possible later: show a warning when a sender ID is unregistered, if a registry exists. *To verify (4.2.4).* |
| A8 | Traceback | 1 | Out of scope |
| A9 | Collaboration with non-telco stakeholders | 1, 3 | Report route to hotlines; confirmed numbers from official sources feed the blocklist. |
| A10 | Regular reporting | 1 | Aggregated, consent-based, anonymised usage statistics are a possible later feature. |
| B | Regional traceback, capacity building | n/a | Out of scope |

## Public education and reporting (Chapter 7, pp.70-72)

| Guide practice | Project feature |
|---|---|
| Reminders before the point of action; flag suspicious SMS | Verdict before the user acts; every red or amber answer ends with next steps |
| Philippines NTC: Identify, Ignore, Report, Block and delete | Stop, Check, Report and block routine |
| Singapore ScamShield: check numbers, messages, websites; report | Number, message and link triage; report route |
| National hotlines: Malaysia NSRC, Thailand AOC 1441, Cambodia TRC, Indonesia Komdigi portal | `data/contacts.json` (numbers unverified) |

## Gaps to close

1. Read Chapters 3-6, especially the consumer-warning and sender-ID sections (referenced as 4.1.4 and 4.2.4 in the Guide), and update this matrix.
2. Decide which countries to support first and source each hotline from official government pages.
3. Add romance and loan scam signals.
