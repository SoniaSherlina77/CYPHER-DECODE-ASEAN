# Project Objectives: Multilingual Scam & Malicious-Link Analyzer for Elders and Rural Communities

Version 0.1 (draft, 2026-10-30). Case file: ASEAN Guide on Anti-Scam Policies and Best Practices (January 2026).

## 1. Purpose

Give people who are most likely to be scammed and least likely to have tech support a simple chat, voice-style and phone-alert helper that tells them, in easy Malay, English, Chinese or Manglish, whether a call, SMS, link or file looks like a scam, and what to do next.

## 2. Scope decisions

| Question | Proposed decision | Why |
|---|---|---|
|**Scam and malicious-link detector.** Malware is limited to risky links, risky file types (for example unknown .apk) and known scam app names. 
|**Calls and SMS first.** WhatsApp and other OTT apps are a clearly labelled extension. | The Guide covers calls and SMS only and excludes OTT apps (p.10). |
| Who is the Guide for? | Governments and telcos. | So "aligned to the Guide" means mapped to its principles, typology, public-education and reporting measures. It does not mean implementing telco controls. |

## 3. Primary objective

Within the hackathon period, deliver a working prototype that, in four languages, gives a clear verdict (red, amber, green-ish, unsure) and one to three next steps on scam calls, SMS and links described by elderly or rural users, and show through testing that it does so accurately, understandably and safely.

## 4. Specific objectives

Targets are **proposed** starting points. Validate against a test set and adjust; do not report them as achieved results.

| # | Objective | Measure (proposed target) | Guide alignment |
|---|---|---|---|
| O1 | Detect common call and SMS scam types | Recall of at least 90% on a labelled test set covering bank, government, parcel, prize, phishing, investment, job and malicious-app-link scams | Typology, Fig. 3, p.17; Tier 2 SMS content filtering (A6, pp.83-84) |
| O2 | Keep false alarms low enough to be trusted | Wrongly flagged genuine messages at most 10% | Guide warns warnings must be high-confidence to keep public trust (A5, p.83) |
| O3 | Understand and reply in Malay, English, Chinese and Manglish | Reply language matches user language in at least 95% of test turns | Regional, inclusive aim (Foreword; ADM2025, p.10) |
| O4 | Speak in easy language | Readers in the target group understand the verdict and next step in at least 8 of 10 tests (small usability test) | Public education, 7.1, p.70 |
| O5 | Interrupt the scam before the "call to action" | Every red or amber answer gives the Stop, Check, Report and block steps | Three stages of scam, Fig. 1, p.12; Philippine four-step campaign, p.70 |
| O6 | Route to official reporting | Correct national hotline given for supported countries; report path offered on every red answer | Public reporting, 7.2, pp.71-72; collaboration with non-telco stakeholders, A9, p.86 |
| O7 | Handle "already scammed" emergencies | Emergency flow triggers on at least 95% of test cases that describe a loss or shared OTP | Impact of scams, 2.2, p.19-20 |
| O8 | Protect privacy and avoid harm | No storage without consent; no request for OTP, PIN or passwords in any test | Data governance principles, 8.2.1, p.89 |
| O9 | Be honest about limits | Never says "100% safe"; says "unsure" when tools fail | Adaptive but trusted interventions, p.7 |

## 4a. Deliverables

1. System instructions (`system_instructions.md`).
2. Scam test set (multilingual, labelled; synthetic or public-source only, no real victim data).
3. Prototype: chat plus voice-style interface; phone-alert design (SMS or notification) as a mock-up if full build is out of scope.
4. Evaluation report: accuracy, false alarms, language match, readability, small user test with consent.
5. Alignment matrix: each Guide measure mapped to a feature or marked out of scope.
6. Work log (kept in the capstone planning doc).

## 5. In scope

- Text and voice-style conversation; phone-alert message design.
- Link, number, message and file-name triage with reputation lists and pattern matching.
- Emergency guidance and official reporting routes.
- Four languages and elder-friendly wording.

## 6. Out of scope

- Real malware sandboxing or reverse engineering.
- Blocking calls or SMS at network level, SIM registration, SMS firewalls, sender ID registries, traceback (these are   telco and regulator measures in the Guide).
- Recovering money, legal or financial advice.
- Collecting real victims' personal data.
- Claiming official endorsement by ASEAN, any government, telco or bank.

## 7. Target users and constraints

- Elderly people and rural communities with limited tech support. The Guide notes elderly victims are more susceptible to phishing and investment scams, with phone calls playing a larger role (p.19).
- Low literacy in some groups, small screens, slow or patchy data, shared phones.
- Likely to be anxious or ashamed; non-financial harm is real (p.20).

