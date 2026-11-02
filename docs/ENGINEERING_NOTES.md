# Engineering notes

## Design decisions

| Decision | Why |
|---|---|
| Rules first, AI optional and raise-only | Safety floor that works offline; an AI error can never lower a warning |
| Three verdicts, no "safe" | A false all-clear is the most harmful error for the target users |
| Hide secrets before everything else | OTP, PIN, card, NRIC and email never reach analysis, logs or any AI call |
| Logging cannot carry message text | Content-like keys are masked; exceptions log type and location only |
| Replies are data in `replies.py` | Native speakers can review and edit wording without touching logic |
| Hotlines are data with a `verified` flag | Numbers change; unverified ones are hidden by default |

## Known limitations

- **Language detection** counts function words. It will misjudge short messages, code-switching and names. Replace it with a trained detector and a labelled set.
- **Rule weights** are starting values chosen by hand, not tuned.
- **Official-domain list** is a short starter list. A brand-name look-alike check can flag a genuine but unlisted domain. Review before use.
- **Redaction** hides OTP-style codes only when a keyword like OTP, TAC, PIN or "验证码" is near the number.
- **Manglish** reasons reuse the English text; only headings, steps and tone are Manglish.
- **Reply wording** in Malay, Chinese and Manglish is a first draft with no native-speaker review.
- **Phone numbers and links** are listed in the report summary, which a user might forward. Keep it that way only if the user agrees.

## Evaluation plan (not yet run)

| Measure | How |
|---|---|
| Missed-scam rate | Held-out labelled set, reported per language and scam type; the headline metric |
| False-alarm rate | Include genuine bank, telco and government notices |
| Language fidelity | Reply language matches input, including mixed Manglish |
| Readability | Native-speaker plain-language review per language |
| Task success | Small pilot: elders check sample messages unaided |
| Safe handling | OTP request, "already paid" and distress cases must all pass |

## Next engineering steps

1. Chat web page with browser speech synthesis (`reply.speech`, `reply.lang_tag`) and speech input.
2. Share-to-app / forward endpoint (small HTTP API returning `CheckResult.to_dict()`).
3. LLM client behind the existing `LLMFn` hook, with the prompt kept in a reviewable file.
4. Corpus builder with anonymisation, then tune weights.
