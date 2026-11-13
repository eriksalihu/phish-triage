# phish-triage

An offline Python command-line tool that reads a `.eml` file and produces an explainable phishing risk report: a score from 0 to 100, the reason for every point, and a defanged indicator list for the ticket.

[![CI](https://github.com/eriksalihu/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/eriksalihu/phish-triage/actions/workflows/ci.yml)

## Why a SOC analyst would use it

"Is this email phishing?" is one of the most common tier-1 tickets. Answering it means reading the same things every time: who really sent it, whether SPF, DKIM and DMARC passed, where the links really go, and what is attached. phish-triage does that first pass in a second and writes it down in a form that can be pasted into the ticket. It never opens a link and never runs an attachment, so it is safe to use on a live sample.

## Features

- **Headers:** From, Reply-To and Return-Path domain mismatches, SPF, DKIM and DMARC results from `Authentication-Results`, display-name spoofing
- **Links:** bare IP-address hosts, punycode domains, URL shorteners, link text that shows a different domain from the real target
- **Attachments:** executable, script, macro and HTML extensions, double extensions, a SHA-256 hash of every attachment
- **Body:** urgency language and requests for credentials
- **Output:** score, low / medium / high verdict, every point explained, defanged indicators (`hxxp://`, `[.]`), optional `--json`
- **Offline:** no network requests at all, checked by a test that blocks sockets
- Python standard library only: no third-party runtime dependencies

## Quick start

Requires Python 3.9 or newer.

```bash
git clone https://github.com/eriksalihu/phish-triage.git
cd phish-triage
python -m phish_triage samples/credential_phish.eml
python -m phish_triage samples/*.eml --json
```

## Example output

Copied from the job summary of this repository's CI run on the three files in `samples/`:

```text
File:    samples/newsletter.eml
Subject: November newsletter: preparing your garden for winter
From:    news[@]example[.]org
Verdict: LOW (score 0/100)

Why:
  nothing suspicious found

Indicators (defanged):
  url     hxxps://www[.]example[.]org/newsletter/2026-11
  url     hxxps://www[.]example[.]org/unsubscribe
  host    www[.]example[.]org

========================================================================

File:    samples/credential_phish.eml
Subject: Action required: your Lumora Pay account will be suspended
From:    alerts[@]account-check[.]test
Verdict: HIGH (score 100/100)
ATT&CK:  T1566.002

Why:
  +20  links        Link text shows www[.]lumorapay[.]example but the link goes to 203[.]0[.]113[.]45
  +15  headers      Reply-To domain lumora-secure[.]test differs from From domain account-check[.]test
  +15  headers      DMARC result is 'fail'
  +15  headers      Display name shows lumorapay[.]example but the real sender domain is account-check[.]test
  +15  links        Link points to a bare IP address: hxxp://203[.]0[.]113[.]45/lumora/login[.]php
  +15  links        Link uses a punycode (look-alike) domain: hxxp://xn--lumorapy-fza[.]test/verify
  +15  body         Asks for credentials or account details: 'verify your account', 'confirm your password'
  +10  headers      SPF result is 'softfail'
  +10  body         Urgency language: 'account will be suspended', 'within 24 hours', 'immediately'

Indicators (defanged):
  url     hxxp://203[.]0[.]113[.]45/lumora/login[.]php
  url     hxxp://xn--lumorapy-fza[.]test/verify
  host    203[.]0[.]113[.]45
  host    xn--lumorapy-fza[.]test

========================================================================

File:    samples/invoice_attachment.eml
Subject: Overdue invoice 4471 - final reminder
From:    billing[@]harborline-supplies[.]example
Verdict: HIGH (score 70/100)
ATT&CK:  T1566.001

Why:
  +35  attachments  Attachment 'Invoice_4471.pdf.exe' has an executable or script extension (.exe)
  +25  attachments  Attachment 'Invoice_4471.pdf.exe' hides its real type behind a double extension
  +10  body         Urgency language: 'final reminder', 'as soon as possible', 'avoid late fees'

Indicators (defanged):
  sha256  95edab315baefd75a802690607457ee0fd2f3479bcbec9d3e0cba4e44de0a124  Invoice_4471.pdf.exe (95 bytes)
```

## How each detection works

| Area | Check | Points | How it works |
|---|---|---|---|
| Headers | Reply-To mismatch | 15 | The Reply-To domain differs from the From domain, so replies go to someone else. |
| Headers | Return-Path mismatch | 10 | The bounce address domain differs from the From domain. |
| Headers | SPF / DKIM / DMARC failed | 10 / 10 / 15 | Reads `spf=`, `dkim=` and `dmarc=` in `Authentication-Results`; `fail` and `softfail` add points. |
| Headers | Display-name spoofing | 15 | The display name contains a domain or address that is not the real sender domain. |
| Links | IP-address host | 15 | The link host is a bare IP address instead of a name. |
| Links | Punycode domain | 15 | A label of the host starts with `xn--`, the encoding used for look-alike characters. |
| Links | URL shortener | 10 | The host is a known shortening service that hides the destination. |
| Links | Misleading link text | 20 | The visible text names one domain but the link goes to another. |
| Attachments | Executable or script | 35 | The file extension is one that runs code, such as `.exe`, `.js` or `.lnk`. |
| Attachments | Macro-enabled Office file | 15 | The extension is `.docm`, `.xlsm` or `.pptm`. |
| Attachments | HTML file | 10 | HTML attachments are often used to deliver a fake login page. |
| Attachments | Double extension | 25 | A harmless-looking extension is followed by a risky one, as in `invoice.pdf.exe`. |
| Body | Urgency language | 10 | Phrases that push the reader to act fast. |
| Body | Credential request | 15 | Phrases that ask the reader to verify an account or enter a password. |

The points are added up and capped at 100. From 25 the verdict is medium, from 60 it is high. Domains are compared by their last two labels, so `mail.example.org` and `example.org` count as the same sender.

The full walkthrough, with the reasoning behind the points and the likely false positives, is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## MITRE ATT&CK mapping

| Where the points come from | Technique | Name |
|---|---|---|
| Attachment checks | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment |
| Link checks | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link |

The report lists a technique only when the matching checks added points.

## Limitations

- The score is a triage aid, not a verdict. A low score does not prove an email is safe, and a high score still needs an analyst to confirm it.
- It is offline by design, so it does not look up domain age, reputation or where a shortened link leads, and it does not verify SPF or DKIM itself. It trusts the `Authentication-Results` header that the receiving mail server wrote.
- Domains are compared by their last two labels. That is wrong for suffixes such as `co.uk`, where two different organisations would look like the same domain.
- Attachments are judged by file name only. The content is hashed but not inspected, so a renamed file is not recognised.
- The phrase lists are English only and short.
- Links hidden in images, QR codes or attached documents are not seen.

## Next steps

- Use a public suffix list for exact domain comparison
- Recognise attachment types by content, not only by name
- Flag look-alike domains that are a few characters away from the claimed sender
- Add phrase lists for other languages

## Related projects

- [log-sentinel](https://github.com/eriksalihu/log-sentinel): finds SSH brute force, password spraying and web attack patterns in Linux auth logs and web access logs
- [soc-playbooks](https://github.com/eriksalihu/soc-playbooks): six tier-1 SOC alert scenarios, each with a Sigma detection rule and a response playbook
- [linux-audit](https://github.com/eriksalihu/linux-audit): read-only Bash script that checks basic Linux hardening and prints PASS, WARN or FAIL

## License

[MIT](LICENSE)
