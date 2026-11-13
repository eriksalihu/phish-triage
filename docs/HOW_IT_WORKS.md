# How phish-triage works

This document explains the design in plain language: how an email file becomes a score, what every check looks for, why it has the points it has, and where it can be wrong.

## The pipeline

```
.eml file -> email parser -> four groups of checks -> findings -> score, verdict and indicators -> text or JSON
```

1. **Parse.** `report.analyse` opens the file with Python's built-in `email` package. This gives a message object with headers, body parts and attachments. Nothing is rendered, opened or executed.
2. **Extract.** `content.py` walks through the text parts of the email. For HTML parts it collects the visible text and every link as a pair: where the link goes (`href`) and what the reader sees (the link text). For plain-text parts it finds URLs with a regular expression.
3. **Check.** Four modules each return a list of findings. A `Finding` is three things: points, a category (headers, links, attachments or body) and a reason in one sentence.
   - `headers.py` looks at who sent the email and whether it passed authentication.
   - `links.py` looks at where the links go.
   - `attachments.py` looks at file names and computes hashes.
   - `body.py` looks at the wording.
4. **Score.** The points of all findings are added and capped at 100. Below 25 the verdict is low, from 25 it is medium, from 60 it is high.
5. **Report.** `report.py` prints the verdict, each finding with its points, and the indicators. `cli.py` handles the command line.

Because the score is only the sum of the listed findings, every point can be explained. There is no hidden weighting.

## Two helpers worth understanding

**`base_domain`** reduces a host name to its last two labels, so `mail.example.org` becomes `example.org`. Legitimate senders often use a subdomain for bounces or newsletters, and without this step every newsletter would look like a mismatch. The cost is that suffixes like `co.uk` are handled wrongly (see Limitations in the README).

**`defang`** rewrites indicators so they cannot be clicked by accident: `http` becomes `hxxp`, every `.` becomes `[.]` and `@` becomes `[@]`. Analysts do this before pasting a malicious URL into a ticket or chat. Every URL and domain in the report, including inside the reasons, is defanged.

## The checks

### Headers

| Check | Points | Looks for |
|---|---|---|
| Reply-To mismatch | 15 | The Reply-To domain is different from the From domain. |
| Return-Path mismatch | 10 | The Return-Path (bounce address) domain is different from the From domain. |
| SPF failed | 10 | `spf=fail` or `spf=softfail` in `Authentication-Results`. |
| DKIM failed | 10 | `dkim=fail` in `Authentication-Results`. |
| DMARC failed | 15 | `dmarc=fail` in `Authentication-Results`. |
| Display-name spoofing | 15 | The display name contains a domain or email address whose domain is not the real sender domain. |

- **Why Reply-To scores more than Return-Path:** a different Reply-To means the victim's answer goes to the attacker, which is the whole point of many scams. A different Return-Path is common with legitimate mailing services, so it gets fewer points.
- **What the three authentication results mean:** SPF checks that the sending server is allowed to send for the domain. DKIM checks a cryptographic signature added by the sending domain. DMARC ties the two to the visible From address and is the strongest signal of the three, so it scores highest.
- **Where the results come from:** the tool does not verify anything itself. It reads the verdict that the receiving mail server wrote into the `Authentication-Results` header. If that header is missing, the report says so with 0 points, because "not checked" is not the same as "passed".
- **Display-name spoofing example:** `"Lumora Pay Support <support@lumorapay.example>" <alerts@account-check.test>`. Many mail clients show only the part in quotes, so the reader sees a trusted address while the real sender is someone else.
- **Likely false positives:** mailing lists and newsletter services that send on behalf of a company (Return-Path and sometimes Reply-To differ); forwarded email, which often breaks SPF; a person who puts their company website in their display name while writing from a private address.

### Links

| Check | Points | Looks for |
|---|---|---|
| IP-address host | 15 | The link goes to a bare IP address, such as `http://203.0.113.45/login`. |
| Punycode domain | 15 | A part of the host name starts with `xn--`. |
| URL shortener | 10 | The host is on a short list of public shortening services. |
| Misleading link text | 20 | The visible text contains a domain, and the link goes to a different domain. |

- **IP-address host:** real organisations publish links with names, not numbers.
- **Punycode:** domain names with non-ASCII characters are stored in an ASCII form that starts with `xn--`. Attackers use characters that look like Latin letters to imitate a known name. Punycode is also used honestly for names in other alphabets, which is why it is a signal and not proof.
- **Misleading link text** has the highest link score because it is a deliberate deception: the reader sees `www.lumorapay.example` and the click goes somewhere else.
- **Scored once per email:** each link rule adds points only for the first link that breaks it. Ten bad links would otherwise push the score to 100 on their own and hide the other reasons.
- **Likely false positives:** marketing emails that route every link through a click-tracking domain (misleading link text); internal tools reached by IP address; shortened links shared by a colleague; legitimate internationalised domain names.

### Attachments

| Check | Points | Looks for |
|---|---|---|
| Executable or script | 35 | Extensions that run code: `.exe .scr .js .vbs .bat .cmd .ps1 .hta .jar .lnk .msi .iso .img` |
| Macro-enabled Office file | 15 | `.docm .xlsm .pptm` |
| HTML file | 10 | `.html .htm` |
| Double extension | 25 | A harmless-looking extension followed by a risky one, such as `invoice.pdf.exe`. |

- **Why these score so high:** there is almost no good reason to email a program to someone, and no good reason at all to disguise it as a PDF. An executable with a double extension reaches 60 points and a high verdict on its own.
- **Hashes:** every attachment gets a SHA-256 hash in the indicator list. The hash identifies the exact file, so the analyst can search for it in other mailboxes or in a threat-intelligence source without touching the file.
- **Safety:** the attachment bytes are only decoded and hashed. They are never written to disk, opened or run.
- **Likely false positives:** developers or IT staff who really do send scripts to each other; finance teams that use macro-enabled spreadsheets; file names with a version number such as `report.v2.pdf` are not flagged, because the last extension is harmless.
- **Can miss:** a dangerous file inside a `.zip`, or a file that has simply been renamed, because only the name is checked.

### Body

| Check | Points | Looks for |
|---|---|---|
| Urgency language | 10 | Phrases such as "immediately", "within 24 hours", "final reminder", "account will be suspended". |
| Credential request | 15 | Phrases such as "verify your account", "confirm your password", "log in to restore". |

- **Why:** phishing works by rushing people. Pressure plus a request for a password is the classic pattern.
- **Why the points are low:** real invoices, reminders and password-reset emails use the same words. Wording alone can lift an email to medium at most (25 points), never to high.
- **Likely false positives:** genuine payment reminders, real security notices, internal IT announcements.

## The verdict thresholds

- **Low (0 to 24):** nothing or one weak signal. Example: only urgency wording.
- **Medium (25 to 59):** several weak signals or one strong one. Worth a closer look.
- **High (60 to 100):** strong signals that agree with each other, such as failed DMARC plus a misleading link plus a credential request.

The thresholds are two constants at the top of `report.py`.

## ATT&CK mapping

If attachment checks added points, the report lists T1566.001 (Spearphishing Attachment). If link checks added points, it lists T1566.002 (Spearphishing Link). An email can have both.

## The sample data

The three files in `samples/` are synthetic. They use reserved domains (`example.org`, `example.net`, `.example`, `.test`), the reserved IP range 203.0.113.0/24 and invented brand names.

- `newsletter.eml`: a harmless newsletter with passing authentication. Score 0.
- `credential_phish.eml`: a fake account warning with a spoofed display name, failed authentication, a misleading link to an IP address and a punycode link.
- `invoice_attachment.eml`: an "overdue invoice" with the attachment `Invoice_4471.pdf.exe`. The attachment is one line of plain text, not a program.

## The tests

`tests/test_checks.py` gives every check one input that must add points and one similar input that must not, for example a Return-Path on a subdomain of the sender. `tests/test_samples.py` runs the whole tool on the three samples, checks that the score equals the sum of the findings, that indicators are defanged, and that the analysis still works when all network sockets are blocked.

## Exit code

The tool exits with 0 when it ran correctly, whatever the score. A high-risk email is a finding, not an error, so CI can run the tool on the samples without failing the build.
