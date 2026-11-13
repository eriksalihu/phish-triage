"""Combine all checks into one report and format it as text or JSON."""
import email
import json
from dataclasses import asdict
from email import policy
from email.utils import parseaddr
from urllib.parse import urlsplit

from .attachments import check_attachments
from .body import check_body
from .common import defang
from .content import read_content
from .headers import check_headers
from .links import check_links

MEDIUM, HIGH = 25, 60  # score at which the verdict becomes medium / high


def analyse(path):
    """Read one .eml file and return its report as a plain dictionary."""
    with open(path, "rb") as handle:
        msg = email.message_from_binary_file(handle, policy=policy.default)
    text, links = read_content(msg)
    attachment_findings, attachments = check_attachments(msg)
    findings = check_headers(msg) + check_links(links) + attachment_findings + check_body(text)
    findings.sort(key=lambda f: -f.points)
    score = min(100, sum(f.points for f in findings))
    scored = {f.category for f in findings if f.points}
    urls = list(dict.fromkeys(url for url, _ in links))  # unique, in order
    hosts = dict.fromkeys(urlsplit(url).hostname or "" for url in urls)
    return {
        "file": str(path),
        "subject": str(msg.get("Subject", "")),
        "from": defang(parseaddr(str(msg.get("From", "")))[1]),
        "score": score,
        "verdict": "high" if score >= HIGH else "medium" if score >= MEDIUM else "low",
        # ATT&CK sub-technique suggested by where the points came from.
        "attack": [technique for category, technique in
                   (("attachments", "T1566.001"), ("links", "T1566.002")) if category in scored],
        "findings": [asdict(f) for f in findings],
        "indicators": {"urls": [defang(url) for url in urls],
                       "hosts": [defang(host) for host in hosts if host],
                       "attachments": attachments},
    }


def to_json(reports):
    return json.dumps(reports, indent=2)


def to_text(report):
    """Return the report as text that can be pasted into a ticket."""
    lines = [f"File:    {report['file']}", f"Subject: {report['subject']}",
             f"From:    {report['from']}",
             f"Verdict: {report['verdict'].upper()} (score {report['score']}/100)"]
    if report["attack"]:
        lines.append("ATT&CK:  " + ", ".join(report["attack"]))
    lines += ["", "Why:"]
    lines += [f"  +{f['points']:<3} {f['category']:<12} {f['reason']}" for f in report["findings"]]
    if not report["findings"]:
        lines.append("  nothing suspicious found")
    indicators = report["indicators"]
    lines += ["", "Indicators (defanged):"]
    lines += [f"  url     {url}" for url in indicators["urls"]]
    lines += [f"  host    {host}" for host in indicators["hosts"]]
    lines += [f"  sha256  {a['sha256']}  {a['filename']} ({a['size']} bytes)"
              for a in indicators["attachments"]]
    if not any(indicators.values()):
        lines.append("  none")
    return "\n".join(lines)
