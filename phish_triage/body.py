"""Body checks: pressure to act fast, and requests for passwords or account details."""
import re

from .common import Finding

URGENCY = re.compile(
    r"urgent|immediately|within \d+ hours?|as soon as possible|final (notice|reminder|warning)"
    r"|action required|(account|access) (will be|has been) (suspended|closed|locked|disabled)"
    r"|avoid (suspension|late fees|legal action)", re.I)
CREDENTIALS = re.compile(
    r"(verify|confirm|validate|update) your (account|identity|password|details|payment)"
    r"|(enter|provide|confirm) your (password|pin|login|username)"
    r"|(log ?in|sign ?in) (now|here|to (verify|confirm|restore|keep))", re.I)


def _phrases(pattern, text):
    """Return the distinct phrases in `text` that match `pattern`, in order."""
    found = [match.group(0).lower() for match in pattern.finditer(text)]
    return list(dict.fromkeys(found))


def check_body(text):
    """Return the body findings for the readable text of an email."""
    findings = []
    urgency = _phrases(URGENCY, text)
    if urgency:
        findings.append(Finding(10, "body",
            "Urgency language: " + ", ".join(f"'{p}'" for p in urgency[:3])))
    credentials = _phrases(CREDENTIALS, text)
    if credentials:
        findings.append(Finding(15, "body",
            "Asks for credentials or account details: "
            + ", ".join(f"'{p}'" for p in credentials[:3])))
    return findings
