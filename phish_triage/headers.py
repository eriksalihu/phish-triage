"""Header checks: sender mismatches, SPF/DKIM/DMARC results, display-name spoofing."""
import re
from email.utils import parseaddr

from .common import Finding, base_domain, defang

# Points for a failed check as recorded by the receiving mail server.
AUTH_POINTS = {"spf": 10, "dkim": 10, "dmarc": 15}
# Points when a header's domain differs from the From domain.
MISMATCH_POINTS = {"Reply-To": 15, "Return-Path": 10}


def _domain_of(header_value):
    """Return the base domain of the address in a header, or '' if there is none."""
    address = parseaddr(str(header_value or ""))[1]
    return base_domain(address.rpartition("@")[2])


def check_headers(msg):
    """Return the header findings for an email.message.EmailMessage."""
    findings = []
    display_name = parseaddr(str(msg.get("From", "")))[0]
    from_domain = _domain_of(msg.get("From"))

    for header, points in MISMATCH_POINTS.items():
        other = _domain_of(msg.get(header))
        if other and from_domain and other != from_domain:
            findings.append(Finding(points, "headers",
                f"{header} domain {defang(other)} differs from From domain {defang(from_domain)}"))

    # The receiving server writes its verdicts as "spf=pass", "dkim=fail" and so on.
    results = " ".join(str(v) for v in msg.get_all("Authentication-Results", [])).lower()
    if not results:
        findings.append(Finding(0, "headers",
            "No Authentication-Results header, so SPF, DKIM and DMARC could not be checked"))
    for mechanism, points in AUTH_POINTS.items():
        match = re.search(rf"\b{mechanism}=(\w+)", results)
        if match and match[1] in ("fail", "softfail"):
            findings.append(Finding(points, "headers",
                f"{mechanism.upper()} result is '{match[1]}'"))

    # Display-name spoofing: the visible name shows a domain or address that is
    # not the real sender, e.g. "support@bank.example" <someone@other.test>.
    shown = re.search(r"[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}", display_name.lower())
    if shown and from_domain and base_domain(shown[0]) != from_domain:
        findings.append(Finding(15, "headers",
            f"Display name shows {defang(shown[0])} but the real sender domain is {defang(from_domain)}"))
    return findings
