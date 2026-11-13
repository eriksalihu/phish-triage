"""Link checks: IP hosts, punycode, URL shorteners and misleading link text."""
import re
from urllib.parse import urlsplit

from .common import Finding, base_domain, defang, is_ip

# Public URL-shortening services. They hide the real destination of a link.
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
              "buff.ly", "rebrand.ly", "cutt.ly"}
_DOMAIN_IN_TEXT = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)


def _rules(url, text):
    """Yield (rule name, points, reason) for every rule this one link breaks."""
    host = (urlsplit(url).hostname or "").lower()
    if is_ip(host):
        yield "ip", 15, f"Link points to a bare IP address: {defang(url)}"
    if any(label.startswith("xn--") for label in host.split(".")):
        yield "punycode", 15, f"Link uses a punycode (look-alike) domain: {defang(url)}"
    if host in SHORTENERS:
        yield "shortener", 10, f"Link hides its target behind a URL shortener: {defang(url)}"
    # Misleading text: the visible text names one domain, the link goes to another.
    shown = _DOMAIN_IN_TEXT.search(text)
    if shown and base_domain(shown[0]) != base_domain(host):
        yield "mismatch", 20, (f"Link text shows {defang(shown[0].lower())} "
                               f"but the link goes to {defang(host)}")


def check_links(links):
    """Return the link findings for a list of (url, link_text) pairs.

    Each rule is scored once per email, on the first link that breaks it, so
    ten bad links do not hide the other reasons behind a wall of points.
    """
    findings, seen = [], set()
    for url, text in links:
        for rule, points, reason in _rules(url, text):
            if rule not in seen:
                seen.add(rule)
                findings.append(Finding(points, "links", reason))
    return findings
