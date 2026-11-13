"""Small helpers shared by all checks: the Finding record, domains and defanging."""
import ipaddress
import re
from dataclasses import dataclass


@dataclass
class Finding:
    """One reason the score went up: how many points, which area, and why."""
    points: int
    category: str  # "headers", "links", "attachments" or "body"
    reason: str


def is_ip(host):
    """True if `host` is an IPv4 or IPv6 address rather than a name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def base_domain(host):
    """Reduce a host name to its last two labels: mail.example.org -> example.org.

    This lets news@example.org and bounce@mail.example.org count as the same
    sender. It is a simplification: it does not know about suffixes such as
    co.uk, where three labels would be needed (see the limitations in the README).
    """
    host = host.lower().strip(".")
    if not host or is_ip(host):
        return host
    return ".".join(host.split(".")[-2:])


def defang(text):
    """Make a URL, domain or address safe to paste into a ticket or chat.

    http becomes hxxp and every dot becomes [.], so nothing turns into a
    clickable link by accident.
    """
    text = re.sub(r"^http", "hxxp", text, flags=re.I)
    return text.replace(".", "[.]").replace("@", "[@]")
