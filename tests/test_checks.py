"""Each check gets one input that must add points and one that must not."""
from email.message import EmailMessage

from phish_triage import links
from phish_triage.attachments import check_attachments
from phish_triage.body import check_body
from phish_triage.common import base_domain, defang
from phish_triage.headers import check_headers


def message(**headers):
    msg = EmailMessage()
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    msg.set_content("Hello")
    return msg


def reasons(findings):
    return " | ".join(f.reason for f in findings if f.points)


def test_reply_to_and_return_path_mismatch_fire():
    msg = message(From="a@example.org", Reply_To="b@other.test", Return_Path="<c@third.test>",
                  Authentication_Results="mx; spf=pass")
    assert sorted(f.points for f in check_headers(msg)) == [10, 15]


def test_subdomain_of_the_same_sender_is_not_a_mismatch():
    msg = message(From="news@example.org", Return_Path="<bounce@mail.example.org>",
                  Reply_To="help@example.org", Authentication_Results="mx; spf=pass")
    assert check_headers(msg) == []


def test_failed_authentication_fires_and_pass_does_not():
    failed = message(From="a@example.org", Authentication_Results="mx; spf=softfail; dkim=fail; dmarc=fail")
    passed = message(From="a@example.org", Authentication_Results="mx; spf=pass; dkim=pass; dmarc=pass")
    assert sum(f.points for f in check_headers(failed)) == 35
    assert check_headers(passed) == []


def test_missing_authentication_results_is_noted_without_points():
    findings = check_headers(message(From="a@example.org"))
    assert [f.points for f in findings] == [0]


def test_display_name_spoofing_fires_only_for_a_foreign_domain():
    spoofed = message(From='"support@bank.example" <x@other.test>', Authentication_Results="mx; spf=pass")
    honest = message(From='"news@example.org" <news@example.org>', Authentication_Results="mx; spf=pass")
    assert "Display name" in reasons(check_headers(spoofed))
    assert check_headers(honest) == []


def test_link_rules_fire():
    shortener = sorted(links.SHORTENERS)[0]
    found = links.check_links([
        ("http://203.0.113.45/login", ""),
        ("http://xn--exmple-cua.test/", ""),
        (f"https://{shortener}/abc", ""),
        ("https://login.other.test/", "www.bank.example"),
    ])
    assert sorted(f.points for f in found) == [10, 15, 15, 20]


def test_ordinary_links_stay_quiet():
    found = links.check_links([("https://www.example.org/news", "Read more"),
                               ("https://shop.example.org/", "www.example.org")])
    assert found == []


def attach(filename):
    msg = message(From="a@example.org")
    msg.add_attachment(b"placeholder", maintype="application", subtype="octet-stream", filename=filename)
    return check_attachments(msg)


def test_risky_double_extension_fires_and_is_hashed():
    findings, files = attach("invoice.pdf.exe")
    assert [f.points for f in findings] == [35, 25]
    # SHA-256 of b"placeholder"
    assert files[0]["sha256"] == "4097889236a2af26c293033feb964c4cf118c0224e0d063fec0a89e9d0569ef2"


def test_plain_pdf_attachment_stays_quiet():
    findings, files = attach("report.v2.pdf")
    assert findings == [] and files[0]["size"] == 11


def test_body_language_fires_and_normal_text_does_not():
    bad = check_body("Your account will be suspended. Verify your account immediately.")
    assert sorted(f.points for f in bad) == [10, 15]
    assert check_body("Here is the agenda for our meeting on Thursday.") == []


def test_helpers():
    assert base_domain("mail.EXAMPLE.org") == "example.org"
    assert base_domain("203.0.113.45") == "203.0.113.45"
    assert defang("http://a.example.org/x") == "hxxp://a[.]example[.]org/x"
