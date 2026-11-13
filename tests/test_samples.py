"""End-to-end tests on the three synthetic sample emails."""
import json
import socket

from phish_triage import cli


def run(capsys, *names):
    code = cli.main(["--json"] + [f"samples/{name}.eml" for name in names])
    assert code == 0
    return json.loads(capsys.readouterr().out)


def test_newsletter_is_low_with_no_points(capsys):
    report = run(capsys, "newsletter")[0]
    assert (report["verdict"], report["score"], report["attack"]) == ("low", 0, [])


def test_credential_phish_is_high_and_maps_to_the_link_technique(capsys):
    report = run(capsys, "credential_phish")[0]
    assert report["verdict"] == "high" and report["attack"] == ["T1566.002"]
    assert {f["category"] for f in report["findings"]} == {"headers", "links", "body"}


def test_invoice_attachment_is_high_and_maps_to_the_attachment_technique(capsys):
    report = run(capsys, "invoice_attachment")[0]
    assert report["verdict"] == "high" and report["attack"] == ["T1566.001"]
    assert report["indicators"]["attachments"][0]["filename"] == "Invoice_4471.pdf.exe"


def test_every_point_has_a_reason_and_scores_add_up(capsys):
    for report in run(capsys, "newsletter", "credential_phish", "invoice_attachment"):
        assert all(f["reason"] for f in report["findings"])
        assert report["score"] == min(100, sum(f["points"] for f in report["findings"]))


def test_indicators_are_defanged(capsys):
    text = json.dumps(run(capsys, "credential_phish")[0]["indicators"])
    assert "http://" not in text and "hxxp://203[.]0[.]113[.]45" in text


def test_analysis_never_opens_a_network_connection(capsys, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("phish-triage must stay offline")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    assert len(run(capsys, "newsletter", "credential_phish", "invoice_attachment")) == 3
