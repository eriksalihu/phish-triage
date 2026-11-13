"""Command-line entry point: analyse one or more .eml files and print the reports."""
import argparse

from . import report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="phish_triage",
        description="Score .eml files for phishing risk and explain every point. "
                    "Works offline: no link is opened and no attachment is run.")
    parser.add_argument("files", nargs="+", metavar="FILE.eml", help="email file(s) to analyse")
    parser.add_argument("--json", action="store_true", help="print the reports as JSON")
    args = parser.parse_args(argv)

    reports = [report.analyse(path) for path in args.files]
    if args.json:
        print(report.to_json(reports))
    else:
        print(("\n\n" + "=" * 72 + "\n\n").join(report.to_text(r) for r in reports))
    return 0  # a high score is a finding, not an error, so the exit code stays 0
