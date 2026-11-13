"""Attachment checks: risky and double extensions, plus a SHA-256 for each file."""
import hashlib
from pathlib import PurePosixPath

from .common import Finding

# Files that run code when opened.
RISKY = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
         ".jar", ".lnk", ".msi", ".iso", ".img"}
# Office files that can carry macros.
MACRO = {".docm", ".xlsm", ".pptm"}
# HTML attachments are a common way to deliver a fake login page.
HTML = {".html", ".htm"}
# Harmless-looking extensions used as a disguise in names like invoice.pdf.exe.
DECOY = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}


def check_attachments(msg):
    """Return (findings, attachments). Attachments are hashed but never opened or run."""
    findings, attachments = [], []
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        data = part.get_payload(decode=True) or b""
        attachments.append({"filename": name, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        suffixes = [s.lower() for s in PurePosixPath(name).suffixes]
        last = suffixes[-1] if suffixes else ""
        if last in RISKY:
            findings.append(Finding(35, "attachments",
                f"Attachment '{name}' has an executable or script extension ({last})"))
        elif last in MACRO:
            findings.append(Finding(15, "attachments",
                f"Attachment '{name}' is a macro-enabled Office file ({last})"))
        elif last in HTML:
            findings.append(Finding(10, "attachments",
                f"Attachment '{name}' is an HTML file, often used for fake login pages"))
        # Double extension: a document-looking name that really ends in a risky type.
        if len(suffixes) >= 2 and suffixes[-2] in DECOY and last in RISKY | MACRO | HTML:
            findings.append(Finding(25, "attachments",
                f"Attachment '{name}' hides its real type behind a double extension"))
    return findings, attachments
