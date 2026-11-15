#!/usr/bin/env python3
"""Regenerates the synthetic NAS fixture set under engine/sample_nas/Shared.

Re-running this script produces byte-identical files, so the committed fixtures
can always be rebuilt and reviewed.

Notes
-----
* Every credential in this tree is a well-known public placeholder (for example
  AWS's documented `AKIAIOSFODNN7EXAMPLE`). Nothing here is a live secret.
* The images are real, viewable PNG/JPEG files written with Pillow (a declared
  engine dependency), not header stubs.
* `Archives/encrypted_keys.zip` is a real ZIP whose general-purpose bit 0 is set
  so Sentry classifies it as password-protected. Sentry never attempts
  decryption, so the entry body is a synthetic placeholder rather than genuine
  ciphertext.
"""

import io
import shutil
import struct
import zipfile
from pathlib import Path

from PIL import Image, PngImagePlugin

SAMPLE_ROOT = Path(__file__).resolve().parent
SHARE = SAMPLE_ROOT / "Shared"

OPENAI_KEY = "sk-live-TESTING993848194810284729184810"
DB_URI = "postgres://app_user:V3ryS3cur3Passw0rd!@127.0.0.1:5432/app_db"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
SLACK_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
GCP_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
PASSPORT_MRZ = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
BIP39_PHRASE = "abandon ability able about above absent absorb abstract absurd abuse access accident"
CARD_NUMBER = "4111 1111 1111 1111"

APP1_ENV = f"""# Production environment configuration
NODE_ENV=production
PORT=8080
OPENAI_API_KEY={OPENAI_KEY}
DATABASE_URL={DB_URI}
"""

APP2_ENV = f"""# Staging cloud deployment
AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY}
AWS_REGION=us-west-2
"""

LOCKFILE = """{
  "name": "enterprise-portal",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {
      "version": "1.6.8",
      "integrity": "sha512-v3b5N0fG3K9A3X9Y4Z1bC9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F=="
    }
  }
}
"""

INDEX_JS = """const port = process.env.PORT || 8080;
console.log(`Enterprise portal listening on ${port}`);
"""

WALLET_TXT = f"""METAMASK ETHEREUM WALLET SEED PHRASE BACKUP
Word Count: 12
Words:
{BIP39_PHRASE}

DO NOT SHARE THIS FILE.
"""

PAYROLL_CSV = """EmployeeID,Name,SSN,Department,GrossPay,NetPay,IBAN
E104,Jane Doe,123-45-6789,Engineering,9500.00,7100.00,DE89370400440532013000
E105,John Smith,219-09-9999,Security,10200.00,7800.00,FR7630006000011234567890189
"""

DEPLOY_SECRETS = f"""# CI deployment tokens - these must never live on shared storage
GITHUB_TOKEN={GITHUB_TOKEN}
SLACK_BOT_TOKEN={SLACK_TOKEN}
GCP_API_KEY={GCP_API_KEY}
STRIPE_SECRET_KEY={STRIPE_KEY}
"""

PASSPORT_TEXT = f"""PASSPORT SCAN (extracted text layer)
{PASSPORT_MRZ}
L898902C36UTO7408122F1204159ZE184226B<<<<<10
"""

MEETING_NOTES = """# Engineering Shared Storage

Weekly sync notes: build pipeline is green, storage quotas reviewed.
No credentials or personal records belong in this directory.
"""


def _pdf_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def build_pdf(lines) -> bytes:
    """Builds a small single-page PDF with a valid cross-reference table."""
    content = ["BT /F1 12 Tf 72 720 Td"]
    for index, line in enumerate(lines):
        if index:
            content.append("0 -18 Td")
        content.append(f"({_pdf_escape(line)}) Tj")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(out)


def build_encrypted_zip() -> bytes:
    """A real ZIP whose entries advertise password protection (flag bit 0)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "wallet-backup.json",
            '{"ciphertext": "synthetic placeholder - Sentry never decrypts archives"}'
        )

    data = bytearray(buffer.getvalue())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = 0
        while True:
            found = data.find(signature, cursor)
            if found < 0:
                break
            data[found + flag_offset] |= 0x01
            cursor = found + 4
    return bytes(data)


def _exif_with_gps() -> bytes:
    """EXIF/TIFF blob containing only a GPS IFD pointer."""
    ifd0_size = 2 + 12 + 4
    gps_ifd_offset = 8 + ifd0_size
    ifd0 = (
        struct.pack("<H", 1)
        + struct.pack("<HHI", 0x8825, 4, 1)
        + struct.pack("<I", gps_ifd_offset)
        + struct.pack("<I", 0)
    )
    gps_ifd = struct.pack("<H", 0) + struct.pack("<I", 0)
    tiff = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8) + ifd0 + gps_ifd
    return b"Exif\x00\x00" + tiff


def build_card_png() -> bytes:
    image = Image.new("RGB", (320, 200), (12, 20, 34))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text(
        "Comment",
        f"VISA CORPORATE {CARD_NUMBER} VALID THRU 11/28 CARDHOLDER A. VANCE"
    )
    metadata.add_text("Software", "UGOS Scan")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", pnginfo=metadata)
    return buffer.getvalue()


def build_plain_jpeg() -> bytes:
    image = Image.new("RGB", (320, 200), (70, 120, 180))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=72)
    return buffer.getvalue()


def build_gps_jpeg() -> bytes:
    """A real JPEG with an APP1 EXIF segment carrying a GPS IFD pointer."""
    jpeg = build_plain_jpeg()
    app1 = _exif_with_gps()
    segment = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    return jpeg[:2] + segment + jpeg[2:]


def build_media_mp4() -> bytes:
    return b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00" * 96


def write_text(relative_path: str, content: str) -> None:
    path = SHARE / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_bytes(relative_path: str, content: bytes) -> None:
    path = SHARE / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def main() -> None:
    if SHARE.exists():
        shutil.rmtree(SHARE)
    SHARE.mkdir(parents=True)

    # Pass 2 — text, code and configuration secrets
    write_text("Projects/app1/.env", APP1_ENV)
    write_text("Projects/app1/index.js", INDEX_JS)
    write_text("Projects/app1/package-lock.json", LOCKFILE)
    write_text("Projects/app2/.env", APP2_ENV)
    write_text("Backups/wallet_seed.txt", WALLET_TXT)
    write_text("Projects/app1/deploy-secrets.txt", DEPLOY_SECRETS)
    write_text("Documents/meeting_notes.md", MEETING_NOTES)
    write_text("Documents/passport_mrz.txt", PASSPORT_TEXT)

    # Pass 3 — structured documents and financial records
    write_text("Finance/payroll_2026.csv", PAYROLL_CSV)
    write_bytes(
        "Documents/Bank_Statement_Jan2026.pdf",
        build_pdf([
            "UGREEN PRIVATE WEALTH STATEMENT",
            "Account Holder: Alexander Vance",
            "Account Balance: $482,910.00 USD",
            "Routing Number: 021000021",
            "Wire Transfer ID: UGR-88921-NYC",
        ])
    )
    write_bytes("Documents/corrupt_doc.pdf", b"")

    # Pass 4 — embedded image text and exposure metadata
    write_bytes("Photos/payment_card.png", build_card_png())
    write_bytes("Photos/vacation.jpg", build_plain_jpeg())
    write_bytes("Photos/camera_upload.jpg", build_gps_jpeg())

    # Pass 1 — edge cases
    write_bytes("Archives/encrypted_keys.zip", build_encrypted_zip())
    write_bytes("Media/product_demo.mp4", build_media_mp4())

    created = sorted(
        path.relative_to(SHARE).as_posix() for path in SHARE.rglob("*") if path.is_file()
    )
    print(f"Regenerated {len(created)} fixture files under {SHARE}")
    for name in created:
        print(f"  + {name}")


if __name__ == "__main__":
    main()
