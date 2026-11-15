"""Pass 4: embedded image text and exposure metadata (no pixel OCR)."""

import struct
import zlib

import pytest

from support import OPENAI_KEY


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )


def make_png(*chunks: bytes) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + b"".join(chunks) + png_chunk(b"IEND", b"")


def png_text(keyword: str, text: str) -> bytes:
    return png_chunk(b"tEXt", keyword.encode() + b"\x00" + text.encode())


def png_ztxt(keyword: str, text: str) -> bytes:
    return png_chunk(b"zTXt", keyword.encode() + b"\x00\x00" + zlib.compress(text.encode()))


def png_itxt(keyword: str, text: str) -> bytes:
    payload = (
        keyword.encode() + b"\x00"
        + b"\x01" + b"\x00"          # compressed, deflate
        + b"en" + b"\x00"
        + b"\x00"                     # empty translated keyword
        + zlib.compress(text.encode())
    )
    return png_chunk(b"iTXt", payload)


def exif_payload(description=None, gps=False) -> bytes:
    """Builds a minimal little-endian EXIF/TIFF blob."""
    entries = []
    extra = b""
    ifd0_size = 2 + (int(bool(description)) + int(gps)) * 12 + 4
    data_start = 8 + ifd0_size

    if description is not None:
        raw = description.encode() + b"\x00"
        if len(raw) <= 4:
            value = raw.ljust(4, b"\x00")
        else:
            value = struct.pack("<I", data_start + len(extra))
            extra += raw
        entries.append((0x010E, 2, len(raw), value))

    if gps:
        entries.append((0x8825, 4, 1, struct.pack("<I", data_start + len(extra))))
        extra += b"\x00\x00"

    ifd = struct.pack("<H", len(entries))
    for tag, value_type, count, value in entries:
        ifd += struct.pack("<HHI", tag, value_type, count) + value
    ifd += struct.pack("<I", 0)

    return b"Exif\x00\x00" + b"II" + struct.pack("<H", 42) + struct.pack("<I", 8) + ifd + extra


def jpeg_bytes(comment=None, app1=None) -> bytes:
    out = b"\xff\xd8"
    if comment is not None:
        payload = comment.encode()
        out += b"\xff\xfe" + struct.pack(">H", len(payload) + 2) + payload
    if app1 is not None:
        out += b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    return out + b"\xff\xd9"


def scan(make_cli, share, path, name="image.png", **kwargs):
    cli = make_cli(**kwargs)
    cli.run_audit()
    assert cli.total_evaluated == 1
    return cli


def categories(cli):
    return [f["category"] for f in cli.findings]


@pytest.fixture
def quiet(capsys):
    capsys.readouterr()
    return capsys


def test_png_text_chunk_card_is_detected(make_cli, share, quiet):
    (share / "card.png").write_bytes(make_png(png_text("Comment", "VISA 4111 1111 1111 1111")))

    cli = scan(make_cli, share, share / "card.png")

    assert len(cli.findings) == 1
    finding = cli.findings[0]
    assert finding["category"] == "Payment Card (image text)"
    assert finding["severity"] == "HIGH"
    assert finding["masked_evidence"] == "4111-****-****-1111"
    assert "4111 1111 1111 1111" not in finding["masked_evidence"]


def test_png_compressed_text_chunk_is_detected(make_cli, share, quiet):
    (share / "notes.png").write_bytes(make_png(png_ztxt("Comment", f"deploy key {OPENAI_KEY}")))

    cli = scan(make_cli, share, share / "notes.png")

    assert categories(cli) == ["OpenAI API Key (image text)"]
    assert cli.findings[0]["severity"] == "CRITICAL"
    assert OPENAI_KEY[4:-4] not in cli.findings[0]["masked_evidence"]


def test_png_itxt_chunk_is_detected(make_cli, share, quiet):
    seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    (share / "recovery.png").write_bytes(make_png(png_itxt("Comment", f"seed: {seed}")))

    cli = scan(make_cli, share, share / "recovery.png")

    assert categories(cli) == ["Crypto Seed Phrase (image text)"]
    assert "ability" not in cli.findings[0]["masked_evidence"]


def test_jpeg_comment_is_scanned(make_cli, share, quiet):
    (share / "shot.jpg").write_bytes(jpeg_bytes(comment=f"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))

    cli = scan(make_cli, share, share / "shot.jpg")

    assert categories(cli) == ["AWS Credentials (image text)"]


def test_exif_text_tag_is_scanned(make_cli, share, quiet):
    (share / "photo.jpg").write_bytes(jpeg_bytes(app1=exif_payload(description=f"key {OPENAI_KEY}")))

    cli = scan(make_cli, share, share / "photo.jpg")

    assert categories(cli) == ["OpenAI API Key (image text)"]


def test_exif_gps_is_reported_without_coordinates(make_cli, share, quiet):
    (share / "trip.jpg").write_bytes(jpeg_bytes(app1=exif_payload(gps=True)))

    cli = scan(make_cli, share, share / "trip.jpg")

    assert categories(cli) == ["Image Metadata (GPS Location)"]
    finding = cli.findings[0]
    assert finding["severity"] == "MEDIUM"
    assert "withheld" in finding["masked_evidence"]
    assert cli.images_textless == 1


def test_image_without_text_or_metadata_is_clean(make_cli, share, quiet):
    (share / "plain.png").write_bytes(make_png())

    cli = scan(make_cli, share, share / "plain.png")

    assert cli.findings == []
    assert cli.images_inspected == 1
    assert cli.images_textless == 1


def test_pixel_bytes_are_not_interpreted_as_text(make_cli, share, quiet):
    """Regression guard: the old pass decoded raw pixels as text."""
    pixel_data = png_chunk(b"IDAT", zlib.compress(bytes(range(256)) * 4 + b"4111222233334444"))
    (share / "noise.png").write_bytes(make_png(pixel_data))

    cli = scan(make_cli, share, share / "noise.png")

    assert cli.findings == [], "only real text chunks may produce findings"


def test_non_luhn_digit_run_is_not_a_card(make_cli, share, quiet):
    (share / "invoice.png").write_bytes(make_png(png_text("Comment", "Order 4111 1111 1111 1112")))

    cli = scan(make_cli, share, share / "invoice.png")

    assert cli.findings == []


def test_truncated_image_does_not_raise(make_cli, share, quiet):
    (share / "broken.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x40tEXt")

    cli = scan(make_cli, share, share / "broken.png")

    assert cli.findings == []


def test_standard_depth_skips_images(make_cli, share, quiet):
    (share / "card.png").write_bytes(make_png(png_text("Comment", "4111 1111 1111 1111")))

    cli = scan(make_cli, share, share / "card.png", scan_depth="standard")

    assert cli.findings == []
    assert cli.images_inspected == 0
