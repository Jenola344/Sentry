"""Dependency-free extraction of embedded text and metadata from image files.

This module performs **no optical character recognition**. It reads text that is
already stored inside the file:

- PNG ``tEXt`` / ``zTXt`` / ``iTXt`` chunks
- JPEG ``COM`` comments and EXIF text tags (ImageDescription, Software, Artist,
  UserComment)

plus privacy-relevant metadata (EXIF GPS presence).

Pixel-level OCR is delegated to the on-device UGOS ``ug-photo ocr`` binary
declared in the Skill; the portable reference engine never claims it.
"""

import zlib
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# EXIF tags whose values are human-readable text.
_EXIF_TEXT_TAGS = {
    0x010E: "ImageDescription",
    0x0131: "Software",
    0x013B: "Artist",
    0x9286: "UserComment",
}
_EXIF_GPS_POINTER = 0x8825


def _png_text_chunks(data: bytes) -> List[str]:
    """Returns the text payloads of every PNG tEXt/zTXt/iTXt chunk."""
    texts: List[str] = []
    offset = len(PNG_SIGNATURE)

    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        if payload_end + 4 > len(data):
            break  # truncated chunk
        payload = data[payload_start:payload_end]

        if chunk_type == b"tEXt":
            _, _, text = payload.partition(b"\x00")
            if text:
                texts.append(text.decode("latin-1", "ignore"))
        elif chunk_type == b"zTXt":
            _, _, compressed = payload.partition(b"\x00")
            if len(compressed) > 1:
                try:
                    texts.append(zlib.decompress(compressed[1:]).decode("latin-1", "ignore"))
                except zlib.error:
                    pass
        elif chunk_type == b"iTXt":
            text = _decode_itxt(payload)
            if text:
                texts.append(text)

        offset = payload_end + 4  # skip the trailing CRC

    return texts


def _decode_itxt(payload: bytes) -> str:
    """Decodes an iTXt payload: keyword, compression flag/method, lang, translated, text."""
    _, _, rest = payload.partition(b"\x00")
    if len(rest) < 2:
        return ""
    compression_flag = rest[0]
    rest = rest[2:]
    _, _, rest = rest.partition(b"\x00")      # language tag
    _, _, text = rest.partition(b"\x00")      # translated keyword
    if compression_flag == 1:
        try:
            text = zlib.decompress(text)
        except zlib.error:
            return ""
    return text.decode("utf-8", "ignore")


def _jpeg_segments(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Yields (marker, payload) for each JPEG segment."""
    offset = 2  # past SOI
    end_of_data = len(data)

    while offset < end_of_data:
        if data[offset] != 0xFF:
            offset += 1
            continue
        while offset + 1 < end_of_data and data[offset + 1] == 0xFF:
            offset += 1  # fill bytes
        if offset + 1 >= end_of_data:
            return
        marker = data[offset + 1]

        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if offset + 4 > end_of_data:
            return

        segment_length = int.from_bytes(data[offset + 2:offset + 4], "big")
        if segment_length < 2:
            return
        segment_end = offset + 2 + segment_length
        yield marker, data[offset + 4:min(segment_end, end_of_data)]
        offset = segment_end


def _parse_exif(payload: bytes) -> Tuple[List[str], bool]:
    """Extracts EXIF text tag values and reports whether a GPS IFD is present."""
    texts: List[str] = []
    if not payload.startswith(b"Exif\x00\x00"):
        return texts, False

    tiff = payload[6:]
    if len(tiff) < 8:
        return texts, False

    byte_order = tiff[:2]
    if byte_order == b"II":
        order = "little"
    elif byte_order == b"MM":
        order = "big"
    else:
        return texts, False

    def read_int(buffer: bytes, start: int, width: int) -> int:
        return int.from_bytes(buffer[start:start + width], order)

    if read_int(tiff, 2, 2) != 42:
        return texts, False

    ifd_offset = read_int(tiff, 4, 4)
    if not 8 <= ifd_offset < len(tiff):
        return texts, False
    entry_count = read_int(tiff, ifd_offset, 2)

    gps_present = False
    for index in range(entry_count):
        entry = ifd_offset + 2 + index * 12
        if entry + 12 > len(tiff):
            break

        tag = read_int(tiff, entry, 2)
        value_type = read_int(tiff, entry + 2, 2)
        count = read_int(tiff, entry + 4, 4)

        if tag == _EXIF_GPS_POINTER:
            gps_present = True
            continue
        if tag not in _EXIF_TEXT_TAGS or count == 0:
            continue
        if value_type not in (2, 7):  # ASCII or UNDEFINED
            continue

        if count <= 4:
            raw = tiff[entry + 8:entry + 8 + count]
        else:
            value_offset = read_int(tiff, entry + 8, 4)
            raw = tiff[value_offset:value_offset + count]
        if not raw:
            continue

        if raw.startswith(b"ASCII\x00"):  # UserComment charset prefix
            raw = raw[8:]
        text = raw.split(b"\x00")[0].decode("utf-8", "ignore").strip()
        if text:
            texts.append(text)

    return texts, gps_present


def extract_image_text(path: Path, max_bytes: int = 52428800) -> Dict[str, Any]:
    """Reads embedded text and exposure metadata from a PNG or JPEG file.

    Returns a dict with ``format`` (``png``/``jpeg``/``unknown``), combined
    ``text``, ``has_exif`` and ``gps`` (EXIF GPS IFD present, coordinates never
    returned).
    """
    result: Dict[str, Any] = {"format": "unknown", "text": "", "has_exif": False, "gps": False}

    try:
        with open(path, "rb") as image_file:
            data = image_file.read(max_bytes)
    except OSError:
        return result

    if data.startswith(PNG_SIGNATURE):
        result["format"] = "png"
        result["text"] = "\n".join(_png_text_chunks(data))
        return result

    if data.startswith(b"\xff\xd8"):
        result["format"] = "jpeg"
        texts: List[str] = []
        for marker, payload in _jpeg_segments(data):
            if marker == 0xFE:  # COM
                comment = payload.split(b"\x00")[0].decode("utf-8", "ignore").strip()
                if comment:
                    texts.append(comment)
            elif marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):  # APP1
                result["has_exif"] = True
                exif_texts, exif_gps = _parse_exif(payload)
                texts.extend(exif_texts)
                result["gps"] = bool(result["gps"] or exif_gps)
        result["text"] = "\n".join(texts)
        return result

    return result
