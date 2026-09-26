"""Tests for metadata sanitization (EXIF, GPS, XMP, IPTC removal)."""

import io
import struct
import zlib
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from imeta.api.server import app
from imeta.core.constants import FormatID
from imeta.core.serializer import serialize_imeta
from imeta.sanitize import get_sanitizer
from imeta.sanitize.gps_redactor import redact_gps

client = TestClient(app)


def build_jpeg_with_gps_and_make() -> bytes:
    """Helper creating a JPEG with both standard IFD tags (Make/Model) and a GPS sub-IFD."""
    img = Image.new("RGB", (100, 80), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    raw_jpeg = buf.getvalue()

    # Build little-endian TIFF with IFD0 (Make, Model, GPSInfo) and GPS sub-IFD (GPSLatitude)
    # TIFF header: II * \0 (offset to IFD0 = 8)
    # IFD0 at 8: 3 entries
    # 0x010F Make: "Nikon\0" (offset 50)
    # 0x0110 Model: "Z9\0" (offset 56)
    # 0x8825 GPSInfo: offset 64
    # Next IFD: 0
    # Offset 50: b"Nikon\x00"
    # Offset 56: b"Z9\x00"
    # Offset 60: Pad (4 bytes)
    # Offset 64: GPS sub-IFD (1 entry: 0x0002 GPSLatitude: RATIONAL[3], offset 80)
    # Offset 80: 3 rationals (24 bytes): 35/1, 40/1, 20/1

    tiff = bytearray()
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")  # 0..8
    tiff.extend(struct.pack("<H", 3))            # 8..10: 3 entries

    # Tag 0x010F Make (offset 50)
    tiff.extend(struct.pack("<HHI4s", 0x010F, 2, 6, struct.pack("<I", 50)))
    # Tag 0x0110 Model (offset 56)
    tiff.extend(struct.pack("<HHI4s", 0x0110, 2, 3, struct.pack("<I", 56)))
    # Tag 0x8825 GPSInfo (offset 64)
    tiff.extend(struct.pack("<HHI4s", 0x8825, 4, 1, struct.pack("<I", 64)))
    # Next IFD offset: 0
    tiff.extend(struct.pack("<I", 0))            # 46..50

    # Values
    tiff.extend(b"Nikon\x00")                    # 50..56
    tiff.extend(b"Z9\x00")                       # 56..59
    tiff.extend(b"\x00\x00\x00\x00\x00")         # 59..64 (pad to 64)

    # GPS Sub-IFD at 64
    tiff.extend(struct.pack("<H", 1))            # 64..66: 1 entry
    # Tag 0x0002 GPSLatitude (type 5 RATIONAL, count 3, offset 80)
    tiff.extend(struct.pack("<HHI4s", 0x0002, 5, 3, struct.pack("<I", 80)))
    tiff.extend(struct.pack("<I", 0))            # 78..82: pad/next IFD

    # Offset 82.. (pad to 84)
    tiff.extend(b"\x00\x00")
    # GPS Latitude values (3 RATIONALs = 24 bytes: 35/1, 40/1, 20/1)
    tiff.extend(struct.pack("<IIIIII", 35, 1, 40, 1, 20, 1))

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload

    return raw_jpeg[:2] + app1_segment + raw_jpeg[2:]


def test_sanitize_jpeg_remove_exif_removes_marker_and_output_still_opens_as_valid_jpeg(sample_jpeg_with_exif_bytes):
    """Sanitizing JPEG with remove_exif removes EXIF and produces a valid openable image."""
    assert b"Exif" in sample_jpeg_with_exif_bytes

    sanitizer = get_sanitizer(FormatID.JPEG)
    result = sanitizer.sanitize(sample_jpeg_with_exif_bytes, remove_exif=True)

    assert b"Exif" not in result.image_bytes
    assert "EXIF" in result.removed

    # Confirm Pillow can open and decode dimensions identically
    img = Image.open(io.BytesIO(result.image_bytes))
    assert img.size == (80, 60)


def test_sanitize_jpeg_gps_only_removes_gps_keeps_camera_model():
    """GPS-only removal removes GPS latitude/longitude bytes while keeping Camera Make/Model."""
    jpeg_with_gps = build_jpeg_with_gps_and_make()
    assert b"Nikon" in jpeg_with_gps
    assert struct.pack("<II", 35, 1) in jpeg_with_gps  # GPS rational

    sanitizer = get_sanitizer(FormatID.JPEG)
    result = sanitizer.sanitize(jpeg_with_gps, remove_gps_only=True)

    assert "GPS" in result.removed
    assert result.gps_only_downgraded is False
    assert b"Nikon" in result.image_bytes
    assert struct.pack("<II", 35, 1) not in result.image_bytes

    img = Image.open(io.BytesIO(result.image_bytes))
    assert img.size == (100, 80)


def test_sanitize_png_removes_exif_chunk_and_recomputes_crc(sample_png_bytes):
    """Sanitizing PNG removes eXIf chunk and recomputes valid chunk CRCs."""
    # Add an eXIf chunk to sample_png_bytes
    exif_data = b"II\x2a\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    crc = zlib.crc32(b"eXIf" + exif_data) & 0xFFFFFFFF
    exif_chunk = struct.pack(">I", len(exif_data)) + b"eXIf" + exif_data + struct.pack(">I", crc)
    # Insert before IEND
    iend_pos = sample_png_bytes.find(b"IEND") - 4
    png_with_exif = sample_png_bytes[:iend_pos] + exif_chunk + sample_png_bytes[iend_pos:]

    sanitizer = get_sanitizer(FormatID.PNG)
    result = sanitizer.sanitize(png_with_exif, remove_exif=True)

    assert b"eXIf" not in result.image_bytes
    assert "EXIF" in result.removed

    # Verify all remaining chunk CRCs in output
    pos = 8
    data = result.image_bytes
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        pos += 8
        chunk_data = data[pos:pos + length]
        crc_stored = struct.unpack(">I", data[pos + length:pos + length + 4])[0]
        pos += length + 4

        crc_computed = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        assert crc_stored == crc_computed

        if chunk_type == b"IEND":
            break


def test_sanitize_webp_removes_exif_and_fixes_riff_size(sample_webp_bytes):
    """Sanitizing WebP removes EXIF and rewrites RIFF size."""
    # Add an EXIF chunk to WebP
    exif_data = b"Exif\x00\x00II\x2a\x00\x08\x00\x00\x00\x00\x00\x00\x00"
    exif_chunk = b"EXIF" + struct.pack("<I", len(exif_data)) + exif_data
    webp_with_exif = sample_webp_bytes + exif_chunk
    # Fix initial RIFF size
    webp_with_exif = webp_with_exif[:4] + struct.pack("<I", len(webp_with_exif) - 8) + webp_with_exif[8:]

    sanitizer = get_sanitizer(FormatID.WEBP)
    result = sanitizer.sanitize(webp_with_exif, remove_exif=True)

    assert b"EXIF" not in result.image_bytes
    # Check RIFF header size
    riff_size = struct.unpack("<I", result.image_bytes[4:8])[0]
    assert riff_size == len(result.image_bytes) - 8


def test_sanitize_gps_only_downgrades_gracefully_on_malformed_offset(sample_jpeg_bytes):
    """Malformed GPS offset overlapping IFD0 safely downgrades to full EXIF removal."""
    # Build EXIF blob where GPS offset (0x8825) points back to 8 (IFD0 table itself!)
    tiff = bytearray()
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")  # 0..8
    tiff.extend(struct.pack("<H", 1))            # 8..10: 1 entry
    # GPSInfo pointing to offset 8 (overlap with IFD0!)
    tiff.extend(struct.pack("<HHI4s", 0x8825, 4, 1, struct.pack("<I", 8)))
    tiff.extend(struct.pack("<I", 0))

    redacted, succeeded = redact_gps(bytes(tiff))
    assert succeeded is False

    # Test through JPEG sanitizer
    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    jpeg_malformed = sample_jpeg_bytes[:2] + app1_segment + sample_jpeg_bytes[2:]

    sanitizer = get_sanitizer(FormatID.JPEG)
    result = sanitizer.sanitize(jpeg_malformed, remove_gps_only=True)

    assert result.gps_only_downgraded is True
    assert "EXIF" in result.removed
    assert b"Exif" not in result.image_bytes


def test_sanitize_via_imeta_container_input(sample_jpeg_with_exif_bytes):
    """Sanitizing an .imeta container file directly unpacks, verifies, and sanitizes payload."""
    imeta_bytes = serialize_imeta(sample_jpeg_with_exif_bytes)

    # 1. Sanitize raw JPEG via endpoint
    res_raw = client.post(
        "/sanitize",
        files={"file": ("photo.jpg", sample_jpeg_with_exif_bytes, "image/jpeg")},
        data={"remove_exif": "true"},
    )
    assert res_raw.status_code == 200

    # 2. Sanitize .imeta container via endpoint
    res_imeta = client.post(
        "/sanitize",
        files={"file": ("photo.imeta", imeta_bytes, "application/octet-stream")},
        data={"remove_exif": "true"},
    )
    assert res_imeta.status_code == 200
    assert res_imeta.content == res_raw.content
    assert res_imeta.headers.get("x-imeta-removed") == "EXIF"


def test_sanitize_rejects_both_flags_true(sample_png_bytes):
    """Selecting both remove_exif and remove_gps_only returns 400 Bad Request."""
    res = client.post(
        "/sanitize",
        files={"file": ("photo.png", sample_png_bytes, "image/png")},
        data={"remove_exif": "true", "remove_gps_only": "true"},
    )
    assert res.status_code == 400
    assert "Choose either 'remove all EXIF' or 'GPS only'" in res.json()["detail"]


def test_sanitize_rejects_no_flags_selected(sample_png_bytes):
    """Selecting no flags returns 400 Bad Request."""
    res = client.post(
        "/sanitize",
        files={"file": ("photo.png", sample_png_bytes, "image/png")},
        data={},
    )
    assert res.status_code == 400
    assert "Select at least one thing to remove" in res.json()["detail"]


def test_sanitize_rejects_corrupted_imeta_input(sample_jpeg_bytes):
    """Corrupted .imeta container returns 422 Unprocessable Entity and refuses to sanitize."""
    imeta_bytes = bytearray(serialize_imeta(sample_jpeg_bytes))
    # Corrupt a byte in payload
    imeta_bytes[32 + 20] ^= 0xFF

    res = client.post(
        "/sanitize",
        files={"file": ("bad.imeta", bytes(imeta_bytes), "application/octet-stream")},
        data={"remove_exif": "true"},
    )
    assert res.status_code == 422
    assert "integrity verification" in res.json()["detail"].lower()
