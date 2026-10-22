"""Tests for CLI sanitize subcommand and Zstandard CLI integration."""

import io
import struct
from pathlib import Path

import pytest
from PIL import Image

from imeta.cli.main import main
from imeta.core.constants import CompressionID
from imeta.core.serializer import serialize_imeta
from imeta.compression import is_zstd_available


def _build_jpeg_with_exif() -> bytes:
    """Minimal JPEG with an EXIF APP1 marker."""
    img = Image.new("RGB", (60, 40), color=(200, 100, 50))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    raw_jpeg = buf.getvalue()

    # Minimal little-endian TIFF with Make tag
    tiff = bytearray()
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")  # TIFF header, IFD0 at 8
    tiff.extend(struct.pack("<H", 1))              # 1 entry
    offset_make = 8 + 2 + 12 + 4  # 26
    tiff.extend(struct.pack("<HHI4s", 0x010F, 2, 6, struct.pack("<I", offset_make)))
    tiff.extend(struct.pack("<I", 0))              # next IFD
    tiff.extend(b"Canon\x00")

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    return raw_jpeg[:2] + app1_segment + raw_jpeg[2:]


# ── CLI sanitize tests ──────────────────────────────────────────────────

def test_cli_sanitize_remove_exif(tmp_path):
    """CLI: sanitize --remove-exif removes EXIF and writes a valid image."""
    jpeg = _build_jpeg_with_exif()
    assert b"Exif" in jpeg

    in_path = tmp_path / "photo.jpg"
    in_path.write_bytes(jpeg)
    out_path = tmp_path / "photo_clean.jpg"

    exit_code = main(["sanitize", str(in_path), "-o", str(out_path), "--remove-exif"])
    assert exit_code == 0
    assert out_path.is_file()

    sanitized = out_path.read_bytes()
    assert b"Exif" not in sanitized
    # Still a valid JPEG
    img = Image.open(io.BytesIO(sanitized))
    assert img.size == (60, 40)


def test_cli_sanitize_remove_gps(tmp_path):
    """CLI: sanitize --remove-gps removes GPS tags from a JPEG."""
    # Build JPEG with GPS
    img = Image.new("RGB", (80, 60), color=(50, 100, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    raw_jpeg = buf.getvalue()

    tiff = bytearray()
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")
    tiff.extend(struct.pack("<H", 2))  # 2 entries: Make + GPSInfo
    offset_make = 8 + 2 + 12 * 2 + 4  # 40
    offset_gps_ifd = offset_make + 6   # 46
    tiff.extend(struct.pack("<HHI4s", 0x010F, 2, 6, struct.pack("<I", offset_make)))
    tiff.extend(struct.pack("<HHI4s", 0x8825, 4, 1, struct.pack("<I", offset_gps_ifd)))
    tiff.extend(struct.pack("<I", 0))
    tiff.extend(b"Canon\x00")  # Make value
    # GPS sub-IFD: 1 entry
    tiff.extend(struct.pack("<H", 1))
    # GPSLatitude (inline value, 4 bytes → type 3 SHORT, count 1)
    tiff.extend(struct.pack("<HHI4s", 0x0001, 3, 1, struct.pack("<I", 78)))
    tiff.extend(struct.pack("<I", 0))  # next IFD

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    jpeg_gps = raw_jpeg[:2] + app1_segment + raw_jpeg[2:]

    in_path = tmp_path / "gps_photo.jpg"
    in_path.write_bytes(jpeg_gps)
    out_path = tmp_path / "no_gps.jpg"

    exit_code = main(["sanitize", str(in_path), "-o", str(out_path), "--remove-gps"])
    assert exit_code == 0
    assert out_path.is_file()
    # Camera Make should still be present
    assert b"Canon" in out_path.read_bytes()


def test_cli_sanitize_imeta_input(tmp_path, sample_jpeg_with_exif_bytes):
    """CLI: sanitize can process .imeta container input and strip EXIF."""
    imeta_bytes = serialize_imeta(sample_jpeg_with_exif_bytes)

    in_path = tmp_path / "photo.imeta"
    in_path.write_bytes(imeta_bytes)
    out_path = tmp_path / "photo_clean.jpg"

    exit_code = main(["sanitize", str(in_path), "-o", str(out_path), "--remove-exif"])
    assert exit_code == 0
    assert out_path.is_file()
    assert b"Exif" not in out_path.read_bytes()


def test_cli_sanitize_no_flags_returns_error(tmp_path, sample_png_bytes):
    """CLI: sanitize with no removal flags prints error and exits 1."""
    in_path = tmp_path / "photo.png"
    in_path.write_bytes(sample_png_bytes)

    exit_code = main(["sanitize", str(in_path)])
    assert exit_code == 1


def test_cli_sanitize_default_output_path(tmp_path):
    """CLI: sanitize without -o writes to <stem>_sanitized.<ext>."""
    jpeg = _build_jpeg_with_exif()
    in_path = tmp_path / "original.jpg"
    in_path.write_bytes(jpeg)

    exit_code = main(["sanitize", str(in_path), "--remove-exif"])
    assert exit_code == 0

    default_out = tmp_path / "original_sanitized.jpg"
    assert default_out.is_file()


def test_cli_sanitize_mutually_exclusive_flags(tmp_path, sample_png_bytes):
    """CLI: --remove-exif and --remove-gps cannot be used together (argparse enforces)."""
    in_path = tmp_path / "photo.png"
    in_path.write_bytes(sample_png_bytes)

    with pytest.raises(SystemExit) as exc_info:
        main(["sanitize", str(in_path), "--remove-exif", "--remove-gps"])
    assert exc_info.value.code == 2  # argparse exits with code 2


# ── CLI zstd encode tests ───────────────────────────────────────────────

@pytest.mark.skipif(not is_zstd_available(), reason="zstandard not installed")
def test_cli_encode_zstd_roundtrip(tmp_path, sample_png_bytes):
    """CLI: encode with --compression zstd and decode produce identical bitstream."""
    img_path = tmp_path / "test.png"
    img_path.write_bytes(sample_png_bytes)

    imeta_path = tmp_path / "test.png.imeta"
    recon_path = tmp_path / "test_out.png"

    # Encode with zstd
    exit_code = main(["encode", str(img_path), "-o", str(imeta_path), "--compression", "zstd"])
    assert exit_code == 0
    assert imeta_path.is_file()

    # Verify
    exit_code = main(["verify", str(imeta_path)])
    assert exit_code == 0

    # Decode
    exit_code = main(["decode", str(imeta_path), "-o", str(recon_path)])
    assert exit_code == 0
    assert recon_path.read_bytes() == sample_png_bytes
