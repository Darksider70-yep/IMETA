"""Tests for corruption detection, malformed inputs, and security boundary enforcement."""

import struct
import zlib
import pytest

from imeta.core.constants import CompressionID, FormatID, HeaderFlags
from imeta.core.deserializer import deserialize_imeta
from imeta.core.exceptions import (
    CorruptedFileError,
    IntegrityError,
    SecurityLimitError,
    UnsupportedFormatError,
    VersionIncompatibilityError,
)
from imeta.core.parser import parse_image_bytes
from imeta.core.serializer import serialize_imeta
from imeta.core.validator import validate_container
from imeta.compression.zlib import DeflateCompressor


def test_corrupted_file_header_magic(sample_png_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes))
    imeta_bytes[0:4] = b"BAD!"

    report = validate_container(bytes(imeta_bytes))
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("Invalid magic" in e for e in report.errors)

    with pytest.raises(CorruptedFileError):
        deserialize_imeta(bytes(imeta_bytes))


def test_corrupted_offsets_out_of_bounds(sample_png_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes))
    # Change metadata_offset to point beyond file end
    struct.pack_into(">Q", imeta_bytes, 8, 999999)

    report = validate_container(bytes(imeta_bytes))
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("metadata_offset" in e for e in report.errors)


def test_corrupted_metadata_length(sample_png_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes))
    # Locate metadata_offset (offset 8 in header)
    meta_off = struct.unpack(">Q", imeta_bytes[8:16])[0]
    
    # Corrupt metadata length to be extremely large (overflows payload offset)
    struct.pack_into(">Q", imeta_bytes, meta_off + 8, 50000)

    report = validate_container(bytes(imeta_bytes))
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("Metadata length" in e for e in report.errors)


def test_truncated_file(sample_jpeg_bytes):
    imeta_bytes = serialize_imeta(sample_jpeg_bytes)
    
    # Truncate at half length
    truncated = imeta_bytes[:len(imeta_bytes) // 2]

    report = validate_container(truncated)
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("truncated" in e.lower() for e in report.errors)

    with pytest.raises(CorruptedFileError):
        deserialize_imeta(truncated)


def test_unsupported_format_id(sample_png_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes))
    payload_off = struct.unpack(">Q", imeta_bytes[16:24])[0]
    
    # Set format_id in payload header to 0x0099 (unsupported)
    struct.pack_into(">H", imeta_bytes, payload_off + 4, 0x0099)

    report = validate_container(bytes(imeta_bytes))
    assert report.is_valid is False
    assert any("Unsupported format ID" in e for e in report.errors)


def test_flag_contradiction_detection(sample_png_bytes):
    """File header flag bit1 contradicts compression_id in payload header."""
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes, compression=CompressionID.NONE))
    
    # Force flag bit1 (PAYLOAD_COMPRESSED) to 1 while compression_id is NONE (0)
    imeta_bytes[6] |= HeaderFlags.PAYLOAD_COMPRESSED

    report = validate_container(bytes(imeta_bytes))
    assert report.is_valid is False
    assert any("Flag contradiction" in e for e in report.errors)


def test_empty_metadata_handling(sample_png_bytes):
    """Empty metadata JSON {} is handled gracefully."""
    imeta_bytes = serialize_imeta(sample_png_bytes, metadata_override={})
    container = deserialize_imeta(imeta_bytes)
    
    assert container.image_bytes == sample_png_bytes
    assert container.metadata["format"] == "PNG"
    assert container.metadata["extension"] == ".png"


def test_unicode_exif_handling(sample_jpeg_with_exif_bytes):
    """EXIF containing unicode strings (Japanese, emojis, etc.) is preserved without crashing."""
    imeta_bytes = serialize_imeta(sample_jpeg_with_exif_bytes)
    container = deserialize_imeta(imeta_bytes)
    
    desc = container.metadata.get("exif", {}).get("ImageDescription", "")
    assert "Tokyo" in desc
    assert "東京" in desc
    assert container.image_bytes == sample_jpeg_with_exif_bytes


def test_unsupported_raw_image_magic():
    """Parsing arbitrary non-image bytes raises UnsupportedFormatError."""
    fake_data = b"NOT_AN_IMAGE_FILE_AT_ALL_123456789"
    with pytest.raises(UnsupportedFormatError):
        parse_image_bytes(fake_data)


def test_decompression_bomb_safety():
    """Decompression bomb with absurd expansion ratio is intercepted safely."""
    # Create 10MB of zeroes compressed to tiny bytes
    bomb_payload = zlib.compress(b"\x00" * (10 * 1024 * 1024))
    
    compressor = DeflateCompressor()
    # If claiming a normal expected size (or 0) but ratio exceeds limit
    with pytest.raises(SecurityLimitError):
        compressor.decompress(bomb_payload, expected_size=600 * 1024 * 1024)
