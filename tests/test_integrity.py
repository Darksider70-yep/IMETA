"""Tests for cryptographic integrity and verification report generation."""

import struct
import pytest
from imeta.core.constants import CompressionID, MAGIC_HASH
from imeta.core.deserializer import deserialize_imeta
from imeta.core.exceptions import IntegrityError
from imeta.core.serializer import serialize_imeta
from imeta.core.validator import validate_container


def test_integrity_valid_container(sample_jpeg_bytes):
    imeta_bytes = serialize_imeta(sample_jpeg_bytes)
    report = validate_container(imeta_bytes, verify_payload_checksum=True)

    assert report.is_valid is True
    assert report.status == "VALID"
    assert report.errors == []
    assert report.expected_sha256 == report.computed_sha256


def test_tampered_payload_detected(sample_png_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes, compression=CompressionID.NONE))
    
    # Locate payload offset from header
    _, _, _, _, _, _, payload_off, integrity_off = struct.unpack(">4sBBBBQQQ", imeta_bytes[:32])
    
    # Tamper with 1 byte inside raw image payload (after 24-byte payload header)
    imeta_bytes[payload_off + 24 + 10] ^= 0xFF

    report = validate_container(bytes(imeta_bytes), verify_payload_checksum=True)
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("mismatch" in e.lower() for e in report.errors)

    with pytest.raises(IntegrityError):
        deserialize_imeta(bytes(imeta_bytes))


def test_tampered_digest_detected(sample_webp_bytes):
    imeta_bytes = bytearray(serialize_imeta(sample_webp_bytes))
    
    # Locate integrity block
    _, _, _, _, _, _, _, integrity_off = struct.unpack(">4sBBBBQQQ", imeta_bytes[:32])
    
    # Corrupt last byte of the 32-byte digest
    imeta_bytes[integrity_off + 8 + 31] ^= 0xAA

    report = validate_container(bytes(imeta_bytes), verify_payload_checksum=True)
    assert report.is_valid is False
    assert report.status == "CORRUPTED"
    assert any("mismatch" in e.lower() for e in report.errors)
