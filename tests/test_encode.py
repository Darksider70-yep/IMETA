"""Tests for IMETA serialization and encoding."""

import struct
from pathlib import Path
from imeta.core.constants import (
    MAGIC_FILE,
    MAGIC_META,
    MAGIC_DATA,
    MAGIC_HASH,
    MAJOR_VERSION,
    MINOR_VERSION,
    FormatID,
    CompressionID,
    HeaderFlags,
)
from imeta.core.serializer import serialize_imeta, encode_file
from imeta.core.hashing import compute_sha256


def test_encode_png_uncompressed(sample_png_bytes):
    imeta_bytes = serialize_imeta(sample_png_bytes, compression=CompressionID.NONE)
    assert len(imeta_bytes) > len(sample_png_bytes)
    assert imeta_bytes[:4] == MAGIC_FILE

    # Check File Header layout
    magic, major, minor, flags, reserved, meta_off, payload_off, integrity_off = struct.unpack(
        ">4sBBBBQQQ", imeta_bytes[:32]
    )
    assert magic == MAGIC_FILE
    assert major == MAJOR_VERSION
    assert minor == MINOR_VERSION
    assert reserved == 0x00
    assert meta_off == 32
    assert payload_off > meta_off
    assert integrity_off > payload_off

    # Check Metadata Header
    meta_magic, meta_type, meta_len = struct.unpack(">4sIQ", imeta_bytes[meta_off:meta_off + 16])
    assert meta_magic == MAGIC_META
    assert meta_type == 1

    # Check Payload Header
    data_magic, fmt_id, comp_id, orig_sz, stored_sz = struct.unpack(">4sHHQQ", imeta_bytes[payload_off:payload_off + 24])
    assert data_magic == MAGIC_DATA
    assert fmt_id == FormatID.PNG
    assert comp_id == CompressionID.NONE
    assert orig_sz == len(sample_png_bytes)
    assert stored_sz == len(sample_png_bytes)

    # Check Integrity Block
    hash_magic, hash_algo, hash_scope, digest = struct.unpack(">4sHH32s", imeta_bytes[integrity_off:integrity_off + 40])
    assert hash_magic == MAGIC_HASH
    assert hash_algo == 1
    assert hash_scope == 1
    assert digest == compute_sha256(sample_png_bytes)


def test_encode_jpeg_deflate(sample_jpeg_with_exif_bytes):
    imeta_bytes = serialize_imeta(sample_jpeg_with_exif_bytes, compression=CompressionID.DEFLATE)
    
    # Check flags for EXIF and compression
    flags = HeaderFlags(imeta_bytes[6])
    assert flags & HeaderFlags.PAYLOAD_COMPRESSED
    assert flags & HeaderFlags.HAS_EXIF

    # Verify integrity offset points to valid HASH block
    _, _, _, _, _, _, payload_off, integrity_off = struct.unpack(">4sBBBBQQQ", imeta_bytes[:32])
    assert imeta_bytes[integrity_off:integrity_off + 4] == MAGIC_HASH


def test_encode_file_roundtrip_disk(tmp_path, sample_webp_bytes):
    in_file = tmp_path / "test.webp"
    in_file.write_bytes(sample_webp_bytes)

    out_imeta = tmp_path / "test.webp.imeta"
    encode_file(in_file, out_imeta)

    assert out_imeta.is_file()
    assert out_imeta.stat().st_size > 0
