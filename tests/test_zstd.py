"""Tests for Zstandard compression support."""

import hashlib
import struct
import pytest

from imeta.core.constants import CompressionID, FormatID, HeaderFlags, MAGIC_FILE, MAGIC_HASH
from imeta.core.deserializer import deserialize_imeta
from imeta.core.serializer import serialize_imeta
from imeta.compression import get_compressor, is_zstd_available


# Guard: skip entire module if zstandard is not installed
pytestmark = pytest.mark.skipif(not is_zstd_available(), reason="zstandard package not installed")


def test_zstd_compress_decompress_identity():
    """Compress → decompress round-trip preserves data identity."""
    compressor = get_compressor(CompressionID.ZSTD)
    original = b"The quick brown fox jumps over the lazy dog" * 500
    compressed = compressor.compress(original)
    decompressed = compressor.decompress(compressed, expected_size=len(original))
    assert decompressed == original
    assert len(compressed) < len(original)


def test_png_roundtrip_zstd(sample_png_bytes):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for PNG via Zstandard."""
    orig_sha256 = hashlib.sha256(sample_png_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_png_bytes, compression=CompressionID.ZSTD)
    container = deserialize_imeta(imeta_bytes)

    recon_sha256 = hashlib.sha256(container.image_bytes).hexdigest()

    assert orig_sha256 == recon_sha256
    assert sample_png_bytes == container.image_bytes
    assert container.format_id == FormatID.PNG
    assert container.compression_id == CompressionID.ZSTD


def test_jpeg_roundtrip_zstd(sample_jpeg_bytes):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for JPEG via Zstandard."""
    orig_sha256 = hashlib.sha256(sample_jpeg_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_jpeg_bytes, compression=CompressionID.ZSTD)
    container = deserialize_imeta(imeta_bytes)

    assert orig_sha256 == hashlib.sha256(container.image_bytes).hexdigest()
    assert sample_jpeg_bytes == container.image_bytes
    assert container.format_id == FormatID.JPEG


def test_webp_roundtrip_zstd(sample_webp_bytes):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for WebP via Zstandard."""
    orig_sha256 = hashlib.sha256(sample_webp_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_webp_bytes, compression=CompressionID.ZSTD)
    container = deserialize_imeta(imeta_bytes)

    assert orig_sha256 == hashlib.sha256(container.image_bytes).hexdigest()
    assert sample_webp_bytes == container.image_bytes
    assert container.format_id == FormatID.WEBP


def test_encode_zstd_sets_payload_compressed_flag(sample_png_bytes):
    """Zstandard encoding sets the PAYLOAD_COMPRESSED header flag."""
    imeta_bytes = serialize_imeta(sample_png_bytes, compression=CompressionID.ZSTD)
    flags = HeaderFlags(imeta_bytes[6])
    assert flags & HeaderFlags.PAYLOAD_COMPRESSED


def test_encode_zstd_smaller_than_uncompressed(sample_png_bytes):
    """Zstandard compressed container should be smaller than uncompressed for reasonable input."""
    uncompressed = serialize_imeta(sample_png_bytes, compression=CompressionID.NONE)
    zstd_compressed = serialize_imeta(sample_png_bytes, compression=CompressionID.ZSTD)
    # Zstd should compress the raw PNG payload (which is already deflated internally,
    # but the container overhead + metadata should still allow some savings, or at worst near-equal)
    assert len(zstd_compressed) <= len(uncompressed)


def test_zstd_integrity_block_valid(sample_jpeg_bytes):
    """Integrity block in a Zstandard container has valid HASH magic and correct digest."""
    imeta_bytes = serialize_imeta(sample_jpeg_bytes, compression=CompressionID.ZSTD)

    _, _, _, _, _, _, _, integrity_off = struct.unpack(">4sBBBBQQQ", imeta_bytes[:32])
    hash_magic = imeta_bytes[integrity_off:integrity_off + 4]
    assert hash_magic == MAGIC_HASH

    container = deserialize_imeta(imeta_bytes, verify_integrity=True)
    assert container.sha256 == hashlib.sha256(sample_jpeg_bytes).hexdigest()
