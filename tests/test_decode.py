"""Tests for IMETA decoding and lossless reconstruction."""

import hashlib
import json
import struct
from pathlib import Path
import pytest

from imeta.core.constants import CompressionID, FormatID, MAJOR_VERSION
from imeta.core.deserializer import decode_file, deserialize_imeta
from imeta.core.exceptions import VersionIncompatibilityError
from imeta.core.serializer import encode_file, serialize_imeta


@pytest.mark.parametrize("compression", [CompressionID.NONE, CompressionID.DEFLATE])
def test_png_roundtrip_lossless(sample_png_bytes, compression):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for PNG."""
    orig_sha256 = hashlib.sha256(sample_png_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_png_bytes, compression=compression)
    container = deserialize_imeta(imeta_bytes)

    recon_sha256 = hashlib.sha256(container.image_bytes).hexdigest()

    assert orig_sha256 == recon_sha256
    assert sample_png_bytes == container.image_bytes
    assert container.format_id == FormatID.PNG
    assert container.metadata["width"] == 64
    assert container.metadata["height"] == 48


@pytest.mark.parametrize("compression", [CompressionID.NONE, CompressionID.DEFLATE])
def test_jpeg_roundtrip_lossless(sample_jpeg_with_exif_bytes, compression):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for JPEG."""
    orig_sha256 = hashlib.sha256(sample_jpeg_with_exif_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_jpeg_with_exif_bytes, compression=compression)
    container = deserialize_imeta(imeta_bytes)

    recon_sha256 = hashlib.sha256(container.image_bytes).hexdigest()

    assert orig_sha256 == recon_sha256
    assert sample_jpeg_with_exif_bytes == container.image_bytes
    assert container.format_id == FormatID.JPEG
    assert container.metadata["width"] == 80
    assert container.metadata["height"] == 60
    assert "Nikon" in str(container.metadata.get("exif", {}))


@pytest.mark.parametrize("compression", [CompressionID.NONE, CompressionID.DEFLATE])
def test_webp_roundtrip_lossless(sample_webp_bytes, compression):
    """Core guarantee: SHA256(original) == SHA256(reconstructed) for WebP."""
    orig_sha256 = hashlib.sha256(sample_webp_bytes).hexdigest()

    imeta_bytes = serialize_imeta(sample_webp_bytes, compression=compression)
    container = deserialize_imeta(imeta_bytes)

    recon_sha256 = hashlib.sha256(container.image_bytes).hexdigest()

    assert orig_sha256 == recon_sha256
    assert sample_webp_bytes == container.image_bytes
    assert container.format_id == FormatID.WEBP
    assert container.metadata["width"] == 50
    assert container.metadata["height"] == 50


def test_file_encode_decode_roundtrip(tmp_path, sample_png_with_metadata_bytes):
    """Roundtrip file on disk."""
    orig_file = tmp_path / "original.png"
    orig_file.write_bytes(sample_png_with_metadata_bytes)

    imeta_file = tmp_path / "package.imeta"
    encode_file(orig_file, imeta_file)

    recon_file = tmp_path / "reconstructed.png"
    decode_file(imeta_file, recon_file)

    assert orig_file.read_bytes() == recon_file.read_bytes()
    assert (
        hashlib.sha256(orig_file.read_bytes()).hexdigest()
        == hashlib.sha256(recon_file.read_bytes()).hexdigest()
    )


def test_version_forward_compatibility(sample_png_bytes):
    """Reader on major version N ignores extra fields and applies sensible defaults."""
    imeta_bytes = serialize_imeta(sample_png_bytes)

    # Modify the metadata JSON inside the container to include future minor version fields
    # and omit some fields
    container = deserialize_imeta(imeta_bytes)
    modified_meta = {
        "future_field_xyz": 12345,
        "new_colorspace_spec": {"gamma": 2.2},
        # omitted width and height to test defaults
    }
    custom_bytes = serialize_imeta(sample_png_bytes, metadata_override=modified_meta)
    
    # Read back - should succeed and preserve new fields while applying defaults
    parsed = deserialize_imeta(custom_bytes)
    assert parsed.metadata["future_field_xyz"] == 12345
    assert parsed.image_bytes == sample_png_bytes


def test_major_version_incompatibility_rejected(sample_png_bytes):
    """Reader rejects containers with a different major version."""
    imeta_bytes = bytearray(serialize_imeta(sample_png_bytes))
    # Mutate major version at byte 4 to 2
    imeta_bytes[4] = 2

    with pytest.raises(VersionIncompatibilityError, match="Incompatible major version: 2"):
        deserialize_imeta(bytes(imeta_bytes))
