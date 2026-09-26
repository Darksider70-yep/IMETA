"""Test fixtures and sample image generators for IMETA test suite."""

import io
import struct
import zlib
import pytest
from PIL import Image, PngImagePlugin


@pytest.fixture
def sample_png_bytes() -> bytes:
    """Generate a clean standard PNG image in memory."""
    img = Image.new("RGB", (64, 48), color=(255, 100, 50))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def sample_png_with_metadata_bytes() -> bytes:
    """Generate a PNG with text metadata and custom chunk."""
    img = Image.new("RGBA", (100, 80), color=(10, 200, 100, 255))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Alice Developer")
    meta.add_text("Description", "Test PNG with metadata")
    meta.add_itxt("XML:com.adobe.xmp", "<x:xmpmeta><rdf:RDF><dc:title>Test XMP Title</dc:title></rdf:RDF></x:xmpmeta>")
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    return buf.getvalue()


@pytest.fixture
def sample_jpeg_bytes() -> bytes:
    """Generate a clean standard JPEG image in memory."""
    img = Image.new("RGB", (120, 90), color=(70, 130, 180))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


@pytest.fixture
def sample_jpeg_with_exif_bytes() -> bytes:
    """Generate a JPEG with genuine UTF-8 EXIF metadata."""
    img = Image.new("RGB", (80, 60), color=(220, 20, 60))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    raw_jpeg = buf.getvalue()

    # Construct custom EXIF APP1 segment containing UTF-8 string
    desc_utf8 = "Sunset in Tokyo 東京 🌅\x00".encode("utf-8")
    desc_len = len(desc_utf8)

    # Little endian TIFF block
    # 0..8: II * \0 (offset to IFD0 = 8)
    # 8..10: num_entries = 3 (Make, Model, ImageDescription)
    # 10..22: Tag 0x010F Make (type 2, count 6, offset 46)
    # 22..34: Tag 0x0110 Model (type 2, count 3, offset 52)
    # 34..46: Tag 0x010E ImageDescription (type 2, count desc_len, offset 56)
    # 46..50: Next IFD offset = 0
    # 50..56: b"Nikon\x00" (offset 50 in TIFF)
    # 56..59: b"Z9\x00" (offset 56 in TIFF)
    # 59.. : desc_utf8 (offset 59 in TIFF)
    
    tiff_data = bytearray()
    tiff_data.extend(b"II\x2a\x00\x08\x00\x00\x00")  # TIFF header, IFD0 at 8
    tiff_data.extend(struct.pack("<H", 3))            # 3 entries

    offset_make = 8 + 2 + 12 * 3 + 4  # 50
    offset_model = offset_make + 6     # 56
    offset_desc = offset_model + 3     # 59

    # Make: Nikon
    tiff_data.extend(struct.pack("<HHI4s", 0x010F, 2, 6, struct.pack("<I", offset_make)))
    # Model: Z9
    tiff_data.extend(struct.pack("<HHI4s", 0x0110, 2, 3, struct.pack("<I", offset_model)))
    # ImageDescription: UTF-8
    tiff_data.extend(struct.pack("<HHI4s", 0x010E, 2, desc_len, struct.pack("<I", offset_desc)))
    # Next IFD offset
    tiff_data.extend(struct.pack("<I", 0))

    # Values
    tiff_data.extend(b"Nikon\x00")
    tiff_data.extend(b"Z9\x00")
    tiff_data.extend(desc_utf8)

    # Pack into APP1 marker
    app1_payload = b"Exif\x00\x00" + bytes(tiff_data)
    app1_segment = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload

    # Insert APP1 after SOI (first 2 bytes \xff\xd8)
    return raw_jpeg[:2] + app1_segment + raw_jpeg[2:]


@pytest.fixture
def sample_webp_bytes() -> bytes:
    """Generate a clean standard WebP image in memory."""
    img = Image.new("RGBA", (50, 50), color=(128, 0, 128, 200))
    buf = io.BytesIO()
    img.save(buf, format="WEBP", lossless=True)
    return buf.getvalue()
