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
    """Generate a JPEG with EXIF metadata (including unicode)."""
    img = Image.new("RGB", (80, 60), color=(220, 20, 60))
    exif = img.getexif()
    exif[0x010E] = "Sunset in Tokyo 東京 🌅"  # ImageDescription with Unicode & Emoji
    exif[0x010F] = "Nikon"                     # Make
    exif[0x0110] = "Z9"                        # Model
    exif[0x0112] = 1                           # Orientation
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


@pytest.fixture
def sample_webp_bytes() -> bytes:
    """Generate a clean standard WebP image in memory."""
    img = Image.new("RGBA", (50, 50), color=(128, 0, 128, 200))
    buf = io.BytesIO()
    img.save(buf, format="WEBP", lossless=True)
    return buf.getvalue()
