"""Unit tests for format adapters (PNG, JPEG, WebP)."""

import io
from PIL import Image, PngImagePlugin
from imeta.core.constants import FormatID
from imeta.formats.jpeg import JPEGAdapter
from imeta.formats.png import PNGAdapter
from imeta.formats.webp import WebPAdapter
from imeta.formats import detect_adapter


def test_png_adapter_metadata():
    adapter = PNGAdapter()
    img = Image.new("RGBA", (128, 96), color=(255, 0, 0, 128))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Title", "Sample Logo")
    meta.add_text("Copyright", "2026 IMETA Project")
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    png_bytes = buf.getvalue()

    assert adapter.matches(png_bytes) is True
    parsed = adapter.parse_metadata(png_bytes)
    assert parsed["format"] == "PNG"
    assert parsed["width"] == 128
    assert parsed["height"] == 96
    assert parsed["color_model"] == "RGBA"
    assert parsed["text"]["Title"] == "Sample Logo"


def test_jpeg_adapter_metadata(sample_jpeg_bytes):
    adapter = JPEGAdapter()
    assert adapter.matches(sample_jpeg_bytes) is True
    parsed = adapter.parse_metadata(sample_jpeg_bytes)
    assert parsed["format"] == "JPEG"
    assert parsed["width"] == 120
    assert parsed["height"] == 90
    assert parsed["color_model"] == "RGB"


def test_webp_adapter_lossless_metadata(sample_webp_bytes):
    adapter = WebPAdapter()
    assert adapter.matches(sample_webp_bytes) is True
    parsed = adapter.parse_metadata(sample_webp_bytes)
    assert parsed["format"] == "WebP"
    assert parsed["width"] == 50
    assert parsed["height"] == 50


def test_detect_adapter_fallback():
    assert detect_adapter(b"RIFF\x00\x00\x00\x00WEBPVP8 ") is not None
    assert detect_adapter(b"\x89PNG\r\n\x1a\n") is not None
    assert detect_adapter(b"\xFF\xD8\xFF\xE0") is not None
    assert detect_adapter(b"GIF89a") is None  # unsupported in MVP
