"""Image sanitization dispatch and public interface."""

from typing import Dict
from imeta.core.constants import FormatID
from imeta.core.exceptions import UnsupportedFormatError
from imeta.sanitize.base import Sanitizer, SanitizeResult
from imeta.sanitize.jpeg_sanitizer import JPEGSanitizer
from imeta.sanitize.png_sanitizer import PNGSanitizer
from imeta.sanitize.webp_sanitizer import WebPSanitizer

SANITIZERS: Dict[FormatID, Sanitizer] = {
    FormatID.JPEG: JPEGSanitizer(),
    FormatID.PNG: PNGSanitizer(),
    FormatID.WEBP: WebPSanitizer(),
}


def get_sanitizer(format_id: FormatID) -> Sanitizer:
    """Retrieve sanitizer adapter for given format ID."""
    if format_id not in SANITIZERS:
        raise UnsupportedFormatError(f"No sanitizer available for format ID: 0x{format_id:04X}")
    return SANITIZERS[format_id]


__all__ = [
    "Sanitizer",
    "SanitizeResult",
    "JPEGSanitizer",
    "PNGSanitizer",
    "WebPSanitizer",
    "get_sanitizer",
    "SANITIZERS",
]
