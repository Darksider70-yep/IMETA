"""Base classes and data models for image metadata sanitization."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List


@dataclass
class SanitizeResult:
    """Result of image metadata sanitization."""
    image_bytes: bytes
    removed: List[str]          # e.g. ["EXIF", "XMP"] or ["GPS"]
    gps_only_downgraded: bool   # True if GPS-only requested but fell back to full EXIF removal
    new_sha256: str


class Sanitizer(ABC):
    """Abstract base class for format-specific metadata sanitizers."""

    @abstractmethod
    def sanitize(
        self,
        image_bytes: bytes,
        remove_exif: bool = False,
        remove_gps_only: bool = False,
        remove_xmp: bool = False,
        remove_iptc: bool = False,
    ) -> SanitizeResult:
        """Sanitize metadata from image bytes per requested options."""
        pass
