"""Base Image Format Adapter."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from imeta.core.constants import FormatID


class ImageFormatAdapter(ABC):
    """Abstract interface for image format recognition and metadata extraction."""

    @property
    @abstractmethod
    def format_id(self) -> FormatID:
        """The FormatID enum value."""
        pass

    @property
    @abstractmethod
    def format_name(self) -> str:
        """The canonical name of the format (e.g. 'PNG', 'JPEG', 'WebP')."""
        pass

    @property
    @abstractmethod
    def default_extension(self) -> str:
        """The canonical file extension with dot (e.g. '.png')."""
        pass

    @abstractmethod
    def matches(self, data: bytes) -> bool:
        """Check if binary data matches this format's magic bytes."""
        pass

    @abstractmethod
    def parse_metadata(self, data: bytes) -> Dict[str, Any]:
        """Parse raw image bytes and extract standard metadata dictionary.
        
        Must return a dict containing at least:
          - format: str
          - extension: str
          - width: int
          - height: int
          - color_model: str (e.g. 'RGB', 'RGBA', 'Grayscale', 'CMYK')
          - bit_depth: int
          - exif: dict
          - xmp: dict
          - iptc: dict
        """
        pass
