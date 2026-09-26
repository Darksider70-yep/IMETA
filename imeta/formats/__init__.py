"""Format adapters registry and factory."""

from typing import Dict, List, Optional
from imeta.core.constants import FormatID
from imeta.formats.base import ImageFormatAdapter
from imeta.formats.jpeg import JPEGAdapter
from imeta.formats.png import PNGAdapter
from imeta.formats.webp import WebPAdapter

# Registered format adapters
ADAPTERS: List[ImageFormatAdapter] = [
    PNGAdapter(),
    JPEGAdapter(),
    WebPAdapter(),
]

ADAPTER_MAP: Dict[FormatID, ImageFormatAdapter] = {
    adapter.format_id: adapter for adapter in ADAPTERS
}


def detect_adapter(data: bytes) -> Optional[ImageFormatAdapter]:
    """Detect image format adapter by inspecting magic bytes."""
    for adapter in ADAPTERS:
        if adapter.matches(data):
            return adapter
    return None


def get_adapter_by_format_id(format_id: FormatID) -> Optional[ImageFormatAdapter]:
    """Retrieve format adapter by its numeric FormatID."""
    return ADAPTER_MAP.get(format_id)


__all__ = [
    "ImageFormatAdapter",
    "PNGAdapter",
    "JPEGAdapter",
    "WebPAdapter",
    "ADAPTERS",
    "ADAPTER_MAP",
    "detect_adapter",
    "get_adapter_by_format_id",
]
