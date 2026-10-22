"""Compression registry and factory."""

from typing import Dict
from imeta.core.constants import CompressionID
from imeta.core.exceptions import UnsupportedFormatError
from imeta.compression.base import Compressor
from imeta.compression.none import NoneCompressor
from imeta.compression.zlib import DeflateCompressor
from imeta.compression.zstd import ZstdCompressor, is_zstd_available

COMPRESSORS: Dict[CompressionID, Compressor] = {
    CompressionID.NONE: NoneCompressor(),
    CompressionID.DEFLATE: DeflateCompressor(),
}

# Register Zstandard only when the optional ``zstandard`` package is installed.
if is_zstd_available():
    COMPRESSORS[CompressionID.ZSTD] = ZstdCompressor()


def get_compressor(compression_id: CompressionID) -> Compressor:
    """Retrieve compressor by compression ID."""
    if compression_id not in COMPRESSORS:
        if compression_id == CompressionID.ZSTD and not is_zstd_available():
            raise UnsupportedFormatError(
                "Zstandard compression requires the 'zstandard' package. "
                "Install it with: pip install zstandard"
            )
        raise UnsupportedFormatError(f"Unsupported compression ID: 0x{compression_id:04X}")
    return COMPRESSORS[compression_id]


__all__ = [
    "Compressor",
    "NoneCompressor",
    "DeflateCompressor",
    "ZstdCompressor",
    "is_zstd_available",
    "get_compressor",
    "COMPRESSORS",
]
