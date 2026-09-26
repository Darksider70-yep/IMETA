"""Compression registry and factory."""

from typing import Dict
from imeta.core.constants import CompressionID
from imeta.core.exceptions import UnsupportedFormatError
from imeta.compression.base import Compressor
from imeta.compression.none import NoneCompressor
from imeta.compression.zlib import DeflateCompressor

COMPRESSORS: Dict[CompressionID, Compressor] = {
    CompressionID.NONE: NoneCompressor(),
    CompressionID.DEFLATE: DeflateCompressor(),
}


def get_compressor(compression_id: CompressionID) -> Compressor:
    """Retrieve compressor by compression ID."""
    if compression_id not in COMPRESSORS:
        raise UnsupportedFormatError(f"Unsupported compression ID: 0x{compression_id:04X}")
    return COMPRESSORS[compression_id]


__all__ = ["Compressor", "NoneCompressor", "DeflateCompressor", "get_compressor", "COMPRESSORS"]
