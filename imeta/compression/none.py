"""No-op / Passthrough compressor."""

from imeta.core.constants import CompressionID
from imeta.compression.base import Compressor


class NoneCompressor(Compressor):
    """Passthrough compressor for uncompressed payloads."""

    @property
    def compression_id(self) -> CompressionID:
        return CompressionID.NONE

    @property
    def name(self) -> str:
        return "None"

    def compress(self, data: bytes) -> bytes:
        return data

    def decompress(self, data: bytes, expected_size: int = 0) -> bytes:
        return data
