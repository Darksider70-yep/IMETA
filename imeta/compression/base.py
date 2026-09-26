"""Base compressor interface."""

from abc import ABC, abstractmethod
from imeta.core.constants import CompressionID


class Compressor(ABC):
    """Abstract interface for payload compression and decompression."""

    @property
    @abstractmethod
    def compression_id(self) -> CompressionID:
        """The compression ID enum value."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable algorithm name."""
        pass

    @abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Compress raw bytes."""
        pass

    @abstractmethod
    def decompress(self, data: bytes, expected_size: int = 0) -> bytes:
        """Decompress compressed bytes, enforcing safety limits."""
        pass
