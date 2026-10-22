"""Zstandard compressor implementation with decompression bomb protection.

This module requires the optional ``zstandard`` package.  When the package is
not installed the module can still be imported, but instantiating
``ZstdCompressor`` will raise ``UnsupportedFormatError``.
"""

from __future__ import annotations

from imeta.core.constants import CompressionID, MAX_DECOMPRESSED_RATIO, MAX_FILE_SIZE
from imeta.core.exceptions import CorruptedFileError, SecurityLimitError, UnsupportedFormatError
from imeta.compression.base import Compressor

try:
    import zstandard as _zstd

    _ZSTD_AVAILABLE = True
except ImportError:
    _zstd = None  # type: ignore[assignment]
    _ZSTD_AVAILABLE = False


def is_zstd_available() -> bool:
    """Return True if the ``zstandard`` runtime dependency is importable."""
    return _ZSTD_AVAILABLE


class ZstdCompressor(Compressor):
    """Zstandard (zstd) compression with decompression-bomb protection.

    The default compression level (3) provides an excellent speed/ratio
    trade-off for photographic payloads.  The level can be overridden at
    construction time for advanced callers.
    """

    def __init__(self, level: int = 3) -> None:
        if not _ZSTD_AVAILABLE:
            raise UnsupportedFormatError(
                "Zstandard compression requires the 'zstandard' package. "
                "Install it with: pip install zstandard"
            )
        self.level = level

    @property
    def compression_id(self) -> CompressionID:
        return CompressionID.ZSTD

    @property
    def name(self) -> str:
        return "Zstandard"

    def compress(self, data: bytes) -> bytes:
        cctx = _zstd.ZstdCompressor(level=self.level)
        return cctx.compress(data)

    def decompress(self, data: bytes, expected_size: int = 0) -> bytes:
        if not data:
            return b""

        # ── Safety limits (mirrors DeflateCompressor logic) ──────────
        max_allowed_size = MAX_FILE_SIZE
        if expected_size > 0:
            if expected_size > MAX_FILE_SIZE:
                raise SecurityLimitError(
                    f"Expected payload size {expected_size} exceeds max file size {MAX_FILE_SIZE}"
                )
            max_allowed_size = expected_size

        ratio_limit = len(data) * MAX_DECOMPRESSED_RATIO
        max_limit = min(max_allowed_size, max(ratio_limit, 10 * 1024 * 1024))

        # ── Streaming decompression with bomb guard ──────────────────
        try:
            dctx = _zstd.ZstdDecompressor()
            decompressed = dctx.decompress(data, max_output_size=max_limit)
        except _zstd.ZstdError as exc:
            # Distinguish between actual corruption and oversized output.
            msg = str(exc).lower()
            if "too large" in msg or "limit" in msg or "output" in msg:
                raise SecurityLimitError(
                    "Decompression bomb detected: decompressed size exceeds safety threshold"
                ) from exc
            raise CorruptedFileError(f"Failed to decompress Zstandard payload: {exc}") from exc
        except Exception as exc:
            raise CorruptedFileError(f"Failed to decompress Zstandard payload: {exc}") from exc

        if expected_size > 0 and len(decompressed) != expected_size:
            raise CorruptedFileError(
                f"Decompressed size {len(decompressed)} does not match expected size {expected_size}"
            )

        return decompressed
