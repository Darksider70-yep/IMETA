"""DEFLATE compressor implementation with decompression bomb protection."""

import zlib
from imeta.core.constants import CompressionID, MAX_DECOMPRESSED_RATIO, MAX_FILE_SIZE
from imeta.core.exceptions import CorruptedFileError, SecurityLimitError
from imeta.compression.base import Compressor


class DeflateCompressor(Compressor):
    """DEFLATE compression via standard zlib."""

    def __init__(self, level: int = 6):
        self.level = level

    @property
    def compression_id(self) -> CompressionID:
        return CompressionID.DEFLATE

    @property
    def name(self) -> str:
        return "DEFLATE"

    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, level=self.level)

    def decompress(self, data: bytes, expected_size: int = 0) -> bytes:
        if not data:
            return b""

        # Check safety limits
        max_allowed_size = MAX_FILE_SIZE
        if expected_size > 0:
            if expected_size > MAX_FILE_SIZE:
                raise SecurityLimitError(
                    f"Expected payload size {expected_size} exceeds max file size {MAX_FILE_SIZE}"
                )
            max_allowed_size = expected_size

        # Check compression ratio safety
        ratio_limit = len(data) * MAX_DECOMPRESSED_RATIO
        max_limit = min(max_allowed_size, max(ratio_limit, 10 * 1024 * 1024))

        try:
            # Use decompress with max_length to protect against decompression bombs
            decompressor = zlib.decompressobj()
            decompressed = decompressor.decompress(data, max_limit)
            
            if decompressor.unconsumed_tail and len(decompressed) >= max_limit:
                raise SecurityLimitError("Decompression bomb detected: decompressed size exceeds safety threshold")

            if expected_size > 0 and len(decompressed) != expected_size:
                raise CorruptedFileError(
                    f"Decompressed size {len(decompressed)} does not match expected size {expected_size}"
                )

            return decompressed
        except (zlib.error, ValueError) as e:
            if isinstance(e, SecurityLimitError):
                raise
            raise CorruptedFileError(f"Failed to decompress DEFLATE payload: {e}") from e
