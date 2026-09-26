"""Image inspection and metadata extraction parser."""

from pathlib import Path
from typing import Any, Dict, Tuple, Union
from imeta.core.constants import FormatID, HeaderFlags, MAX_FILE_SIZE
from imeta.core.exceptions import SecurityLimitError, UnsupportedFormatError
from imeta.formats import detect_adapter, ImageFormatAdapter


class ImageParseResult:
    """Encapsulates parsed image details."""

    def __init__(
        self,
        format_id: FormatID,
        format_name: str,
        extension: str,
        metadata: Dict[str, Any],
        raw_bytes: bytes,
        flags: HeaderFlags,
    ):
        self.format_id = format_id
        self.format_name = format_name
        self.extension = extension
        self.metadata = metadata
        self.raw_bytes = raw_bytes
        self.flags = flags

    def __repr__(self) -> str:
        return f"<ImageParseResult format={self.format_name} size={len(self.raw_bytes)} bytes>"


def parse_image_bytes(data: bytes) -> ImageParseResult:
    """Inspect and extract metadata from raw image bytes.
    
    Validates safety limits, detects actual format by magic bytes (ignoring extensions/MIME),
    and builds structured metadata dict and header flags.
    """
    if len(data) > MAX_FILE_SIZE:
        raise SecurityLimitError(f"Image size ({len(data)} bytes) exceeds maximum limit ({MAX_FILE_SIZE} bytes)")

    adapter: ImageFormatAdapter = detect_adapter(data)
    if not adapter:
        raise UnsupportedFormatError(
            f"Unsupported or unrecognized image format (magic bytes: {data[:8]!r})"
        )

    metadata = adapter.parse_metadata(data)

    # Determine metadata presence flags
    flags = HeaderFlags.NONE
    if metadata.get("exif"):
        flags |= HeaderFlags.HAS_EXIF
    if metadata.get("xmp"):
        flags |= HeaderFlags.HAS_XMP
    if metadata.get("iptc"):
        flags |= HeaderFlags.HAS_IPTC

    return ImageParseResult(
        format_id=adapter.format_id,
        format_name=adapter.format_name,
        extension=adapter.default_extension,
        metadata=metadata,
        raw_bytes=data,
        flags=flags,
    )


def parse_image_file(file_path: Union[str, Path]) -> ImageParseResult:
    """Read image from file and parse its metadata."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image file not found: {file_path}")

    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise SecurityLimitError(f"File size ({file_size} bytes) exceeds limit ({MAX_FILE_SIZE} bytes)")

    data = path.read_bytes()
    return parse_image_bytes(data)
