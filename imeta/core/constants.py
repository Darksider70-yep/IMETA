"""IMETA Format Constants and Enumerations."""

from enum import IntEnum, IntFlag

# File Header
MAGIC_FILE = b"IMTA"
FILE_HEADER_SIZE = 32
MAJOR_VERSION = 1
MINOR_VERSION = 0

# Metadata Header
MAGIC_META = b"META"
META_HEADER_SIZE = 16
META_TYPE_JSON = 0x00000001

# Payload Header
MAGIC_DATA = b"DATA"
DATA_HEADER_SIZE = 24

# Integrity Block
MAGIC_HASH = b"HASH"
INTEGRITY_BLOCK_SIZE = 40
HASH_ALGO_SHA256 = 0x0001
HASH_SCOPE_ORIGINAL_PAYLOAD = 0x0001


class HeaderFlags(IntFlag):
    """File header bitfield flags (byte 6)."""
    NONE = 0
    METADATA_COMPRESSED = 1 << 0  # bit 0
    PAYLOAD_COMPRESSED = 1 << 1   # bit 1
    METADATA_ENCRYPTED = 1 << 2   # bit 2 (reserved)
    PAYLOAD_ENCRYPTED = 1 << 3    # bit 3 (reserved)
    HAS_EXIF = 1 << 4             # bit 4
    HAS_XMP = 1 << 5              # bit 5
    HAS_IPTC = 1 << 6             # bit 6
    RESERVED = 1 << 7             # bit 7


class FormatID(IntEnum):
    """Supported and reserved image format IDs."""
    UNKNOWN = 0x0000
    JPEG = 0x0001
    PNG = 0x0002
    WEBP = 0x0003
    GIF = 0x0004
    BMP = 0x0005
    TIFF = 0x0006
    HEIF = 0x0007
    AVIF = 0x0008


FORMAT_EXTENSIONS = {
    FormatID.JPEG: ".jpg",
    FormatID.PNG: ".png",
    FormatID.WEBP: ".webp",
    FormatID.GIF: ".gif",
    FormatID.BMP: ".bmp",
    FormatID.TIFF: ".tiff",
    FormatID.HEIF: ".heif",
    FormatID.AVIF: ".avif",
}

FORMAT_NAMES = {
    FormatID.JPEG: "JPEG",
    FormatID.PNG: "PNG",
    FormatID.WEBP: "WebP",
    FormatID.GIF: "GIF",
    FormatID.BMP: "BMP",
    FormatID.TIFF: "TIFF",
    FormatID.HEIF: "HEIF",
    FormatID.AVIF: "AVIF",
}

NAME_TO_FORMAT = {name.upper(): fmt for fmt, name in FORMAT_NAMES.items()}
EXT_TO_FORMAT = {
    ".jpg": FormatID.JPEG,
    ".jpeg": FormatID.JPEG,
    ".png": FormatID.PNG,
    ".webp": FormatID.WEBP,
    ".gif": FormatID.GIF,
    ".bmp": FormatID.BMP,
    ".tif": FormatID.TIFF,
    ".tiff": FormatID.TIFF,
    ".heif": FormatID.HEIF,
    ".heic": FormatID.HEIF,
    ".avif": FormatID.AVIF,
}


class CompressionID(IntEnum):
    """Payload compression algorithms."""
    NONE = 0x0000
    DEFLATE = 0x0001
    ZSTD = 0x0002


# Security Limits
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB default max file size
MAX_DECOMPRESSED_RATIO = 100        # Guard against decompression bombs
