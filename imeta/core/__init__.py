"""IMETA core module exports."""

from .constants import (
    CompressionID,
    FormatID,
    HeaderFlags,
    MAJOR_VERSION,
    MINOR_VERSION,
)
from .exceptions import (
    CorruptedFileError,
    IMETAError,
    IntegrityError,
    SecurityLimitError,
    UnsupportedFormatError,
    ValidationError,
    VersionIncompatibilityError,
)
from .hashing import (
    compute_file_sha256,
    compute_file_sha256_hex,
    compute_sha256,
    compute_sha256_hex,
)
from .parser import ImageParseResult, parse_image_bytes, parse_image_file
from .serializer import encode_file, serialize_imeta
from .deserializer import IMETAContainer, decode_file, deserialize_imeta
from .validator import ValidationReport, validate_container

__all__ = [
    "CompressionID",
    "FormatID",
    "HeaderFlags",
    "MAJOR_VERSION",
    "MINOR_VERSION",
    "IMETAError",
    "ValidationError",
    "CorruptedFileError",
    "IntegrityError",
    "UnsupportedFormatError",
    "VersionIncompatibilityError",
    "SecurityLimitError",
    "compute_sha256",
    "compute_sha256_hex",
    "compute_file_sha256",
    "compute_file_sha256_hex",
    "ImageParseResult",
    "parse_image_bytes",
    "parse_image_file",
    "serialize_imeta",
    "encode_file",
    "deserialize_imeta",
    "decode_file",
    "IMETAContainer",
    "validate_container",
    "ValidationReport",
]
