"""IMETA binary container deserializer."""

import json
import struct
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional, Tuple, Union

from imeta.core.constants import (
    MAGIC_FILE,
    MAGIC_META,
    MAGIC_DATA,
    MAGIC_HASH,
    MAJOR_VERSION,
    FILE_HEADER_SIZE,
    META_HEADER_SIZE,
    DATA_HEADER_SIZE,
    INTEGRITY_BLOCK_SIZE,
    META_TYPE_JSON,
    FormatID,
    CompressionID,
    HeaderFlags,
    FORMAT_EXTENSIONS,
)
from imeta.core.exceptions import (
    CorruptedFileError,
    IntegrityError,
    VersionIncompatibilityError,
)
from imeta.core.validator import validate_container
from imeta.compression import get_compressor


class IMETAContainer(NamedTuple):
    """Container representation holding decoded components."""
    major_version: int
    minor_version: int
    flags: HeaderFlags
    format_id: FormatID
    compression_id: CompressionID
    metadata: Dict[str, Any]
    image_bytes: bytes
    sha256: str


def deserialize_imeta(imeta_bytes: bytes, verify_integrity: bool = True) -> IMETAContainer:
    """Deserialize an .imeta binary container back into its metadata and original image bytes.
    
    Guarantees:
      - Returns exact byte-for-byte original image payload.
      - Enforces version compatibility rules.
      - Ignores unknown metadata fields and provides defaults for missing fields.
      - Verifies SHA-256 integrity digest against decompressed payload.
    """
    report = validate_container(imeta_bytes, verify_payload_checksum=verify_integrity)
    if not report.is_valid:
        if report.status == "INCOMPATIBLE_VERSION":
            raise VersionIncompatibilityError("; ".join(report.errors))
        elif "mismatch" in "; ".join(report.errors).lower():
            raise IntegrityError("; ".join(report.errors))
        else:
            raise CorruptedFileError("; ".join(report.errors))

    # Read sections using authoritative offsets
    magic, major, minor, flags_raw, reserved, meta_off, payload_off, integrity_off = struct.unpack(
        ">4sBBBBQQQ", imeta_bytes[:FILE_HEADER_SIZE]
    )

    flags = HeaderFlags(flags_raw)

    # 1. Read Metadata Header & Body
    meta_hdr = imeta_bytes[meta_off:meta_off + META_HEADER_SIZE]
    _, _, meta_len = struct.unpack(">4sIQ", meta_hdr)
    meta_json_raw = imeta_bytes[meta_off + META_HEADER_SIZE:meta_off + META_HEADER_SIZE + meta_len]
    raw_metadata = json.loads(meta_json_raw.decode("utf-8"))

    # Apply defaults for any missing core fields (minor version compatibility)
    metadata: Dict[str, Any] = {
        "format": raw_metadata.get("format", "UNKNOWN"),
        "extension": raw_metadata.get("extension", ""),
        "width": raw_metadata.get("width", 0),
        "height": raw_metadata.get("height", 0),
        "color_model": raw_metadata.get("color_model", "RGB"),
        "bit_depth": raw_metadata.get("bit_depth", 8),
        "exif": raw_metadata.get("exif", {}),
        "xmp": raw_metadata.get("xmp", {}),
        "iptc": raw_metadata.get("iptc", {}),
    }
    # Preserve all other fields from future minor versions
    for k, v in raw_metadata.items():
        if k not in metadata:
            metadata[k] = v

    # 2. Read Payload Header & Payload Bytes
    payload_hdr = imeta_bytes[payload_off:payload_off + DATA_HEADER_SIZE]
    _, fmt_id_val, comp_id_val, orig_size, stored_size = struct.unpack(">4sHHQQ", payload_hdr)
    format_id = FormatID(fmt_id_val)
    compression_id = CompressionID(comp_id_val)

    stored_payload = imeta_bytes[payload_off + DATA_HEADER_SIZE:payload_off + DATA_HEADER_SIZE + stored_size]

    compressor = get_compressor(compression_id)
    original_image_bytes = compressor.decompress(stored_payload, expected_size=orig_size)

    # If extension was missing from metadata, infer from format_id
    if not metadata.get("extension"):
        metadata["extension"] = FORMAT_EXTENSIONS.get(format_id, "")

    return IMETAContainer(
        major_version=major,
        minor_version=minor,
        flags=flags,
        format_id=format_id,
        compression_id=compression_id,
        metadata=metadata,
        image_bytes=original_image_bytes,
        sha256=report.expected_sha256 or "",
    )


def decode_file(
    input_imeta_path: Union[str, Path],
    output_image_path: Optional[Union[str, Path]] = None,
    verify_integrity: bool = True,
) -> Path:
    """Decode an .imeta container file back into the reconstructed original image file.
    
    If output_image_path is not specified, it will use the input path with the reconstructed
    image extension (e.g. 'photo.imeta' -> 'photo_reconstructed.png').
    """
    input_path = Path(input_imeta_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"IMETA container file not found: {input_imeta_path}")

    container_bytes = input_path.read_bytes()
    container = deserialize_imeta(container_bytes, verify_integrity=verify_integrity)

    if output_image_path is None:
        ext = container.metadata.get("extension") or FORMAT_EXTENSIONS.get(container.format_id, ".bin")
        out_path = input_path.with_name(f"{input_path.stem}_reconstructed{ext}")
    else:
        out_path = Path(output_image_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(container.image_bytes)
    return out_path
