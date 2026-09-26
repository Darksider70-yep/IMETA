"""IMETA binary container serializer."""

import json
import struct
from pathlib import Path
from typing import Any, Dict, Optional, Union
from imeta.core.constants import (
    MAGIC_FILE,
    MAGIC_META,
    MAGIC_DATA,
    MAGIC_HASH,
    MAJOR_VERSION,
    MINOR_VERSION,
    FILE_HEADER_SIZE,
    META_HEADER_SIZE,
    DATA_HEADER_SIZE,
    INTEGRITY_BLOCK_SIZE,
    META_TYPE_JSON,
    HASH_ALGO_SHA256,
    HASH_SCOPE_ORIGINAL_PAYLOAD,
    FormatID,
    CompressionID,
    HeaderFlags,
)
from imeta.core.hashing import compute_sha256
from imeta.core.parser import parse_image_bytes, parse_image_file
from imeta.compression import get_compressor


def serialize_imeta(
    image_bytes: bytes,
    metadata_override: Optional[Dict[str, Any]] = None,
    compression: CompressionID = CompressionID.NONE,
) -> bytes:
    """Serialize raw image bytes and extracted metadata into an .imeta binary container.
    
    Layout:
      1. File Header (32 bytes)
      2. Metadata Header (16 bytes) + UTF-8 JSON
      3. Payload Header (24 bytes) + stored image payload
      4. Integrity Block (40 bytes)
    """
    # 1. Parse image and extract metadata
    parse_result = parse_image_bytes(image_bytes)
    
    metadata = parse_result.metadata
    if metadata_override:
        metadata = {**metadata, **metadata_override}

    # Ensure format and extension are consistent
    metadata.setdefault("format", parse_result.format_name)
    metadata.setdefault("extension", parse_result.extension)

    # 2. Serialize metadata to UTF-8 JSON
    metadata_json_bytes = json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    metadata_length = len(metadata_json_bytes)

    # 3. Handle payload compression
    compressor = get_compressor(compression)
    stored_payload = compressor.compress(image_bytes)
    original_size = len(image_bytes)
    stored_size = len(stored_payload)

    # 4. Compute original image SHA-256
    sha256_digest = compute_sha256(image_bytes)

    # 5. Determine Flags
    flags = parse_result.flags
    if compression != CompressionID.NONE:
        flags |= HeaderFlags.PAYLOAD_COMPRESSED
    # In v1.0, metadata is uncompressed

    # 6. Calculate offsets
    metadata_offset = FILE_HEADER_SIZE
    payload_offset = metadata_offset + META_HEADER_SIZE + metadata_length
    integrity_offset = payload_offset + DATA_HEADER_SIZE + stored_size

    # 7. Construct File Header (32 bytes)
    # >4sBBBBQQQ
    file_header = struct.pack(
        ">4sBBBBQQQ",
        MAGIC_FILE,
        MAJOR_VERSION,
        MINOR_VERSION,
        int(flags),
        0x00,  # reserved
        metadata_offset,
        payload_offset,
        integrity_offset,
    )

    # 8. Construct Metadata Header (16 bytes)
    # >4sIQ
    meta_header = struct.pack(
        ">4sIQ",
        MAGIC_META,
        META_TYPE_JSON,
        metadata_length,
    )

    # 9. Construct Payload Header (24 bytes)
    # >4sHHQQ
    payload_header = struct.pack(
        ">4sHHQQ",
        MAGIC_DATA,
        int(parse_result.format_id),
        int(compression),
        original_size,
        stored_size,
    )

    # 10. Construct Integrity Block (40 bytes)
    # >4sHH32s
    integrity_block = struct.pack(
        ">4sHH32s",
        MAGIC_HASH,
        HASH_ALGO_SHA256,
        HASH_SCOPE_ORIGINAL_PAYLOAD,
        sha256_digest,
    )

    # 11. Assemble final container bytes
    container = bytearray()
    container.extend(file_header)
    container.extend(meta_header)
    container.extend(metadata_json_bytes)
    container.extend(payload_header)
    container.extend(stored_payload)
    container.extend(integrity_block)

    return bytes(container)


def encode_file(
    input_image_path: Union[str, Path],
    output_imeta_path: Union[str, Path],
    compression: CompressionID = CompressionID.NONE,
) -> Path:
    """Encode an image file on disk into an .imeta container file."""
    input_path = Path(input_image_path)
    output_path = Path(output_imeta_path)

    image_bytes = input_path.read_bytes()
    imeta_bytes = serialize_imeta(image_bytes, compression=compression)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(imeta_bytes)
    return output_path
