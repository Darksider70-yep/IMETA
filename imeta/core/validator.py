"""Validation and integrity verification for IMETA containers."""

import io
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Union

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
    HASH_ALGO_SHA256,
    HASH_SCOPE_ORIGINAL_PAYLOAD,
    FormatID,
    CompressionID,
    HeaderFlags,
    MAX_FILE_SIZE,
)
from imeta.core.exceptions import (
    CorruptedFileError,
    IntegrityError,
    SecurityLimitError,
    UnsupportedFormatError,
    ValidationError,
    VersionIncompatibilityError,
)
from imeta.core.hashing import compute_sha256
from imeta.compression import get_compressor


@dataclass
class ValidationReport:
    """Detailed container validation report."""
    is_valid: bool
    status: str  # "VALID", "CORRUPTED", "INCOMPATIBLE_VERSION", "INTEGRITY_FAIL"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    major_version: Optional[int] = None
    minor_version: Optional[int] = None
    flags: Optional[HeaderFlags] = None
    format_id: Optional[FormatID] = None
    compression_id: Optional[CompressionID] = None
    original_size: Optional[int] = None
    stored_size: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None
    expected_sha256: Optional[str] = None
    computed_sha256: Optional[str] = None


def validate_container(
    data: Union[bytes, BinaryIO],
    verify_payload_checksum: bool = True,
) -> ValidationReport:
    """Perform comprehensive structural and cryptographic validation of an .imeta container."""
    errors: List[str] = []
    warnings: List[str] = []

    if isinstance(data, bytes):
        stream = io.BytesIO(data)
        total_len = len(data)
    else:
        stream = data
        stream.seek(0, io.SEEK_END)
        total_len = stream.tell()
        stream.seek(0)

    if total_len > MAX_FILE_SIZE:
        raise SecurityLimitError(f"Container size ({total_len} bytes) exceeds limit ({MAX_FILE_SIZE} bytes)")

    min_required_size = FILE_HEADER_SIZE + META_HEADER_SIZE + DATA_HEADER_SIZE + INTEGRITY_BLOCK_SIZE
    if total_len < min_required_size:
        return ValidationReport(
            is_valid=False,
            status="CORRUPTED",
            errors=[f"File truncated: length is {total_len} bytes, minimum required is {min_required_size} bytes"],
        )

    # 1. Validate File Header (32 bytes)
    stream.seek(0)
    file_hdr_bytes = stream.read(FILE_HEADER_SIZE)
    if len(file_hdr_bytes) < FILE_HEADER_SIZE:
        return ValidationReport(is_valid=False, status="CORRUPTED", errors=["Cannot read 32-byte file header"])

    magic, major, minor, flags_raw, reserved, meta_off, payload_off, integrity_off = struct.unpack(
        ">4sBBBBQQQ", file_hdr_bytes
    )

    if magic != MAGIC_FILE:
        return ValidationReport(
            is_valid=False,
            status="CORRUPTED",
            errors=[f"Invalid magic bytes: expected {MAGIC_FILE!r}, got {magic!r}"],
        )

    if major != MAJOR_VERSION:
        return ValidationReport(
            is_valid=False,
            status="INCOMPATIBLE_VERSION",
            major_version=major,
            minor_version=minor,
            errors=[f"Incompatible major version: {major} (supported: {MAJOR_VERSION})"],
        )

    flags = HeaderFlags(flags_raw)

    # Validate offsets sanity
    if meta_off < FILE_HEADER_SIZE or meta_off >= total_len:
        errors.append(f"File truncated or invalid metadata_offset {meta_off} (file length {total_len})")
    if payload_off < meta_off + META_HEADER_SIZE or payload_off >= total_len:
        errors.append(f"File truncated or invalid payload_offset {payload_off} (file length {total_len})")
    if integrity_off < payload_off + DATA_HEADER_SIZE or integrity_off + INTEGRITY_BLOCK_SIZE > total_len:
        errors.append(f"File truncated or invalid integrity_offset {integrity_off} (file length {total_len})")

    if errors:
        return ValidationReport(
            is_valid=False,
            status="CORRUPTED",
            errors=errors,
            major_version=major,
            minor_version=minor,
            flags=flags,
        )

    # 2. Validate Metadata Section
    stream.seek(meta_off)
    meta_hdr_bytes = stream.read(META_HEADER_SIZE)
    if len(meta_hdr_bytes) < META_HEADER_SIZE:
        errors.append("Truncated metadata header")
        return ValidationReport(is_valid=False, status="CORRUPTED", errors=errors)

    meta_magic, meta_type, meta_length = struct.unpack(">4sIQ", meta_hdr_bytes)
    if meta_magic != MAGIC_META:
        errors.append(f"Invalid metadata magic: expected {MAGIC_META!r}, got {meta_magic!r}")
    if meta_type != META_TYPE_JSON:
        errors.append(f"Unsupported metadata type: 0x{meta_type:08X} (expected JSON 0x00000001)")
    if meta_off + META_HEADER_SIZE + meta_length > payload_off:
        errors.append(
            f"Metadata length ({meta_length}) overflows payload offset ({payload_off})"
        )

    parsed_metadata = None
    if not errors:
        meta_json_bytes = stream.read(meta_length)
        if len(meta_json_bytes) != meta_length:
            errors.append(f"Metadata truncated: expected {meta_length} bytes, got {len(meta_json_bytes)}")
        else:
            try:
                parsed_metadata = json.loads(meta_json_bytes.decode("utf-8"))
            except Exception as e:
                errors.append(f"Malformed UTF-8 JSON in metadata: {e}")

    # 3. Validate Payload Section
    stream.seek(payload_off)
    payload_hdr_bytes = stream.read(DATA_HEADER_SIZE)
    if len(payload_hdr_bytes) < DATA_HEADER_SIZE:
        errors.append("Truncated payload header")
        return ValidationReport(is_valid=False, status="CORRUPTED", errors=errors)

    data_magic, format_id_val, comp_id_val, orig_size, stored_size = struct.unpack(">4sHHQQ", payload_hdr_bytes)
    if data_magic != MAGIC_DATA:
        errors.append(f"Invalid payload magic: expected {MAGIC_DATA!r}, got {data_magic!r}")

    try:
        format_id = FormatID(format_id_val)
    except ValueError:
        errors.append(f"Unsupported format ID: 0x{format_id_val:04X}")
        format_id = None

    try:
        compression_id = CompressionID(comp_id_val)
    except ValueError:
        errors.append(f"Unsupported compression ID: 0x{comp_id_val:04X}")
        compression_id = None

    # Check flag consistency: bit1 (PAYLOAD_COMPRESSED) must match compression_id != NONE
    if compression_id is not None:
        flag_compressed = bool(flags & HeaderFlags.PAYLOAD_COMPRESSED)
        id_compressed = (compression_id != CompressionID.NONE)
        if flag_compressed != id_compressed:
            errors.append(
                f"Flag contradiction: PAYLOAD_COMPRESSED flag is {flag_compressed} "
                f"but compression_id is {compression_id.name} (0x{compression_id.value:04X})"
            )

    if payload_off + DATA_HEADER_SIZE + stored_size > integrity_off:
        errors.append(
            f"Stored payload size ({stored_size}) overflows integrity offset ({integrity_off})"
        )

    stored_payload_bytes = stream.read(stored_size)
    if len(stored_payload_bytes) != stored_size:
        errors.append(f"Stored payload truncated: expected {stored_size} bytes, got {len(stored_payload_bytes)}")

    # 4. Validate Integrity Block
    stream.seek(integrity_off)
    integrity_hdr_bytes = stream.read(INTEGRITY_BLOCK_SIZE)
    if len(integrity_hdr_bytes) < INTEGRITY_BLOCK_SIZE:
        errors.append("Truncated integrity block")
        return ValidationReport(is_valid=False, status="CORRUPTED", errors=errors)

    hash_magic, hash_algo, hash_scope, expected_digest = struct.unpack(">4sHH32s", integrity_hdr_bytes)
    if hash_magic != MAGIC_HASH:
        errors.append(f"Invalid integrity magic: expected {MAGIC_HASH!r}, got {hash_magic!r}")
    if hash_algo != HASH_ALGO_SHA256:
        errors.append(f"Unsupported hash algorithm: 0x{hash_algo:04X}")
    if hash_scope != HASH_SCOPE_ORIGINAL_PAYLOAD:
        errors.append(f"Unsupported hash scope: 0x{hash_scope:04X}")

    if errors:
        return ValidationReport(
            is_valid=False,
            status="CORRUPTED",
            errors=errors,
            major_version=major,
            minor_version=minor,
            flags=flags,
            format_id=format_id,
            compression_id=compression_id,
            original_size=orig_size,
            stored_size=stored_size,
            metadata=parsed_metadata,
            expected_sha256=expected_digest.hex() if len(integrity_hdr_bytes) == INTEGRITY_BLOCK_SIZE else None,
        )

    # 5. Check Cryptographic Integrity
    expected_hex = expected_digest.hex()
    computed_hex = None

    if verify_payload_checksum and compression_id is not None:
        try:
            compressor = get_compressor(compression_id)
            reconstructed_bytes = compressor.decompress(stored_payload_bytes, expected_size=orig_size)
            if len(reconstructed_bytes) != orig_size:
                errors.append(
                    f"Decompressed payload size mismatch: expected {orig_size}, got {len(reconstructed_bytes)}"
                )
            computed_digest = compute_sha256(reconstructed_bytes)
            computed_hex = computed_digest.hex()

            if computed_digest != expected_digest:
                errors.append(
                    f"Integrity checksum mismatch: expected SHA-256 {expected_hex}, computed {computed_hex}"
                )
                return ValidationReport(
                    is_valid=False,
                    status="CORRUPTED",
                    errors=errors,
                    major_version=major,
                    minor_version=minor,
                    flags=flags,
                    format_id=format_id,
                    compression_id=compression_id,
                    original_size=orig_size,
                    stored_size=stored_size,
                    metadata=parsed_metadata,
                    expected_sha256=expected_hex,
                    computed_sha256=computed_hex,
                )
        except Exception as e:
            errors.append(f"Payload decompression/verification failed: {e}")
            return ValidationReport(
                is_valid=False,
                status="CORRUPTED",
                errors=errors,
                major_version=major,
                minor_version=minor,
                flags=flags,
                format_id=format_id,
                compression_id=compression_id,
                original_size=orig_size,
                stored_size=stored_size,
                metadata=parsed_metadata,
                expected_sha256=expected_hex,
            )

    return ValidationReport(
        is_valid=True,
        status="VALID",
        errors=[],
        warnings=warnings,
        major_version=major,
        minor_version=minor,
        flags=flags,
        format_id=format_id,
        compression_id=compression_id,
        original_size=orig_size,
        stored_size=stored_size,
        metadata=parsed_metadata,
        expected_sha256=expected_hex,
        computed_sha256=computed_hex or expected_hex,
    )
