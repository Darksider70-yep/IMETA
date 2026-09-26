"""Cryptographic and integrity hashing helpers for IMETA."""

import hashlib
from typing import BinaryIO, Union
from pathlib import Path


def compute_sha256(data: Union[bytes, bytearray, memoryview]) -> bytes:
    """Compute raw 32-byte SHA-256 digest of byte data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()


def compute_sha256_hex(data: Union[bytes, bytearray, memoryview]) -> str:
    """Compute hex-encoded SHA-256 digest of byte data."""
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> bytes:
    """Compute raw 32-byte SHA-256 digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.digest()


def compute_file_sha256_hex(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Compute hex-encoded SHA-256 digest of a file on disk."""
    return compute_file_sha256(file_path, chunk_size).hex()


def compute_stream_sha256(stream: BinaryIO, length: int, chunk_size: int = 65536) -> bytes:
    """Compute raw SHA-256 digest of a slice of an open binary stream."""
    hasher = hashlib.sha256()
    remaining = length
    while remaining > 0:
        to_read = min(remaining, chunk_size)
        chunk = stream.read(to_read)
        if not chunk:
            break
        hasher.update(chunk)
        remaining -= len(chunk)
    return hasher.digest()
