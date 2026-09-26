"""FastAPI server for IMETA image serialization and verification."""

import io
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from imeta.core.constants import (
    CompressionID,
    FormatID,
    FORMAT_EXTENSIONS,
    FORMAT_NAMES,
    MAX_FILE_SIZE,
)
from imeta.core.deserializer import deserialize_imeta
from imeta.core.exceptions import (
    CorruptedFileError,
    IMETAError,
    IntegrityError,
    SecurityLimitError,
    UnsupportedFormatError,
    VersionIncompatibilityError,
)
from imeta.core.hashing import compute_sha256_hex
from imeta.core.parser import parse_image_bytes
from imeta.core.serializer import serialize_imeta
from imeta.core.validator import validate_container
from imeta.api.models import InspectResponse, VerifyResponse

app = FastAPI(
    title="IMETA API",
    description="Deterministic, lossless image serialization system (.imeta)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {
        "service": "IMETA Image Serialization Engine",
        "version": "1.0.0",
        "status": "operational",
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


async def _read_upload_file(file: UploadFile, max_size: int = MAX_FILE_SIZE) -> bytes:
    """Read upload file securely with size threshold enforcement."""
    contents = await file.read(max_size + 1)
    if len(contents) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum allowed size of {max_size} bytes",
        )
    return contents


@app.post("/encode", response_class=Response)
async def encode_image(
    file: UploadFile = File(..., description="Image file to encode (JPEG, PNG, WebP)"),
    compression: str = Form(
        "none",
        description="Compression algorithm ('none' or 'deflate')",
    ),
):
    """Encode an image into a lossless .imeta binary container."""
    data = await _read_upload_file(file)

    comp_id = CompressionID.DEFLATE if compression.lower() == "deflate" else CompressionID.NONE

    try:
        container_bytes = serialize_imeta(data, compression=comp_id)
    except UnsupportedFormatError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SecurityLimitError as e:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(e))
    except IMETAError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Encoding failed: {e}")

    original_filename = Path(file.filename or "image").stem
    download_filename = f"{original_filename}.imeta"

    return Response(
        content=container_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{download_filename}"'},
    )


@app.post("/decode", response_class=Response)
async def decode_imeta(
    file: UploadFile = File(..., description=".imeta container file to decode"),
    verify: bool = Form(True, description="Verify SHA-256 integrity checksum during decode"),
):
    """Decode an .imeta container back into the byte-for-byte exact original image."""
    data = await _read_upload_file(file)

    try:
        container = deserialize_imeta(data, verify_integrity=verify)
    except VersionIncompatibilityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Version error: {e}")
    except IntegrityError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Integrity check failed: {e}")
    except (CorruptedFileError, IMETAError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Corrupted container: {e}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Decoding failed: {e}")

    ext = container.metadata.get("extension") or FORMAT_EXTENSIONS.get(container.format_id, ".bin")
    stem = Path(file.filename or "reconstructed").stem
    if stem.endswith(".imeta"):
        stem = stem[:-6]
    download_filename = f"{stem}{ext}"

    media_types = {
        FormatID.JPEG: "image/jpeg",
        FormatID.PNG: "image/png",
        FormatID.WEBP: "image/webp",
    }
    media_type = media_types.get(container.format_id, "application/octet-stream")

    return Response(
        content=container.image_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{download_filename}"'},
    )


@app.post("/inspect", response_model=InspectResponse)
async def inspect_file_post(
    file: UploadFile = File(..., description="Image or .imeta container file to inspect")
):
    """Inspect metadata, format properties, and hashes from an uploaded file."""
    data = await _read_upload_file(file)
    return _inspect_data(data)


@app.get("/inspect", response_model=InspectResponse)
def inspect_file_get(
    path: str = Query(..., description="Server path to file to inspect")
):
    """Inspect metadata from a file on the server filesystem."""
    file_path = Path(path)
    if not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File not found: {path}")

    try:
        data = file_path.read_bytes()
        return _inspect_data(data)
    except IMETAError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def _inspect_data(data: bytes) -> InspectResponse:
    if data.startswith(b"IMTA"):
        try:
            container = deserialize_imeta(data, verify_integrity=False)
            return InspectResponse(
                container_type="IMETA v1.0",
                format_id=int(container.format_id),
                format_name=FORMAT_NAMES.get(container.format_id, "UNKNOWN"),
                sha256=container.sha256,
                major_version=container.major_version,
                minor_version=container.minor_version,
                flags=int(container.flags),
                compression=container.compression_id.name,
                metadata=container.metadata,
            )
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot inspect IMETA container: {e}")
    else:
        try:
            parse_result = parse_image_bytes(data)
            return InspectResponse(
                container_type="Raw Image",
                format_id=int(parse_result.format_id),
                format_name=parse_result.format_name,
                sha256=compute_sha256_hex(data),
                metadata=parse_result.metadata,
            )
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot inspect image: {e}")


@app.post("/verify", response_model=VerifyResponse)
async def verify_container(
    file: UploadFile = File(..., description=".imeta container file to verify")
):
    """Verify structural integrity and cryptographic checksum of an .imeta container."""
    data = await _read_upload_file(file)

    report = validate_container(data, verify_payload_checksum=True)
    return VerifyResponse(
        is_valid=report.is_valid,
        status=report.status,
        major_version=report.major_version,
        minor_version=report.minor_version,
        flags=int(report.flags) if report.flags is not None else None,
        format_id=int(report.format_id) if report.format_id is not None else None,
        compression_id=int(report.compression_id) if report.compression_id is not None else None,
        original_size=report.original_size,
        stored_size=report.stored_size,
        expected_sha256=report.expected_sha256,
        computed_sha256=report.computed_sha256,
        errors=report.errors,
        warnings=report.warnings,
    )
