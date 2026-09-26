"""Pydantic request/response models for IMETA API."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class VerifyResponse(BaseModel):
    is_valid: bool
    status: str
    major_version: Optional[int] = None
    minor_version: Optional[int] = None
    flags: Optional[int] = None
    format_id: Optional[int] = None
    compression_id: Optional[int] = None
    original_size: Optional[int] = None
    stored_size: Optional[int] = None
    expected_sha256: Optional[str] = None
    computed_sha256: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class InspectResponse(BaseModel):
    container_type: str
    format_id: Optional[int] = None
    format_name: Optional[str] = None
    sha256: str
    major_version: Optional[int] = None
    minor_version: Optional[int] = None
    flags: Optional[int] = None
    compression: Optional[str] = None
    metadata: Dict[str, Any]
