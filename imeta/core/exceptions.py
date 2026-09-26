"""Custom exceptions for the IMETA system."""


class IMETAError(Exception):
    """Base class for all IMETA exceptions."""
    pass


class ValidationError(IMETAError):
    """Raised when an input or container fails validation."""
    pass


class CorruptedFileError(ValidationError):
    """Raised when an .imeta container is corrupted or structurally invalid."""
    pass


class IntegrityError(IMETAError):
    """Raised when payload checksum fails (SHA-256 mismatch)."""
    pass


class UnsupportedFormatError(IMETAError):
    """Raised when an image format is unsupported or unrecognized."""
    pass


class VersionIncompatibilityError(IMETAError):
    """Raised when container major version is incompatible."""
    pass


class SecurityLimitError(IMETAError):
    """Raised when file size or decompression ratio exceeds safety thresholds."""
    pass
