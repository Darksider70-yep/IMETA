"""WebP metadata sanitizer removing EXIF and XMP chunks and adjusting RIFF size."""

import struct
from typing import List
from imeta.core.hashing import compute_sha256_hex
from imeta.sanitize.base import Sanitizer, SanitizeResult
from imeta.sanitize.gps_redactor import redact_gps


class WebPSanitizer(Sanitizer):
    """Sanitizer for WebP images."""

    def sanitize(
        self,
        image_bytes: bytes,
        remove_exif: bool = False,
        remove_gps_only: bool = False,
        remove_xmp: bool = False,
        remove_iptc: bool = False,
    ) -> SanitizeResult:
        if len(image_bytes) < 12 or not image_bytes.startswith(b"RIFF") or image_bytes[8:12] != b"WEBP":
            raise ValueError("Invalid WebP signature")

        if remove_exif:
            remove_gps_only = False

        removed: List[str] = []
        gps_only_downgraded = False

        output_chunks = []
        data_len = len(image_bytes)
        pos = 12

        while pos + 8 <= data_len:
            fourcc = image_bytes[pos:pos + 4]
            chunk_size = struct.unpack("<I", image_bytes[pos + 4:pos + 8])[0]
            pos += 8

            chunk_end = pos + chunk_size
            chunk_data = image_bytes[pos:chunk_end]

            # Advance pos to next chunk (accounting for 2-byte alignment pad)
            pos = chunk_end + (chunk_size % 2)

            if fourcc == b"EXIF":
                if remove_exif:
                    if "EXIF" not in removed:
                        removed.append("EXIF")
                elif remove_gps_only:
                    redacted_exif, succeeded = redact_gps(chunk_data)
                    if succeeded:
                        chunk_hdr = fourcc + struct.pack("<I", len(redacted_exif))
                        pad = b"\x00" if len(redacted_exif) % 2 != 0 else b""
                        output_chunks.append(chunk_hdr + redacted_exif + pad)
                        if "GPS" not in removed:
                            removed.append("GPS")
                    else:
                        gps_only_downgraded = True
                        if "EXIF" not in removed:
                            removed.append("EXIF")
                else:
                    pad = b"\x00" if len(chunk_data) % 2 != 0 else b""
                    output_chunks.append(fourcc + struct.pack("<I", len(chunk_data)) + chunk_data + pad)

            elif fourcc == b"XMP ":
                if remove_xmp or remove_gps_only:
                    if "XMP" not in removed:
                        removed.append("XMP")
                else:
                    pad = b"\x00" if len(chunk_data) % 2 != 0 else b""
                    output_chunks.append(fourcc + struct.pack("<I", len(chunk_data)) + chunk_data + pad)

            else:
                # Keep all other chunks (VP8, VP8L, VP8X, ANIM, etc.)
                pad = b"\x00" if len(chunk_data) % 2 != 0 else b""
                output_chunks.append(fourcc + struct.pack("<I", len(chunk_data)) + chunk_data + pad)

        chunks_body = b"".join(output_chunks)
        total_file_size = 12 + len(chunks_body)
        riff_header = b"RIFF" + struct.pack("<I", total_file_size - 8) + b"WEBP"
        sanitized_bytes = riff_header + chunks_body

        return SanitizeResult(
            image_bytes=sanitized_bytes,
            removed=removed,
            gps_only_downgraded=gps_only_downgraded,
            new_sha256=compute_sha256_hex(sanitized_bytes),
        )
