"""JPEG metadata sanitizer removing EXIF, GPS, XMP, and IPTC segments."""

import struct
from typing import List
from imeta.core.hashing import compute_sha256_hex
from imeta.sanitize.base import Sanitizer, SanitizeResult
from imeta.sanitize.gps_redactor import redact_gps

XMP_GUID_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
EXIF_PREFIX = b"Exif\x00\x00"
IPTC_PREFIX = b"Photoshop 3.0\x00"


class JPEGSanitizer(Sanitizer):
    """Sanitizer for JPEG images."""

    def sanitize(
        self,
        image_bytes: bytes,
        remove_exif: bool = False,
        remove_gps_only: bool = False,
        remove_xmp: bool = False,
        remove_iptc: bool = False,
    ) -> SanitizeResult:
        if not image_bytes.startswith(b"\xff\xd8"):
            raise ValueError("Invalid JPEG signature")

        # Mutually exclusive handling: remove_exif takes precedence
        if remove_exif:
            remove_gps_only = False

        removed: List[str] = []
        gps_only_downgraded = False

        data_len = len(image_bytes)
        output_segments = [b"\xff\xd8"]  # Start with SOI

        pos = 2
        while pos < data_len:
            if image_bytes[pos] != 0xFF:
                pos += 1
                continue

            while pos < data_len and image_bytes[pos] == 0xFF:
                pos += 1

            if pos >= data_len:
                break

            marker = image_bytes[pos]
            pos += 1

            # Standalone markers with no payload
            if marker in (0x00, 0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9):
                output_segments.append(bytes([0xFF, marker]))
                if marker == 0xD9:
                    break
                continue

            if pos + 2 > data_len:
                break

            segment_len = struct.unpack(">H", image_bytes[pos:pos + 2])[0]
            if segment_len < 2 or pos + segment_len > data_len:
                break

            segment_payload = image_bytes[pos + 2:pos + segment_len]
            next_pos = pos + segment_len

            if marker == 0xDA:  # SOS - Start of Scan (entropy coded image data follows to end)
                # Keep SOS header and all remaining image bitstream verbatim
                output_segments.append(image_bytes[pos - 2:])
                break

            # Check for metadata segments
            if marker == 0xE1 and segment_payload.startswith(EXIF_PREFIX):
                if remove_exif:
                    if "EXIF" not in removed:
                        removed.append("EXIF")
                elif remove_gps_only:
                    exif_tiff = segment_payload[len(EXIF_PREFIX):]
                    redacted_tiff, succeeded = redact_gps(exif_tiff)
                    if succeeded:
                        rebuilt_payload = EXIF_PREFIX + redacted_tiff
                        rebuilt_segment = b"\xff\xe1" + struct.pack(">H", len(rebuilt_payload) + 2) + rebuilt_payload
                        output_segments.append(rebuilt_segment)
                        if "GPS" not in removed:
                            removed.append("GPS")
                    else:
                        gps_only_downgraded = True
                        if "EXIF" not in removed:
                            removed.append("EXIF")
                else:
                    output_segments.append(image_bytes[pos - 2:next_pos])

            elif marker == 0xE1 and segment_payload.startswith(XMP_GUID_PREFIX):
                # If remove_xmp OR remove_gps_only is true, remove XMP
                if remove_xmp or remove_gps_only:
                    if "XMP" not in removed:
                        removed.append("XMP")
                else:
                    output_segments.append(image_bytes[pos - 2:next_pos])

            elif marker == 0xED and segment_payload.startswith(IPTC_PREFIX):
                if remove_iptc:
                    if "IPTC" not in removed:
                        removed.append("IPTC")
                else:
                    output_segments.append(image_bytes[pos - 2:next_pos])

            else:
                # Retain all other segments untouched (SOF, DHT, DQT, DRI, COM, etc.)
                output_segments.append(image_bytes[pos - 2:next_pos])

            pos = next_pos

        sanitized_bytes = b"".join(output_segments)
        return SanitizeResult(
            image_bytes=sanitized_bytes,
            removed=removed,
            gps_only_downgraded=gps_only_downgraded,
            new_sha256=compute_sha256_hex(sanitized_bytes),
        )
