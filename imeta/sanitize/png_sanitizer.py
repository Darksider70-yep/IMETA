"""PNG metadata sanitizer removing eXIf, XMP, and IPTC chunks."""

import struct
import zlib
from typing import List
from imeta.core.hashing import compute_sha256_hex
from imeta.sanitize.base import Sanitizer, SanitizeResult
from imeta.sanitize.gps_redactor import redact_gps

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PNGSanitizer(Sanitizer):
    """Sanitizer for PNG images."""

    def sanitize(
        self,
        image_bytes: bytes,
        remove_exif: bool = False,
        remove_gps_only: bool = False,
        remove_xmp: bool = False,
        remove_iptc: bool = False,
    ) -> SanitizeResult:
        if not image_bytes.startswith(PNG_SIGNATURE):
            raise ValueError("Invalid PNG signature")

        if remove_exif:
            remove_gps_only = False

        removed: List[str] = []
        gps_only_downgraded = False

        output_chunks = [PNG_SIGNATURE]
        data_len = len(image_bytes)
        pos = 8

        while pos + 8 <= data_len:
            length = struct.unpack(">I", image_bytes[pos:pos + 4])[0]
            chunk_type = image_bytes[pos + 4:pos + 8]
            pos += 8

            if pos + length + 4 > data_len:
                break

            chunk_data = image_bytes[pos:pos + length]
            crc = image_bytes[pos + length:pos + length + 4]
            pos += length + 4

            full_chunk_bytes = (
                struct.pack(">I", length) + chunk_type + chunk_data + crc
            )

            if chunk_type == b"eXIf":
                if remove_exif:
                    if "EXIF" not in removed:
                        removed.append("EXIF")
                elif remove_gps_only:
                    redacted_exif, succeeded = redact_gps(chunk_data)
                    if succeeded:
                        new_crc = zlib.crc32(b"eXIf" + redacted_exif) & 0xFFFFFFFF
                        rebuilt = struct.pack(">I", len(redacted_exif)) + b"eXIf" + redacted_exif + struct.pack(">I", new_crc)
                        output_chunks.append(rebuilt)
                        if "GPS" not in removed:
                            removed.append("GPS")
                    else:
                        gps_only_downgraded = True
                        if "EXIF" not in removed:
                            removed.append("EXIF")
                else:
                    output_chunks.append(full_chunk_bytes)

            elif chunk_type in (b"iTXt", b"tEXt", b"zTXt"):
                null_pos = chunk_data.find(b"\x00")
                keyword = chunk_data[:null_pos].decode("latin-1", errors="replace") if null_pos != -1 else ""

                if keyword == "XML:com.adobe.xmp":
                    if remove_xmp or remove_gps_only:
                        if "XMP" not in removed:
                            removed.append("XMP")
                    else:
                        output_chunks.append(full_chunk_bytes)

                elif keyword.lower() == "raw profile type iptc":
                    if remove_iptc:
                        if "IPTC" not in removed:
                            removed.append("IPTC")
                    else:
                        output_chunks.append(full_chunk_bytes)

                else:
                    output_chunks.append(full_chunk_bytes)

            else:
                # Keep all critical and other ancillary chunks unchanged (IHDR, PLTE, IDAT, IEND, etc.)
                output_chunks.append(full_chunk_bytes)

            if chunk_type == b"IEND":
                break

        sanitized_bytes = b"".join(output_chunks)
        return SanitizeResult(
            image_bytes=sanitized_bytes,
            removed=removed,
            gps_only_downgraded=gps_only_downgraded,
            new_sha256=compute_sha256_hex(sanitized_bytes),
        )
