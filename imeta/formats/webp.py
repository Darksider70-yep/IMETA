"""WebP image format adapter and RIFF chunk parser."""

import struct
from typing import Any, Dict
from imeta.core.constants import FormatID
from imeta.formats.base import ImageFormatAdapter
from imeta.metadata.exif import parse_exif
from imeta.metadata.xmp import parse_xmp

WEBP_RIFF = b"RIFF"
WEBP_FORMAT = b"WEBP"


class WebPAdapter(ImageFormatAdapter):
    """Adapter for WebP image container."""

    @property
    def format_id(self) -> FormatID:
        return FormatID.WEBP

    @property
    def format_name(self) -> str:
        return "WebP"

    @property
    def default_extension(self) -> str:
        return ".webp"

    def matches(self, data: bytes) -> bool:
        return len(data) >= 12 and data.startswith(WEBP_RIFF) and data[8:12] == WEBP_FORMAT

    def parse_metadata(self, data: bytes) -> Dict[str, Any]:
        if not self.matches(data):
            raise ValueError("Invalid WebP signature")

        width = 0
        height = 0
        bit_depth = 8
        color_model = "RGB"
        exif_dict: Dict[str, Any] = {}
        xmp_dict: Dict[str, Any] = {}
        iptc_dict: Dict[str, Any] = {}

        pos = 12
        data_len = len(data)

        while pos + 8 <= data_len:
            fourcc = data[pos:pos + 4]
            chunk_size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            pos += 8

            chunk_end = pos + chunk_size
            if chunk_end > data_len:
                chunk_data = data[pos:]
            else:
                chunk_data = data[pos:chunk_end]

            # Next chunk is aligned to 2 bytes
            pos += chunk_size + (chunk_size % 2)

            if fourcc == b"VP8 " and len(chunk_data) >= 10:
                # Keyframe check (bit 0 of first byte == 0)
                # 3 bytes start code \x9D\x01\x2A at offset 3
                if chunk_data[3:6] == b"\x9d\x01\x2a":
                    w_raw = struct.unpack("<H", chunk_data[6:8])[0]
                    h_raw = struct.unpack("<H", chunk_data[8:10])[0]
                    width = w_raw & 0x3FFF
                    height = h_raw & 0x3FFF
                    color_model = "RGB"

            elif fourcc == b"VP8L" and len(chunk_data) >= 5:
                # Signature byte 0x2F
                if chunk_data[0] == 0x2F:
                    b0, b1, b2, b3 = chunk_data[1:5]
                    width = 1 + (b0 | ((b1 & 0x3F) << 8))
                    height = 1 + (((b1 >> 6) | (b2 << 2) | ((b3 & 0x0F) << 10)))
                    has_alpha = bool((b3 >> 4) & 1)
                    color_model = "RGBA" if has_alpha else "RGB"

            elif fourcc == b"VP8X" and len(chunk_data) >= 10:
                flags = chunk_data[0]
                has_alpha = bool(flags & (1 << 4))
                color_model = "RGBA" if has_alpha else "RGB"
                # 24-bit canvas width and height
                w_bytes = chunk_data[4:7]
                h_bytes = chunk_data[7:10]
                width = 1 + (w_bytes[0] | (w_bytes[1] << 8) | (w_bytes[2] << 16))
                height = 1 + (h_bytes[0] | (h_bytes[1] << 8) | (h_bytes[2] << 16))

            elif fourcc == b"EXIF":
                exif_dict = parse_exif(chunk_data)

            elif fourcc == b"XMP ":
                xmp_dict = parse_xmp(chunk_data)

        return {
            "format": self.format_name,
            "extension": self.default_extension,
            "width": width,
            "height": height,
            "color_model": color_model,
            "bit_depth": bit_depth,
            "exif": exif_dict,
            "xmp": xmp_dict,
            "iptc": iptc_dict,
        }
