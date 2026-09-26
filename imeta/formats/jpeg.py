"""JPEG image format adapter and segment parser."""

import struct
from typing import Any, Dict
from imeta.core.constants import FormatID
from imeta.formats.base import ImageFormatAdapter
from imeta.metadata.exif import parse_exif
from imeta.metadata.xmp import parse_xmp
from imeta.metadata.iptc import parse_iptc

JPEG_SIGNATURE = b"\xFF\xD8\xFF"

SOF_MARKERS = {
    0xC0: "Baseline",
    0xC1: "Extended sequential",
    0xC2: "Progressive",
    0xC3: "Lossless",
    0xC5: "Differential sequential",
    0xC6: "Differential progressive",
    0xC7: "Differential lossless",
    0xC9: "Extended sequential (arithmetic)",
    0xCA: "Progressive (arithmetic)",
    0xCB: "Lossless (arithmetic)",
    0xCD: "Differential sequential (arithmetic)",
    0xCE: "Differential progressive (arithmetic)",
    0xCF: "Differential lossless (arithmetic)",
}


class JPEGAdapter(ImageFormatAdapter):
    """Adapter for JPEG (JFIF/EXIF)."""

    @property
    def format_id(self) -> FormatID:
        return FormatID.JPEG

    @property
    def format_name(self) -> str:
        return "JPEG"

    @property
    def default_extension(self) -> str:
        return ".jpg"

    def matches(self, data: bytes) -> bool:
        return data.startswith(JPEG_SIGNATURE)

    def parse_metadata(self, data: bytes) -> Dict[str, Any]:
        if not self.matches(data):
            raise ValueError("Invalid JPEG signature")

        width = 0
        height = 0
        bit_depth = 8
        color_model = "RGB"
        exif_dict: Dict[str, Any] = {}
        xmp_dict: Dict[str, Any] = {}
        iptc_dict: Dict[str, Any] = {}

        pos = 2  # Skip SOI (\xFF\xD8)
        data_len = len(data)

        while pos < data_len:
            # Look for marker prefix \xFF
            if data[pos] != 0xFF:
                pos += 1
                continue

            # Skip padding \xFF bytes
            while pos < data_len and data[pos] == 0xFF:
                pos += 1

            if pos >= data_len:
                break

            marker = data[pos]
            pos += 1

            # Standalone markers with no payload
            if marker in (0x00, 0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9):
                if marker == 0xD9:  # EOI (End of Image)
                    break
                continue

            if pos + 2 > data_len:
                break

            segment_len = struct.unpack(">H", data[pos:pos + 2])[0]
            if segment_len < 2 or pos + segment_len > data_len:
                break

            segment_data = data[pos + 2:pos + segment_len]
            pos += segment_len

            # Check for SOF markers (dimensions, bit depth, color channels)
            if marker in SOF_MARKERS:
                if len(segment_data) >= 6:
                    bd, h, w, num_components = struct.unpack(">BHHB", segment_data[:6])
                    bit_depth = bd
                    height = h
                    width = w
                    if num_components == 1:
                        color_model = "Grayscale"
                    elif num_components == 3:
                        color_model = "RGB"
                    elif num_components == 4:
                        color_model = "CMYK"

            # Check APP1 for EXIF or XMP
            elif marker == 0xE1:
                if segment_data.startswith(b"Exif\x00\x00"):
                    exif_dict = parse_exif(segment_data)
                elif segment_data.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                    xmp_payload = segment_data[len(b"http://ns.adobe.com/xap/1.0/\x00"):]
                    xmp_dict = parse_xmp(xmp_payload)

            # Check APP13 for IPTC
            elif marker == 0xED:
                if segment_data.startswith(b"Photoshop 3.0\x00"):
                    iptc_dict = parse_iptc(segment_data)

            # Check APP2 for FlashPix / ICC or other metadata if needed
            elif marker == 0xDA:  # SOS (Start of Scan) - image bitstream follows
                # Metadata is in header segments before SOS
                break

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
