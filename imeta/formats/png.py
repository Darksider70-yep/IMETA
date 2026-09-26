"""PNG image format adapter and chunk parser."""

import struct
import zlib
from typing import Any, Dict
from imeta.core.constants import FormatID
from imeta.formats.base import ImageFormatAdapter
from imeta.metadata.exif import parse_exif
from imeta.metadata.xmp import parse_xmp
from imeta.metadata.iptc import parse_iptc

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

COLOR_TYPES = {
    0: ("Grayscale", 1),
    2: ("RGB", 3),
    3: ("Indexed", 1),
    4: ("Grayscale+Alpha", 2),
    6: ("RGBA", 4),
}


class PNGAdapter(ImageFormatAdapter):
    """Adapter for Portable Network Graphics (PNG)."""

    @property
    def format_id(self) -> FormatID:
        return FormatID.PNG

    @property
    def format_name(self) -> str:
        return "PNG"

    @property
    def default_extension(self) -> str:
        return ".png"

    def matches(self, data: bytes) -> bool:
        return data.startswith(PNG_SIGNATURE)

    def parse_metadata(self, data: bytes) -> Dict[str, Any]:
        if not self.matches(data):
            raise ValueError("Invalid PNG signature")

        width = 0
        height = 0
        bit_depth = 8
        color_model = "RGB"
        exif_dict: Dict[str, Any] = {}
        xmp_dict: Dict[str, Any] = {}
        iptc_dict: Dict[str, Any] = {}
        text_metadata: Dict[str, Any] = {}

        pos = 8  # Skip 8-byte PNG signature
        data_len = len(data)

        while pos + 8 <= data_len:
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            pos += 8

            if pos + length + 4 > data_len:
                break

            chunk_data = data[pos:pos + length]
            pos += length + 4  # Skip CRC (4 bytes)

            if chunk_type == b"IHDR" and length >= 13:
                w, h, bd, ct, comp, flt, inter = struct.unpack(">IIBBBBB", chunk_data[:13])
                width = w
                height = h
                bit_depth = bd
                color_model = COLOR_TYPES.get(ct, ("RGB", 3))[0]

            elif chunk_type == b"eXIf":
                exif_dict = parse_exif(chunk_data)

            elif chunk_type == b"iTXt":
                # Keyword\0 Null Compression_flag Compression_method Language_tag\0 Translated_keyword\0 Text
                null_pos = chunk_data.find(b"\x00")
                if null_pos != -1:
                    keyword = chunk_data[:null_pos].decode("latin-1", errors="replace")
                    rest = chunk_data[null_pos + 1:]
                    if len(rest) >= 2:
                        comp_flag = rest[0]
                        comp_method = rest[1]
                        # Find 2 more null terminators for lang_tag and trans_keyword
                        rest2 = rest[2:]
                        first_null = rest2.find(b"\x00")
                        if first_null != -1:
                            second_null = rest2.find(b"\x00", first_null + 1)
                            if second_null != -1:
                                text_payload = rest2[second_null + 1:]
                                if comp_flag == 1:
                                    try:
                                        text_payload = zlib.decompress(text_payload)
                                    except Exception:
                                        pass
                                if keyword == "XML:com.adobe.xmp":
                                    xmp_dict = parse_xmp(text_payload)
                                else:
                                    text_metadata[keyword] = text_payload.decode("utf-8", errors="replace")

            elif chunk_type == b"tEXt":
                null_pos = chunk_data.find(b"\x00")
                if null_pos != -1:
                    keyword = chunk_data[:null_pos].decode("latin-1", errors="replace")
                    val = chunk_data[null_pos + 1:].decode("latin-1", errors="replace")
                    if keyword == "XML:com.adobe.xmp":
                        xmp_dict = parse_xmp(chunk_data[null_pos + 1:])
                    elif keyword.lower() == "raw profile type iptc":
                        iptc_dict = parse_iptc(chunk_data[null_pos + 1:])
                    else:
                        text_metadata[keyword] = val

            elif chunk_type == b"zTXt":
                null_pos = chunk_data.find(b"\x00")
                if null_pos != -1 and len(chunk_data) > null_pos + 2:
                    keyword = chunk_data[:null_pos].decode("latin-1", errors="replace")
                    compressed_val = chunk_data[null_pos + 2:]
                    try:
                        decompressed = zlib.decompress(compressed_val)
                        if keyword == "XML:com.adobe.xmp":
                            xmp_dict = parse_xmp(decompressed)
                        elif keyword.lower() == "raw profile type iptc":
                            iptc_dict = parse_iptc(decompressed)
                        else:
                            text_metadata[keyword] = decompressed.decode("latin-1", errors="replace")
                    except Exception:
                        pass

            elif chunk_type == b"IEND":
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
            **({"text": text_metadata} if text_metadata else {}),
        }
