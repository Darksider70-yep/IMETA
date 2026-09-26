"""EXIF metadata parser and serializable representation."""

import struct
from typing import Any, Dict, Optional, Tuple


# Common EXIF Tag IDs
EXIF_TAGS = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifOffset",
    0x8825: "GPSInfo",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue",
    0x9206: "SubjectDistance",
    0x9207: "MeteringMode",
    0x9208: "LightSource",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0x9286: "UserComment",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
}


def parse_exif(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw EXIF binary data into a clean JSON-serializable dict.
    
    Supports TIFF header (II for little-endian, MM for big-endian) and IFD traversal.
    Handles unicode strings, numbers, rationals, and binary blobs safely.
    """
    if not raw_bytes or len(raw_bytes) < 8:
        return {}

    # Strip "Exif\x00\x00" header prefix if present
    if raw_bytes.startswith(b"Exif\x00\x00"):
        raw_bytes = raw_bytes[6:]
    elif raw_bytes.startswith(b"Exif\x00"):
        raw_bytes = raw_bytes[5:]

    if len(raw_bytes) < 8:
        return {}

    # Check byte order
    endian_marker = raw_bytes[:2]
    if endian_marker == b"II":
        endian = "<"
    elif endian_marker == b"MM":
        endian = ">"
    else:
        return {}

    try:
        magic = struct.unpack(f"{endian}H", raw_bytes[2:4])[0]
        if magic != 42:
            return {}

        first_ifd_offset = struct.unpack(f"{endian}I", raw_bytes[4:8])[0]
        result: Dict[str, Any] = {}
        _parse_ifd(raw_bytes, first_ifd_offset, endian, result)
        return result
    except Exception:
        # Never crash on malformed/unusual EXIF - return whatever was parsed
        return {}


def _parse_ifd(raw_bytes: bytes, ifd_offset: int, endian: str, result: Dict[str, Any], depth: int = 0) -> None:
    if depth > 5 or ifd_offset + 2 > len(raw_bytes):
        return

    num_entries = struct.unpack(f"{endian}H", raw_bytes[ifd_offset:ifd_offset + 2])[0]
    pos = ifd_offset + 2

    sub_ifd_offsets = []

    for _ in range(num_entries):
        if pos + 12 > len(raw_bytes):
            break
        tag_id, tag_type, count, val_or_offset = struct.unpack(f"{endian}HHI4s", raw_bytes[pos:pos + 12])
        pos += 12

        tag_name = EXIF_TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")

        val = _read_tag_value(raw_bytes, tag_type, count, val_or_offset, endian)
        if val is not None:
            if tag_name in ("ExifOffset", "GPSInfo") and isinstance(val, int):
                sub_ifd_offsets.append(val)
            else:
                result[tag_name] = val

    for sub_offset in sub_ifd_offsets:
        _parse_ifd(raw_bytes, sub_offset, endian, result, depth + 1)


def _read_tag_value(raw_bytes: bytes, tag_type: int, count: int, val_or_offset: bytes, endian: str) -> Any:
    # Types:
    # 1: BYTE (1)
    # 2: ASCII (1)
    # 3: SHORT (2)
    # 4: LONG (4)
    # 5: RATIONAL (8)
    # 7: UNDEFINED (1)
    # 9: SLONG (4)
    # 10: SRATIONAL (8)
    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
    size = type_sizes.get(tag_type)
    if not size:
        return None

    total_size = size * count
    if total_size <= 4:
        data = val_or_offset[:total_size]
    else:
        offset = struct.unpack(f"{endian}I", val_or_offset)[0]
        if offset + total_size > len(raw_bytes):
            return None
        data = raw_bytes[offset:offset + total_size]

    try:
        if tag_type == 2:  # ASCII
            text = data.decode("utf-8", errors="replace").rstrip("\x00").strip()
            return text
        elif tag_type == 3:  # SHORT
            vals = [struct.unpack(f"{endian}H", data[i*2:(i+1)*2])[0] for i in range(count)]
            return vals[0] if count == 1 else vals
        elif tag_type == 4:  # LONG
            vals = [struct.unpack(f"{endian}I", data[i*4:(i+1)*4])[0] for i in range(count)]
            return vals[0] if count == 1 else vals
        elif tag_type == 5:  # RATIONAL
            vals = []
            for i in range(count):
                num, den = struct.unpack(f"{endian}II", data[i*8:(i+1)*8])
                vals.append(f"{num}/{den}" if den != 0 else f"{num}/0")
            return vals[0] if count == 1 else vals
        elif tag_type in (1, 7):  # BYTE / UNDEFINED
            try:
                # If it's valid UTF-8, decode it
                return data.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                return data.hex()
    except Exception:
        return None
    return None
