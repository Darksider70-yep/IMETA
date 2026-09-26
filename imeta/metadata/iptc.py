"""IPTC-IIM metadata parser."""

import struct
from typing import Any, Dict, List


IPTC_TAGS = {
    5: "ObjectName",
    10: "Urgency",
    15: "Category",
    20: "SupplementalCategories",
    25: "Keywords",
    40: "SpecialInstructions",
    55: "DateCreated",
    60: "TimeCreated",
    80: "Byline",
    85: "BylineTitle",
    90: "City",
    92: "Sublocation",
    95: "ProvinceState",
    100: "CountryPrimaryLocationCode",
    101: "CountryPrimaryLocationName",
    103: "OriginalTransmissionReference",
    105: "Headline",
    110: "Credit",
    115: "Source",
    116: "CopyrightNotice",
    118: "Contact",
    120: "Caption",
    122: "WriterEditor",
}


def parse_iptc(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw IPTC IIM data or Photoshop 8BIM Resource block containing IPTC.
    
    Returns structured JSON-serializable dictionary.
    """
    if not raw_bytes:
        return {}

    # If it's a Photoshop 8BIM block (common in JPEG APP13), extract IPTC segment
    data = raw_bytes
    if b"Photoshop 3.0\x00" in data or data.startswith(b"8BIM"):
        data = _extract_iptc_from_8bim(data)

    if not data:
        return {}

    result: Dict[str, Any] = {}
    pos = 0
    length = len(data)

    while pos < length:
        # IPTC tag starts with tag marker 0x1C
        tag_marker_pos = data.find(b"\x1c", pos)
        if tag_marker_pos == -1 or tag_marker_pos + 5 > length:
            break

        pos = tag_marker_pos
        marker, record_num, tag_num = struct.unpack(">BBB", data[pos:pos + 3])
        tag_len = struct.unpack(">H", data[pos + 3:pos + 5])[0]
        pos += 5

        # Extended tag length check
        if tag_len & 0x8000:
            # Extended dataset
            len_bytes_count = tag_len & 0x7FFF
            if pos + len_bytes_count > length:
                break
            tag_len = int.from_bytes(data[pos:pos + len_bytes_count], "big")
            pos += len_bytes_count

        if pos + tag_len > length:
            break

        val_bytes = data[pos:pos + tag_len]
        pos += tag_len

        if record_num == 2:  # Application Record
            tag_name = IPTC_TAGS.get(tag_num, f"Tag_{record_num}_{tag_num}")
            try:
                val_str = val_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    val_str = val_bytes.decode("latin-1")
                except Exception:
                    val_str = val_bytes.hex()

            # Some tags are repeatable (e.g., Keywords)
            if tag_name in ("Keywords", "SupplementalCategories"):
                if tag_name not in result:
                    result[tag_name] = []
                if isinstance(result[tag_name], list):
                    result[tag_name].append(val_str)
            else:
                result[tag_name] = val_str

    return result


def _extract_iptc_from_8bim(data: bytes) -> bytes:
    """Extract IPTC block from Photoshop 8BIM metadata."""
    pos = 0
    while True:
        pos = data.find(b"8BIM", pos)
        if pos == -1 or pos + 12 > len(data):
            break
        pos += 4
        resource_id = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        # Name pascal string (1 length byte + text + pad to even)
        name_len = data[pos]
        pos += 1 + name_len
        if (1 + name_len) % 2 != 0:
            pos += 1  # Pad byte
        if pos + 4 > len(data):
            break
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        if pos + size > len(data):
            break

        if resource_id == 0x0404:  # IPTC-NAA record
            return data[pos:pos + size]

        pos += size
        if size % 2 != 0:
            pos += 1
    return b""
