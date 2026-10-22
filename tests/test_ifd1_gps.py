"""Tests for IFD1 (thumbnail IFD) GPS redaction in gps_redactor."""

import struct
from typing import List, Tuple

from imeta.sanitize.gps_redactor import redact_gps


def _build_tiff_with_ifd1_gps() -> bytes:
    """Build a little-endian TIFF blob with GPS in both IFD0 and IFD1.

    Layout (all offsets relative to TIFF start):
      TIFF Header (8 bytes):  II * \\0  ifd0_offset=8
      IFD0 at 8:  3 entries (Make, Model, GPSInfo) + next_ifd → IFD1
        Make value at 56: "Nikon\\0"
        Model value at 62: "Z9\\0"
        GPS sub-IFD at 68: 1 entry (GPSLatitude) pointing to rationals at 84
        GPS Latitude rationals at 84: 35/1 40/1 20/1 (24 bytes)
      IFD1 at 108: 1 entry (GPSInfo) + next_ifd = 0
        GPS sub-IFD at 124: 1 entry (GPSLongitude) pointing to rationals at 140
        GPS Longitude rationals at 140: 139/1 45/1 30/1 (24 bytes)
    """
    endian = "<"
    tiff = bytearray()

    # TIFF Header (0..8)
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")

    # ── IFD0 at 8 ──
    ifd0_offset = 8
    num_ifd0 = 3
    tiff.extend(struct.pack(f"{endian}H", num_ifd0))  # 8..10

    # IFD0 entry positions: 10, 22, 34
    # Next IFD pointer at 46..50
    # Values start at 50

    make_offset = 10 + num_ifd0 * 12 + 4  # 50
    model_offset = make_offset + 6          # 56
    gps0_ifd_offset = model_offset + 3 + 3  # 62 (pad to align) → actually let's compute precisely

    # Plan value offsets:
    # 50: Make "Nikon\0" (6 bytes)  → 50..56
    # 56: Model "Z9\0" (3 bytes)    → 56..59
    # Pad to 60 for alignment
    # 60: GPS0 sub-IFD
    gps0_sub_ifd = 60

    # Tag 0x010F Make (type 2 ASCII, count 6, offset 50)
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x010F, 2, 6, struct.pack(f"{endian}I", 50)))
    # Tag 0x0110 Model (type 2 ASCII, count 3, offset 56)
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x0110, 2, 3, struct.pack(f"{endian}I", 56)))
    # Tag 0x8825 GPSInfo (type 4 LONG, count 1, offset → gps0_sub_ifd)
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x8825, 4, 1, struct.pack(f"{endian}I", gps0_sub_ifd)))

    # Next IFD pointer → IFD1
    # GPS0 sub-IFD: 60 + 2 + 1*12 + 4 = 78
    # GPS0 rationals at 78: 24 bytes → ends at 102
    # IFD1 at 102
    ifd1_offset = 102
    tiff.extend(struct.pack(f"{endian}I", ifd1_offset))  # 46..50

    # Values
    tiff.extend(b"Nikon\x00")  # 50..56
    tiff.extend(b"Z9\x00")    # 56..59
    tiff.extend(b"\x00")      # 59..60 (pad)

    # ── GPS0 sub-IFD at 60 ──
    gps0_lat_offset = 78
    tiff.extend(struct.pack(f"{endian}H", 1))  # 60..62: 1 entry
    # GPSLatitude (tag 0x0002, type 5 RATIONAL, count 3, offset → 78)
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x0002, 5, 3, struct.pack(f"{endian}I", gps0_lat_offset)))
    tiff.extend(struct.pack(f"{endian}I", 0))  # 74..78: next IFD (0)

    # GPS Latitude rationals at 78: 35/1 40/1 20/1
    tiff.extend(struct.pack(f"{endian}IIIIII", 35, 1, 40, 1, 20, 1))  # 78..102

    # ── IFD1 at 102 ──
    num_ifd1 = 1
    tiff.extend(struct.pack(f"{endian}H", num_ifd1))  # 102..104

    # GPS1 sub-IFD location
    # IFD1 entries: 104..116
    # next IFD pointer: 116..120
    # GPS1 sub-IFD at 120
    gps1_sub_ifd = 120
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x8825, 4, 1, struct.pack(f"{endian}I", gps1_sub_ifd)))
    tiff.extend(struct.pack(f"{endian}I", 0))  # 116..120: no more IFDs

    # ── GPS1 sub-IFD at 120 ──
    gps1_lon_offset = 138
    tiff.extend(struct.pack(f"{endian}H", 1))  # 120..122: 1 entry
    # GPSLongitude (tag 0x0004, type 5 RATIONAL, count 3, offset → 138)
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x0004, 5, 3, struct.pack(f"{endian}I", gps1_lon_offset)))
    tiff.extend(struct.pack(f"{endian}I", 0))  # 134..138: next IFD (0)

    # GPS Longitude rationals at 138: 139/1 45/1 30/1
    tiff.extend(struct.pack(f"{endian}IIIIII", 139, 1, 45, 1, 30, 1))  # 138..162

    return bytes(tiff)


def test_redact_gps_ifd0_and_ifd1_both_zeroed():
    """GPS tags in both IFD0 and IFD1 are zeroed, while Make/Model survive."""
    tiff = _build_tiff_with_ifd1_gps()

    # Sanity: original contains both GPS latitude and longitude rationals
    assert struct.pack("<II", 35, 1) in tiff  # IFD0 GPS latitude
    assert struct.pack("<II", 139, 1) in tiff  # IFD1 GPS longitude
    assert b"Nikon" in tiff
    assert b"Z9" in tiff

    redacted, succeeded = redact_gps(tiff)

    assert succeeded is True
    # GPS data should be zeroed
    assert struct.pack("<II", 35, 1) not in redacted
    assert struct.pack("<II", 139, 1) not in redacted
    # Camera metadata should survive
    assert b"Nikon" in redacted
    assert b"Z9" in redacted


def test_redact_gps_ifd1_only():
    """When only IFD1 has GPS tags, they are still zeroed."""
    endian = "<"
    tiff = bytearray()

    # TIFF Header
    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")

    # IFD0 at 8: 1 entry (Make), next IFD → IFD1
    tiff.extend(struct.pack(f"{endian}H", 1))    # 8..10
    make_offset = 10 + 12 + 4  # 26
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x010F, 2, 6, struct.pack(f"{endian}I", make_offset)))
    ifd1_offset = make_offset + 6  # 32
    tiff.extend(struct.pack(f"{endian}I", ifd1_offset))  # 22..26
    tiff.extend(b"Canon\x00")  # 26..32

    # IFD1 at 32: 1 entry (GPSInfo), next IFD = 0
    gps_sub_ifd = 32 + 2 + 12 + 4  # 50
    tiff.extend(struct.pack(f"{endian}H", 1))    # 32..34
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x8825, 4, 1, struct.pack(f"{endian}I", gps_sub_ifd)))
    tiff.extend(struct.pack(f"{endian}I", 0))    # 46..50

    # GPS sub-IFD at 50: 1 entry (GPSLatitude), inline 4-byte value
    tiff.extend(struct.pack(f"{endian}H", 1))    # 50..52
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x0001, 3, 1, struct.pack(f"{endian}I", 42)))
    tiff.extend(struct.pack(f"{endian}I", 0))    # next IFD

    data = bytes(tiff)
    assert b"Canon" in data

    redacted, succeeded = redact_gps(data)

    assert succeeded is True
    assert b"Canon" in redacted
    # The GPS sub-IFD table bytes at offset 50 should now be zeroed
    gps_table_region = redacted[gps_sub_ifd:gps_sub_ifd + 2 + 12 + 4]
    assert gps_table_region == b"\x00" * len(gps_table_region)


def test_redact_gps_no_gps_in_either_ifd():
    """When neither IFD0 nor IFD1 contains GPS, redact returns success with no changes."""
    endian = "<"
    tiff = bytearray()

    tiff.extend(b"II\x2a\x00\x08\x00\x00\x00")
    tiff.extend(struct.pack(f"{endian}H", 1))
    make_offset = 10 + 12 + 4
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x010F, 2, 6, struct.pack(f"{endian}I", make_offset)))
    ifd1_offset = make_offset + 6
    tiff.extend(struct.pack(f"{endian}I", ifd1_offset))
    tiff.extend(b"Canon\x00")

    # IFD1: 1 entry (Model), no GPS
    model_offset = ifd1_offset + 2 + 12 + 4
    tiff.extend(struct.pack(f"{endian}H", 1))
    tiff.extend(struct.pack(f"{endian}HHI4s", 0x0110, 2, 3, struct.pack(f"{endian}I", model_offset)))
    tiff.extend(struct.pack(f"{endian}I", 0))
    tiff.extend(b"R5\x00")

    data = bytes(tiff)
    redacted, succeeded = redact_gps(data)

    assert succeeded is True
    assert redacted == data  # No modification
