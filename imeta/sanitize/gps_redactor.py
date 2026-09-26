"""Surgical GPS metadata redactor for EXIF TIFF binary structures."""

import struct
from typing import List, Tuple

TYPE_SIZES = {
    1: 1,   # BYTE
    2: 1,   # ASCII
    3: 2,   # SHORT
    4: 4,   # LONG
    5: 8,   # RATIONAL
    7: 1,   # UNDEFINED
    9: 4,   # SLONG
    10: 8,  # SRATIONAL
}


def redact_gps(exif_tiff_bytes: bytes) -> Tuple[bytes, bool]:
    """Surgically zero-fill GPS metadata within a raw EXIF TIFF binary blob.
    
    Returns (possibly-modified copy of exif_tiff_bytes, succeeded).
    succeeded=False means the structure was not safely editable without risking
    other metadata corruption, so caller must fall back to full EXIF removal.

    Note on scope:
      This surgical redactor inspects and modifies IFD0 and its linked GPS sub-IFD
      (tag 0x8825). It intentionally does not traverse the secondary IFD1 chain
      (embedded thumbnail IFD). In rare scenarios where hardware records location
      metadata into IFD1, users requiring absolute forensic redaction should use
      full EXIF removal (remove_exif=True) instead of GPS-only mode.
    """
    if not exif_tiff_bytes or len(exif_tiff_bytes) < 8:
        return (exif_tiff_bytes, False)

    try:
        # 1. Parse TIFF Header
        endian_marker = exif_tiff_bytes[:2]
        if endian_marker == b"II":
            endian = "<"
        elif endian_marker == b"MM":
            endian = ">"
        else:
            return (exif_tiff_bytes, False)

        magic = struct.unpack(f"{endian}H", exif_tiff_bytes[2:4])[0]
        if magic != 42:
            return (exif_tiff_bytes, False)

        ifd0_offset = struct.unpack(f"{endian}I", exif_tiff_bytes[4:8])[0]
        data_len = len(exif_tiff_bytes)

        if ifd0_offset < 8 or ifd0_offset + 2 > data_len:
            return (exif_tiff_bytes, False)

        # 2. Walk IFD0 entries
        num_ifd0 = struct.unpack(f"{endian}H", exif_tiff_bytes[ifd0_offset:ifd0_offset + 2])[0]
        ifd0_table_start = ifd0_offset
        ifd0_table_end = ifd0_offset + 2 + num_ifd0 * 12 + 4

        if ifd0_table_end > data_len:
            return (exif_tiff_bytes, False)

        gps_entry_pos = None
        gps_sub_ifd_offset = None
        non_gps_spans: List[Tuple[int, int]] = []

        pos = ifd0_offset + 2
        for _ in range(num_ifd0):
            tag_id, tag_type, count, val_or_offset = struct.unpack(
                f"{endian}HHI4s", exif_tiff_bytes[pos:pos + 12]
            )

            if tag_id == 0x8825:  # GPSInfo tag
                gps_entry_pos = pos
                gps_sub_ifd_offset = struct.unpack(f"{endian}I", val_or_offset)[0]
            else:
                # Collect out-of-line data spans for non-GPS tags
                size_per_unit = TYPE_SIZES.get(tag_type, 0)
                total_size = size_per_unit * count
                if total_size > 4:
                    offset = struct.unpack(f"{endian}I", val_or_offset)[0]
                    if offset + total_size <= data_len:
                        non_gps_spans.append((offset, offset + total_size))

            pos += 12

        # If no GPSInfo tag found, nothing to remove -> success
        if gps_entry_pos is None or gps_sub_ifd_offset is None:
            return (exif_tiff_bytes, True)

        # 3. Walk GPS sub-IFD
        if gps_sub_ifd_offset < 8 or gps_sub_ifd_offset + 2 > data_len:
            return (exif_tiff_bytes, False)

        num_gps = struct.unpack(f"{endian}H", exif_tiff_bytes[gps_sub_ifd_offset:gps_sub_ifd_offset + 2])[0]
        gps_table_start = gps_sub_ifd_offset
        gps_table_end = gps_sub_ifd_offset + 2 + num_gps * 12 + 4

        if gps_table_end > data_len:
            return (exif_tiff_bytes, False)

        gps_spans: List[Tuple[int, int]] = [(gps_table_start, gps_table_end)]

        gpos = gps_sub_ifd_offset + 2
        for _ in range(num_gps):
            gtag_id, gtag_type, gcount, gval_or_offset = struct.unpack(
                f"{endian}HHI4s", exif_tiff_bytes[gpos:gpos + 12]
            )
            gsize_unit = TYPE_SIZES.get(gtag_type, 0)
            gtotal_size = gsize_unit * gcount
            if gtotal_size > 4:
                goffset = struct.unpack(f"{endian}I", gval_or_offset)[0]
                gps_spans.append((goffset, goffset + gtotal_size))
            gpos += 12

        # 4. Safety Checks
        for start, end in gps_spans:
            # Check buffer bounds
            if start < 0 or end > data_len or start >= end:
                return (exif_tiff_bytes, False)

            # Check overlap with IFD0 main table
            if max(start, ifd0_table_start) < min(end, ifd0_table_end):
                return (exif_tiff_bytes, False)

            # Check overlap with non-GPS out-of-line data
            for ns, ne in non_gps_spans:
                if max(start, ns) < min(end, ne):
                    return (exif_tiff_bytes, False)

        # 5. Apply Zeroing
        buf = bytearray(exif_tiff_bytes)
        for start, end in gps_spans:
            buf[start:end] = b"\x00" * (end - start)

        # Zero out the 12-byte IFD0 entry for tag 0x8825 itself
        buf[gps_entry_pos:gps_entry_pos + 12] = b"\x00" * 12

        return (bytes(buf), True)

    except Exception:
        return (exif_tiff_bytes, False)
