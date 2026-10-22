"""Surgical GPS metadata redactor for EXIF TIFF binary structures."""

import struct
from typing import List, Optional, Tuple

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


def _parse_ifd(
    data: bytes,
    ifd_offset: int,
    endian: str,
) -> Optional[Tuple[int, int, List[Tuple[int, int, int, bytes]], int]]:
    """Parse a single IFD at *ifd_offset*.

    Returns ``(table_start, table_end, entries, next_ifd_offset)`` or ``None``
    if the offset is out-of-bounds.
    Each entry tuple is ``(tag_id, tag_type, count, val_or_offset_raw_4bytes)``.
    """
    data_len = len(data)
    if ifd_offset < 8 or ifd_offset + 2 > data_len:
        return None

    num_entries = struct.unpack(f"{endian}H", data[ifd_offset:ifd_offset + 2])[0]
    table_start = ifd_offset
    table_end = ifd_offset + 2 + num_entries * 12 + 4  # +4 for next-IFD pointer

    if table_end > data_len:
        return None

    entries: List[Tuple[int, int, int, bytes]] = []
    pos = ifd_offset + 2
    for _ in range(num_entries):
        tag_id, tag_type, count, val_or_offset = struct.unpack(
            f"{endian}HHI4s", data[pos:pos + 12]
        )
        entries.append((tag_id, tag_type, count, val_or_offset))
        pos += 12

    next_ifd_offset = struct.unpack(f"{endian}I", data[pos:pos + 4])[0]
    return (table_start, table_end, entries, next_ifd_offset)


def _collect_gps_info(
    data: bytes,
    ifd_offset: int,
    endian: str,
) -> Optional[Tuple[
    int,                          # gps_entry_pos  (byte position of the 0x8825 entry)
    int,                          # gps_sub_ifd_offset
    int,                          # ifd_table_start
    int,                          # ifd_table_end
    List[Tuple[int, int]],        # non_gps_spans
    List[Tuple[int, int]],        # gps_spans  (sub-IFD table + out-of-line data)
]]:
    """Inspect a single IFD for a GPSInfo (0x8825) tag and collect spans to zero.

    Returns ``None`` if parsing fails or no GPS tag is found.
    """
    data_len = len(data)
    parsed = _parse_ifd(data, ifd_offset, endian)
    if parsed is None:
        return None

    table_start, table_end, entries, _ = parsed

    gps_entry_pos: Optional[int] = None
    gps_sub_ifd_offset: Optional[int] = None
    non_gps_spans: List[Tuple[int, int]] = []

    entry_pos = ifd_offset + 2
    for (tag_id, tag_type, count, val_or_offset_raw) in entries:
        if tag_id == 0x8825:  # GPSInfo tag
            gps_entry_pos = entry_pos
            gps_sub_ifd_offset = struct.unpack(f"{endian}I", val_or_offset_raw)[0]
        else:
            # Collect out-of-line data spans for non-GPS tags
            size_per_unit = TYPE_SIZES.get(tag_type, 0)
            total_size = size_per_unit * count
            if total_size > 4:
                offset = struct.unpack(f"{endian}I", val_or_offset_raw)[0]
                if offset + total_size <= data_len:
                    non_gps_spans.append((offset, offset + total_size))
        entry_pos += 12

    # No GPS tag in this IFD
    if gps_entry_pos is None or gps_sub_ifd_offset is None:
        return None

    # Walk GPS sub-IFD
    if gps_sub_ifd_offset < 8 or gps_sub_ifd_offset + 2 > data_len:
        return None

    num_gps = struct.unpack(f"{endian}H", data[gps_sub_ifd_offset:gps_sub_ifd_offset + 2])[0]
    gps_table_start = gps_sub_ifd_offset
    gps_table_end = gps_sub_ifd_offset + 2 + num_gps * 12 + 4

    if gps_table_end > data_len:
        return None

    gps_spans: List[Tuple[int, int]] = [(gps_table_start, gps_table_end)]

    gpos = gps_sub_ifd_offset + 2
    for _ in range(num_gps):
        gtag_id, gtag_type, gcount, gval_or_offset = struct.unpack(
            f"{endian}HHI4s", data[gpos:gpos + 12]
        )
        gsize_unit = TYPE_SIZES.get(gtag_type, 0)
        gtotal_size = gsize_unit * gcount
        if gtotal_size > 4:
            goffset = struct.unpack(f"{endian}I", gval_or_offset)[0]
            gps_spans.append((goffset, goffset + gtotal_size))
        gpos += 12

    return (gps_entry_pos, gps_sub_ifd_offset, table_start, table_end, non_gps_spans, gps_spans)


def redact_gps(exif_tiff_bytes: bytes) -> Tuple[bytes, bool]:
    """Surgically zero-fill GPS metadata within a raw EXIF TIFF binary blob.
    
    Returns (possibly-modified copy of exif_tiff_bytes, succeeded).
    succeeded=False means the structure was not safely editable without risking
    other metadata corruption, so caller must fall back to full EXIF removal.

    This redactor inspects both IFD0 **and** the secondary IFD1 chain (embedded
    thumbnail IFD).  If either contains a GPSInfo tag (0x8825), its entry and
    linked GPS sub-IFD data are zeroed.
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

        # 2. Parse IFD0
        ifd0_parsed = _parse_ifd(exif_tiff_bytes, ifd0_offset, endian)
        if ifd0_parsed is None:
            return (exif_tiff_bytes, False)

        _, _, _, next_ifd_offset = ifd0_parsed

        # 3. Collect GPS info from IFD0 and optionally IFD1
        gps_hits: List[Tuple[int, int, int, int, List[Tuple[int, int]], List[Tuple[int, int]]]] = []

        ifd0_gps = _collect_gps_info(exif_tiff_bytes, ifd0_offset, endian)
        if ifd0_gps is not None:
            gps_hits.append(ifd0_gps)

        # Walk IFD1 if present
        if next_ifd_offset != 0:
            ifd1_gps = _collect_gps_info(exif_tiff_bytes, next_ifd_offset, endian)
            if ifd1_gps is not None:
                gps_hits.append(ifd1_gps)

        # If no GPS tag found in any IFD -> nothing to remove, that's a success
        if not gps_hits:
            return (exif_tiff_bytes, True)

        # 4. Aggregate all spans and perform safety checks
        all_gps_entry_positions: List[int] = []
        all_gps_spans: List[Tuple[int, int]] = []
        # For overlap checks we combine non-GPS spans from all IFDs
        all_non_gps_spans: List[Tuple[int, int]] = []
        # IFD table boundaries for overlap checks
        all_ifd_tables: List[Tuple[int, int]] = []

        for (gps_entry_pos, _, ifd_table_start, ifd_table_end, non_gps_spans, gps_spans) in gps_hits:
            all_gps_entry_positions.append(gps_entry_pos)
            all_gps_spans.extend(gps_spans)
            all_non_gps_spans.extend(non_gps_spans)
            all_ifd_tables.append((ifd_table_start, ifd_table_end))

        for start, end in all_gps_spans:
            # Check buffer bounds
            if start < 0 or end > data_len or start >= end:
                return (exif_tiff_bytes, False)

            # Check overlap with any IFD main table
            for ifd_start, ifd_end in all_ifd_tables:
                if max(start, ifd_start) < min(end, ifd_end):
                    return (exif_tiff_bytes, False)

            # Check overlap with non-GPS out-of-line data
            for ns, ne in all_non_gps_spans:
                if max(start, ns) < min(end, ne):
                    return (exif_tiff_bytes, False)

        # 5. Apply Zeroing
        buf = bytearray(exif_tiff_bytes)
        for start, end in all_gps_spans:
            buf[start:end] = b"\x00" * (end - start)

        # Zero out the 12-byte IFD entry for tag 0x8825 in each IFD
        for gps_entry_pos in all_gps_entry_positions:
            buf[gps_entry_pos:gps_entry_pos + 12] = b"\x00" * 12

        return (bytes(buf), True)

    except Exception:
        return (exif_tiff_bytes, False)

