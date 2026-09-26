# IMETA Binary Container Format Specification
**Version:** 1.0.0  
**Status:** Standard / Active  
**Byte Order:** Big-Endian (`>`)  
**Text Fields:** UTF-8  
**Hash Function:** SHA-256 (32 bytes)  

---

## 1. Overview & Core Guarantee
IMETA is a deterministic, lossless image serialization container designed for archival, metadata extraction, and bit-level integrity verification.

### Core Invariant
For any supported image:
$$\text{SHA256}(\text{original}) == \text{SHA256}(\text{reconstructed})$$
Under no circumstances are image pixels decoded and re-encoded. Original image payloads are stored verbatim (or compressed losslessly via container-level DEFLATE/Zstandard) and reconstructed byte-for-byte identically upon extraction.

---

## 2. Container Layout
The file layout is sequential with zero padding gaps between sections:
```
+-------------------------------------------------------------+
| File Header (32 bytes)                                      |
+-------------------------------------------------------------+
| Metadata Header (16 bytes) at metadata_offset               |
| UTF-8 JSON String (metadata_length bytes)                   |
+-------------------------------------------------------------+
| Payload Header (24 bytes) at payload_offset                 |
| Stored Image Payload (stored_payload_size bytes)            |
+-------------------------------------------------------------+
| Integrity Block (40 bytes) at integrity_offset              |
+-------------------------------------------------------------+
```

Readers **MUST** treat `metadata_offset`, `payload_offset`, and `integrity_offset` as authoritative for seeking and never assume static section lengths.

---

## 3. Section Specifications

### 3.1. File Header (32 Bytes)
| Offset | Size (Bytes) | Type | Field Name | Description / Value |
|---|---|---|---|---|
| `0` | 4 | ASCII | `magic` | Magic identifier: `"IMTA"` (`0x49 0x4D 0x54 0x41`) |
| `4` | 1 | uint8 | `major_version` | Major version number (`0x01`) |
| `5` | 1 | uint8 | `minor_version` | Minor version number (`0x00`) |
| `6` | 1 | bitfield | `flags` | Header bitfield flags (see Section 3.1.1) |
| `7` | 1 | uint8 | `reserved` | Reserved field, MUST be `0x00` |
| `8` | 8 | uint64 | `metadata_offset` | Absolute byte offset to Metadata Header |
| `16` | 8 | uint64 | `payload_offset` | Absolute byte offset to Payload Header |
| `24` | 8 | uint64 | `integrity_offset` | Absolute byte offset to Integrity Block |

#### 3.1.1. Flags Bitfield (Byte 6)
- **`bit0` (0x01):** `metadata_compressed` — Single source of truth for metadata compression.
- **`bit1` (0x02):** `payload_compressed` — Fast-path hint that payload is compressed (`compression_id != 0x0000`).
- **`bit2` (0x04):** `metadata_encrypted` — Reserved for future encryption.
- **`bit3` (0x08):** `payload_encrypted` — Reserved for future encryption.
- **`bit4` (0x10):** `has_exif` — Image contains EXIF metadata.
- **`bit5` (0x20):** `has_xmp` — Image contains XMP metadata.
- **`bit6` (0x40):** `has_iptc` — Image contains IPTC-IIM metadata.
- **`bit7` (0x80):** Reserved (MUST be 0).

---

### 3.2. Metadata Header & Body (at `metadata_offset`)

#### 3.2.1. Metadata Header (16 Bytes)
| Offset | Size (Bytes) | Type | Field Name | Description / Value |
|---|---|---|---|---|
| `+0` | 4 | ASCII | `magic` | Magic identifier: `"META"` (`0x4D 0x45 0x54 0x41`) |
| `+4` | 4 | uint32 | `metadata_type` | `0x00000001` = UTF-8 JSON |
| `+8` | 8 | uint64 | `metadata_length` | Exact length of metadata payload in bytes |

#### 3.2.2. Metadata Body
Immediately following the 16-byte Metadata Header is `metadata_length` bytes of valid UTF-8 JSON.
Example structure:
```json
{
  "format": "JPEG",
  "extension": ".jpg",
  "width": 1920,
  "height": 1080,
  "color_model": "RGB",
  "bit_depth": 8,
  "exif": {
    "Make": "Canon",
    "Model": "EOS R5",
    "Orientation": 1
  },
  "xmp": {
    "title": "Sunset Horizon"
  },
  "iptc": {
    "Keywords": ["landscape", "sunset"]
  }
}
```

---

### 3.3. Payload Header & Body (at `payload_offset`)

#### 3.3.1. Payload Header (24 Bytes)
| Offset | Size (Bytes) | Type | Field Name | Description / Value |
|---|---|---|---|---|
| `+0` | 4 | ASCII | `magic` | Magic identifier: `"DATA"` (`0x44 0x41 0x54 0x41`) |
| `+4` | 2 | uint16 | `format_id` | Image format identifier (see Section 3.3.2) |
| `+6` | 2 | uint16 | `compression_id` | Compression algorithm (see Section 3.3.3) |
| `+8` | 8 | uint64 | `original_payload_size` | Uncompressed original image size in bytes |
| `+16` | 8 | uint64 | `stored_payload_size` | Stored byte length following this header |

#### 3.3.2. Format IDs (`format_id`)
- `0x0001`: JPEG
- `0x0002`: PNG
- `0x0003`: WebP
- `0x0004`: GIF
- `0x0005`: BMP
- `0x0006`: TIFF
- `0x0007`: HEIF
- `0x0008`: AVIF

#### 3.3.3. Compression IDs (`compression_id`)
- `0x0000`: None (Verbatim original bytes)
- `0x0001`: DEFLATE (RFC 1951 / zlib)
- `0x0002`: Zstandard (RFC 8878)

**Consistency Rule:** `flags.bit1` (`payload_compressed`) **MUST** agree with `compression_id != 0x0000`. Any mismatch indicates corruption and MUST cause the container to be rejected.

---

### 3.4. Integrity Block (40 Bytes, at `integrity_offset`)
| Offset | Size (Bytes) | Type | Field Name | Description / Value |
|---|---|---|---|---|
| `+0` | 4 | ASCII | `magic` | Magic identifier: `"HASH"` (`0x48 0x41 0x53 0x48`) |
| `+4` | 2 | uint16 | `hash_algorithm` | `0x0001` = SHA-256 |
| `+6` | 2 | uint16 | `hash_scope` | `0x0001` = Original uncompressed image payload |
| `+8` | 32 | raw bytes | `digest` | 32-byte SHA-256 digest of original uncompressed image |

---

## 4. Version Compatibility Rules
- **Same Major Version:** Readers for major version $N$ must remain backward and forward compatible across minor versions $N.x$:
  1. Any unknown or extra fields in the metadata JSON **MUST** be safely ignored.
  2. Sensible defaults **MUST** be applied for fields introduced in later minor versions if omitted in earlier versions.
- **Different Major Version:** Readers **MUST** reject any file with a major version different from their supported version with a clear error message.

---

## 5. Security & Robustness
1. **Magic Signature Verification:** Never trust file extensions or HTTP MIME types. All image formats and containers are validated by their magic signatures.
2. **Decompression Bomb Protection:** Decompression operations enforce an explicit expansion ratio threshold and maximum decompressed size limit.
3. **Structured Validation:** Deserialization and validation functions catch malformed structures and return actionable diagnostic reports instead of uncaught crashes.
