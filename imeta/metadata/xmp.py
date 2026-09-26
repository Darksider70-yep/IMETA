"""XMP (Extensible Metadata Platform) parser."""

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict


def parse_xmp(raw_xmp: bytes) -> Dict[str, Any]:
    """Parse raw XMP byte packet into a structured dictionary.
    
    Extracts XML elements/attributes and produces a clean JSON-serializable dictionary.
    """
    if not raw_xmp:
        return {}

    # Decode XMP
    try:
        text = raw_xmp.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw_xmp.decode("latin-1")
        except Exception:
            return {"raw": raw_xmp.hex()}

    # Clean out <?xpacket begin=... ?> wrappers if present
    text = re.sub(r"<\?xpacket[^>]*\?>", "", text).strip()
    if not text:
        return {}

    result: Dict[str, Any] = {}
    try:
        root = ET.fromstring(text)
        # Traverse elements
        for elem in root.iter():
            tag = elem.tag
            if "}" in tag:
                tag = tag.split("}", 1)[1]  # Remove XML namespace prefix for clean JSON
            
            # Extract text if present
            if elem.text and elem.text.strip():
                result[tag] = elem.text.strip()

            # Extract attributes
            for attr_name, attr_val in elem.attrib.items():
                if "}" in attr_name:
                    attr_name = attr_name.split("}", 1)[1]
                result[attr_name] = attr_val.strip()
    except Exception:
        # Fallback regex extraction for simple properties
        for match in re.finditer(r"<([a-zA-Z0-9_:-]+)>([^<]+)</\1>", text):
            k, v = match.group(1), match.group(2).strip()
            if ":" in k:
                k = k.split(":", 1)[1]
            result[k] = v

    return result
