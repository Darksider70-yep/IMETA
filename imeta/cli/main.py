"""IMETA Command-Line Interface."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from imeta.core.constants import CompressionID, FormatID, FORMAT_NAMES
from imeta.core.deserializer import decode_file, deserialize_imeta
from imeta.core.exceptions import IMETAError
from imeta.core.hashing import compute_file_sha256_hex
from imeta.core.parser import parse_image_file
from imeta.core.serializer import encode_file
from imeta.core.validator import validate_container


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="imeta",
        description="IMETA: Deterministic, lossless image serialization system (.imeta)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # encode
    p_encode = subparsers.add_parser("encode", help="Encode an image into an .imeta container")
    p_encode.add_argument("image", help="Path to input image file (JPEG, PNG, WebP)")
    p_encode.add_argument("-o", "--output", help="Path to output .imeta file (default: <image>.imeta)")
    p_encode.add_argument(
        "--compression",
        choices=["none", "deflate"],
        default="none",
        help="Payload compression algorithm (default: none)",
    )

    # decode
    p_decode = subparsers.add_parser("decode", help="Decode an .imeta container back to the original image")
    p_decode.add_argument("container", help="Path to input .imeta file")
    p_decode.add_argument("-o", "--output", help="Path to output image file")
    p_decode.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip cryptographic SHA-256 integrity verification during decoding",
    )

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect metadata from an image or .imeta container")
    p_inspect.add_argument("file", help="Path to image or .imeta container file")
    p_inspect.add_argument("--json", action="store_true", help="Output raw JSON")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify integrity and structure of an .imeta container")
    p_verify.add_argument("container", help="Path to .imeta file to verify")
    p_verify.add_argument("--json", action="store_true", help="Output verification report in JSON")

    return parser


def cmd_encode(args: argparse.Namespace) -> int:
    input_path = Path(args.image)
    if not input_path.is_file():
        print(f"Error: Input file not found: {args.image}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".imeta")
    comp_id = CompressionID.DEFLATE if args.compression == "deflate" else CompressionID.NONE

    try:
        orig_sha = compute_file_sha256_hex(input_path)
        encode_file(input_path, output_path, compression=comp_id)
        print(f"Encoded '{input_path}' -> '{output_path}'")
        print(f"Original SHA-256: {orig_sha}")
        return 0
    except IMETAError as e:
        print(f"Encoding error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_decode(args: argparse.Namespace) -> int:
    input_path = Path(args.container)
    if not input_path.is_file():
        print(f"Error: Container file not found: {args.container}", file=sys.stderr)
        return 1

    try:
        out_path = decode_file(input_path, args.output, verify_integrity=not args.no_verify)
        recon_sha = compute_file_sha256_hex(out_path)
        print(f"Decoded '{input_path}' -> '{out_path}'")
        print(f"Reconstructed SHA-256: {recon_sha}")
        return 0
    except IMETAError as e:
        print(f"Decoding error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_inspect(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1

    data = path.read_bytes()

    try:
        # Check if it's an .imeta container
        if data.startswith(b"IMTA"):
            container = deserialize_imeta(data, verify_integrity=False)
            info = {
                "container_type": "IMETA v1.0",
                "major_version": container.major_version,
                "minor_version": container.minor_version,
                "flags": int(container.flags),
                "format_id": int(container.format_id),
                "format_name": FORMAT_NAMES.get(container.format_id, "UNKNOWN"),
                "compression": container.compression_id.name,
                "sha256": container.sha256,
                "metadata": container.metadata,
            }
        else:
            parse_result = parse_image_file(path)
            info = {
                "container_type": "Raw Image",
                "format_id": int(parse_result.format_id),
                "format_name": parse_result.format_name,
                "sha256": compute_file_sha256_hex(path),
                "metadata": parse_result.metadata,
            }

        if args.json:
            print(json.dumps(info, indent=2, ensure_ascii=False))
        else:
            print("=" * 60)
            print(f"File: {path.name} ({info['container_type']})")
            print(f"Format: {info.get('format_name')} (ID: {info.get('format_id')})")
            if "compression" in info:
                print(f"Payload Compression: {info['compression']}")
            print(f"SHA-256: {info['sha256']}")
            print("-" * 60)
            print("Metadata:")
            print(json.dumps(info["metadata"], indent=2, ensure_ascii=False))
            print("=" * 60)
        return 0
    except IMETAError as e:
        print(f"Inspect error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.container)
    if not path.is_file():
        print(f"Error: Container file not found: {args.container}", file=sys.stderr)
        return 1

    try:
        report = validate_container(path.read_bytes(), verify_payload_checksum=True)

        if args.json:
            out_dict = {
                "status": report.status,
                "is_valid": report.is_valid,
                "major_version": report.major_version,
                "minor_version": report.minor_version,
                "flags": int(report.flags) if report.flags is not None else None,
                "format_id": int(report.format_id) if report.format_id is not None else None,
                "compression_id": int(report.compression_id) if report.compression_id is not None else None,
                "original_size": report.original_size,
                "stored_size": report.stored_size,
                "expected_sha256": report.expected_sha256,
                "computed_sha256": report.computed_sha256,
                "errors": report.errors,
                "warnings": report.warnings,
            }
            print(json.dumps(out_dict, indent=2))
        else:
            if report.is_valid:
                print(f"VALID: '{path}' passed all structural and integrity checks.")
                print(f"SHA-256 digest: {report.computed_sha256}")
            else:
                print(f"{report.status}: '{path}' failed validation!")
                for err in report.errors:
                    print(f"  - ERROR: {err}")

        return 0 if report.is_valid else 1
    except Exception as e:
        print(f"CORRUPTED: Verification failed with exception: {e}", file=sys.stderr)
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "encode":
        return cmd_encode(args)
    elif args.command == "decode":
        return cmd_decode(args)
    elif args.command == "inspect":
        return cmd_inspect(args)
    elif args.command == "verify":
        return cmd_verify(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
