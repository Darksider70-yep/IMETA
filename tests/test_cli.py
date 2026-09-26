"""Tests for IMETA CLI operations."""

from pathlib import Path
from imeta.cli.main import main


def test_cli_encode_decode_flow(tmp_path, sample_png_bytes):
    img_path = tmp_path / "photo.png"
    img_path.write_bytes(sample_png_bytes)

    imeta_path = tmp_path / "photo.png.imeta"
    recon_path = tmp_path / "photo_out.png"

    # 1. Encode
    exit_code = main(["encode", str(img_path), "-o", str(imeta_path)])
    assert exit_code == 0
    assert imeta_path.is_file()

    # 2. Verify
    exit_code = main(["verify", str(imeta_path)])
    assert exit_code == 0

    # 3. Inspect
    exit_code = main(["inspect", str(imeta_path), "--json"])
    assert exit_code == 0

    # 4. Decode
    exit_code = main(["decode", str(imeta_path), "-o", str(recon_path)])
    assert exit_code == 0
    assert recon_path.read_bytes() == sample_png_bytes


def test_cli_verify_corrupted(tmp_path, sample_jpeg_bytes):
    imeta_path = tmp_path / "corrupted.imeta"
    imeta_path.write_bytes(b"CORRUPTED_DATA_HEADER_HERE_123")

    exit_code = main(["verify", str(imeta_path)])
    assert exit_code == 1
