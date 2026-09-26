"""Tests for IMETA FastAPI server endpoints."""

from fastapi.testclient import TestClient
from imeta.api.server import app
from imeta.core.serializer import serialize_imeta

client = TestClient(app)


def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_api_encode_and_decode_roundtrip(sample_png_bytes):
    # 1. POST /encode
    encode_res = client.post(
        "/encode",
        files={"file": ("test.png", sample_png_bytes, "image/png")},
        data={"compression": "none"},
    )
    assert encode_res.status_code == 200
    imeta_data = encode_res.content
    assert imeta_data.startswith(b"IMTA")

    # 2. POST /verify
    verify_res = client.post(
        "/verify",
        files={"file": ("test.imeta", imeta_data, "application/octet-stream")},
    )
    assert verify_res.status_code == 200
    verify_json = verify_res.json()
    assert verify_json["is_valid"] is True
    assert verify_json["status"] == "VALID"

    # 3. POST /inspect
    inspect_res = client.post(
        "/inspect",
        files={"file": ("test.imeta", imeta_data, "application/octet-stream")},
    )
    assert inspect_res.status_code == 200
    inspect_json = inspect_res.json()
    assert inspect_json["container_type"] == "IMETA v1.0"
    assert inspect_json["format_name"] == "PNG"

    # 4. POST /decode
    decode_res = client.post(
        "/decode",
        files={"file": ("test.imeta", imeta_data, "application/octet-stream")},
    )
    assert decode_res.status_code == 200
    assert decode_res.headers["content-type"] == "image/png"
    assert decode_res.content == sample_png_bytes


def test_api_verify_corrupted_container():
    res = client.post(
        "/verify",
        files={"file": ("bad.imeta", b"GARBAGE_PAYLOAD_DATA", "application/octet-stream")},
    )
    assert res.status_code == 200
    report = res.json()
    assert report["is_valid"] is False
    assert report["status"] == "CORRUPTED"
