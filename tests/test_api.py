"""Tests for IMETA FastAPI server endpoints."""

from fastapi.testclient import TestClient
from imeta.api.server import app
from imeta.core.serializer import serialize_imeta

client = TestClient(app)


def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_api_ui_endpoint():
    res = client.get("/ui/")
    assert res.status_code == 200
    assert "IMETA" in res.text
    assert "container map" in res.text.lower()


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


def test_inspect_get_rejects_path_traversal():
    """GET /inspect rejects relative path traversal escaping the base dir."""
    res = client.get("/inspect", params={"path": "../../../../etc/passwd"})
    assert res.status_code != 200
    assert res.status_code in (403, 404)


def test_inspect_get_rejects_absolute_path_escape():
    """GET /inspect rejects absolute path escapes."""
    res = client.get("/inspect", params={"path": "/etc/passwd"})
    assert res.status_code != 200
    assert res.status_code in (403, 404)


def test_inspect_get_allows_file_inside_base_dir(monkeypatch, tmp_path, sample_png_bytes):
    """GET /inspect succeeds when reading a valid file inside the sandboxed base dir."""
    # Point INSPECT_BASE_DIR at tmp_path
    monkeypatch.setattr("imeta.api.server.INSPECT_BASE_DIR", tmp_path.resolve())

    test_image = tmp_path / "valid_image.png"
    test_image.write_bytes(sample_png_bytes)

    res = client.get("/inspect", params={"path": "valid_image.png"})
    assert res.status_code == 200
    data = res.json()
    assert data["format_name"] == "PNG"
    assert data["metadata"]["width"] == 64
    assert data["metadata"]["height"] == 48


def test_cors_rejects_unlisted_origin():
    """Unlisted origins must not receive Access-Control-Allow-Origin headers."""
    res = client.get("/health", headers={"Origin": "https://unauthorized-domain.com"})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") != "https://unauthorized-domain.com"
    assert res.headers.get("access-control-allow-origin") != "*"

