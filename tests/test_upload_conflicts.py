<<<<<<< HEAD
import base64
=======
>>>>>>> origin/main
import io
import json
import os
import sys
import time
from pathlib import Path
<<<<<<< HEAD
import hashlib
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET
=======
>>>>>>> origin/main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as app_module


def _auth_client(client):
    token = "test-token"
    app_module.UI_SESSIONS[token] = {
        "username": "admin",
        "expires_at": int(time.time()) + 3600,
    }
    client.set_cookie(app_module.UI_SESSION_COOKIE, token)


def test_upload_check_detects_same_size_and_mtime(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    existing = tmp_path / "same.txt"
    payload_bytes = b"same-content"
    existing.write_bytes(payload_bytes)
    mtime = int(time.time()) - 100
    os.utime(existing, (mtime, mtime))

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.post(
            "/ui/upload/check",
            json={
                "current_path": "",
                "files": [
                    {
                        "path": "same.txt",
                        "size": len(payload_bytes),
                        "modified_ms": (mtime * 1000) + 500,
                        "preserve_tree": False,
                    }
                ],
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["conflicts"][0]["saved_as"] == "same.txt"
    assert data["conflicts"][0]["same_metadata"] is True


def test_upload_check_detects_same_name_even_when_metadata_differs(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    existing = tmp_path / "other.txt"
    existing.write_bytes(b"existing")
    mtime = int(time.time()) - 100
    os.utime(existing, (mtime, mtime))

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.post(
            "/ui/upload/check",
            json={
                "current_path": "",
                "files": [
                    {
                        "path": "other.txt",
                        "size": 999,
                        "modified_ms": mtime * 1000,
                        "preserve_tree": False,
                    }
                ],
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["conflicts"][0]["saved_as"] == "other.txt"
    assert data["conflicts"][0]["same_metadata"] is False


def test_upload_check_detects_same_name_with_different_metadata(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    existing = tmp_path / "conflict.txt"
    existing.write_bytes(b"existing-content")
    mtime = int(time.time()) - 300
    os.utime(existing, (mtime, mtime))

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.post(
            "/ui/upload/check",
            json={
                "current_path": "",
                "files": [
                    {
                        "path": "conflict.txt",
                        "size": 1,
                        "modified_ms": (mtime + 100) * 1000,
                        "preserve_tree": False,
                    }
                ],
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["conflicts"][0]["saved_as"] == "conflict.txt"
    assert data["conflicts"][0]["same_metadata"] is False


def test_upload_preserves_mtime_from_source_payload(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    target_mtime_ms = (int(time.time()) - 250) * 1000

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.post(
            "/ui/upload",
            data={
                "current_path": "",
                "__mtime_payload": json.dumps(
                    [
                        {
                            "path": "mt-preserve.txt",
                            "size": 11,
                            "modified_ms": target_mtime_ms,
                            "preserve_tree": False,
                        }
                    ]
                ),
                "files": (io.BytesIO(b"hello world"), "mt-preserve.txt"),
            },
            content_type="multipart/form-data",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["uploaded"] == 1

    uploaded = tmp_path / "mt-preserve.txt"
    assert uploaded.exists()
    assert abs(uploaded.stat().st_mtime - (target_mtime_ms / 1000.0)) <= 1.0


def test_ampache_handshake_and_ping(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.AMPACHE_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    timestamp = str(int(time.time()))
    auth = hashlib.sha256((timestamp + app_module.AUTH_PASS).encode("utf-8")).hexdigest()

    with app_module.app.test_client() as client:
        handshake = client.get(
            "/server/xml.server.php",
            query_string={
                "action": "handshake",
                "timestamp": timestamp,
                "auth": auth,
                "user": app_module.AUTH_USER,
                "version": "6.0.0",
            },
        )

        assert handshake.status_code == 200
        root = ET.fromstring(handshake.data)
        token = root.findtext("auth")
        assert token

        ping = client.get(
            "/server/xml.server.php",
            query_string={
                "action": "ping",
                "auth": token,
            },
        )

    assert ping.status_code == 200
    ping_root = ET.fromstring(ping.data)
    assert ping_root.findtext("ping") == "1"


def test_ui_download_includes_last_modified(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    payload = b"download-me"
    source = tmp_path / "ui-file.txt"
    source.write_bytes(payload)
    mtime = int(time.time()) - 120
    os.utime(source, (mtime, mtime))

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.get("/ui/download/ui-file.txt")

    assert response.status_code == 200
    assert response.data == payload
    assert "Last-Modified" in response.headers
    got_ts = int(parsedate_to_datetime(response.headers["Last-Modified"]).timestamp())
    assert abs(got_ts - mtime) <= 1


def test_webdav_get_includes_last_modified(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.app.config["TESTING"] = True

    payload = b"dav-file"
    source = tmp_path / "dav-file.txt"
    source.write_bytes(payload)
    mtime = int(time.time()) - 240
    os.utime(source, (mtime, mtime))

    token = base64.b64encode(f"{app_module.AUTH_USER}:{app_module.AUTH_PASS}".encode("utf-8")).decode("ascii")
    auth_header = {"Authorization": f"Basic {token}"}

    with app_module.app.test_client() as client:
        response = client.get("/dav-file.txt", headers=auth_header)

    assert response.status_code == 200
    assert response.data == payload
    assert "Last-Modified" in response.headers
    got_ts = int(parsedate_to_datetime(response.headers["Last-Modified"]).timestamp())
    assert abs(got_ts - mtime) <= 1


def test_upload_overwrite_creates_prior_version(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    original = tmp_path / "notes.txt"
    original.write_bytes(b"first")

    with app_module.app.test_client() as client:
        _auth_client(client)
        response = client.post(
            "/ui/upload",
            data={
                "current_path": "",
                "files": (io.BytesIO(b"second"), "notes.txt"),
            },
            content_type="multipart/form-data",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200
    assert original.read_bytes() == b"second"

    version_root = tmp_path / app_module.VERSION_DIR_NAME / "notes.txt"
    assert version_root.exists()
    versions = [p for p in version_root.iterdir() if p.is_file()]
    assert len(versions) == 1
    assert versions[0].read_bytes() == b"first"


def test_restore_prior_version_from_ui(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    target = tmp_path / "restore-me.txt"
    target.write_bytes(b"v1")

    with app_module.app.test_client() as client:
        _auth_client(client)
        upload_resp = client.post(
            "/ui/upload",
            data={
                "current_path": "",
                "files": (io.BytesIO(b"v2"), "restore-me.txt"),
            },
            content_type="multipart/form-data",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )
        assert upload_resp.status_code == 200

        page = client.get("/ui/versions/restore-me.txt")
        assert page.status_code == 200

        versions_dir = tmp_path / app_module.VERSION_DIR_NAME / "restore-me.txt"
        latest_version = sorted([p for p in versions_dir.iterdir() if p.is_file()], key=lambda p: p.name, reverse=True)[0]

        restore_resp = client.post(
            "/ui/versions/restore",
            data={
                "file_rel_path": "restore-me.txt",
                "version_id": latest_version.name,
            },
            follow_redirects=True,
        )

    assert restore_resp.status_code == 200
    assert target.read_bytes() == b"v1"


def test_download_prior_version_from_ui(tmp_path):
    app_module.DATA_ROOT = tmp_path
    app_module.DATA_ROOT.mkdir(parents=True, exist_ok=True)
    app_module.UI_SESSIONS.clear()
    app_module.app.config["TESTING"] = True

    target = tmp_path / "history.txt"
    target.write_bytes(b"alpha")

    with app_module.app.test_client() as client:
        _auth_client(client)
        upload_resp = client.post(
            "/ui/upload",
            data={
                "current_path": "",
                "files": (io.BytesIO(b"beta"), "history.txt"),
            },
            content_type="multipart/form-data",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        )
        assert upload_resp.status_code == 200

        versions_dir = tmp_path / app_module.VERSION_DIR_NAME / "history.txt"
        version = sorted([p for p in versions_dir.iterdir() if p.is_file()], key=lambda p: p.name, reverse=True)[0]

        download_resp = client.get(
            f"/ui/versions/download/history.txt?version_id={version.name}"
        )

    assert download_resp.status_code == 200
    assert download_resp.data == b"alpha"
    assert "attachment" in download_resp.headers.get("Content-Disposition", "")
