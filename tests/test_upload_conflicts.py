import io
import json
import os
import sys
import time
from pathlib import Path
import hashlib
from xml.etree import ElementTree as ET

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
