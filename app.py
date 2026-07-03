import base64
import datetime as dt
import hashlib
import io
import json
import mimetypes
import os
import posixpath
import secrets
import shutil
import time
import urllib.parse
import uuid
import zipfile
from functools import wraps
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, send_file, url_for


app = Flask(__name__)

# Config via environment variables.
DATA_ROOT = Path(os.environ.get("WEBDAV_ROOT", "./data")).resolve()
AUTH_USER = os.environ.get("WEBDAV_USERNAME", "admin")
AUTH_PASS = os.environ.get("WEBDAV_PASSWORD", "pass")
UI_SESSION_COOKIE = "ui_session"
UI_SESSION_TTL_SECONDS = 12 * 60 * 60
UI_SESSIONS = {}
AMPACHE_SESSION_TTL_SECONDS = 12 * 60 * 60
AMPACHE_API_VERSION = "6.0.0"
AMPACHE_AUDIO_EXTS = {".mp3", ".flac", ".m4a", ".aac", ".ogg", ".wav", ".opus"}
AMPACHE_SESSIONS = {}
AMPACHE_ROUTE_PATHS = {"/server/xml.server.php", "/ampache/server/xml.server.php"}
VERSION_DIR_NAME = "versions"
LEGACY_VERSION_DIR_NAME = ".versions"
MAX_VERSIONS_PER_FILE = 500

DATA_ROOT.mkdir(parents=True, exist_ok=True)

legacy_version_root = DATA_ROOT / LEGACY_VERSION_DIR_NAME
current_version_root = DATA_ROOT / VERSION_DIR_NAME
if legacy_version_root.exists() and legacy_version_root.is_dir() and not current_version_root.exists():
		shutil.move(str(legacy_version_root), str(current_version_root))


def _version_root() -> Path:
		return DATA_ROOT / VERSION_DIR_NAME


def _is_reserved_rel_path(rel_path: str) -> bool:
		return (
				rel_path == VERSION_DIR_NAME
				or rel_path.startswith(f"{VERSION_DIR_NAME}/")
				or rel_path == LEGACY_VERSION_DIR_NAME
				or rel_path.startswith(f"{LEGACY_VERSION_DIR_NAME}/")
		)


def _auth_failed(message: str = "Authentication required", realm: str = "Flask-WebDAV") -> Response:
		response = Response(message, status=401)
		response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
		return response


def _check_basic_auth() -> bool:
		header = request.headers.get("Authorization", "")
		if not header.startswith("Basic "):
				return False
		token = header.split(" ", 1)[1].strip()
		try:
				decoded = base64.b64decode(token).decode("utf-8")
		except Exception:
				return False
		if ":" not in decoded:
				return False
		username, password = decoded.split(":", 1)
		return username == AUTH_USER and password == AUTH_PASS


def _check_user_password(username: str, password: str) -> bool:
		return username == AUTH_USER and password == AUTH_PASS


def _cleanup_ui_sessions() -> None:
		now = int(time.time())
		expired = [token for token, payload in UI_SESSIONS.items() if payload.get("expires_at", 0) <= now]
		for token in expired:
				UI_SESSIONS.pop(token, None)


def _create_ui_session(username: str) -> str:
		_cleanup_ui_sessions()
		token = secrets.token_urlsafe(32)
		UI_SESSIONS[token] = {
				"username": username,
				"expires_at": int(time.time()) + UI_SESSION_TTL_SECONDS,
		}
		return token


def _get_ui_session_username() -> str | None:
		_cleanup_ui_sessions()
		token = request.cookies.get(UI_SESSION_COOKIE, "")
		if not token:
				return None
		session_info = UI_SESSIONS.get(token)
		if not session_info:
				return None
		return session_info.get("username")


def _set_ui_cookie(response: Response, token: str) -> Response:
		response.set_cookie(
				UI_SESSION_COOKIE,
				token,
				max_age=UI_SESSION_TTL_SECONDS,
				httponly=True,
				samesite="Lax",
		)
		return response


def _clear_ui_cookie(response: Response) -> Response:
		response.delete_cookie(UI_SESSION_COOKIE)
		return response


def _cleanup_ampache_sessions() -> None:
		now = int(time.time())
		expired = [token for token, payload in AMPACHE_SESSIONS.items() if payload.get("expires_at", 0) <= now]
		for token in expired:
				AMPACHE_SESSIONS.pop(token, None)


def _verify_ampache_handshake(user: str, timestamp: str, auth: str) -> bool:
		if not user or user != AUTH_USER:
				return False
		if not auth:
				return False

		auth_lower = auth.lower()
		candidates = {
				hashlib.sha256((timestamp + AUTH_PASS).encode("utf-8")).hexdigest(),
				hashlib.sha256((AUTH_PASS + timestamp).encode("utf-8")).hexdigest(),
				hashlib.sha256(AUTH_PASS.encode("utf-8")).hexdigest(),
		}
		return auth_lower in candidates


def _create_ampache_session(user: str) -> str:
		_cleanup_ampache_sessions()
		token = uuid.uuid4().hex
		AMPACHE_SESSIONS[token] = {
				"username": user,
				"expires_at": int(time.time()) + AMPACHE_SESSION_TTL_SECONDS,
		}
		return token


def _validate_ampache_session(token: str) -> bool:
		_cleanup_ampache_sessions()
		if not token:
				return False
		return token in AMPACHE_SESSIONS


def _ampache_media_entries() -> list[dict]:
		entries = []
		song_id = 1
		for path in sorted(DATA_ROOT.rglob("*")):
				if not path.is_file() or path.suffix.lower() not in AMPACHE_AUDIO_EXTS:
						continue
				rel_path = str(path.relative_to(DATA_ROOT)).replace(os.sep, "/")
				entries.append({
						"id": str(song_id),
						"title": path.stem,
						"rel_path": rel_path,
						"size": str(path.stat().st_size),
				})
				song_id += 1
		return entries


def _ampache_error_xml(message: str) -> Response:
		root = Element("root")
		error = SubElement(root, "error")
		error.text = message
		xml_body = tostring(root, encoding="utf-8", xml_declaration=True)
		return Response(xml_body, status=200, content_type="application/xml; charset=utf-8")


def _ampache_simple_xml(values: dict[str, str]) -> Response:
		root = Element("root")
		for key, value in values.items():
			node = SubElement(root, key)
			node.text = value
		xml_body = tostring(root, encoding="utf-8", xml_declaration=True)
		return Response(xml_body, status=200, content_type="application/xml; charset=utf-8")


def _ampache_songs_xml(entries: list[dict]) -> Response:
		root = Element("root")
		for entry in entries:
			song = SubElement(root, "song", id=entry["id"])
			title = SubElement(song, "title")
			title.text = entry["title"]
			url = SubElement(song, "url")
			url.text = request.url_root.rstrip("/") + "/" + urllib.parse.quote(entry["rel_path"])
			size = SubElement(song, "size")
			size.text = entry["size"]
		xml_body = tostring(root, encoding="utf-8", xml_declaration=True)
		return Response(xml_body, status=200, content_type="application/xml; charset=utf-8")


def requires_auth(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
				if request.path in AMPACHE_ROUTE_PATHS:
						return fn(*args, **kwargs)
				if not _check_basic_auth():
						return _auth_failed()
				return fn(*args, **kwargs)

		return wrapper


def requires_ui_auth(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
				username = _get_ui_session_username()
				if username:
						return fn(*args, **kwargs)

				if request.headers.get("X-Requested-With", "") == "XMLHttpRequest":
						return jsonify({"ok": False, "summary": "Not authenticated"}), 401

				next_path = request.full_path if request.full_path else request.path
				return redirect(url_for("ui_login", next=next_path))

		return wrapper


def _to_safe_rel_path(raw_path: str) -> str:
		clean = urllib.parse.unquote(raw_path or "")
		clean = clean.lstrip("/")
		normalized = posixpath.normpath(clean)
		if normalized in (".", ""):
				return ""
		if normalized.startswith("../") or normalized == "..":
				abort(400, "Invalid path")
		if _is_reserved_rel_path(normalized):
				abort(403, "Path not accessible")
		return normalized


def _full_path(rel_path: str) -> Path:
		candidate = (DATA_ROOT / rel_path).resolve()
		try:
				candidate.relative_to(DATA_ROOT)
		except ValueError:
				abort(403, "Path escapes root")
		return candidate


def _format_http_date(ts: float) -> str:
		return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _iso_utc(ts: float) -> str:
		return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _entry_payload(path: Path, rel_path: str):
		stat = path.stat()
		return {
				"name": path.name,
				"rel_path": rel_path,
				"is_dir": path.is_dir(),
				"size": stat.st_size,
				"mtime": dt.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
		}


def _dav_href(rel_path: str, is_dir: bool) -> str:
		encoded = urllib.parse.quote(rel_path)
		href = "/" + encoded if encoded else "/"
		if is_dir and not href.endswith("/"):
				href += "/"
		return href


def _add_prop_response(multistatus: Element, rel_path: str, full_path: Path) -> None:
		response = SubElement(multistatus, "{DAV:}response")
		href = SubElement(response, "{DAV:}href")
		href.text = _dav_href(rel_path, full_path.is_dir())

		propstat = SubElement(response, "{DAV:}propstat")
		prop = SubElement(propstat, "{DAV:}prop")
		status = SubElement(propstat, "{DAV:}status")
		status.text = "HTTP/1.1 200 OK"

		st = full_path.stat()
		creation = SubElement(prop, "{DAV:}creationdate")
		creation.text = _iso_utc(st.st_ctime)

		last_modified = SubElement(prop, "{DAV:}getlastmodified")
		last_modified.text = _format_http_date(st.st_mtime)

		length = SubElement(prop, "{DAV:}getcontentlength")
		length.text = "0" if full_path.is_dir() else str(st.st_size)

		ctype = SubElement(prop, "{DAV:}getcontenttype")
		guessed = mimetypes.guess_type(full_path.name)[0] if full_path.is_file() else "httpd/unix-directory"
		ctype.text = guessed or "application/octet-stream"

		resource_type = SubElement(prop, "{DAV:}resourcetype")
		if full_path.is_dir():
				SubElement(resource_type, "{DAV:}collection")


def _propfind(rel_path: str) -> Response:
		base = _full_path(rel_path)
		if not base.exists():
				return Response(status=404)

		depth = request.headers.get("Depth", "0")
		depth_is_one = depth == "1"

		multistatus = Element("{DAV:}multistatus")
		_add_prop_response(multistatus, rel_path, base)

		if depth_is_one and base.is_dir():
				for child in sorted(base.iterdir(), key=lambda p: p.name.lower()):
						child_rel = f"{rel_path}/{child.name}" if rel_path else child.name
						_add_prop_response(multistatus, child_rel, child)

		xml_body = tostring(multistatus, encoding="utf-8", xml_declaration=True)
		response = Response(xml_body, status=207, content_type="application/xml; charset=utf-8")
		return response


def _copy_recursive(src: Path, dst: Path) -> None:
		if src.is_dir():
				shutil.copytree(src, dst)
		else:
				dst.parent.mkdir(parents=True, exist_ok=True)
				shutil.copy2(src, dst)


def _delete_path(target: Path) -> None:
		if target.is_dir():
				shutil.rmtree(target)
		else:
				target.unlink()


def _zip_directory_bytes(folder: Path) -> io.BytesIO:
		buffer = io.BytesIO()
		with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
				for root, dirs, files in os.walk(folder):
						root_path = Path(root)
						rel_root = root_path.relative_to(folder)
						if not files and not dirs and rel_root != Path("."):
								zf.writestr(str(rel_root).replace("\\", "/") + "/", "")
						for name in files:
								full = root_path / name
								arcname = full.relative_to(folder)
								zf.write(full, arcname=str(arcname).replace("\\", "/"))
		buffer.seek(0)
		return buffer


def _sanitize_upload_filename(raw_name: str, preserve_tree: bool) -> str:
		name = (raw_name or "").replace("\\", "/").strip()
		if not name:
				raise ValueError("Invalid upload filename")

		if preserve_tree:
				normalized = posixpath.normpath(name.lstrip("/"))
				if normalized in ("", ".") or normalized.startswith("../") or normalized == "..":
						raise ValueError("Invalid folder upload path")
				return normalized

		base = os.path.basename(name)
		if not base:
				raise ValueError("Invalid upload filename")
		return base


def _wants_json_upload_response() -> bool:
		accept = request.headers.get("Accept", "")
		requested_with = request.headers.get("X-Requested-With", "")
		return "application/json" in accept or requested_with == "XMLHttpRequest"


def _extract_mtime_lookup() -> dict[tuple[bool, str], int]:
		raw_payload = request.form.get("__mtime_payload", "")
		if not raw_payload:
				return {}

		try:
				data = json.loads(raw_payload)
		except Exception:
				return {}

		if not isinstance(data, list):
				return {}

		lookup: dict[tuple[bool, str], int] = {}
		for item in data:
				if not isinstance(item, dict):
						continue

				path = str(item.get("path", "") or "")
				preserve_tree = bool(item.get("preserve_tree", False))
				if not path:
						continue

				try:
						safe_name = _sanitize_upload_filename(path, preserve_tree=preserve_tree)
				except Exception:
						continue

				try:
						modified_ms = int(item.get("modified_ms", -1))
				except Exception:
						continue

				if modified_ms >= 0:
						lookup[(preserve_tree, safe_name)] = modified_ms

		return lookup


def _apply_source_mtime(destination: Path, modified_ms: int) -> bool:
		if modified_ms < 0:
				return False

		try:
				mtime_seconds = max(0.0, modified_ms / 1000.0)
				os.utime(destination, (mtime_seconds, mtime_seconds))
				return True
		except Exception:
				return False


def _version_bucket(rel_path: str) -> Path:
		parent = posixpath.dirname(rel_path)
		name = posixpath.basename(rel_path)
		base = _version_root()
		if parent and parent != ".":
				base = base / Path(parent)
		return base / name


def _prune_versions(bucket: Path) -> None:
		if not bucket.exists() or not bucket.is_dir():
				return
		versions = [p for p in bucket.iterdir() if p.is_file()]
		versions.sort(key=lambda p: p.name, reverse=True)
		for stale in versions[MAX_VERSIONS_PER_FILE:]:
				stale.unlink(missing_ok=True)


def _snapshot_file_version(file_rel_path: str, reason: str) -> None:
		if not file_rel_path:
				return
		if _is_reserved_rel_path(file_rel_path):
				return

		source = _full_path(file_rel_path)
		if not source.exists() or not source.is_file():
				return

		timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
		reason_token = "".join(ch for ch in (reason or "update") if ch.isalnum() or ch in ("-", "_"))[:20] or "update"
		version_id = f"{timestamp}__{reason_token}.bak"
		bucket = _version_bucket(file_rel_path)
		bucket.mkdir(parents=True, exist_ok=True)
		shutil.copy2(source, bucket / version_id)
		_prune_versions(bucket)


def _try_snapshot_file_version(file_rel_path: str, reason: str) -> bool:
		try:
				_snapshot_file_version(file_rel_path, reason)
				return True
		except Exception as err:
				app.logger.warning("Version snapshot skipped for %s (%s): %s", file_rel_path, reason, err)
				return False


def _list_file_versions(file_rel_path: str) -> list[dict]:
		bucket = _version_bucket(file_rel_path)
		if not bucket.exists() or not bucket.is_dir():
				return []

		items = []
		for entry in sorted(bucket.iterdir(), key=lambda p: p.name, reverse=True):
				if not entry.is_file():
						continue
				parts = entry.name.split("__", 1)
				reason = "unknown"
				if len(parts) == 2:
					reason = parts[1].rsplit(".", 1)[0]
				stat = entry.stat()
				items.append({
						"id": entry.name,
						"size": stat.st_size,
						"mtime": dt.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
						"reason": reason,
				})
		return items


def _restore_file_version(file_rel_path: str, version_id: str) -> None:
		bucket = _version_bucket(file_rel_path)
		version_name = os.path.basename((version_id or "").strip())
		if not version_name:
				abort(400, "Version id is required")

		version_file = (bucket / version_name).resolve()
		try:
				version_file.relative_to(bucket.resolve())
		except ValueError:
				abort(403, "Invalid version path")

		if not version_file.exists() or not version_file.is_file():
				abort(404)

		target = _full_path(file_rel_path)
		target.parent.mkdir(parents=True, exist_ok=True)
		if target.exists() and target.is_file():
				_try_snapshot_file_version(file_rel_path, "restore")
		shutil.copy2(version_file, target)


def _get_version_file(file_rel_path: str, version_id: str) -> Path:
		bucket = _version_bucket(file_rel_path)
		version_name = os.path.basename((version_id or "").strip())
		if not version_name:
				abort(400, "Version id is required")

		version_file = (bucket / version_name).resolve()
		try:
				version_file.relative_to(bucket.resolve())
		except ValueError:
				abort(403, "Invalid version path")

		if not version_file.exists() or not version_file.is_file():
				abort(404)

		return version_file


def _store_uploaded_file(upload, target_dir: Path, rel_path: str, preserve_tree: bool, mtime_lookup: dict[tuple[bool, str], int] | None = None) -> dict:
		source_name = upload.filename or "<unnamed>"
		try:
				safe_name = _sanitize_upload_filename(source_name, preserve_tree=preserve_tree)
				if preserve_tree:
						saved_rel = f"{rel_path}/{safe_name}" if rel_path else safe_name
						destination = _full_path(saved_rel)
				else:
						saved_rel = f"{rel_path}/{safe_name}" if rel_path else safe_name
						destination = target_dir / safe_name

				if destination.exists() and destination.is_file():
						_try_snapshot_file_version(saved_rel, "upload")

				destination.parent.mkdir(parents=True, exist_ok=True)
				upload.save(destination)
				mtime_preserved = False
				if mtime_lookup:
						modified_ms = mtime_lookup.get((preserve_tree, safe_name))
						if modified_ms is not None:
								mtime_preserved = _apply_source_mtime(destination, modified_ms)
				return {
						"ok": True,
						"source_name": source_name,
						"saved_as": saved_rel,
						"message": "uploaded",
						"mtime_preserved": mtime_preserved,
				}
		except Exception as err:
				return {
						"ok": False,
						"source_name": source_name,
						"saved_as": "-",
						"message": str(err),
				}


def _build_upload_destination(rel_path: str, requested_name: str, preserve_tree: bool) -> tuple[str, Path]:
		safe_name = _sanitize_upload_filename(requested_name, preserve_tree=preserve_tree)
		saved_rel = f"{rel_path}/{safe_name}" if rel_path else safe_name
		if preserve_tree:
				destination = _full_path(saved_rel)
		else:
				destination = _full_path(saved_rel)
		return saved_rel, destination


@app.get("/ui/login")
def ui_login():
		next_path = request.args.get("next", "/ui/")
		if not next_path.startswith("/ui"):
				next_path = "/ui/"
		return render_template("login.html", next_path=next_path, error=None)


@app.post("/ui/login")
def ui_login_post():
		username = request.form.get("username", "")
		password = request.form.get("password", "")
		next_path = request.form.get("next", "/ui/")
		if not next_path.startswith("/ui"):
				next_path = "/ui/"

		if not _check_user_password(username, password):
				return render_template("login.html", next_path=next_path, error="Invalid username or password"), 401

		token = _create_ui_session(username)
		response = redirect(next_path)
		return _set_ui_cookie(response, token)


@app.route("/ui/")
@app.route("/ui/<path:subpath>")
@requires_ui_auth
def ui_list(subpath: str = ""):
		rel_path = _to_safe_rel_path(subpath)
		current = _full_path(rel_path)
		if not current.exists() or not current.is_dir():
				abort(404)

		entries = []
		for item in sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
				child_rel = f"{rel_path}/{item.name}" if rel_path else item.name
				if _is_reserved_rel_path(child_rel):
						continue
				entries.append(_entry_payload(item, child_rel))

		parent_path = None
		if rel_path:
				parent_path = posixpath.dirname(rel_path)
				if parent_path == ".":
						parent_path = ""

		breadcrumbs = [{"name": "/", "path": ""}]
		if rel_path:
				acc = []
				for part in rel_path.split("/"):
						if not part:
								continue
						acc.append(part)
						breadcrumbs.append({"name": part, "path": "/".join(acc)})

		return render_template(
				"index.html",
				current_path=rel_path,
				parent_path=parent_path,
				breadcrumbs=breadcrumbs,
				entries=entries,
				webdav_base=request.url_root.rstrip("/"),
		)


@app.get("/ui/logoff")
def ui_logoff():
		token = request.cookies.get(UI_SESSION_COOKIE, "")
		if token:
				UI_SESSIONS.pop(token, None)
		response = redirect(url_for("ui_login", next="/ui/"))
		_clear_ui_cookie(response)
		response.headers["Cache-Control"] = "no-store"
		return response


@app.post("/ui/upload/check")
@requires_ui_auth
def ui_upload_check():
		payload = request.get_json(silent=True) or {}
		rel_path = _to_safe_rel_path(payload.get("current_path", ""))
		target_dir = _full_path(rel_path)
		if not target_dir.exists() or not target_dir.is_dir():
				return jsonify({"ok": False, "summary": "Target folder not found", "conflicts": []}), 404

		candidates = payload.get("files", [])
		if not isinstance(candidates, list):
				return jsonify({"ok": False, "summary": "Invalid payload", "conflicts": []}), 400

		conflicts = []
		for item in candidates:
				if not isinstance(item, dict):
						continue

				requested_name = str(item.get("path", "") or "")
				if not requested_name:
						continue

				preserve_tree = bool(item.get("preserve_tree", False))
				try:
						saved_rel, destination = _build_upload_destination(rel_path, requested_name, preserve_tree)
				except Exception:
						continue

				if not destination.exists() or not destination.is_file():
						continue

				try:
						size = int(item.get("size", -1))
						modified_ms = int(item.get("modified_ms", -1))
				except Exception:
						continue

				if size < 0 or modified_ms < 0:
						continue

				st = destination.stat()
				same_size = st.st_size == size
				same_mtime = abs(st.st_mtime - (modified_ms / 1000.0)) <= 1.0
				conflicts.append({
						"source_path": requested_name,
						"saved_as": saved_rel,
						"existing_size": st.st_size,
						"incoming_size": size,
						"existing_mtime": int(st.st_mtime),
						"incoming_mtime": int(modified_ms / 1000),
						"same_size": same_size,
						"same_mtime": same_mtime,
						"same_metadata": same_size and same_mtime,
				})

		summary = "No existing-name conflicts found" if not conflicts else f"Found {len(conflicts)} existing-name conflict(s)"
		return jsonify({"ok": True, "summary": summary, "conflicts": conflicts, "count": len(conflicts)})


@app.post("/ui/upload")
@requires_ui_auth
def ui_upload():
		rel_path = _to_safe_rel_path(request.form.get("current_path", ""))
		target_dir = _full_path(rel_path)
		if not target_dir.exists() or not target_dir.is_dir():
				abort(404)

		plain_files = [f for f in request.files.getlist("files") if f and f.filename]
		folder_files = [f for f in request.files.getlist("folder_files") if f and f.filename]
		mtime_lookup = _extract_mtime_lookup()
		if not plain_files and not folder_files:
				if _wants_json_upload_response():
						return jsonify({
								"ok": False,
								"uploaded": 0,
								"failed": 0,
								"summary": "No files provided",
								"results": [],
						}), 400
				abort(400, "No files provided")

		results = []
		for upload in plain_files:
				results.append(_store_uploaded_file(upload, target_dir, rel_path, preserve_tree=False, mtime_lookup=mtime_lookup))

		for upload in folder_files:
				results.append(_store_uploaded_file(upload, target_dir, rel_path, preserve_tree=True, mtime_lookup=mtime_lookup))

		uploaded = sum(1 for r in results if r["ok"])
		failed = sum(1 for r in results if not r["ok"])
		summary = f"Uploaded {uploaded} file(s), failed {failed}."

		if _wants_json_upload_response():
				status_code = 200 if failed == 0 else 207
				return jsonify({
						"ok": failed == 0,
						"uploaded": uploaded,
						"failed": failed,
						"summary": summary,
						"results": results,
				}), status_code

		return redirect(url_for("ui_list", subpath=rel_path))


@app.post("/ui/mkdir")
@requires_ui_auth
def ui_mkdir():
		rel_path = _to_safe_rel_path(request.form.get("current_path", ""))
		folder_name = request.form.get("folder_name", "").strip()
		if not folder_name:
				abort(400, "Folder name is required")

		folder_name = os.path.basename(folder_name)
		target = _full_path(rel_path) / folder_name
		target.mkdir(parents=False, exist_ok=False)
		return redirect(url_for("ui_list", subpath=rel_path))


@app.post("/ui/delete")
@requires_ui_auth
def ui_delete():
		target_rel = _to_safe_rel_path(request.form.get("target", ""))
		current_rel = _to_safe_rel_path(request.form.get("current_path", ""))
		target = _full_path(target_rel)
		if not target.exists():
				abort(404)
		if target.is_file():
				_try_snapshot_file_version(target_rel, "delete")
		_delete_path(target)
		return redirect(url_for("ui_list", subpath=current_rel))


@app.get("/ui/versions/<path:file_path>")
@requires_ui_auth
def ui_versions(file_path: str):
		rel_path = _to_safe_rel_path(file_path)
		full = _full_path(rel_path)
		if not full.exists() or not full.is_file():
				abort(404)

		versions = _list_file_versions(rel_path)
		current_path = posixpath.dirname(rel_path)
		if current_path == ".":
				current_path = ""

		return render_template(
				"versions.html",
				file_rel_path=rel_path,
				file_name=full.name,
				current_path=current_path,
				versions=versions,
		)


@app.post("/ui/versions/restore")
@requires_ui_auth
def ui_restore_version():
		file_rel_path = _to_safe_rel_path(request.form.get("file_rel_path", ""))
		version_id = request.form.get("version_id", "")
		_restore_file_version(file_rel_path, version_id)
		return redirect(url_for("ui_versions", file_path=file_rel_path))


@app.get("/ui/versions/download/<path:file_path>")
@requires_ui_auth
def ui_download_version(file_path: str):
		rel_path = _to_safe_rel_path(file_path)
		version_id = request.args.get("version_id", "")
		version_file = _get_version_file(rel_path, version_id)

		download_name = f"{Path(rel_path).name}.{version_file.name}"
		return send_file(version_file, as_attachment=True, download_name=download_name)


@app.get("/ui/download/<path:file_path>")
@requires_ui_auth
def ui_download(file_path: str):
		rel_path = _to_safe_rel_path(file_path)
		full = _full_path(rel_path)
		if not full.exists() or not full.is_file():
				abort(404)
		return send_file(full, as_attachment=True, last_modified=full.stat().st_mtime, conditional=True)


@app.get("/ui/download-folder/<path:folder_path>")
@requires_ui_auth
def ui_download_folder(folder_path: str):
		rel_path = _to_safe_rel_path(folder_path)
		full = _full_path(rel_path)
		if not full.exists() or not full.is_dir():
				abort(404)

		archive = _zip_directory_bytes(full)
		archive_name = f"{full.name or 'folder'}.zip"
		return send_file(archive, as_attachment=True, download_name=archive_name, mimetype="application/zip")


@app.route("/", defaults={"req_path": ""}, methods=["GET", "HEAD", "OPTIONS", "PROPFIND", "MKCOL", "PUT", "DELETE", "MOVE", "COPY"])
@app.route("/<path:req_path>", methods=["GET", "HEAD", "OPTIONS", "PROPFIND", "MKCOL", "PUT", "DELETE", "MOVE", "COPY"])
@requires_auth
def webdav(req_path: str):
		rel_path = _to_safe_rel_path(req_path)
		target = _full_path(rel_path)
		method = request.method.upper()

		if request.path in AMPACHE_ROUTE_PATHS and method in ("GET", "HEAD"):
				return ampache_api()

		if method == "OPTIONS":
				response = Response(status=200)
				response.headers["DAV"] = "1,2"
				response.headers["MS-Author-Via"] = "DAV"
				response.headers["Allow"] = "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY"
				return response

		if method == "PROPFIND":
				return _propfind(rel_path)

		if method == "MKCOL":
				if target.exists():
						return Response(status=405)
				if not target.parent.exists():
						return Response(status=409)
				target.mkdir(parents=False)
				return Response(status=201)

		if method == "PUT":
				if target.exists() and target.is_file():
						_try_snapshot_file_version(rel_path, "put")
				target.parent.mkdir(parents=True, exist_ok=True)
				with target.open("wb") as out:
						out.write(request.get_data())
				return Response(status=201)

		if method == "DELETE":
				if not target.exists():
						return Response(status=404)
				if target.is_file():
						_try_snapshot_file_version(rel_path, "delete")
				_delete_path(target)
				return Response(status=204)

		if method in ("MOVE", "COPY"):
				destination = request.headers.get("Destination", "")
				if not destination:
						return Response(status=400)
				parsed = urllib.parse.urlparse(destination)
				dest_rel = _to_safe_rel_path(parsed.path)
				dest_path = _full_path(dest_rel)
				overwrite = request.headers.get("Overwrite", "T").upper() == "T"

				if not target.exists():
						return Response(status=404)

				if dest_path.exists():
						if not overwrite:
								return Response(status=412)
						if dest_path.is_file():
								_try_snapshot_file_version(dest_rel, method.lower())
						_delete_path(dest_path)

				if not dest_path.parent.exists():
						return Response(status=409)

				if method == "COPY":
						_copy_recursive(target, dest_path)
				else:
						shutil.move(str(target), str(dest_path))
				return Response(status=201)

		# Browser users visiting root are redirected to the UI.
		if rel_path == "" and method == "GET":
				return redirect(url_for("ui_list", subpath=""))

		if method in ("GET", "HEAD"):
				if not target.exists():
						return Response(status=404)
				if target.is_dir():
						return Response(status=200)
				return send_file(target, as_attachment=False, last_modified=target.stat().st_mtime, conditional=True)

		return Response(status=405)


@app.get("/healthz")
def healthz():
		return {"status": "ok", "data_root": str(DATA_ROOT)}


@app.get("/server/xml.server.php")
@app.get("/ampache/server/xml.server.php")
def ampache_api():
		action = request.args.get("action", "")

		if action == "handshake":
			timestamp = request.args.get("timestamp", "")
			auth = request.args.get("auth", "")
			user = request.args.get("user", "")
			if not _verify_ampache_handshake(user=user, timestamp=timestamp, auth=auth):
					return _ampache_error_xml("Invalid Ampache handshake")

			token = _create_ampache_session(user)
			return _ampache_simple_xml({
					"auth": token,
					"api": AMPACHE_API_VERSION,
					"session_expire": str(AMPACHE_SESSION_TTL_SECONDS),
					"update": "0",
					"add": "0",
					"clean": "0",
			})

		auth_token = request.args.get("auth", "")
		if not _validate_ampache_session(auth_token):
				return _ampache_error_xml("Invalid Ampache session")

		if action == "ping":
			return _ampache_simple_xml({
					"ping": "1",
					"session_expire": str(AMPACHE_SESSION_TTL_SECONDS),
					"api": AMPACHE_API_VERSION,
			})

		if action in ("songs", "song"):
			entries = _ampache_media_entries()
			offset = int(request.args.get("offset", "0") or "0")
			limit = int(request.args.get("limit", "250") or "250")
			sliced = entries[offset:offset + max(0, limit)]
			return _ampache_songs_xml(sliced)

		if action in ("artists", "albums", "playlists"):
			return _ampache_simple_xml({"total_count": "0"})

		return _ampache_error_xml("Unsupported Ampache action")


if __name__ == "__main__":
		host = os.environ.get("HOST", "0.0.0.0")
		port = int(os.environ.get("PORT", "5000"))
		app.run(host=host, port=port, debug=False)
