"""Camofox browser backend — local anti-detection browser via REST API.

Camofox-browser is a self-hosted Node.js server wrapping Camoufox (Firefox
fork with C++ fingerprint spoofing).  It exposes a REST API that maps 1:1
to our browser tool interface: accessibility snapshots with element refs,
click/type/scroll by ref, screenshots, etc.

When ``CAMOFOX_URL`` is set (e.g. ``http://localhost:9377``), the browser
tools route through this module instead of the ``agent-browser`` CLI.

Setup::

    # Option 1: npm
    git clone https://github.com/jo-inc/camofox-browser && cd camofox-browser
    npm install && npm start   # downloads Camoufox (~300MB) on first run

    # Option 2: Docker
    docker run -p 9377:9377 -e CAMOFOX_PORT=9377 jo-inc/camofox-browser

Then set ``CAMOFOX_URL=http://localhost:9377`` in ``~/.hermes/.env``.
For Docker Camofox, optionally set ``CAMOFOX_REWRITE_LOOPBACK_URLS=true``
so page URLs like ``http://127.0.0.1:3000`` are opened inside the
container as ``http://host.docker.internal:3000``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import struct
import threading
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import SplitResult, urlsplit, urlunsplit

import requests

from agent.secret_scope import get_secret
from hermes_cli.config import cfg_get, load_config, read_raw_config
from tools.browser_camofox_state import get_camofox_identity
from tools.registry import tool_error

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 30  # fallback when config is unreadable
_SNAPSHOT_MAX_CHARS = 80_000  # camofox paginates at this limit
_vnc_url: Optional[str] = None  # cached from /health response
_vnc_url_checked = False  # only probe once per process

# Cached command timeout from config (resolved lazily, like browser_tool)
_cached_cmd_timeout: Optional[int] = None
_cmd_timeout_resolved = False

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_VIEWPORT_MIN = 100
_VIEWPORT_MAX = 4000


def _get_command_timeout() -> int:
    """Return ``browser.command_timeout`` from config, falling back to 30s.

    Mirrors :func:`tools.browser_tool._get_command_timeout` so both the
    local browser path and the Camofox path honour the same config knob.
    Result is cached after the first call.
    """
    global _cached_cmd_timeout, _cmd_timeout_resolved
    if _cmd_timeout_resolved:
        return _cached_cmd_timeout  # type: ignore[return-value]

    _cmd_timeout_resolved = True
    result = _DEFAULT_TIMEOUT
    try:
        cfg = read_raw_config()
        val = cfg_get(cfg, "browser", "command_timeout")
        if val is not None:
            result = max(int(val), 5)  # floor at 5s
    except Exception as exc:
        logger.debug("Could not read browser.command_timeout: %s", exc)
    _cached_cmd_timeout = result
    return result


def _auth_headers() -> Dict[str, str]:
    """Return Authorization header when CAMOFOX_API_KEY is set."""
    key = (get_secret("CAMOFOX_API_KEY", "") or "").strip()
    if key:
        return {"Authorization": f"Bearer {key}"}
    return {}


def get_camofox_url() -> str:
    """Return the configured Camofox server URL, or empty string."""
    return (get_secret("CAMOFOX_URL", "") or "").rstrip("/")


def _config_cdp_url() -> str:
    """Persistent ``browser.cdp_url`` from config.yaml, or empty string.

    Read here (instead of importing ``browser_tool._get_cdp_override`` to avoid
    a circular import) so Camofox can yield to a config-based CDP override the
    same way it already yields to the ``BROWSER_CDP_URL`` env override.
    """
    try:
        from hermes_cli.config import read_raw_config

        browser_cfg = read_raw_config().get("browser", {})
        if isinstance(browser_cfg, dict):
            return str(browser_cfg.get("cdp_url", "") or "").strip()
    except Exception:
        pass
    return ""


def is_camofox_mode() -> bool:
    """True when Camofox backend is configured and no CDP override is active.

    A CDP override takes priority over Camofox so the browser tools operate on
    the real CDP browser (and a CDP backend is treated as non-local for SSRF
    checks) instead of being silently routed to Camofox. The override may come
    from the ``BROWSER_CDP_URL`` env var (set by ``/browser connect``) OR a
    persistent ``browser.cdp_url`` in config.yaml — both are honored, matching
    ``browser_tool._get_cdp_override()``'s precedence. (Previously only the env
    var suppressed Camofox, so ``CAMOFOX_URL`` + a config CDP override still
    routed navigation through Camofox.)
    """
    if os.getenv("BROWSER_CDP_URL", "").strip():
        return False
    if _config_cdp_url():
        return False
    return bool(get_camofox_url())


def check_camofox_available() -> bool:
    """Verify the Camofox server is reachable."""
    global _vnc_url, _vnc_url_checked
    url = get_camofox_url()
    if not url:
        return False
    try:
        resp = requests.get(f"{url}/health", timeout=5)
        if resp.status_code == 200 and not _vnc_url_checked:
            try:
                data = resp.json()
                vnc_port = data.get("vncPort")
                if isinstance(vnc_port, int) and 1 <= vnc_port <= 65535:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    host = parsed.hostname or "localhost"
                    _vnc_url = f"http://{host}:{vnc_port}"
            except (ValueError, KeyError):
                pass
            _vnc_url_checked = True
        return resp.status_code == 200
    except Exception:
        return False


def get_vnc_url() -> Optional[str]:
    """Return the VNC URL if the Camofox server exposes one, or None."""
    if not _vnc_url_checked:
        check_camofox_available()
    return _vnc_url


def _get_camofox_config() -> Dict[str, Any]:
    """Return the ``browser.camofox`` config block, or an empty dict."""
    try:
        camofox_cfg = load_config().get("browser", {}).get("camofox", {})
    except Exception as exc:
        logger.warning("camofox config check failed, defaulting to disabled: %s", exc)
        return {}
    return camofox_cfg if isinstance(camofox_cfg, dict) else {}


def _managed_persistence_enabled() -> bool:
    """Return whether Hermes-managed persistence is enabled for Camofox.

    When enabled, sessions use a stable profile-scoped userId so the
    Camofox server can map it to a persistent browser profile directory.
    When disabled (default), each session gets a random userId (ephemeral).

    Controlled by ``browser.camofox.managed_persistence`` in config.yaml.
    """
    return bool(_get_camofox_config().get("managed_persistence"))


def _camofox_identity_override(task_id: Optional[str], camofox_cfg: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return an externally configured Camofox identity, if one is set.

    Integrations that own the visible Camofox browser can set a shared user ID
    so Hermes operates in the same browser profile instead of creating a
    separate private session.
    """
    user_id = (
        (get_secret("CAMOFOX_USER_ID", "") or "").strip()
        or str(camofox_cfg.get("user_id") or "").strip()
    )
    if not user_id:
        return None

    session_key = (
        (get_secret("CAMOFOX_SESSION_KEY", "") or "").strip()
        or str(camofox_cfg.get("session_key") or "").strip()
        or f"task_{(task_id or 'default')[:16]}"
    )
    return {"user_id": user_id, "session_key": session_key}


def _env_flag(name: str) -> Optional[bool]:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return None
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    logger.debug("Ignoring invalid boolean env %s=%r", name, raw)
    return None


def _adopt_existing_tab_enabled(camofox_cfg: Dict[str, Any]) -> bool:
    """Return whether Hermes should recover an existing Camofox tab ID."""
    env_value = _env_flag("CAMOFOX_ADOPT_EXISTING_TAB")
    if env_value is not None:
        return env_value
    return bool(camofox_cfg.get("adopt_existing_tab"))


def _loopback_rewrite_enabled(camofox_cfg: Dict[str, Any]) -> bool:
    """Return whether loopback navigation URLs should be rewritten for Docker.

    ``CAMOFOX_URL`` itself often points at a host-published Docker port such as
    ``http://127.0.0.1:9377``.  That is correct for Hermes talking to the
    Camofox control API, but a page URL like ``http://127.0.0.1:3000`` is opened
    by the browser *inside* the Docker container.  In that context loopback
    points at the container, not the host running the web app.

    The rewrite is opt-in because non-Docker Camofox installs run the browser on
    the host, where loopback URLs are already correct.
    """
    env_value = _env_flag("CAMOFOX_REWRITE_LOOPBACK_URLS")
    if env_value is not None:
        return env_value
    return bool(camofox_cfg.get("rewrite_loopback_urls"))


def _loopback_rewrite_host(camofox_cfg: Dict[str, Any]) -> str:
    """Return the host alias used when rewriting loopback page URLs."""
    return (
        os.getenv("CAMOFOX_LOOPBACK_HOST_ALIAS", "").strip()
        or str(camofox_cfg.get("loopback_host_alias") or "").strip()
        or "host.docker.internal"
    )


def _is_loopback_hostname(hostname: Optional[str]) -> bool:
    """Return True for localhost/127.0.0.0/8/::1-style hostnames."""
    if not hostname:
        return False
    host = hostname.strip().strip("[]").lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _rewrite_loopback_url_for_camofox(url: str) -> tuple[str, Optional[Dict[str, str]]]:
    """Rewrite loopback page URLs for Docker-hosted Camofox, if configured.

    Returns ``(rewritten_url, metadata)``.  ``metadata`` is present only when a
    rewrite happened so the tool result can disclose the change to the model.
    """
    camofox_cfg = _get_camofox_config()
    if not _loopback_rewrite_enabled(camofox_cfg):
        return url, None

    try:
        parsed = urlsplit(url)
    except ValueError:
        return url, None

    if parsed.scheme not in {"http", "https"} or not _is_loopback_hostname(parsed.hostname):
        return url, None

    alias = _loopback_rewrite_host(camofox_cfg)
    if not alias:
        return url, None

    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    host_part = f"[{alias}]" if ":" in alias and not alias.startswith("[") else alias
    port_part = f":{parsed.port}" if parsed.port else ""
    rewritten = urlunsplit(
        SplitResult(parsed.scheme, f"{userinfo}{host_part}{port_part}", parsed.path, parsed.query, parsed.fragment)
    )
    return rewritten, {
        "from": parsed.hostname or "",
        "to": alias,
        "original_url": url,
        "rewritten_url": rewritten,
    }


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
# Maps task_id -> {"user_id": str, "tab_id": str|None}
_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = threading.Lock()


def _adopt_existing_tab(session: Dict[str, Any]) -> Dict[str, Any]:
    """Attach process-local state to an already-open managed Camofox tab.

    Some integrations own the visible Camofox tab outside Hermes. Gateway
    restarts can leave this module's in-memory session cache empty even though
    Camofox still has that tab, so rehydrate tab_id before creating a new tab.
    """
    if session.get("tab_id") or not session.get("adopt_existing_tab"):
        return session

    if not get_camofox_url():
        return session

    try:
        tabs = _get("/tabs", params={"userId": session["user_id"]}, timeout=5).get("tabs", [])
    except Exception as exc:
        logger.debug("Camofox tab adoption failed for %s: %s", session.get("user_id"), exc)
        return session

    if not isinstance(tabs, list) or not tabs:
        return session

    session_key = session.get("session_key")
    matching_tabs = [
        tab
        for tab in tabs
        if isinstance(tab, dict) and tab.get("listItemId") == session_key
    ]
    candidates = matching_tabs or [tab for tab in tabs if isinstance(tab, dict)]
    latest = candidates[-1] if candidates else None
    tab_id = latest.get("tabId") if isinstance(latest, dict) else None
    if isinstance(tab_id, str) and tab_id:
        session["tab_id"] = tab_id
        logger.debug("Adopted existing Camofox tab %s for %s", tab_id, session.get("user_id"))

    return session


def _get_session(task_id: Optional[str]) -> Dict[str, Any]:
    """Get or create a camofox session for the given task.

    When managed persistence is enabled, uses a deterministic userId
    derived from the Hermes profile so the Camofox server can map it
    to the same persistent browser profile across restarts.
    """
    task_id = task_id or "default"
    with _sessions_lock:
        if task_id in _sessions:
            return _adopt_existing_tab(_sessions[task_id])

        camofox_cfg = _get_camofox_config()
        identity_override = _camofox_identity_override(task_id, camofox_cfg)
        if identity_override:
            session = {
                "user_id": identity_override["user_id"],
                "tab_id": None,
                "session_key": identity_override["session_key"],
                "managed": True,
                "adopt_existing_tab": _adopt_existing_tab_enabled(camofox_cfg),
            }
        elif bool(camofox_cfg.get("managed_persistence")):
            identity = get_camofox_identity(task_id)
            session = {
                "user_id": identity["user_id"],
                "tab_id": None,
                "session_key": identity["session_key"],
                "managed": True,
                "adopt_existing_tab": _adopt_existing_tab_enabled(camofox_cfg),
            }
        else:
            session = {
                "user_id": f"hermes_{uuid.uuid4().hex[:10]}",
                "tab_id": None,
                "session_key": f"task_{task_id[:16]}",
                "managed": False,
                "adopt_existing_tab": False,
            }
        _sessions[task_id] = session
        return _adopt_existing_tab(session)


def _ensure_tab(task_id: Optional[str], url: str = "about:blank") -> Dict[str, Any]:
    """Ensure a tab exists for the session, creating one if needed."""
    session = _get_session(task_id)
    if session["tab_id"]:
        return session
    base = get_camofox_url()
    resp = requests.post(
        f"{base}/tabs",
        json={
            "userId": session["user_id"],
            "listItemId": session["session_key"],
            "url": url,
        },
        timeout=_get_command_timeout(),
        headers=_auth_headers(),
    )
    resp.raise_for_status()
    data = resp.json()
    session["tab_id"] = data.get("tabId")
    return session


def _drop_session(task_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Remove and return session info."""
    task_id = task_id or "default"
    with _sessions_lock:
        return _sessions.pop(task_id, None)


def camofox_soft_cleanup(task_id: Optional[str] = None) -> bool:
    """Release the in-memory session without destroying the server-side context.

    When managed persistence is enabled the browser profile (and its cookies)
    must survive across agent tasks.  This helper drops only the local tracking
    entry and returns ``True``.  When managed persistence is *not* enabled it
    does nothing and returns ``False`` so the caller can fall back to
    :func:`camofox_close`.
    """
    camofox_cfg = _get_camofox_config()
    if bool(camofox_cfg.get("managed_persistence")) or _camofox_identity_override(task_id, camofox_cfg):
        _drop_session(task_id)
        logger.debug("Camofox soft cleanup for task %s (managed persistence)", task_id)
        return True
    return False


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post(path: str, body: dict, timeout: Optional[int] = None) -> dict:
    """POST JSON to camofox and return parsed response."""
    if timeout is None:
        timeout = _get_command_timeout()
    url = f"{get_camofox_url()}{path}"
    resp = requests.post(url, json=body, timeout=timeout, headers=_auth_headers())
    resp.raise_for_status()
    return resp.json()


def _get(path: str, params: dict = None, timeout: Optional[int] = None) -> dict:
    """GET from camofox and return parsed response."""
    if timeout is None:
        timeout = _get_command_timeout()
    url = f"{get_camofox_url()}{path}"
    resp = requests.get(url, params=params, timeout=timeout, headers=_auth_headers())
    resp.raise_for_status()
    return resp.json()


def _get_raw(path: str, params: dict = None, timeout: Optional[int] = None) -> requests.Response:
    """GET from camofox and return raw response (for binary data)."""
    if timeout is None:
        timeout = _get_command_timeout()
    url = f"{get_camofox_url()}{path}"
    resp = requests.get(url, params=params, timeout=timeout, headers=_auth_headers())
    resp.raise_for_status()
    return resp


def _delete(path: str, body: dict = None, timeout: Optional[int] = None) -> dict:
    """DELETE to camofox and return parsed response."""
    if timeout is None:
        timeout = _get_command_timeout()
    url = f"{get_camofox_url()}{path}"
    resp = requests.delete(url, json=body, timeout=timeout, headers=_auth_headers())
    resp.raise_for_status()
    return resp.json()


def _validated_viewport(
    viewport_width: Optional[int],
    viewport_height: Optional[int],
) -> Optional[tuple[int, int]]:
    """Validate an optional exact viewport without coercing caller input."""
    if viewport_width is None and viewport_height is None:
        return None
    if viewport_width is None or viewport_height is None:
        raise ValueError(
            "viewport_width and viewport_height must be provided together; "
            "no screenshot was captured"
        )

    for name, value in (
        ("viewport_width", viewport_width),
        ("viewport_height", viewport_height),
    ):
        if type(value) is not int or not _VIEWPORT_MIN <= value <= _VIEWPORT_MAX:
            raise ValueError(
                f"{name} must be an integer from {_VIEWPORT_MIN} to "
                f"{_VIEWPORT_MAX}; no screenshot was captured"
            )
    return viewport_width, viewport_height


def _png_bytes_from_screenshot_response(resp: requests.Response) -> bytes:
    """Require and return the raw PNG bytes served by Camofox."""
    content = resp.content
    if isinstance(content, bytes) and content.startswith(_PNG_SIGNATURE):
        return content
    raise ValueError("Camofox screenshot response was not a raw PNG")


def _png_ihdr_dimensions(png: bytes) -> tuple[int, int]:
    """Return PNG dimensions after validating the complete PNG container.

    Exact viewport evidence must be a complete image, not merely a payload that
    starts with a PNG signature and a plausible IHDR.  Keep this stdlib-only so
    the browser integration does not depend on Pillow being installed.
    """
    if not png.startswith(_PNG_SIGNATURE):
        raise ValueError("Camofox screenshot had an invalid PNG signature")

    offset = len(_PNG_SIGNATURE)
    width = height = 0
    color_type: Optional[int] = None
    saw_idat = False
    idat_ended = False
    saw_plte = False
    chunk_index = 0

    while offset < len(png):
        # Length, type, and CRC require twelve bytes before any chunk payload.
        if len(png) - offset < 12:
            raise ValueError("Camofox screenshot had truncated PNG chunk framing")
        length = struct.unpack(">I", png[offset : offset + 4])[0]
        chunk_type = png[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        chunk_end = data_end + 4
        if chunk_end > len(png):
            raise ValueError("Camofox screenshot had a truncated PNG chunk")
        if (
            len(chunk_type) != 4
            or not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in chunk_type)
            # PNG's third chunk-type byte is reserved and must be uppercase.
            or chunk_type[2] & 0x20
        ):
            raise ValueError("Camofox screenshot had an invalid PNG chunk type")

        data = png[data_start:data_end]
        expected_crc = struct.unpack(">I", png[data_end:chunk_end])[0]
        actual_crc = zlib.crc32(data, zlib.crc32(chunk_type)) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("Camofox screenshot had an invalid PNG chunk CRC")

        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                raise ValueError("Camofox screenshot had an invalid PNG IHDR header")
            width, height = struct.unpack(">II", data[:8])
            bit_depth, color_type, compression, image_filter, interlace = data[8:]
            valid_bit_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width <= 0
                or height <= 0
                or bit_depth not in valid_bit_depths.get(color_type, set())
                or compression != 0
                or image_filter != 0
                or interlace not in (0, 1)
            ):
                raise ValueError("Camofox screenshot had invalid PNG IHDR values")
        elif chunk_type == b"IHDR":
            raise ValueError("Camofox screenshot had a duplicate PNG IHDR chunk")
        elif chunk_type == b"PLTE":
            if saw_idat or saw_plte or not 3 <= length <= 768 or length % 3:
                raise ValueError("Camofox screenshot had an invalid PNG palette")
            saw_plte = True
        elif chunk_type == b"IDAT":
            if idat_ended:
                raise ValueError("Camofox screenshot had non-contiguous PNG IDAT chunks")
            saw_idat = True
        elif chunk_type == b"IEND":
            if length != 0 or not saw_idat or (color_type == 3 and not saw_plte):
                raise ValueError("Camofox screenshot had an invalid PNG ending")
            if chunk_end != len(png):
                raise ValueError("Camofox screenshot had trailing bytes after PNG IEND")
            return width, height
        else:
            # Unknown critical chunks cannot be safely interpreted.  Ancillary
            # chunks are permitted once their framing and CRC have been checked.
            if not chunk_type[0] & 0x20:
                raise ValueError("Camofox screenshot had an unknown critical PNG chunk")
            if saw_idat:
                idat_ended = True

        offset = chunk_end
        chunk_index += 1

    raise ValueError("Camofox screenshot was missing a terminating PNG IEND chunk")


def _safe_evidence_identifier(value: Any) -> Optional[str]:
    """Return a bounded identifier only when forced redaction leaves it intact."""
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    from agent.redact import redact_sensitive_text

    redacted = redact_sensitive_text(
        value,
        force=True,
        redact_url_credentials=True,
    )
    return value if redacted == value else None


def _sanitized_evidence_url(value: Any) -> str:
    """Redact credentials from a capture URL at the model-output boundary."""
    from agent.redact import redact_sensitive_text

    return redact_sensitive_text(
        str(value or ""),
        force=True,
        redact_url_credentials=True,
    )


def _require_capture_stats(data: Any, expected_tab_id: str) -> Dict[str, Any]:
    """Validate the stable identity fields required for exact capture proof."""
    if not isinstance(data, dict):
        raise ValueError("Camofox tab stats response was not an object")
    if data.get("tabId") != expected_tab_id:
        raise ValueError("Camofox tab stats did not match the active tab")
    if not isinstance(data.get("url"), str) or not data["url"]:
        raise ValueError("Camofox tab stats did not include a URL")
    return data


def _capture_stats_projection(data: Dict[str, Any]) -> Dict[str, Any]:
    """Project Camofox stats into a small, secret-safe evidence record."""
    projected: Dict[str, Any] = {"url": _sanitized_evidence_url(data.get("url"))}
    tab_id = _safe_evidence_identifier(data.get("tabId"))
    if tab_id is not None:
        projected["tab_id"] = tab_id

    for source_key, result_key in (
        ("toolCalls", "tool_calls"),
        ("downloadCount", "download_count"),
        ("downloadsCount", "download_count"),
        ("consecutiveFailures", "consecutive_failures"),
        ("refsCount", "refs_count"),
    ):
        value = data.get(source_key)
        if type(value) is int and result_key not in projected:
            projected[result_key] = value
    visited_urls = data.get("visitedUrls")
    if isinstance(visited_urls, list):
        projected["visited_url_count"] = len(visited_urls)
    return projected


def _stats_stability_evidence(
    before: Dict[str, Any],
    after: Dict[str, Any],
    expected_tab_id: str,
) -> Dict[str, Any]:
    """Build tab/URL stability evidence without returning visited URLs."""
    checks = {
        "tab_id_matches_request_before": before.get("tabId") == expected_tab_id,
        "tab_id_matches_request_after": after.get("tabId") == expected_tab_id,
        "tab_id_unchanged": before.get("tabId") == after.get("tabId"),
        "url_unchanged": before.get("url") == after.get("url"),
    }
    result: Dict[str, Any] = {
        "stable": all(checks.values()),
        "checks": checks,
        "before": _capture_stats_projection(before),
        "after": _capture_stats_projection(after),
    }
    before_calls = before.get("toolCalls")
    after_calls = after.get("toolCalls")
    if type(before_calls) is int and type(after_calls) is int:
        result["tool_calls_delta"] = after_calls - before_calls
    return result


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def camofox_navigate(url: str, task_id: Optional[str] = None) -> str:
    """Navigate to a URL via Camofox."""
    try:
        browser_url, rewrite_info = _rewrite_loopback_url_for_camofox(url)
        session = _get_session(task_id)
        if not session["tab_id"]:
            # Create tab with the target URL directly
            session = _ensure_tab(task_id, browser_url)
            data = {"ok": True, "url": browser_url}
        else:
            # Navigate existing tab — recover from stale tab 404
            try:
                data = _post(
                    f"/tabs/{session['tab_id']}/navigate",
                    {"userId": session["user_id"], "url": browser_url},
                    timeout=60,
                )
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.warning(
                        "Camofox tab %s returned 404 — tab was garbage collected. "
                        "Creating a fresh tab.",
                        session["tab_id"],
                    )
                    session["tab_id"] = None
                    session = _ensure_tab(task_id, browser_url)
                    data = {"ok": True, "url": browser_url}
                else:
                    raise
        result = {
            "success": True,
            "url": data.get("url", browser_url),
            "title": data.get("title", ""),
        }
        if rewrite_info:
            result["requested_url"] = url
            result["url_rewrite"] = rewrite_info
            result["warning"] = (
                "Rewrote loopback URL for Docker-hosted Camofox: "
                f"{rewrite_info['from']} -> {rewrite_info['to']}"
            )
        vnc = get_vnc_url()
        if vnc:
            result["vnc_url"] = vnc
            result["vnc_hint"] = (
                "Browser is visible via VNC. "
                "Share this link with the user so they can watch the browser live."
            )

        # Auto-take a compact snapshot so the model can act immediately
        try:
            snap_data = _get(
                f"/tabs/{session['tab_id']}/snapshot",
                params={"userId": session["user_id"]},
            )
            snapshot_text = snap_data.get("snapshot", "")
            from tools.browser_tool import (
                SNAPSHOT_SUMMARIZE_THRESHOLD,
                _truncate_snapshot,
            )
            if len(snapshot_text) > SNAPSHOT_SUMMARIZE_THRESHOLD:
                snapshot_text = _truncate_snapshot(snapshot_text)
            result["snapshot"] = snapshot_text
            result["element_count"] = snap_data.get("refsCount", 0)
        except Exception:
            pass  # Navigation succeeded; snapshot is a bonus

        return json.dumps(result)
    except requests.HTTPError as e:
        return tool_error(f"Navigation failed: {e}", success=False)
    except requests.ConnectionError:
        return json.dumps({
            "success": False,
            "error": f"Cannot connect to Camofox at {get_camofox_url()}. "
                     "Is the server running? Start with: npm start (in camofox-browser dir) "
                     "or: docker run -p 9377:9377 -e CAMOFOX_PORT=9377 jo-inc/camofox-browser",
        })
    except Exception as e:
        return tool_error(str(e), success=False)


def _camofox_private_page_block(session: Dict[str, Any], task_id: Optional[str], action: str) -> Optional[str]:
    """Return a blocked payload when the current Camofox page is private/internal.

    Mirrors the eval-path guard added for ``_camofox_eval`` (browser_tool.py):
    Camofox snapshot / vision / image-extraction all read current page state, so
    on a non-local backend they can leak the content of an intranet/metadata
    page the terminal itself can't reach.  The gate matches ``browser_snapshot``
    / ``browser_vision`` — only active when the SSRF guard applies (non-local
    backend, not a local sidecar, ``allow_private_urls`` unset).  Fail-open on
    probe failure, matching the sibling guards.

    Imports are deferred to call time because ``browser_tool`` imports this
    module; importing it at module load would create a circular import.
    """
    from tools.browser_tool import (
        _camofox_current_page_private_url,
        _eval_ssrf_guard_active,
    )

    if not _eval_ssrf_guard_active(task_id or "default"):
        return None
    blocked_url = _camofox_current_page_private_url(session["tab_id"], session["user_id"])
    if not blocked_url:
        return None
    return json.dumps({
        "success": False,
        "error": (
            "Blocked: page URL targets a private or internal address "
            f"({blocked_url}). Refusing to {action} on this page in this "
            "browser mode."
        ),
    }, ensure_ascii=False)


def camofox_snapshot(full: bool = False, task_id: Optional[str] = None,
                     user_task: Optional[str] = None) -> str:
    """Get accessibility tree snapshot from Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "read a page snapshot")
        if blocked:
            return blocked

        data = _get(
            f"/tabs/{session['tab_id']}/snapshot",
            params={"userId": session["user_id"]},
        )

        snapshot = data.get("snapshot", "")
        refs_count = data.get("refsCount", 0)

        # Apply same summarization logic as the main browser tool
        from tools.browser_tool import (
            SNAPSHOT_SUMMARIZE_THRESHOLD,
            _extract_relevant_content,
            _truncate_snapshot,
        )

        if len(snapshot) > SNAPSHOT_SUMMARIZE_THRESHOLD:
            if user_task:
                snapshot = _extract_relevant_content(snapshot, user_task)
            else:
                snapshot = _truncate_snapshot(snapshot)

        return json.dumps({
            "success": True,
            "snapshot": snapshot,
            "element_count": refs_count,
        })
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_click(ref: str, task_id: Optional[str] = None) -> str:
    """Click an element by ref via Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "click")
        if blocked:
            return blocked

        # Strip @ prefix if present (our tool convention)
        clean_ref = ref.lstrip("@")

        data = _post(
            f"/tabs/{session['tab_id']}/click",
            {"userId": session["user_id"], "ref": clean_ref},
        )
        return json.dumps({
            "success": True,
            "clicked": clean_ref,
            "url": data.get("url", ""),
        })
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_type(ref: str, text: str, task_id: Optional[str] = None) -> str:
    """Type text into an element by ref via Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "type")
        if blocked:
            return blocked

        clean_ref = ref.lstrip("@")

        _post(
            f"/tabs/{session['tab_id']}/type",
            {"userId": session["user_id"], "ref": clean_ref, "text": text},
        )
        from agent.display import (
            redact_browser_typed_text_for_display,
            redact_tool_args_for_display,
        )

        display_text = (redact_tool_args_for_display("browser_type", {"text": text}) or {})["text"]

        response = {
            "success": True,
            # Match browser_tool.browser_type: run typed text through the
            # secret-pattern redactor so API keys / tokens don't leak into
            # tool progress or chat history.  The raw text is still typed into
            # the page; only the returned display value is redacted.
            "typed": display_text,
            "element": clean_ref,
        }
        response = redact_browser_typed_text_for_display(response, text)
        return json.dumps(response)
    except Exception as e:
        from agent.display import redact_browser_typed_text_for_display

        return tool_error(redact_browser_typed_text_for_display(str(e), text), success=False)


def camofox_scroll(direction: str, task_id: Optional[str] = None) -> str:
    """Scroll the page via Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        _post(
            f"/tabs/{session['tab_id']}/scroll",
            {"userId": session["user_id"], "direction": direction},
        )
        return json.dumps({"success": True, "scrolled": direction})
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_back(task_id: Optional[str] = None) -> str:
    """Navigate back via Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        data = _post(
            f"/tabs/{session['tab_id']}/back",
            {"userId": session["user_id"]},
        )
        return json.dumps({"success": True, "url": data.get("url", "")})
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_press(key: str, task_id: Optional[str] = None) -> str:
    """Press a keyboard key via Camofox."""
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "press")
        if blocked:
            return blocked

        _post(
            f"/tabs/{session['tab_id']}/press",
            {"userId": session["user_id"], "key": key},
        )
        return json.dumps({"success": True, "pressed": key})
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_close(task_id: Optional[str] = None) -> str:
    """Close the browser session via Camofox."""
    try:
        session = _drop_session(task_id)
        if not session:
            return json.dumps({"success": True, "closed": True})

        _delete(
            f"/sessions/{session['user_id']}",
        )
        return json.dumps({"success": True, "closed": True})
    except Exception as e:
        return json.dumps({"success": True, "closed": True, "warning": str(e)})


def camofox_get_images(task_id: Optional[str] = None) -> str:
    """Get images on the current page via Camofox.

    Extracts image information from the accessibility tree snapshot,
    since Camofox does not expose a dedicated /images endpoint.
    """
    try:
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "extract page images")
        if blocked:
            return blocked

        import re

        data = _get(
            f"/tabs/{session['tab_id']}/snapshot",
            params={"userId": session["user_id"]},
        )
        snapshot = data.get("snapshot", "")

        # Parse img elements from the accessibility tree.
        # Format: img "alt text" or img "alt text" [eN]
        # URLs appear on /url: lines following img entries
        images = []
        lines = snapshot.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(("- img ", "img ")):
                alt_match = re.search(r'img\s+"([^"]*)"', stripped)
                alt = alt_match.group(1) if alt_match else ""
                # Look for URL on the next line
                src = ""
                if i + 1 < len(lines):
                    url_match = re.search(r'/url:\s*(\S+)', lines[i + 1].strip())
                    if url_match:
                        src = url_match.group(1)
                if alt or src:
                    images.append({"src": src, "alt": alt})

        return json.dumps({
            "success": True,
            "images": images,
            "count": len(images),
        })
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_vision(
    question: str,
    annotate: bool = False,
    task_id: Optional[str] = None,
    viewport_width: Optional[int] = None,
    viewport_height: Optional[int] = None,
) -> str:
    """Take a screenshot and analyze it with vision AI via Camofox.

    Supplying both viewport dimensions enables an exact-capture protocol:
    resize acknowledgement, provider-reported CSS layout dimensions, tab/URL
    stability probes, and PNG IHDR verification must all succeed before the
    screenshot is persisted or sent to vision AI. Omitting both dimensions
    preserves the existing capture path.
    """
    try:
        requested_viewport = _validated_viewport(viewport_width, viewport_height)
        session = _get_session(task_id)
        if not session["tab_id"]:
            return tool_error("No browser session. Call browser_navigate first.", success=False)

        blocked = _camofox_private_page_block(session, task_id, "capture a screenshot")
        if blocked:
            return blocked

        stats_before: Optional[Dict[str, Any]] = None
        capture_id: Optional[str] = None
        source_url: Optional[str] = None
        if requested_viewport is not None:
            stats_path = f"/tabs/{session['tab_id']}/stats"
            stats_params = {"userId": session["user_id"]}
            try:
                raw_stats_before = _get(stats_path, params=stats_params)
            except Exception as exc:
                raise ValueError(
                    "Could not obtain Camofox tab stats before exact capture"
                ) from exc
            stats_before = _require_capture_stats(raw_stats_before, session["tab_id"])

            width, height = requested_viewport
            try:
                receipt = _post(
                    f"/tabs/{session['tab_id']}/viewport",
                    {
                        "userId": session["user_id"],
                        "width": width,
                        "height": height,
                    },
                )
            except Exception as exc:
                raise ValueError(
                    "Camofox exact viewport request failed; no screenshot was captured"
                ) from exc
            if (
                not isinstance(receipt, dict)
                or receipt.get("ok") is not True
                or type(receipt.get("width")) is not int
                or type(receipt.get("height")) is not int
                or receipt["width"] != width
                or receipt["height"] != height
            ):
                raise ValueError(
                    "Camofox did not acknowledge the exact requested viewport; "
                    "no screenshot was captured"
                )
            layout_viewport = receipt.get("layoutViewport")
            device_pixel_ratio = (
                layout_viewport.get("devicePixelRatio")
                if isinstance(layout_viewport, dict)
                else None
            )
            if (
                not isinstance(layout_viewport, dict)
                or type(layout_viewport.get("width")) is not int
                or type(layout_viewport.get("height")) is not int
                or layout_viewport["width"] != width
                or layout_viewport["height"] != height
                or isinstance(device_pixel_ratio, bool)
                or not isinstance(device_pixel_ratio, (int, float))
                or not math.isfinite(device_pixel_ratio)
                or device_pixel_ratio <= 0
            ):
                raise ValueError(
                    "Camofox did not prove the exact requested CSS layout "
                    "viewport; no screenshot was captured"
                )

            capture_id_value = receipt.get("captureId")
            if (
                not isinstance(capture_id_value, str)
                or len(capture_id_value) != 32
                or any(character not in "0123456789abcdef" for character in capture_id_value)
            ):
                raise ValueError(
                    "Camofox exact viewport receipt did not include a valid capture ID; "
                    "no screenshot was captured"
                )
            source_url_value = receipt.get("sourceUrl")
            if source_url_value != stats_before["url"]:
                raise ValueError(
                    "Camofox exact viewport receipt source URL did not match the "
                    "pre-capture tab URL; no screenshot was captured"
                )
            capture_id = capture_id_value
            source_url = source_url_value

        # Get screenshot as binary PNG
        screenshot_params = {"userId": session["user_id"]}
        if capture_id is not None:
            screenshot_params["exactCaptureId"] = capture_id
        try:
            resp = _get_raw(
                f"/tabs/{session['tab_id']}/screenshot",
                params=screenshot_params,
            )
        except Exception as exc:
            if requested_viewport is not None:
                raise ValueError("Camofox exact screenshot capture failed") from exc
            raise
        captured_at = None
        if requested_viewport is not None:
            captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        screenshot_bytes = resp.content
        capture_evidence: Optional[Dict[str, Any]] = None
        if requested_viewport is not None:
            assert stats_before is not None
            assert captured_at is not None
            assert capture_id is not None
            assert source_url is not None
            try:
                raw_stats_after = _get(stats_path, params=stats_params)
            except Exception as exc:
                raise ValueError(
                    "Could not obtain Camofox tab stats after exact capture"
                ) from exc
            stats_after = _require_capture_stats(raw_stats_after, session["tab_id"])
            stats_stability = _stats_stability_evidence(
                stats_before,
                stats_after,
                session["tab_id"],
            )
            if not stats_stability["stable"]:
                raise ValueError(
                    "Camofox tab identity or URL changed during exact viewport "
                    "capture; the screenshot was rejected"
                )

            screenshot_bytes = _png_bytes_from_screenshot_response(resp)
            actual_width, actual_height = _png_ihdr_dimensions(screenshot_bytes)
            requested_width, requested_height = requested_viewport
            if (actual_width, actual_height) != requested_viewport:
                raise ValueError(
                    "Camofox screenshot PNG dimensions did not match the exact "
                    "requested viewport"
                )

            identifiers = {}
            for name, value in (
                ("tab_id", session.get("tab_id")),
                ("user_id", session.get("user_id")),
                ("session_key", session.get("session_key")),
            ):
                safe_value = _safe_evidence_identifier(value)
                if safe_value is not None:
                    identifiers[name] = safe_value

            capture_evidence = {
                "requested_viewport": {
                    "width": requested_width,
                    "height": requested_height,
                },
                "actual_viewport": {
                    "width": layout_viewport["width"],
                    "height": layout_viewport["height"],
                    "device_pixel_ratio": device_pixel_ratio,
                    "source": "provider_layout_viewport",
                },
                "screenshot_dimensions": {
                    "width": actual_width,
                    "height": actual_height,
                    "source": "png_ihdr",
                },
                "screenshot_sha256": hashlib.sha256(screenshot_bytes).hexdigest(),
                "captured_at": captured_at,
                "url": _sanitized_evidence_url(stats_after["url"]),
                "capture_id": capture_id,
                "source_url": _sanitized_evidence_url(source_url),
                "identifiers": identifiers,
                "stats_stability": stats_stability,
            }

        # Save screenshot to cache
        from hermes_constants import get_hermes_home
        screenshots_dir = get_hermes_home() / "browser_screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = str(screenshots_dir / f"browser_screenshot_{uuid.uuid4().hex[:8]}.png")

        with open(screenshot_path, "wb") as f:
            f.write(screenshot_bytes)

        # Encode for vision LLM
        img_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        # Also get annotated snapshot if requested
        annotation_context = ""
        if annotate:
            try:
                snap_data = _get(
                    f"/tabs/{session['tab_id']}/snapshot",
                    params={"userId": session["user_id"]},
                )
                annotation_context = f"\n\nAccessibility tree (element refs for interaction):\n{snap_data.get('snapshot', '')[:3000]}"
            except Exception:
                pass

        # Redact secrets from annotation context before sending to vision LLM.
        # The screenshot image itself cannot be redacted, but at least the
        # text-based accessibility tree snippet won't leak secret values.
        from agent.redact import redact_sensitive_text
        annotation_context = redact_sensitive_text(annotation_context)

        # Send to vision LLM
        from agent.auxiliary_client import call_llm

        vision_prompt = (
            f"Analyze this browser screenshot and answer: {question}"
            f"{annotation_context}"
        )

        try:
            _cfg = load_config()
            _vision_cfg = cfg_get(_cfg, "auxiliary", "vision", default={})
            _vision_timeout = float(_vision_cfg.get("timeout", 120))
            _vision_temperature = float(_vision_cfg.get("temperature", 0.1))
        except Exception:
            _vision_timeout = 120.0
            _vision_temperature = 0.1

        response = call_llm(
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": vision_prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{img_b64}",
                        },
                    },
                ],
            }],
            task="vision",
            temperature=_vision_temperature,
            timeout=_vision_timeout,
        )
        analysis = (response.choices[0].message.content or "").strip() if response.choices else ""

        # Redact secrets the vision LLM may have read from the screenshot.
        from agent.redact import redact_sensitive_text
        analysis = redact_sensitive_text(analysis)

        result: Dict[str, Any] = {
            "success": True,
            "analysis": analysis,
            "screenshot_path": screenshot_path,
        }
        if capture_evidence is not None:
            capture_evidence["screenshot_path"] = screenshot_path
            result["capture_evidence"] = capture_evidence
        return json.dumps(result)
    except Exception as e:
        return tool_error(str(e), success=False)


def camofox_console(clear: bool = False, task_id: Optional[str] = None) -> str:
    """Get console output — limited support in Camofox.

    Camofox does not expose browser console logs via its REST API.
    Returns an empty result with a note.
    """
    return json.dumps({
        "success": True,
        "console_messages": [],
        "js_errors": [],
        "total_messages": 0,
        "total_errors": 0,
        "note": "Console log capture is not available with the Camofox backend. "
                "Use browser_snapshot or browser_vision to inspect page state.",
    })
