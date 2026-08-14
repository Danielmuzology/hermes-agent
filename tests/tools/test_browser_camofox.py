"""Tests for the Camofox browser backend."""

import hashlib
import json
import struct
import zlib
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest


from tools.browser_camofox import (
    camofox_back,
    camofox_click,
    camofox_close,
    camofox_console,
    camofox_get_images,
    camofox_navigate,
    camofox_press,
    camofox_scroll,
    camofox_snapshot,
    camofox_type,
    camofox_vision,
    check_camofox_available,
    is_camofox_mode,
    _rewrite_loopback_url_for_camofox,
)


# ---------------------------------------------------------------------------
# Configuration detection
# ---------------------------------------------------------------------------


class TestCamofoxMode:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("CAMOFOX_URL", raising=False)
        assert is_camofox_mode() is False


    def test_health_check_unreachable(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:19999")
        assert check_camofox_available() is False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _config_with_camofox(**camofox_config):
    return {"browser": {"camofox": camofox_config}}


def _mock_response(status=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data or {}
    resp.content = b"\x89PNG\r\n\x1a\nfake"
    resp.raise_for_status = MagicMock()
    return resp


def _png_chunk(chunk_type, data):
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", zlib.crc32(data, zlib.crc32(chunk_type)) & 0xFFFFFFFF)
    )


def _png_bytes(width, height):
    """Return a small, complete, valid RGBA PNG using only the stdlib."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    # One filter byte plus transparent RGBA pixels per scanline.
    image_data = zlib.compress((b"\x00" + b"\x00" * (width * 4)) * height)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", image_data)
        + _png_chunk(b"IEND", b"")
    )


def _vision_response(text="Camofox screenshot analysis"):
    response = MagicMock()
    choice = MagicMock()
    choice.message.content = text
    response.choices = [choice]
    return response


_EXACT_CAPTURE_ID = "0123456789abcdef0123456789abcdef"


def _exact_viewport_receipt(source_url="https://example.com"):
    return {
        "ok": True,
        "width": 390,
        "height": 844,
        "captureId": _EXACT_CAPTURE_ID,
        "sourceUrl": source_url,
        "layoutViewport": {
            "width": 390,
            "height": 844,
            "devicePixelRatio": 1,
        },
    }


# ---------------------------------------------------------------------------
# Navigate
# ---------------------------------------------------------------------------


class TestCamofoxLoopbackRewrite:
    @patch("tools.browser_camofox.load_config")
    def test_rewrites_localhost_when_enabled(self, mock_config, monkeypatch):
        monkeypatch.delenv("CAMOFOX_REWRITE_LOOPBACK_URLS", raising=False)
        monkeypatch.delenv("CAMOFOX_LOOPBACK_HOST_ALIAS", raising=False)
        mock_config.return_value = _config_with_camofox(rewrite_loopback_urls=True)

        rewritten, metadata = _rewrite_loopback_url_for_camofox("http://127.0.0.1:8766/#settings")

        assert rewritten == "http://host.docker.internal:8766/#settings"
        assert metadata == {
            "from": "127.0.0.1",
            "to": "host.docker.internal",
            "original_url": "http://127.0.0.1:8766/#settings",
            "rewritten_url": "http://host.docker.internal:8766/#settings",
        }


    @patch("tools.browser_camofox.load_config")
    def test_env_alias_takes_precedence(self, mock_config, monkeypatch):
        monkeypatch.setenv("CAMOFOX_REWRITE_LOOPBACK_URLS", "true")
        monkeypatch.setenv("CAMOFOX_LOOPBACK_HOST_ALIAS", "192.168.1.10")
        mock_config.return_value = _config_with_camofox(
            rewrite_loopback_urls=False,
            loopback_host_alias="host.docker.internal",
        )

        rewritten, metadata = _rewrite_loopback_url_for_camofox("http://[::1]:8080/path")

        assert rewritten == "http://192.168.1.10:8080/path"
        assert metadata is not None
        assert metadata["from"] == "::1"
        assert metadata["to"] == "192.168.1.10"


class TestCamofoxNavigate:
    @patch("tools.browser_camofox.requests.post")
    def test_creates_tab_on_first_navigate(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab1", "url": "https://example.com"})

        result = json.loads(camofox_navigate("https://example.com", task_id="t1"))
        assert result["success"] is True
        assert result["url"] == "https://example.com"


    def test_connection_error_returns_helpful_message(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:19999")
        result = json.loads(camofox_navigate("https://example.com", task_id="t_err"))
        assert result["success"] is False
        assert "Cannot connect" in result["error"]


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


class TestCamofoxSnapshot:
    def test_no_session_returns_error(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        result = json.loads(camofox_snapshot(task_id="no_such_task"))
        assert result["success"] is False
        assert "browser_navigate" in result["error"]

    @patch("tools.browser_camofox.requests.post")
    @patch("tools.browser_camofox.requests.get")
    def test_returns_snapshot(self, mock_get, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        # Create session
        mock_post.return_value = _mock_response(json_data={"tabId": "tab3", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t3")

        # Return snapshot
        mock_get.return_value = _mock_response(json_data={
            "snapshot": "- heading \"Test\" [e1]\n- button \"Submit\" [e2]",
            "refsCount": 2,
        })
        result = json.loads(camofox_snapshot(task_id="t3"))
        assert result["success"] is True
        assert "[e1]" in result["snapshot"]
        assert result["element_count"] == 2


# ---------------------------------------------------------------------------
# Click / Type / Scroll / Back / Press
# ---------------------------------------------------------------------------


class TestCamofoxInteractions:
    @patch("tools.browser_camofox.requests.post")
    def test_click(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab4", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t4")

        mock_post.return_value = _mock_response(json_data={"ok": True, "url": "https://x.com"})
        result = json.loads(camofox_click("@e5", task_id="t4"))
        assert result["success"] is True
        assert result["clicked"] == "e5"


    @patch("tools.browser_camofox.requests.post")
    def test_type_redacts_api_key(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        monkeypatch.setenv("HERMES_REDACT_SECRETS", "true")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab5b", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t5b")

        secret = "sk-proj-ABCD1234567890EFGH"
        mock_post.return_value = _mock_response(json_data={"ok": True})
        result = json.loads(camofox_type("@apikey", secret, task_id="t5b"))
        assert result["success"] is True
        assert secret not in json.dumps(result)
        assert result["typed"].startswith("sk-pro")

    @patch("tools.browser_camofox.requests.post")
    def test_type_failure_redacts_api_key(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        monkeypatch.setenv("HERMES_REDACT_SECRETS", "true")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab5c", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t5c")

        secret = "sk-proj-ABCD1234567890EFGH"
        mock_post.side_effect = RuntimeError(f"camofox failed while typing {secret}")
        raw_result = camofox_type("@apikey", secret, task_id="t5c")
        result = json.loads(raw_result)

        assert result["success"] is False
        assert secret not in raw_result
        assert "sk-pro" in raw_result


    @patch("tools.browser_camofox.requests.post")
    def test_press(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab8", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t8")

        mock_post.return_value = _mock_response(json_data={"ok": True})
        result = json.loads(camofox_press("Enter", task_id="t8"))
        assert result["success"] is True
        assert result["pressed"] == "Enter"


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


class TestCamofoxClose:
    @patch("tools.browser_camofox.requests.delete")
    @patch("tools.browser_camofox.requests.post")
    def test_close_session(self, mock_post, mock_delete, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab9", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t9")

        mock_delete.return_value = _mock_response(json_data={"ok": True})
        result = json.loads(camofox_close(task_id="t9"))
        assert result["success"] is True
        assert result["closed"] is True

    def test_close_nonexistent_session(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        result = json.loads(camofox_close(task_id="nonexistent"))
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Console (limited support)
# ---------------------------------------------------------------------------


class TestCamofoxConsole:
    def test_console_returns_empty_with_note(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        result = json.loads(camofox_console(task_id="t_console"))
        assert result["success"] is True
        assert result["total_messages"] == 0
        assert "not available" in result["note"]


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------


class TestCamofoxGetImages:
    @patch("tools.browser_camofox.requests.post")
    @patch("tools.browser_camofox.requests.get")
    def test_get_images(self, mock_get, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab10", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t10")

        # camofox_get_images parses images from the accessibility tree snapshot
        snapshot_text = (
            '- img "Logo"\n'
            '  /url: https://x.com/img.png\n'
        )
        mock_get.return_value = _mock_response(json_data={
            "snapshot": snapshot_text,
        })
        result = json.loads(camofox_get_images(task_id="t10"))
        assert result["success"] is True
        assert result["count"] == 1
        assert result["images"][0]["src"] == "https://x.com/img.png"


class TestCamofoxVisionConfig:
    @patch("tools.browser_camofox.requests.post")
    @patch("tools.browser_camofox._get")
    @patch("tools.browser_camofox._get_raw")
    def test_camofox_vision_uses_configured_temperature_and_timeout(self, mock_get_raw, mock_get, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab11", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t11")

        snapshot_text = '- button "Submit"\n'
        raw_resp = MagicMock()
        raw_resp.content = b"fakepng"
        mock_get_raw.return_value = raw_resp
        mock_get.return_value = {"snapshot": snapshot_text}

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Camofox screenshot analysis"
        mock_response.choices = [mock_choice]

        with (
            patch("tools.browser_camofox.open", create=True) as mock_open,
            patch("agent.auxiliary_client.call_llm", return_value=mock_response) as mock_llm,
            patch("tools.browser_camofox.load_config", return_value={"auxiliary": {"vision": {"temperature": 1, "timeout": 45}}}),
        ):
            mock_open.return_value.__enter__.return_value.read.return_value = b"fakepng"
            result = json.loads(camofox_vision("what is on the page?", annotate=True, task_id="t11"))

        assert result["success"] is True
        assert result["analysis"] == "Camofox screenshot analysis"
        assert mock_llm.call_args.kwargs["temperature"] == 1.0
        assert mock_llm.call_args.kwargs["timeout"] == 45.0

    @patch("tools.browser_camofox.requests.post")
    @patch("tools.browser_camofox._get")
    @patch("tools.browser_camofox._get_raw")
    def test_camofox_vision_defaults_temperature_when_config_omits_it(self, mock_get_raw, mock_get, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab12", "url": "https://x.com"})
        camofox_navigate("https://x.com", task_id="t12")

        snapshot_text = '- button "Submit"\n'
        raw_resp = MagicMock()
        raw_resp.content = b"fakepng"
        mock_get_raw.return_value = raw_resp
        mock_get.return_value = {"snapshot": snapshot_text}

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Default camofox screenshot analysis"
        mock_response.choices = [mock_choice]

        with (
            patch("tools.browser_camofox.open", create=True) as mock_open,
            patch("agent.auxiliary_client.call_llm", return_value=mock_response) as mock_llm,
            patch("tools.browser_camofox.load_config", return_value={"auxiliary": {"vision": {}}}),
        ):
            mock_open.return_value.__enter__.return_value.read.return_value = b"fakepng"
            result = json.loads(camofox_vision("what is on the page?", annotate=True, task_id="t12"))

        assert result["success"] is True
        assert result["analysis"] == "Default camofox screenshot analysis"
        assert mock_llm.call_args.kwargs["temperature"] == 0.1
        assert mock_llm.call_args.kwargs["timeout"] == 120.0


class TestCamofoxExactViewport:
    SESSION = {
        "tab_id": "tab_exact",
        "user_id": "uiux-assistant",
        "session_key": "audit-session",
    }

    @pytest.mark.parametrize(
        ("width", "height", "message"),
        [
            (390, None, "provided together"),
            (None, 844, "provided together"),
            (99, 844, "100 to 4000"),
            (4001, 844, "100 to 4000"),
            (True, 844, "integer"),
            (390.0, 844, "integer"),
        ],
    )
    def test_invalid_viewport_fails_before_browser_access(self, width, height, message):
        with patch("tools.browser_camofox._get_session") as mock_session:
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="invalid-viewport",
                    viewport_width=width,
                    viewport_height=height,
                )
            )

        assert result["success"] is False
        assert message in result["error"]
        mock_session.assert_not_called()

    @pytest.mark.parametrize(
        ("command_timeout", "expected_viewport_timeout"),
        [(30, 60), (75, 75)],
    )
    def test_exact_capture_returns_verified_evidence(
        self,
        command_timeout,
        expected_viewport_timeout,
    ):
        png = _png_bytes(390, 844)
        raw_response = MagicMock()
        raw_response.content = png
        stats_before = {
            "tabId": "tab_exact",
            "url": "https://example.com/dashboard?token=do-not-return&view=full",
            "toolCalls": 10,
            "visitedUrls": ["https://example.com/dashboard"],
            "downloadCount": 0,
            "consecutiveFailures": 0,
        }
        stats_after = {**stats_before, "toolCalls": 11}

        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", side_effect=[stats_before, stats_after]) as mock_get,
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(stats_before["url"]),
            ) as mock_post,
            patch(
                "tools.browser_camofox._get_command_timeout",
                return_value=command_timeout,
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response) as mock_get_raw,
            patch("tools.browser_camofox.load_config", return_value={}),
            patch("agent.auxiliary_client.call_llm", return_value=_vision_response()),
        ):
            result = json.loads(
                camofox_vision(
                    "inspect the responsive layout",
                    task_id="exact-viewport",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is True
        evidence = result["capture_evidence"]
        assert evidence["requested_viewport"] == {"width": 390, "height": 844}
        assert evidence["actual_viewport"] == {
            "width": 390,
            "height": 844,
            "device_pixel_ratio": 1,
            "source": "provider_layout_viewport",
        }
        assert evidence["screenshot_dimensions"] == {
            "width": 390,
            "height": 844,
            "source": "png_ihdr",
        }
        assert evidence["screenshot_sha256"] == hashlib.sha256(png).hexdigest()
        assert evidence["captured_at"].endswith("Z")
        assert evidence["url"] == "https://example.com/dashboard?token=***&view=full"
        assert evidence["capture_id"] == _EXACT_CAPTURE_ID
        assert evidence["source_url"] == "https://example.com/dashboard?token=***&view=full"
        assert evidence["identifiers"] == {
            "tab_id": "tab_exact",
            "user_id": "uiux-assistant",
            "session_key": "audit-session",
        }
        stability = evidence["stats_stability"]
        assert stability["stable"] is True
        assert stability["tool_calls_delta"] == 1
        assert stability["before"]["visited_url_count"] == 1
        assert "visitedUrls" not in json.dumps(stability)
        assert "do-not-return" not in json.dumps(evidence)
        assert Path(result["screenshot_path"]).read_bytes() == png
        assert evidence["screenshot_path"] == result["screenshot_path"]

        assert mock_get.call_count == 2
        mock_post.assert_called_once_with(
            "/tabs/tab_exact/viewport",
            {"userId": "uiux-assistant", "width": 390, "height": 844},
            timeout=expected_viewport_timeout,
        )
        mock_get_raw.assert_called_once_with(
            "/tabs/tab_exact/screenshot",
            params={
                "userId": "uiux-assistant",
                "exactCaptureId": _EXACT_CAPTURE_ID,
            },
        )

    def test_secret_shaped_session_identifiers_are_omitted(self):
        session = {
            "tab_id": "tab_exact",
            "user_id": "sk-proj-ABCD1234567890EFGH",
            "session_key": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        }
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        raw_response = MagicMock()
        raw_response.content = _png_bytes(390, 844)
        with (
            patch("tools.browser_camofox._get_session", return_value=session),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", side_effect=[stats, stats]),
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(),
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("tools.browser_camofox.load_config", return_value={}),
            patch("agent.auxiliary_client.call_llm", return_value=_vision_response()),
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="secret-identifiers",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is True
        assert result["capture_evidence"]["identifiers"] == {"tab_id": "tab_exact"}
        assert "ABCD1234567890EFGH" not in json.dumps(result)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in json.dumps(result)

    @pytest.mark.parametrize(
        "receipt",
        [
            {"ok": False, "width": 390, "height": 844},
            {"ok": True, "width": 391, "height": 844},
            {"ok": True, "width": 390, "height": 843},
            {"ok": True, "width": True, "height": 844},
        ],
    )
    def test_viewport_receipt_mismatch_fails_before_screenshot(self, receipt):
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", return_value=stats),
            patch("tools.browser_camofox._post", return_value=receipt),
            patch("tools.browser_camofox._get_raw") as mock_get_raw,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="receipt-mismatch",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "did not acknowledge" in result["error"]
        mock_get_raw.assert_not_called()

    @pytest.mark.parametrize(
        "layout_viewport",
        [
            None,
            {"width": 1536, "height": 735, "devicePixelRatio": 1},
            {"width": 390, "height": 735, "devicePixelRatio": 1},
            {"width": True, "height": 844, "devicePixelRatio": 1},
            {"width": 390, "height": 844},
            {"width": 390, "height": 844, "devicePixelRatio": 0},
            {"width": 390, "height": 844, "devicePixelRatio": True},
            {"width": 390, "height": 844, "devicePixelRatio": float("inf")},
        ],
    )
    def test_layout_viewport_must_be_present_and_exact(self, layout_viewport):
        receipt = _exact_viewport_receipt()
        if layout_viewport is not None:
            receipt["layoutViewport"] = layout_viewport
        else:
            receipt.pop("layoutViewport")
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", return_value=stats),
            patch("tools.browser_camofox._post", return_value=receipt),
            patch("tools.browser_camofox._get_raw") as mock_get_raw,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="layout-viewport-mismatch",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "CSS layout viewport" in result["error"]
        mock_get_raw.assert_not_called()

    @pytest.mark.parametrize(
        "capture_id",
        [
            None,
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
            123,
        ],
        ids=["missing", "empty", "short", "long", "uppercase", "non-hex", "non-string"],
    )
    def test_capture_id_must_be_exact_lowercase_hex(self, capture_id):
        receipt = _exact_viewport_receipt()
        if capture_id is None:
            receipt.pop("captureId")
        else:
            receipt["captureId"] = capture_id
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", return_value=stats),
            patch("tools.browser_camofox._post", return_value=receipt),
            patch("tools.browser_camofox._get_raw") as mock_get_raw,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="invalid-capture-id",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "valid capture ID" in result["error"]
        mock_get_raw.assert_not_called()

    def test_receipt_source_url_must_match_pre_capture_stats(self):
        stats = {"tabId": "tab_exact", "url": "https://example.com/dashboard"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", return_value=stats),
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt("https://example.com/other"),
            ),
            patch("tools.browser_camofox._get_raw") as mock_get_raw,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="source-url-mismatch",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "source URL did not match" in result["error"]
        mock_get_raw.assert_not_called()

    def test_png_dimension_mismatch_fails_closed(self):
        raw_response = MagicMock()
        raw_response.content = _png_bytes(391, 844)
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", return_value=stats) as mock_get,
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(),
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("agent.auxiliary_client.call_llm") as mock_llm,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="png-mismatch",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "PNG dimensions did not match" in result["error"]
        assert mock_get.call_count == 2
        mock_llm.assert_not_called()

    @pytest.mark.parametrize(
        "png",
        [
            b"\x89PNG\r\n\x1a\nnot-a-complete-chunk",
            _png_bytes(390, 844)[:-1],
            _png_bytes(390, 844)[:32] + b"\x01" + _png_bytes(390, 844)[33:],
            _png_bytes(390, 844)[:-12],
            _png_bytes(390, 844) + b"unexpected trailing bytes",
        ],
        ids=["fake-header", "truncated", "bad-crc", "missing-iend", "trailing-bytes"],
    )
    def test_malformed_png_evidence_fails_closed(self, png):
        """Exact captures reject deceptive PNG-looking screenshot payloads."""
        raw_response = MagicMock()
        raw_response.content = png
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", side_effect=[stats, stats]),
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(),
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("agent.auxiliary_client.call_llm") as mock_llm,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="malformed-png",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "PNG" in result["error"]
        mock_llm.assert_not_called()

    def test_non_png_response_fails_closed(self):
        raw_response = MagicMock()
        raw_response.content = b'{"screenshot":{"data":"stale-openapi-envelope"}}'
        stats = {"tabId": "tab_exact", "url": "https://example.com"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", side_effect=[stats, stats]),
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(),
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("agent.auxiliary_client.call_llm") as mock_llm,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="not-raw-png",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "not a raw PNG" in result["error"]
        mock_llm.assert_not_called()

    def test_tab_url_change_rejects_capture(self):
        raw_response = MagicMock()
        raw_response.content = _png_bytes(390, 844)
        stats_before = {"tabId": "tab_exact", "url": "https://example.com/a"}
        stats_after = {"tabId": "tab_exact", "url": "https://example.com/b"}
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get", side_effect=[stats_before, stats_after]),
            patch(
                "tools.browser_camofox._post",
                return_value=_exact_viewport_receipt(stats_before["url"]),
            ),
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("agent.auxiliary_client.call_llm") as mock_llm,
        ):
            result = json.loads(
                camofox_vision(
                    "inspect",
                    task_id="unstable-tab",
                    viewport_width=390,
                    viewport_height=844,
                )
            )

        assert result["success"] is False
        assert "identity or URL changed" in result["error"]
        mock_llm.assert_not_called()

    def test_omitted_viewport_preserves_existing_capture_path(self):
        raw_response = MagicMock()
        raw_response.content = b"legacy-screenshot-bytes"
        with (
            patch("tools.browser_camofox._get_session", return_value=self.SESSION),
            patch("tools.browser_camofox._camofox_private_page_block", return_value=None),
            patch("tools.browser_camofox._get") as mock_get,
            patch("tools.browser_camofox._post") as mock_post,
            patch("tools.browser_camofox._get_raw", return_value=raw_response),
            patch("tools.browser_camofox.load_config", return_value={}),
            patch("agent.auxiliary_client.call_llm", return_value=_vision_response()),
        ):
            result = json.loads(camofox_vision("inspect", task_id="legacy-capture"))

        assert result["success"] is True
        assert "capture_evidence" not in result
        assert Path(result["screenshot_path"]).read_bytes() == raw_response.content
        mock_get.assert_not_called()
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Routing integration — verify browser_tool routes to camofox
# ---------------------------------------------------------------------------


class TestBrowserToolRouting:
    """Verify that browser_tool.py delegates to camofox when CAMOFOX_URL is set."""

    @patch("tools.browser_camofox.requests.post")
    def test_browser_navigate_routes_to_camofox(self, mock_post, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        mock_post.return_value = _mock_response(json_data={"tabId": "tab_rt", "url": "https://example.com"})

        from tools.browser_tool import browser_navigate
        # Bypass SSRF check for test URL
        with patch("tools.browser_tool._is_safe_url", return_value=True):
            result = json.loads(browser_navigate("https://example.com", task_id="t_route"))
        assert result["success"] is True

    def test_check_requirements_passes_with_camofox(self, monkeypatch):
        monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9377")
        from tools.browser_tool import check_browser_requirements
        assert check_browser_requirements() is True

    def test_browser_vision_schema_exposes_bounded_paired_viewport(self):
        from tools.browser_tool import BROWSER_TOOL_SCHEMAS

        schema = cast(
            dict[str, Any],
            next(
                item for item in BROWSER_TOOL_SCHEMAS
                if item["name"] == "browser_vision"
            ),
        )
        properties = schema["parameters"]["properties"]
        for name in ("viewport_width", "viewport_height"):
            assert properties[name]["type"] == "integer"
            assert properties[name]["minimum"] == 100
            assert properties[name]["maximum"] == 4000
        assert "viewport_width" not in schema["parameters"]["required"]
        assert "viewport_height" not in schema["parameters"]["required"]

    def test_browser_vision_forwards_exact_viewport_to_camofox(self):
        from tools.browser_tool import browser_vision

        with (
            patch("tools.browser_tool._is_camofox_mode", return_value=True),
            patch(
                "tools.browser_camofox.camofox_vision",
                return_value='{"success": true}',
            ) as mock_vision,
        ):
            result = browser_vision(
                "inspect",
                annotate=True,
                task_id="route-exact",
                viewport_width=390,
                viewport_height=844,
            )

        assert isinstance(result, str)
        assert json.loads(result)["success"] is True
        mock_vision.assert_called_once_with(
            "inspect",
            True,
            "route-exact",
            viewport_width=390,
            viewport_height=844,
        )

    def test_non_camofox_backend_rejects_exact_viewport(self):
        from tools.browser_tool import browser_vision

        with (
            patch("tools.browser_tool._is_camofox_mode", return_value=False),
            patch("tools.browser_tool._run_browser_command") as mock_command,
        ):
            raw_result = browser_vision(
                "inspect",
                task_id="route-non-camofox",
                viewport_width=390,
                viewport_height=844,
            )

        assert isinstance(raw_result, str)
        result = json.loads(raw_result)
        assert result["success"] is False
        assert "only with the Camofox" in result["error"]
        mock_command.assert_not_called()
