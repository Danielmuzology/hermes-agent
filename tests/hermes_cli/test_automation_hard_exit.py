from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import pytest
from rich.console import Console

from hermes_cli._parser import build_top_level_parser
from hermes_cli import main
from tools import approval
from tools import file_tools
from agent import shell_hooks
from hermes_state import SessionDB


@pytest.fixture(autouse=True)
def _clean_automation_environment():
    names = (
        "HERMES_AUTOMATION_MODE",
        "HERMES_SESSION_SOURCE",
        "HERMES_YOLO_MODE",
        "HERMES_ACCEPT_HOOKS",
        "HERMES_EXEC_ASK",
        "HERMES_SAFE_MODE",
        "HERMES_IGNORE_USER_CONFIG",
    )
    previous = {name: os.environ.get(name) for name in names}
    for name in names:
        os.environ.pop(name, None)
    yield
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _args(**overrides):
    values = {
        "automation_hard_exit": True,
        "quiet": True,
        "query": "return a bounded result",
        "source": "tool",
        "yolo": False,
        "accept_hooks": False,
        "tui": False,
        "resume": None,
        "continue_last": None,
        "safe_mode": False,
        "ignore_user_config": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_parser_scopes_hard_exit_to_chat():
    parser, _, _ = build_top_level_parser()
    parsed = parser.parse_args(
        [
            "chat",
            "-Q",
            "-q",
            "hello",
            "--source",
            "tool",
            "--automation-hard-exit",
        ]
    )
    assert parsed.command == "chat"
    assert parsed.automation_hard_exit is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"quiet": False},
        {"query": ""},
        {"source": "cli"},
        {"yolo": True},
        {"accept_hooks": True},
        {"tui": True},
        {"resume": "prior-session"},
        {"continue_last": True},
        {"safe_mode": True},
        {"ignore_user_config": True},
    ],
)
def test_boundary_rejects_unsafe_or_interactive_shapes(monkeypatch, overrides):
    for key in (
        "HERMES_YOLO_MODE",
        "HERMES_ACCEPT_HOOKS",
        "HERMES_EXEC_ASK",
        "HERMES_AUTOMATION_MODE",
        "HERMES_SESSION_SOURCE",
    ):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(SystemExit) as exc:
        main._prepare_automation_hard_exit_boundary(_args(**overrides))
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "name",
    [
        "HERMES_YOLO_MODE",
        "HERMES_ACCEPT_HOOKS",
        "HERMES_EXEC_ASK",
        "HERMES_SAFE_MODE",
        "HERMES_IGNORE_USER_CONFIG",
    ],
)
def test_boundary_rejects_inherited_authority_overrides(monkeypatch, name):
    monkeypatch.setenv(name, "1")
    with pytest.raises(SystemExit) as exc:
        main._prepare_automation_hard_exit_boundary(_args())
    assert exc.value.code == 2


def test_boundary_binds_fail_closed_mode_and_source_before_startup(monkeypatch):
    for key in (
        "HERMES_YOLO_MODE",
        "HERMES_ACCEPT_HOOKS",
        "HERMES_EXEC_ASK",
        "HERMES_AUTOMATION_MODE",
        "HERMES_SESSION_SOURCE",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(approval, "_get_approval_mode", lambda: "smart")
    assert main._prepare_automation_hard_exit_boundary(_args()) is True
    assert os.environ["HERMES_AUTOMATION_MODE"] == "1"
    assert os.environ["HERMES_SESSION_SOURCE"] == "tool"
    assert "HERMES_YOLO_MODE" not in os.environ
    assert "HERMES_ACCEPT_HOOKS" not in os.environ
    assert "HERMES_EXEC_ASK" not in os.environ


def test_bound_source_is_persisted_on_the_exact_session_row(monkeypatch, tmp_path):
    """The early boundary must survive the same DB write used by HermesCLI."""
    monkeypatch.setattr(approval, "_get_approval_mode", lambda: "smart")
    assert main._prepare_automation_hard_exit_boundary(_args()) is True

    session_id = "automation-source-contract"
    database = SessionDB(db_path=tmp_path / "state.db")
    try:
        database.create_session(
            session_id=session_id,
            source=os.environ.get("HERMES_SESSION_SOURCE", "cli"),
        )
        persisted = database.get_session(session_id)
        assert persisted is not None
        assert persisted["id"] == session_id
        assert persisted["source"] == "tool"
    finally:
        database.close()


@pytest.mark.parametrize("mode", ["manual", "off"])
def test_boundary_requires_smart_profile_policy(monkeypatch, mode):
    monkeypatch.setattr(approval, "_get_approval_mode", lambda: mode)
    with pytest.raises(SystemExit) as exc:
        main._prepare_automation_hard_exit_boundary(_args())
    assert exc.value.code == 2


def _prepare_approval(monkeypatch, verdict: str):
    monkeypatch.setenv("HERMES_AUTOMATION_MODE", "1")
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval, "_get_approval_config", lambda: {"mode": "smart"})
    monkeypatch.setattr(approval, "_smart_approve", lambda *_: verdict)
    monkeypatch.setattr(
        "tools.tirith_security.check_command_security",
        lambda _: {"action": "allow", "findings": [], "summary": ""},
    )
    monkeypatch.setenv("HERMES_SESSION_KEY", "automation-hard-exit-test")
    approval.clear_session("automation-hard-exit-test")


def test_smart_approve_runs_but_deny_is_bounded_pending(monkeypatch):
    _prepare_approval(monkeypatch, "approve")
    approved = approval.check_all_command_guards("python -c 'print(1)'", "local")
    assert approved["approved"] is True
    assert approved["smart_approved"] is True

    _prepare_approval(monkeypatch, "deny")
    denied = approval.check_all_command_guards("python -c 'print(1)'", "local")
    assert denied["approved"] is False
    assert denied["status"] == "pending_approval"
    assert denied["approval_pending"] is True


def test_configured_mode_cannot_be_downgraded_by_yolo_or_mode_off(monkeypatch):
    _prepare_approval(monkeypatch, "deny")
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", True)
    monkeypatch.setattr(approval, "_get_approval_config", lambda: {"mode": "off"})
    assert approval.is_approval_bypass_active() is False
    denied = approval.check_all_command_guards("python -c 'print(1)'", "local")
    assert denied["approved"] is False
    assert denied["status"] == "pending_approval"


def test_plugin_gate_and_hook_config_cannot_autoaccept(monkeypatch):
    monkeypatch.setenv("HERMES_AUTOMATION_MODE", "1")
    monkeypatch.setenv("HERMES_SESSION_KEY", "automation-plugin-test")
    approval.clear_session("automation-plugin-test")
    gated = approval.request_tool_approval(
        "write_file", "review required", rule_key="automation-test"
    )
    assert gated["approved"] is False
    assert gated["status"] == "approval_required"
    assert shell_hooks._resolve_effective_accept(
        {"hooks_auto_accept": True}, True
    ) is False


def test_execute_code_smart_deny_is_bounded_pending(monkeypatch):
    _prepare_approval(monkeypatch, "deny")
    denied = approval.check_execute_code_guard("print('unsafe')", "local")
    assert denied["approved"] is False
    assert denied["status"] == "pending_approval"
    assert denied["approval_pending"] is True


def test_protected_file_and_mcp_elicitation_fail_closed_without_prompt(monkeypatch):
    monkeypatch.setenv("HERMES_AUTOMATION_MODE", "1")
    monkeypatch.setattr(
        approval,
        "prompt_dangerous_approval",
        lambda *_args, **_kwargs: pytest.fail("automation must never prompt"),
    )
    blocked = file_tools._request_protected_instruction_approval(
        ["SOUL.md (protected agent instructions)"], "automation-test"
    )
    assert blocked is not None
    assert "BLOCKED" in blocked
    assert approval.request_elicitation_consent("approve", "MCP request") == "decline"


def test_hard_exit_happens_after_cli_main_unwinds(monkeypatch):
    events = []

    def fake_cli_main(**_kwargs):
        try:
            events.append("query")
            raise SystemExit(0)
        finally:
            events.extend(["finalize", "cleanup", "lease-release"])

    monkeypatch.setattr(main, "_cleanup_oneshot_runtime", lambda: events.append("global-cleanup"))
    monkeypatch.setattr(main, "_automation_hard_exit", lambda code: events.append(("exit", code)))
    main._run_cli_with_automation_exit(fake_cli_main, {}, enabled=True)
    assert events == [
        "query",
        "finalize",
        "cleanup",
        "lease-release",
        "global-cleanup",
        ("exit", 0),
    ]


@pytest.mark.parametrize(
    ("outcome", "expected_code"),
    [
        ("return", 1),
        ("system-exit", 0),
        ("value-error", 1),
        ("runtime-error", 1),
        ("keyboard-interrupt", 130),
    ],
)
def test_enabled_wrapper_hard_exits_in_real_subprocess(outcome, expected_code):
    script = textwrap.dedent(
        f"""
        import sys
        from hermes_cli import main

        def fake_cli_main(**_kwargs):
            outcome = {outcome!r}
            if outcome == "return":
                return None
            if outcome == "system-exit":
                print("FINAL_ONLY", flush=True)
                raise SystemExit(0)
            if outcome == "value-error":
                raise ValueError("secret-value-must-not-escape")
            if outcome == "runtime-error":
                raise RuntimeError("secret-value-must-not-escape")
            raise KeyboardInterrupt()

        main._cleanup_oneshot_runtime = lambda: print(
            "CLEANUP_COMPLETE", file=sys.stderr, flush=True
        )
        main._run_cli_with_automation_exit(fake_cli_main, {{}}, enabled=True)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.fspath(main.PROJECT_ROOT),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == expected_code
    assert completed.stdout == ("FINAL_ONLY\n" if outcome == "system-exit" else "")
    assert "CLEANUP_COMPLETE" in completed.stderr
    assert "secret-value-must-not-escape" not in completed.stdout
    assert "secret-value-must-not-escape" not in completed.stderr


def test_disabled_wrapper_preserves_legacy_return_and_value_error(monkeypatch, capsys):
    assert main._run_cli_with_automation_exit(lambda **_: None, {}, enabled=False) is None

    with pytest.raises(SystemExit) as exc:
        main._run_cli_with_automation_exit(
            lambda **_: (_ for _ in ()).throw(ValueError("legacy detail")),
            {},
            enabled=False,
        )
    assert exc.value.code == 1
    assert capsys.readouterr().out == "Error: legacy detail\n"


def test_automation_diagnostics_use_stderr_and_stdout_stays_result_only(
    monkeypatch, capsys
):
    import cli

    monkeypatch.setenv("HERMES_AUTOMATION_MODE", "1")
    cli._cprint("scanner diagnostic")
    console = Console(stderr=True, force_terminal=False)
    console.print("toolset diagnostic")
    print("FINAL_ONLY")
    captured = capsys.readouterr()
    assert captured.out == "FINAL_ONLY\n"
    assert "scanner diagnostic" in captured.err
    assert "toolset diagnostic" in captured.err
