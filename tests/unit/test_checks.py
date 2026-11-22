"""Original-shell outcomes and exact Native Linux wildcard semantics."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.checks import native_pattern, project_check, require_shell_allow
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.domain.checks import (
    ApprovedCheck,
    CheckCatalog,
    check_message_id,
)
from tests.support import REF

CHECK = ApprovedCheck(id="unit", title="Approved unit suite", command="python -m pytest tests")


def observed(status="exited", exit_code=0):
    message = {
        "id": check_message_id("a"),
        "type": "shell",
        "command": CHECK.command,
        "shellID": "sh_original",
        "status": status,
        "time": {"created": 101, "completed": 201},
        "output": {"output": "2 passed", "cursor": 8, "size": 8, "truncated": False},
    }
    shell = {
        "id": "sh_original",
        "command": CHECK.command,
        "cwd": REF.canonical_directory,
        "metadata": {"sessionID": REF.upstream_session_id, "background": True},
        "status": status,
        "time": {"started": 100, "completed": 200},
    }
    if status == "running":
        message["time"].pop("completed")
        shell["time"].pop("completed")
    elif exit_code is not None:
        message["exit"] = exit_code
        shell["exit"] = exit_code
    return message, shell


@pytest.mark.parametrize(
    ("value", "pattern", "expected"),
    [
        ("shell", "*", True),
        ("shell", "sh?ll", True),
        ("SHELL", "shell", False),
        ("a[bc]", "a[bc]", True),
        ("ab", "a[bc]", False),
        ("a]", "a]", True),
        ("git", "git *", True),
        ("git status", "git *", True),
        ("gitx", "git *", False),
        ("a", "a * *", False),
        ("a ", "a * *", True),
        ("a b", "a * *", True),
        ("a\\b", "a/b", True),
        ("a\nb", "a?b", True),
        ("x.y", "x.y", True),
        ("xay", "x.y", False),
        ("中文", "中*", True),
        ("x$(echo y)", "x$(echo y)", True),
    ],
)
def test_native_linux_wildcards_keep_brackets_literal_and_one_optional_suffix(
    value, pattern, expected
):
    assert native_pattern(value, pattern) is expected


@pytest.mark.parametrize("effect", ["ask", "deny"])
def test_configured_native_permission_must_allow_shell_even_if_check_is_approved(effect):
    facts = {
        "agent": {"permissions": [{"action": "*", "resource": "*", "effect": effect}]},
        "session_permissions": [],
    }
    with pytest.raises(ContractError):
        require_shell_allow(facts, CHECK.command)
    facts["session_permissions"] = [
        {"action": "shell", "resource": CHECK.command, "effect": "allow"}
    ]
    require_shell_allow(facts, CHECK.command)
    facts["session_permissions"].append({"action": "shell", "resource": "*", "effect": "deny"})
    with pytest.raises(ContractError):
        require_shell_allow(facts, CHECK.command)


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("running", None, "running"),
        ("exited", 0, "passed"),
        ("exited", 1, "failed"),
        ("exited", -9, "failed"),
        ("exited", None, "unknown"),
        ("timeout", None, "timeout"),
        ("killed", None, "killed"),
    ],
)
def test_only_original_exited_exact_integer_zero_is_passed(status, exit_code, expected):
    message, shell = observed(status, exit_code)
    value = project_check(REF, "a", CHECK, message, shell, qualification_sha256="d" * 64)
    assert value.outcome == expected and value.message_id == check_message_id("a")


@pytest.mark.parametrize("bad", [True, False, 0.0, 1.1, "0", "NaN", "Infinity"])
def test_non_integer_or_non_finite_shell_exit_never_passes(bad):
    message, shell = observed()
    message["exit"] = shell["exit"] = bad
    with pytest.raises((ContractError, ValidationError)):
        project_check(REF, "a", CHECK, message, shell, qualification_sha256="d" * 64)


@pytest.mark.parametrize(
    ("where", "field", "value"),
    [
        ("message", "id", "msg_other"),
        ("message", "type", "synthetic"),
        ("message", "command", "echo passed"),
        ("message", "shellID", "sh_other"),
        ("message", "status", "running"),
        ("shell", "id", "sh_other"),
        ("shell", "command", "echo passed"),
        ("shell", "cwd", "/foreign"),
        ("shell", "signal", "SIGTERM"),
        ("shell", "metadata", {"sessionID": "ses_other", "background": True}),
        ("shell", "metadata", {"sessionID": REF.upstream_session_id, "background": False}),
    ],
)
def test_foreign_or_unassociated_shell_never_becomes_this_check_result(where, field, value):
    message, shell = observed()
    (message if where == "message" else shell)[field] = value
    with pytest.raises((ContractError, ValidationError)):
        project_check(REF, "a", CHECK, message, shell, qualification_sha256="d" * 64)


@pytest.mark.parametrize(
    "change", [{"completed": 99}, {"started": 100.0}, {"started": True}, {"completed": None}]
)
def test_bad_shell_times_fail_closed(change):
    message, shell = observed()
    shell["time"].update(change)
    with pytest.raises((ContractError, ValidationError)):
        project_check(REF, "a", CHECK, message, shell, qualification_sha256="d" * 64)


def test_approved_check_definitions_are_exact_bounded_and_unique():
    catalog = CheckCatalog(reference=REF, contract_sha256="a" * 64, checks=(CHECK,))
    assert catalog.checks[0].command == "python -m pytest tests"
    with pytest.raises(ValidationError):
        CheckCatalog(reference=REF, contract_sha256="a" * 64, checks=(CHECK, CHECK))
    for updates in (
        {"id": "../run"},
        {"command": " "},
        {"command": "x\x00y"},
        {"title": "x" * 121},
        {"command": "x" * 8193},
    ):
        with pytest.raises(ValidationError):
            ApprovedCheck.model_validate(CHECK.model_dump() | updates)


# Generated once from the retained upstream JS function with its actual 's'
# RegExp flags. Each independent case remains visible in the full inventory.

_ORACLE = json.loads(
    Path("tests/fixtures/installed/opencode-v2.0.32/native-check-wildcard-oracle.json").read_text()
)


@pytest.mark.parametrize(
    ("value", "pattern", "expected"),
    _ORACLE["cases"],
    ids=[f"native-{i:03}" for i in range(len(_ORACLE["cases"]))],
)
def test_native_wildcard_matches_retained_javascript_oracle(value, pattern, expected):
    assert native_pattern(value, pattern) is expected
