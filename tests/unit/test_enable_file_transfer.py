"""Pure planning logic of ops/server/enable_file_transfer.py; no host, Native or Zulip.

Certificates are synthetic and only checked against the product validators' shape.
They are not installed qualification, Human evidence or mobile acceptance.
"""

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode import native_workspace
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_attachments import WORKSPACE_SEMANTICS
from jt_oz_bridge.services import upload_associations
from jt_oz_bridge.services.file_enrollment import component_sha
from jt_oz_bridge.services.workspace_enrollment import (
    SOURCE_NEGATIVES,
    source_qualification,
    workspace_qualification,
)
from jt_oz_bridge.storage import workspace_files

TOOL = Path(__file__).parents[2] / "ops" / "server" / "enable_file_transfer.py"
SPEC = importlib.util.spec_from_file_location("enable_file_transfer_tool", TOOL)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

REAL = "ses_real"
PIN = {"path": "/etc/x/workspace.json", "sha256": "a" * 64}


def reference(session, directory="/opt/project", project="real"):
    return {
        "backend_id": "b",
        "backend_identity": "i",
        "canonical_directory": directory,
        "project_id": project,
        "upstream_session_id": session,
    }


def manifest():
    return {
        "format": "qualified-consumer-runtime-v5",
        "operator_review": "reviewed",
        "directory_scope": {"path": "/etc/d", "sha256": "d" * 64},
        "directory_socket": "/run/s",
        "grants": [{"project_id": "real", "roles": ["administrator"], "user_id": 8}],
        "realm": {"realm_id": "2", "url": "https://chat.invalid", "bot_user_id": 11},
        "backends": [
            {
                "reference": reference("ses_one", "/home/user/w", "integration"),
                "file_read": {"path": "/etc/1", "sha256": "1" * 64},
                "workspace": None,
                "generated_outputs": None,
            },
            {
                "reference": reference("ses_two", "/home/user/w", "integration"),
                "file_read": {"path": "/etc/2", "sha256": "2" * 64},
                "workspace": None,
                "generated_outputs": None,
            },
            {
                "reference": reference(REAL),
                "file_read": {"path": "/etc/3", "sha256": "3" * 64},
                "workspace": None,
                "generated_outputs": None,
            },
        ],
    }


def merged(**changes):
    values = dict(
        session_id=REAL,
        workspace=PIN,
        source_uploads={"path": "/etc/u", "sha256": "b" * 64},
        source_evidence={"path": "/etc/e", "sha256": "c" * 64},
    )
    return tool.merge_file_manifest(manifest(), **{**values, **changes})


def test_module_imports_no_product_code_at_load_time():
    imported = [
        node
        for node in ast.parse(TOOL.read_text()).body
        if isinstance(node, ast.Import | ast.ImportFrom)
    ]
    names = [
        alias.name if isinstance(node, ast.Import) else node.module
        for node in imported
        for alias in node.names
    ]
    assert not any(name.startswith("jt_oz_bridge") for name in names)


@pytest.mark.parametrize(
    "name",
    [
        ".jt-oz-incoming-",
        "incoming",
        ".jt-oz-preview-x",
        ".jt-oz-incoming-../x",
        ".jt-oz-incoming-a b",
    ],
)
def test_namespace_name_rejected(name):
    with pytest.raises(RuntimeError):
        tool.namespace_for("/opt/project", name)


def test_namespace_is_direct_child_of_project():
    path = tool.namespace_for("/opt/project/", ".jt-oz-incoming-service")
    assert path == "/opt/project/.jt-oz-incoming-service"
    with pytest.raises(RuntimeError):
        tool.namespace_for("relative", ".jt-oz-incoming-service")
    with pytest.raises(RuntimeError):
        tool.namespace_for("/opt/../etc", ".jt-oz-incoming-service")


def test_dropin_grants_only_exact_namespace_and_fails_closed():
    text = tool.main_dropin("/opt/project/.jt-oz-incoming-service")
    assert text == "[Service]\nReadWritePaths=/opt/project/.jt-oz-incoming-service\n"
    assert "ProtectSystem" not in text and "ProtectHome" not in text


@pytest.mark.parametrize(
    "path",
    [
        "/home/user/w/.jt-oz-incoming-service",
        "/root/w/.jt-oz-incoming-service",
        "/opt/a b/x",
        "/opt/a\nb",
    ],
)
def test_dropin_refuses_hidden_home_and_unit_injection(path):
    with pytest.raises(RuntimeError):
        tool.main_dropin(path)


def test_manifest_scopes_only_the_real_root_and_keeps_others_identical():
    before = manifest()
    after = merged()
    assert after["backends"][:2] == before["backends"][:2]
    assert after["backends"][2]["workspace"] == PIN
    assert after["backends"][2]["generated_outputs"] is None
    assert after["backends"][2]["file_read"] == before["backends"][2]["file_read"]
    assert after["workspace_roots"] == [reference(REAL)]
    assert after["generated_roots"] == []
    assert after["format"] == "qualified-consumer-runtime-v7"
    assert after["grants"] == before["grants"]


def test_manifest_generated_is_only_added_with_a_supplied_packet():
    packet = {"path": "/etc/g", "sha256": "e" * 64}
    after = merged(generated=packet)
    assert after["backends"][2]["generated_outputs"] == packet
    assert after["generated_roots"] == [reference(REAL)]
    assert after["backends"][0]["generated_outputs"] is None


def test_manifest_input_not_mutated_and_unknown_root_refused():
    before = manifest()
    snapshot = copy.deepcopy(before)
    merged()
    assert before == snapshot
    with pytest.raises(RuntimeError):
        merged(session_id="ses_foreign")


def test_manifest_refuses_a_second_merge():
    once = merged()
    with pytest.raises(RuntimeError):
        tool.merge_file_manifest(
            once,
            session_id=REAL,
            workspace=PIN,
            source_uploads=PIN,
            source_evidence=PIN,
        )


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m["backends"][0].update(workspace=PIN),
        lambda m: m["backends"][1].update(generated_outputs=PIN),
        lambda m: m["grants"].append({"project_id": "real", "roles": ["viewer"], "user_id": 9}),
        lambda m: m.update(directory_socket="/run/other"),
    ],
)
def test_other_root_or_grant_change_is_detected(change):
    before, after = manifest(), manifest()
    change(after)
    with pytest.raises(RuntimeError):
        tool.assert_other_roots_unchanged(before, after, REAL)


CONFIG = """["runtime"]
"enabled" = true
"file_returns_enabled" = true
"generated_returns_enabled" = false
"workspace_inputs_enabled" = false
"workspace_menus_enabled" = true
"enrollment_file" = "/etc/old/runtime.json"
"""


def test_config_changes_only_pin_and_requested_flags():
    out = tool.merge_file_config(
        CONFIG, enrollment_file="/etc/new/runtime.json", inputs=True, generated=False
    )
    changed = sorted(set(out.splitlines()) ^ set(CONFIG.splitlines()))
    assert changed == [
        '"enrollment_file" = "/etc/new/runtime.json"',
        '"enrollment_file" = "/etc/old/runtime.json"',
        '"workspace_inputs_enabled" = false',
        '"workspace_inputs_enabled" = true',
    ]


def test_config_refuses_flag_already_on_and_missing_line():
    with pytest.raises(RuntimeError):
        tool.merge_file_config(
            CONFIG.replace(
                '"workspace_inputs_enabled" = false', '"workspace_inputs_enabled" = true'
            ),
            enrollment_file="/x",
            inputs=True,
            generated=False,
        )
    with pytest.raises(RuntimeError):
        tool.merge_file_config(
            CONFIG.replace('"enrollment_file" = "/etc/old/runtime.json"\n', ""),
            enrollment_file="/x",
            inputs=True,
            generated=False,
        )


def ref_model():
    return SessionRef.model_validate(reference(REAL))


OWNER = SimpleNamespace(executable_sha256="e" * 64, native_uid=1000, client_uid=1001)


def observation():
    return dict(
        files=10,
        bytes_each=20 * 1024**2,
        aggregate_original_object_current=True,
        namespace_identity_preserved=True,
        controlled_files_removed=True,
        namespace_retained=True,
        native_get_count=321,
    )


def certificate(**changes):
    values = dict(
        reference=reference(REAL),
        namespace=dict(
            path="/opt/project/.jt-oz-incoming-service",
            device=1,
            inode=2,
            owner_uid=1001,
            reader_gid=1000,
        ),
        contract_sha256="c" * 64,
        native_policy_sha256="d" * 64,
        executable_sha256=OWNER.executable_sha256,
        native_uid=OWNER.native_uid,
        workspace_component_sha256=component_sha(native_workspace),
        storage_component_sha256=component_sha(workspace_files),
        workspace_semantics_sha256=WORKSPACE_SEMANTICS,
        observation=observation(),
        evidence_sha256="f" * 64,
        tool_sha256="0" * 64,
    )
    return tool.workspace_certificate(**{**values, **changes})


def qualify_workspace(doc):
    return workspace_qualification(
        json.dumps(doc).encode(),
        reference=ref_model(),
        contract_sha256="c" * 64,
        policy_sha256="d" * 64,
        owner=OWNER,
    )


def test_workspace_certificate_passes_the_product_validator():
    pin = qualify_workspace(certificate())
    assert str(pin.path) == "/opt/project/.jt-oz-incoming-service"
    assert (pin.owner_uid, pin.reader_gid) == (1001, 1000)


@pytest.mark.parametrize(
    "changes",
    [
        {"native_policy_sha256": "9" * 64},
        {"contract_sha256": "9" * 64},
        {"native_uid": 1001},
        {"reference": reference("ses_one")},
        {"workspace_component_sha256": "9" * 64},
        {
            "namespace": dict(
                path="/opt/other/.jt-oz-incoming-service",
                device=1,
                inode=2,
                owner_uid=1001,
                reader_gid=1000,
            )
        },
    ],
)
def test_stale_workspace_certificate_is_rejected_by_the_product_validator(changes):
    with pytest.raises(ValueError):
        qualify_workspace(certificate(**changes))


def test_workspace_certificate_requires_complete_cleaned_probe():
    with pytest.raises(RuntimeError):
        certificate(observation={**observation(), "controlled_files_removed": False})
    with pytest.raises(RuntimeError):
        certificate(observation={**observation(), "files": 9})


ASSOCIATION = {
    "format": "jt-oz-upload-association-v1",
    "realm_id": "2",
    "realm_url": "https://chat.invalid",
    "channel_ids": [4],
    "host": "zulip.invalid",
    "user": "claim-reader",
    "key_file": "/etc/synthetic/key",
    "key_sha256": "a" * 64,
    "known_hosts_file": "/etc/synthetic/known",
    "known_hosts_sha256": "b" * 64,
    "helper_sha256": "c" * 64,
    "remote_policy_sha256": "d" * 64,
    "installed_evidence_sha256": "e" * 64,
}


def positive(**changes):
    return {
        "author_id": 8,
        "channel_id": 4,
        "message_id": 123,
        "upload_count": 1,
        "mode": "human-source",
        "is_bot": False,
        "transaction_read_only": True,
        "original_association_current": True,
        "source_sha256": "a" * 64,
        **changes,
    }


def source_doc(**changes):
    raw = json.dumps(ASSOCIATION).encode()
    values = dict(
        realm_id="2",
        realm_url="https://chat.invalid",
        bot_user_id=11,
        config_raw=raw,
        config=ASSOCIATION,
        transport_component_sha256=component_sha(upload_associations),
        positive=positive(),
        negatives={key: True for key in SOURCE_NEGATIVES},
        tool_sha256="0" * 64,
    )
    return tool.source_certificate(**{**values, **changes}), raw


def qualify_source(doc, raw):
    return source_qualification(
        json.dumps(doc).encode(),
        raw,
        config_sha256=hashlib.sha256(raw).hexdigest(),
        realm_id="2",
        realm_url="https://chat.invalid",
        bot_user_id=11,
        allowed_channels=frozenset({4}),
        allowed_users=frozenset({8, 9}),
    )


def test_source_certificate_passes_the_product_validator():
    doc, raw = source_doc()
    assert qualify_source(doc, raw).host == "zulip.invalid"
    assert doc["config_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        {"positive": positive(author_id=11)},
        {"positive": positive(is_bot=True)},
        {"negatives": {key: key != "wrong-author" for key in SOURCE_NEGATIVES}},
    ],
)
def test_source_certificate_cannot_be_built_from_a_bot_or_undenied_negative(changes):
    with pytest.raises(RuntimeError):
        source_doc(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"positive": positive(author_id=77)},
        {"positive": positive(channel_id=99)},
        {"positive": positive(upload_count=0)},
        {"negatives": {"bot-source": True}},
        {"transport_component_sha256": "9" * 64},
    ],
)
def test_source_certificate_shape_rejected_by_the_product_validator(changes):
    doc, raw = source_doc(**changes)
    with pytest.raises(ValueError):
        qualify_source(doc, raw)


SOURCE = {
    "realm_id": "2",
    "channel_id": 4,
    "topic": "t",
    "message_id": 123,
    "revision": 0,
    "author_id": 8,
    "text": "[f](/user_uploads/2/a/f.txt)",
    "deleted": False,
    "is_bot": False,
}


def negatives(**changes):
    values = dict(
        other_author=9,
        foreign_channel=1000004,
        unlinked_path="/user_uploads/2/b/bot.txt",
        nonce="0" * 32,
    )
    return tool.negative_requests(SOURCE, ["/user_uploads/2/a/f.txt"], **{**values, **changes})


def test_negative_requests_cover_exactly_the_validator_set_and_one_change_each():
    requests = negatives()
    assert set(requests) == SOURCE_NEGATIVES
    assert requests["bot-source"]["source"] == {**SOURCE, "is_bot": True}
    assert requests["foreign-source"]["source"] == {**SOURCE, "channel_id": 1000004}
    assert requests["wrong-author"]["source"] == {**SOURCE, "author_id": 9}
    assert requests["unlinked-upload"]["source"] == SOURCE
    assert requests["unlinked-upload"]["upload_paths"] == ["/user_uploads/2/b/bot.txt"]
    for name in ("bot-source", "foreign-source", "wrong-author"):
        assert requests[name]["upload_paths"] == ["/user_uploads/2/a/f.txt"]
    for request in requests.values():
        assert set(request) == {"format", "nonce", "source", "upload_paths"}


@pytest.mark.parametrize(
    "changes",
    [
        {"other_author": 8},
        {"foreign_channel": 4},
        {"unlinked_path": "/user_uploads/2/a/f.txt"},
    ],
)
def test_negative_requests_refuse_a_negative_equal_to_the_positive(changes):
    with pytest.raises(RuntimeError):
        negatives(**changes)


def test_upload_candidates_split_human_from_bot_and_need_a_rendered_link():
    messages = [
        {"id": 1, "sender_id": 8, "content": "hello"},
        {"id": 2, "sender_id": 8, "content": "see [a.txt](/user_uploads/2/a/a.txt) now"},
        {"id": 3, "sender_id": 11, "content": "[b](/user_uploads/2/b/b.txt)"},
        {"id": 4, "sender_id": 9, "content": "mentions /user_uploads/2/c/c.txt without a link"},
        {
            "id": 5,
            "sender_id": 9,
            "content": "[d](/user_uploads/2/d/d.txt) [d](/user_uploads/2/d/d.txt) "
            "[e](/user_uploads/2/e/e.txt)",
        },
    ]
    found = tool.upload_candidates(messages, 11)
    assert [m["id"] for m in found["human"]] == [2, 5]
    assert [m["id"] for m in found["bot"]] == [3]
    assert found["human"][1]["paths"] == ["/user_uploads/2/d/d.txt", "/user_uploads/2/e/e.txt"]


def test_generated_gaps_for_a_plain_workspace_and_a_git_workspace():
    # A workspace with no .git, no snapshot keys and tool contents that are all text.
    assert tool.generated_gaps(git_project=False, tool_file_uris={}) == [
        "generated_snapshot_origin_unavailable_project_not_git",
        "generated_workspace_tool_origin_not_emitted_by_builtin_tools",
        "generated_twenty_mib_inline_case_requires_prompt_in_real_session",
    ]
    assert tool.generated_gaps(git_project=True, tool_file_uris={"file": 1, "data": 1}) == []


CLEAN = {
    "config_sha256": "1" * 64,
    "runtime_sha256": "2" * 64,
    "observer_sha256": "3" * 64,
    "release_selected": True,
    "main_active": "active",
    "observer_active": "active",
    "native_active": "active",
    "native_nrestarts": 0,
    "promotion_guard": False,
    "dropin_present": False,
    "root_enrolled": True,
    "inputs_enabled": False,
    "generated_enabled": False,
    "release_scopes_workspace_roots": True,
    "namespace_state": "absent",
    "project_owner_uid": 1000,
    "project_under_hidden_home": False,
    "association_problem": None,
    "free_bytes": 20 * 1024**3,
    "used_fraction_after_probe": 0.78,
    "human_upload_candidates": [123],
}
EXPECTED = {key: CLEAN[key] for key in ("config_sha256", "runtime_sha256", "observer_sha256")}


def test_assess_is_clean_when_every_fact_is_expected():
    assert tool.assess(CLEAN, EXPECTED) == []
    assert tool.assess({**CLEAN, "namespace_state": "pinned-empty"}, EXPECTED) == []


@pytest.mark.parametrize(
    "fact,value,code",
    [
        ("config_sha256", "9" * 64, "config_changed_since_spec"),
        ("runtime_sha256", "9" * 64, "runtime_changed_since_spec"),
        ("observer_sha256", "9" * 64, "observer_changed_since_spec"),
        ("release_selected", False, "spec_release_is_not_the_selected_release"),
        ("main_active", "failed", "main_or_observer_not_active"),
        ("observer_active", "inactive", "main_or_observer_not_active"),
        ("native_active", "failed", "native_not_active_or_restarted"),
        ("native_nrestarts", 1, "native_not_active_or_restarted"),
        ("promotion_guard", True, "promotion_guard_present"),
        ("dropin_present", True, "file_transfer_dropin_already_present"),
        ("root_enrolled", False, "root_not_enrolled"),
        ("inputs_enabled", True, "file_flag_already_enabled"),
        ("generated_enabled", True, "file_flag_already_enabled"),
        ("release_scopes_workspace_roots", False, "release_lacks_workspace_roots_scope"),
        ("namespace_state", "nonempty", "namespace_state_unexpected"),
        ("namespace_state", "foreign", "namespace_state_unexpected"),
        ("project_owner_uid", 0, "project_directory_owner_unexpected"),
        ("project_under_hidden_home", True, "project_under_protect_home"),
        ("association_problem", "key_owner_or_mode", "association_key_owner_or_mode"),
        ("free_bytes", 11 * 1024**3, "capacity_free_below_12gib"),
        ("used_fraction_after_probe", 0.80, "capacity_probe_would_cross_80_percent"),
        ("human_upload_candidates", [], "human_upload_missing"),
    ],
)
def test_assess_reports_each_changed_fact(fact, value, code):
    assert code in tool.assess({**CLEAN, fact: value}, EXPECTED)


def test_missing_human_upload_blocks_only_the_source_stage():
    blockers = ["human_upload_missing", "promotion_guard_present"]
    assert tool.stage_blockers(blockers, source_stage=True) == blockers
    assert tool.stage_blockers(blockers, source_stage=False) == ["promotion_guard_present"]


def test_mutating_steps_all_start_from_a_recheck_or_a_sealed_receipt():
    tree = ast.parse(TOOL.read_text())
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for name in ("cmd_namespace", "cmd_probe_workspace", "cmd_probe_source", "cmd_seal"):
        assert "require_ready" in ast.dump(functions[name]), name
    assert "require_ready" in ast.dump(functions["cmd_activate"])
    assert "seal.json" in ast.dump(functions["cmd_activate"])
    source = TOOL.read_text()
    # The tool has no write path to Native or Zulip, and never restarts Native.
    assert 'method="GET"' in source and "method=" not in source.replace('method="GET"', "")
    assert "opencode.service" in source
    assert '"restart"' not in source and "POST" not in source


def run_main(monkeypatch, tmp_path, *arguments):
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "tag": "files01",
                "release": "/opt/x/releases/abc",
                "session_id": REAL,
                "expected": {},
                "source_message_id": 1,
            }
        )
    )
    seen = []
    monkeypatch.setattr(tool, "STEPS", {name: seen.append for name in tool.STEPS})
    monkeypatch.setattr("sys.argv", ["tool", *[str(spec) if a == "@" else a for a in arguments]])
    tool.main()
    return seen[0]


def test_message_id_argument_overrides_without_changing_the_frozen_spec(monkeypatch, tmp_path):
    before = run_main(monkeypatch, tmp_path, "prepare", "--spec", "@")
    after = run_main(monkeypatch, tmp_path, "prepare", "--spec", "@", "--message-id", "77")
    assert before.source_message_id == 1 and after.source_message_id == 77
    assert before.raw_bytes == after.raw_bytes


def test_inline_spec_is_only_for_the_read_only_preflight(monkeypatch, tmp_path):
    inline = json.dumps({"tag": "files01", "release": "/opt/x", "session_id": REAL, "expected": {}})
    assert run_main(monkeypatch, tmp_path, "preflight", "--spec-inline", inline).tag == "files01"
    with pytest.raises(RuntimeError):
        run_main(monkeypatch, tmp_path, "activate", "--spec-inline", inline)
