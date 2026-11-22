"""Pure parser controls; synthetic pin is not installed Native qualification."""

import json
import warnings

import pytest

from jt_oz_bridge.domain.checks import ApprovedCheck
from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin, parse_git_evidence
from jt_oz_bridge.storage.durable import digest
from tests.support import REF

SCOPE = digest(REF.model_dump(mode="json"))


@pytest.mark.parametrize(
    "version",
    ["2.43.0", "2.56.0", "2.56.0.jtoz-metadata0", "2.56.0.jtoz-metadata2", ""],
)
def test_root_packet_refuses_unqualified_config_policy(version):
    with pytest.raises(ValueError, match="git_version"):
        pin(git_version=version)


def test_model_copy_cannot_restore_vanilla_git_qualification():
    old = pin().model_copy(update={"git_version": "2.56.0"})
    with warnings.catch_warnings(record=True) as caught:
        with pytest.raises(ValueError, match="git_version"):
            parse_git_evidence(json.dumps(document()), pin=old)
    assert not caught


def pin(**changes):
    fields = dict(
        reference=REF,
        check=ApprovedCheck(
            id="evidence",
            title="Git evidence",
            command="/usr/bin/python3 -I -B /opt/jt-oz-bridge/git-inspect225.py --scope " + SCOPE,
        ),
        script_version="git-inspect225-v1",
        python_version="3.12.3",
        git_version="2.56.0.jtoz-metadata1",
    )
    for key in (
        "catalog_sha256",
        "contract_sha256",
        "qualification_sha256",
        "scope_sha256",
        "script_sha256",
        "python_binary_sha256",
        "git_binary_sha256",
        "physical_scope_sha256",
        "native_policy_sha256",
        "plugin_policy_sha256",
        "installed_qualification_sha256",
    ):
        fields[key] = "a" * 64
    fields["scope_sha256"] = SCOPE
    return RootReviewedGitEvidencePin(**(fields | changes))


def document(**changes):
    return (
        dict(
            format="native-git-index-evidence-v1",
            scope_sha256=SCOPE,
            capture_started_at=100,
            capture_finished_at=101,
            git_binary_sha256="a" * 64,
            script_sha256="a" * 64,
            object_format="sha1",
            branch_safe_label="feature/topic",
            head_oid="a" * 40,
            head_tree_oid="b" * 40,
            index_sha256="c" * 64,
            index_semantic_sha256="d" * 64,
            index_tree_oid="e" * 40,
            index_entries=1,
            staged_paths=[dict(safe_relative_path="src/app.py", change="modified", mode="100644")],
            remote_aliases=[dict(safe_alias="origin", push_config_sha256="f" * 64)],
            complete_index=True,
            remote_live_verified=False,
            working_tree_content_verified=False,
        )
        | changes
    )


def test_complete_historical_sha1_and_sha256_are_data_only():
    one = parse_git_evidence(json.dumps(document()), pin=pin())
    assert one.index_entries == 1 and not one.remote_live_verified
    two = parse_git_evidence(
        json.dumps(
            document(
                object_format="sha256",
                head_oid="a" * 64,
                head_tree_oid="b" * 64,
                index_tree_oid="c" * 64,
            )
        ),
        pin=pin(),
    )
    assert two.object_format == "sha256"
    # Deletions need not remain in the new index.
    assert parse_git_evidence(
        json.dumps(
            document(
                index_entries=0,
                staged_paths=[
                    dict(safe_relative_path="removed.py", change="deleted", mode="100644")
                ],
            )
        ),
        pin=pin(),
    )


@pytest.mark.parametrize(
    "change",
    [
        {"complete_index": False},
        {"complete_index": 1},
        {"index_entries": True},
        {"remote_live_verified": True},
        {"remote_live_verified": 0},
        {"working_tree_content_verified": True},
        {"working_tree_content_verified": 0},
        {"head_oid": "a" * 64},
        {"capture_finished_at": 106},
        {"capture_finished_at": 99},
        {"capture_started_at": True},
        {"scope_sha256": "b" * 64},
        {"script_sha256": "b" * 64},
        {"git_binary_sha256": "b" * 64},
        {"index_entries": 4097},
        {"unknown": "no"},
        {"branch_safe_label": "https://user:password@remote"},
        {"remote_aliases": [{"safe_alias": "origin", "push_config_sha256": "f" * 64}] * 2},
        {
            "staged_paths": [
                {"safe_relative_path": "src/app.py", "change": "modified", "mode": "100644"}
            ]
            * 2
        },
    ],
)
def test_rejects_incomplete_spoofed_or_unbounded_schema(change):
    with pytest.raises(ValueError):
        parse_git_evidence(json.dumps(document(**change)), pin=pin())


@pytest.mark.parametrize(
    "path",
    [".env", ".git/config", "../outside", "/secret", "id_rsa", "src/<script>.py", "a\\b", "x/@all"],
)
def test_rejects_sensitive_or_active_paths(path):
    with pytest.raises(ValueError):
        parse_git_evidence(
            json.dumps(
                document(
                    staged_paths=[dict(safe_relative_path=path, change="modified", mode="100644")]
                )
            ),
            pin=pin(),
        )


@pytest.mark.parametrize(
    "wire", ['{"format":1,"format":2}', '{"x":NaN}', "{} {}", "[]", " ", "x" * 65537]
)
def test_rejects_duplicate_nan_trailing_nonobject_oversize(wire):
    with pytest.raises(ValueError):
        parse_git_evidence(wire, pin=pin())


def test_pin_requires_every_field_and_full_exact_command_even_model_copy():
    original = pin()
    with pytest.raises(ValueError):
        pin(check=original.check.model_copy(update={"command": "git status"}))
    malformed = original.model_copy(update={"script_sha256": "missing"})
    with pytest.raises(ValueError):
        parse_git_evidence(json.dumps(document()), pin=malformed)
    fields = original.model_dump(mode="python")
    del fields["plugin_policy_sha256"]
    with pytest.raises(ValueError):
        RootReviewedGitEvidencePin.model_validate(fields)


def test_rejects_full_index_or_staged_name_capacity_instead_of_truncating():
    entries = [
        dict(safe_relative_path=f"src/{i:04d}" + "a" * 220, change="added", mode="100644")
        for i in range(150)
    ]
    with pytest.raises(ValueError):
        parse_git_evidence(json.dumps(document(staged_paths=entries)), pin=pin())


def test_scope_cannot_cross_reference_even_when_exact_command_is_changed_together():
    original = pin()
    with pytest.raises(ValueError):
        pin(
            scope_sha256="b" * 64,
            check=original.check.model_copy(
                update={
                    "command": "/usr/bin/python3 -I -B /opt/jt-oz-bridge/git-inspect225.py --scope "
                    + "b" * 64,
                }
            ),
        )
