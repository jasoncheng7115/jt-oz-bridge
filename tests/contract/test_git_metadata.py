"""Actual installed OpenAPI with synthetic HTTP/owner fixtures; no installed certification."""

import copy
import hashlib
from dataclasses import replace

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.native_metadata import GIT_OPERATIONS, project_git
from jt_oz_bridge.domain.git import NativeGitContext
from jt_oz_bridge.domain.native_metadata import NativeMetadataSnapshot
from tests.contract.test_native_metadata import REF, prepared


async def git_reader(hook=None):
    p, t, data, reader, _, _ = await prepared()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | GIT_OPERATIONS
    )
    source = {
        "info": {"provider": "git", "branch": {"current": "feature/original", "default": "main"}},
        "status": [
            {"file": "src/z.py", "status": "modified", "additions": 2, "deletions": 1},
            {"file": "src/a.py", "status": "added", "additions": 4, "deletions": 0},
        ],
    }
    source["location"] = {
        "directory": REF.canonical_directory,
        "project": {
            "id": reader.client.selected(REF).upstream_project_id,
            "directory": REF.canonical_directory,
            "canonical": REF.canonical_directory,
        },
    }
    calls = []
    delegate = t.client._transport

    def handle(request):
        kind = {"/api/vcs": "info", "/api/vcs/status": "status", "/api/location": "location"}.get(
            request.url.path
        )
        if kind:
            assert request.method == "GET" and dict(request.url.params) == {
                "location[directory]": REF.canonical_directory
            }
            calls.append(kind)
            value = (
                copy.deepcopy(source[kind])
                if kind == "location"
                else {
                    "location": {"directory": REF.canonical_directory},
                    "data": copy.deepcopy(source[kind]),
                }
            )
            if hook:
                hook(kind, calls.count(kind), value, p, t, data)
            return httpx.Response(200, json=value)
        return delegate.handler(request)

    t.client._transport = httpx.MockTransport(handle)
    # Git RPC qualification was added after metadata setup's original watch.
    await p.watch(REF)
    return p, t, data, reader, calls, source


async def test_git_reports_actual_original_branch_and_combined_files_without_staged_or_check_claims():
    p, t, data, reader, calls, source = await git_reader()
    try:
        snapshot = await reader.read(REF, "git")
        assert reader.current(snapshot) and snapshot.git.branch == "feature/original"
        assert [item.name for item in snapshot.items] == ["src/a.py", "src/z.py"]
        assert [item.change for item in snapshot.items] == ["added", "modified"]
        assert snapshot.items[0].native_id == hashlib.sha256(b"src/a.py").hexdigest()
        assert (
            snapshot.git.reported_files == 2
            and snapshot.git.status_scope == "native_combined_status"
        )
        assert not any(
            getattr(snapshot.git, key)
            for key in [
                "staged_index_verified",
                "head_and_remote_verified",
                "clean_verified",
                "checks_verified",
                "mutation_confirmation_usable",
            ]
        )
        assert calls == [
            "location",
            "info",
            "status",
            "location",
            "location",
            "info",
            "status",
            "location",
        ]
        assert not reader.current(snapshot.model_copy())
        assert not reader.current(
            NativeMetadataSnapshot.model_validate_json(snapshot.model_dump_json())
        )
    finally:
        await t.close()


@pytest.mark.parametrize("operation", sorted(GIT_OPERATIONS))
async def test_each_unqualified_git_rpc_prevents_every_git_request(operation):
    p, t, data, reader, calls, source = await git_reader()
    try:
        t.attestation = replace(
            t.attestation, verified_operations=t.attestation.verified_operations - {operation}
        )
        assert "git" not in reader.available_kinds(REF)
        with pytest.raises(ContractError):
            await reader.read(REF, "git")
        assert calls == []
    finally:
        await t.close()


@pytest.mark.parametrize(
    "change",
    [
        "branch",
        "default",
        "provider",
        "file-count",
        "file-status",
        "line-count",
        "location",
        "duplicate",
        "parent",
        "absolute",
        "null",
        "owner",
        "attestation",
    ],
)
async def test_git_rejects_changed_or_foreign_snapshot_without_retaining_authority(change):
    def hook(kind, count, value, p, t, data):
        if change in {"branch", "default", "provider"} and kind == "info" and count == 2:
            if change == "provider":
                value["data"]["provider"] = "different"
            else:
                value["data"]["branch"]["current" if change == "branch" else "default"] = (
                    "different"
                )
        elif kind == "status" and count == 2:
            if change == "file-count":
                value["data"].pop()
            elif change == "file-status":
                value["data"][0]["status"] = "deleted"
            elif change == "line-count":
                value["data"][0]["additions"] += 1
            elif change == "location":
                value["location"]["directory"] = "/foreign"
            elif change == "duplicate":
                value["data"].append(copy.deepcopy(value["data"][0]))
            elif change in {"parent", "absolute", "null"}:
                value["data"][0]["file"] = {
                    "parent": "../secret",
                    "absolute": "/secret",
                    "null": "a\0b",
                }[change]
        if change == "owner":
            p.feed.owner.read.side_effect = ContractError("original-owner-lost")
        elif change == "attestation":
            t.attestation = replace(t.attestation)

    p, t, data, reader, calls, source = await git_reader(hook)
    try:
        with pytest.raises(ValueError):
            await reader.read(REF, "git")
        assert not reader._observed
    finally:
        await t.close()


async def test_order_changes_are_stable_but_unknown_branches_and_zero_changes_do_not_mean_clean():
    def hook(kind, count, value, p, t, data):
        if kind == "status" and count == 2:
            value["data"].reverse()

    p, t, data, reader, calls, source = await git_reader(hook)
    try:
        assert (await reader.read(REF, "git")).git.reported_files == 2
        source["info"] = {"branch": {}}
        source["status"] = []
        snapshot = await reader.read(REF, "git")
        assert (
            snapshot.git.branch is None
            and snapshot.git.default_branch is None
            and snapshot.git.provider is None
        )
        assert (
            snapshot.items == ()
            and snapshot.git.reported_files == 0
            and not snapshot.git.clean_verified
        )
    finally:
        await t.close()


@pytest.mark.parametrize("value", [True, -1, 1.5, "12", 10**500])
def test_reported_git_counts_are_strict_and_bounded(value):
    with pytest.raises(ValidationError):
        project_git(
            {"branch": {}},
            [{"file": "valid", "status": "added", "additions": value, "deletions": 0}],
            root_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "field",
    [
        "clean_verified",
        "staged_index_verified",
        "checks_verified",
        "head_and_remote_verified",
        "mutation_confirmation_usable",
    ],
)
def test_reported_status_cannot_be_promoted_to_confirmation_or_verified_success(field):
    with pytest.raises(ValidationError):
        NativeGitContext(reported_files=0, native_project_root_sha256="a" * 64, **{field: True})


@pytest.mark.parametrize(
    "name", ["src/has spaces.py", "src/a[b].py", "src/C++.cc", "src/繁體中文.py"]
)
def test_metadata_file_names_keep_exact_identity_without_becoming_shell_arguments(name):
    context, items = project_git(
        {"branch": {}},
        [{"file": name, "status": "modified", "additions": 1, "deletions": 1}],
        root_sha256="a" * 64,
    )
    assert items[0].name == name and items[0].native_id == hashlib.sha256(name.encode()).hexdigest()


async def test_git_capacity_is_fail_closed_not_a_truncated_clean_or_complete_report():
    p, t, data, reader, calls, source = await git_reader()
    source["status"] = [
        {"file": "file" + str(i), "status": "added", "additions": 0, "deletions": 0}
        for i in range(4097)
    ]
    try:
        with pytest.raises(ContractError, match="capacity"):
            await reader.read(REF, "git")
        assert not reader._observed
    finally:
        await t.close()


@pytest.mark.parametrize("change", ["parent-project", "foreign-project", "foreign-location"])
async def test_git_root_mismatch_stops_before_any_repository_metadata_request(change):
    def hook(kind, count, value, p, t, data):
        if kind == "location":
            if change == "parent-project":
                value["project"]["directory"] = "/parent"
            elif change == "foreign-project":
                value["project"]["id"] = "foreign-project"
            else:
                value["directory"] = "/foreign"

    p, t, data, reader, calls, source = await git_reader(hook)
    try:
        with pytest.raises(ContractError, match="exact_project_root"):
            await reader.read(REF, "git")
        assert calls == ["location"] and not reader._observed
    finally:
        await t.close()


@pytest.mark.parametrize("location_read", [2, 3])
async def test_git_root_identity_drift_invalidates_observation_even_with_same_visible_status(
    location_read,
):
    def hook(kind, count, value, p, t, data):
        if kind == "location" and count >= location_read:
            value["project"]["canonical"] = "/different/project-root"

    p, t, data, reader, calls, source = await git_reader(hook)
    try:
        with pytest.raises(ContractError, match="root_changed|changed_during_read"):
            await reader.read(REF, "git")
        assert not reader._observed
    finally:
        await t.close()


@pytest.mark.parametrize(
    "path",
    [
        ".jt-oz-incoming-service/private.bin",
        ".jt-oz-preview-user/private.html",
        ".env",
        ".env.production",
        ".ssh/id_ed25519",
        "secrets/private.json",
        "credentials.json",
        "src/private.key",
    ],
)
async def test_git_protected_paths_are_omitted_before_public_projection_and_do_not_mean_clean(path):
    p, t, data, reader, calls, source = await git_reader()
    source["status"] = [
        {"file": path, "status": "added", "additions": 1, "deletions": 0},
        {"file": "src/public.py", "status": "modified", "additions": 2, "deletions": 1},
    ]
    try:
        snapshot = await reader.read(REF, "git")
        assert [item.name for item in snapshot.items] == ["src/public.py"]
        assert (
            snapshot.git.reported_files == 2
            and snapshot.git.hidden_files == 1
            and not snapshot.git.clean_verified
        )
        assert path not in snapshot.model_dump_json()
        source["status"].pop()
        hidden = await reader.read(REF, "git")
        assert (
            hidden.items == ()
            and hidden.git.reported_files == hidden.git.hidden_files == 1
            and not hidden.git.clean_verified
        )
    finally:
        await t.close()


@pytest.mark.parametrize(
    "path", ["src/a\nb.py", "src/a\tb.py", "src/a\\b.py", "src//b.py", "src/./b.py"]
)
def test_git_ambiguous_paths_follow_existing_shared_disclosure_policy(path):
    with pytest.raises(ValueError):
        project_git(
            {"branch": {}},
            [{"file": path, "status": "added", "additions": 0, "deletions": 0}],
            root_sha256="a" * 64,
        )


async def test_duplicate_protected_paths_are_still_rejected_without_leaking_them():
    p, t, data, reader, calls, source = await git_reader()
    row = {"file": ".env", "status": "added", "additions": 1, "deletions": 0}
    source["status"] = [row, dict(row)]
    try:
        with pytest.raises(ContractError, match="duplicate"):
            await reader.read(REF, "git")
    finally:
        await t.close()
