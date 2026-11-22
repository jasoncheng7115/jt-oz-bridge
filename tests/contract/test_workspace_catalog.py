"""Synthetic fixed-route catalog/diff contracts, not installed qualification."""

import asyncio
import copy
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.workspace_catalog import (
    CATALOG_SEMANTICS,
    V2WorkspaceCatalog,
    WorkspaceCatalogAttestation,
    entry_path,
)
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.contract.test_public_live_feed import REAL
from tests.support_directory_scope import SyntheticDirectoryScope


async def setup(*, operations=frozenset({"fs.list", "fs.find", "session.diff"}), hook=None):
    p, t, d, guard, client, _, writes = await policy_setup()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | operations
    )
    payload = {
        "list": {
            "location": {"directory": REF.canonical_directory},
            "data": [
                {"path": "報表.html", "type": "file"},
                {"path": "reports/", "type": "directory"},
                {"path": ".env", "type": "file"},
                {"path": ".jt-oz-incoming-123", "type": "directory"},
            ],
        },
        "find": {
            "location": {"directory": REF.canonical_directory},
            "data": [{"path": "reports/報表.html", "type": "file"}],
        },
        "diff": {
            "data": [
                {
                    "file": "報表.html",
                    "patch": "@@ -1 +1 @@\n-old\n+new\n",
                    "additions": 1,
                    "deletions": 1,
                    "status": "modified",
                }
            ]
        },
    }
    original, calls = t.client._transport, []

    def handle(request):
        routes = {
            "/api/fs/list": "list",
            "/api/fs/find": "find",
            f"/api/session/{REF.upstream_session_id}/diff": "diff",
        }
        kind = routes.get(request.url.path)
        if kind is None:
            return original.handler(request)
        assert request.method == "GET"
        calls.append(request)
        if hook:
            hook(kind, payload, p, d)
        return httpx.Response(200, json=copy.deepcopy(payload[kind]))

    t.client._transport = httpx.MockTransport(handle)
    attestation = WorkspaceCatalogAttestation(
        REF,
        t.profile.sha256,
        guard.enrollments[REF].fingerprint_sha256,
        CATALOG_SEMANTICS,
        "e" * 64,
        operations,
    )
    catalog = V2WorkspaceCatalog(
        client, {REF: attestation}, directories=SyntheticDirectoryScope(REF)
    )
    # Qualify only after the final catalog contract and routes are installed.
    await p.watch(REF)
    return p, t, d, catalog, payload, calls, writes


async def test_original_catalog_search_and_diff_are_get_only_and_never_freeze_bytes():
    p, t, d, c, data, calls, writes = await setup()
    try:
        files = await c.listing(REF)
        assert [(e.path, e.kind) for e in files.entries] == [
            ("reports", "directory"),
            ("報表.html", "file"),
        ]
        assert files.hidden_count == 2 and files.complete and c.current(files)
        assert not c.current(files.model_copy())
        assert "size" not in files.entries[0].model_dump()
        found = await c.listing(REF, query="報表")
        assert found.entries[0].path == "reports/報表.html"
        assert calls[-1].url.params["query"] == "報表"
        assert calls[-1].url.params["limit"] == "1001"
        assert calls[-1].url.params["type"] == "file"
        changes = await c.diff(REF)
        assert changes.files[0].patch.endswith("+new\n") and c.current(changes)
        assert all(
            r.url.params.get("location[directory]") == REF.canonical_directory for r in calls[:2]
        )
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["list", "find", "diff"])
async def test_schema_presence_alone_never_qualifies_a_catalog_operation(kind):
    p, t, d, c, data, calls, writes = await setup(operations=frozenset())
    try:
        assert not c.qualified(REF, kind)
        with pytest.raises(ValueError):
            await (
                c.diff(REF)
                if kind == "diff"
                else c.listing(REF, query="x" if kind == "find" else "")
            )
        assert not calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "failure", ["absolute", "traversal", "backslash", "duplicate", "nested", "location", "capacity"]
)
async def test_untrusted_listing_cannot_escape_or_silently_change_the_workspace(failure):
    p, t, d, c, data, calls, writes = await setup()
    try:
        if failure == "location":
            data["list"]["location"]["directory"] = "/other"
        elif failure == "capacity":
            data["list"]["data"] = [{"path": f"f{x}", "type": "file"} for x in range(1001)]
        else:
            path = {
                "absolute": "/etc/passwd",
                "traversal": "../other",
                "backslash": "a\\b",
                "duplicate": "報表.html",
                "nested": "other/deep.html",
            }[failure]
            data["list"]["data"].append({"path": path, "type": "file"})
        with pytest.raises(ValueError):
            await c.listing(REF)
        assert not writes
    finally:
        await finish(p, t)


async def test_search_probe_reports_truncation_and_subdirectory_listing_is_exact():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [{"path": f"reports/f{x:04}", "type": "file"} for x in range(1001)]
        found = await c.listing(REF, query="reports")
        assert not found.complete and len(found.entries) == 1000
        data["list"]["data"] = [{"path": "reports/child.html", "type": "file"}]
        result = await c.listing(REF, directory="reports")
        assert result.entries[0].path == "reports/child.html"
        assert calls[-1].url.params["path"] == "reports"
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("failure", ["policy", "fence", "connection"])
async def test_change_during_native_read_cannot_publish_a_catalog(failure):
    def hook(kind, payload, proofs, data):
        if failure == "policy":
            data["session.get"]["data"]["permissions"] = []
        elif failure == "fence":
            # Native resource proof advances even though the listing response looks unchanged.
            proofs.feed.index._notice_arrival(REAL[0])
        else:
            proofs.feed.index.invalidate("synthetic-disconnected")

    p, t, d, c, data, calls, writes = await setup(hook=hook)
    try:
        with pytest.raises((ValueError, KeyError)):
            await c.listing(REF)
        assert len(calls) == 1 and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("failure", ["secret", "duplicate", "large", "invalid"])
async def test_diff_protects_names_and_bounds_content(failure):
    p, t, d, c, data, calls, writes = await setup()
    try:
        if failure == "secret":
            data["diff"]["data"][0]["file"] = ".ssh/id_ed25519"
            result = await c.diff(REF)
            assert not result.files and result.hidden_count == 1
        else:
            if failure == "duplicate":
                data["diff"]["data"] *= 2
            elif failure == "large":
                data["diff"]["data"][0]["patch"] = "漢" * 400000
            else:
                data["diff"]["data"][0]["additions"] = -1
            with pytest.raises(ValueError):
                await c.diff(REF)
        assert not writes
    finally:
        await finish(p, t)


async def test_observation_expires_without_dto_reconstruction_or_timeout_extension(monkeypatch):
    p, t, d, c, data, calls, writes = await setup()
    try:
        listing = await c.listing(REF)
        current = time.monotonic()
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.workspace_catalog.time.monotonic", lambda: current + 6
        )
        assert not c.current(listing)
        assert not c.current(listing.model_copy())
    finally:
        await finish(p, t)


@pytest.mark.parametrize("path", ["reports/", "reports", "文件/子目錄/", "文件/子目錄"])
def test_installed_directory_marker_has_one_canonical_logical_path(path):
    assert entry_path(path, "directory") == path.removesuffix("/")


@pytest.mark.parametrize(
    "path,kind",
    [
        ("/outside/", "directory"),
        ("../", "directory"),
        ("foo/../", "directory"),
        ("foo//", "directory"),
        ("foo//child/", "directory"),
        ("./", "directory"),
        ("/", "directory"),
        ("", "directory"),
        ("foo/", "file"),
        ("foo/", "symlink"),
    ],
)
def test_directory_marker_rule_never_repairs_an_unsafe_or_file_path(path, kind):
    with pytest.raises(ValueError):
        entry_path(path, kind)


async def test_marked_and_unmarked_duplicate_directory_entries_reject():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["list"]["data"] = [
            {"path": "reports/", "type": "directory"},
            {"path": "reports", "type": "directory"},
        ]
        with pytest.raises(ValueError, match="duplicate_path"):
            await c.listing(REF)
        assert len(calls) == 1 and not writes
    finally:
        await finish(p, t)


async def test_file_only_search_cannot_silently_accept_a_directory():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [{"path": "reports/", "type": "directory"}]
        with pytest.raises(ValueError, match="search_file_type_changed"):
            await c.listing(REF, query="reports")
        assert len(calls) == 1 and not writes
    finally:
        await finish(p, t)


async def test_schema_and_native_attestation_without_physical_scope_never_enable_catalog():
    p, t, d, c, data, calls, writes = await setup()
    try:
        bare = V2WorkspaceCatalog(c.client, c.attestations)
        assert not any(bare.qualified(REF, kind) for kind in ("list", "find", "diff"))
        with pytest.raises(ValueError, match="operation_not_qualified"):
            await bare.listing(REF)
        assert not calls and not writes
    finally:
        await finish(p, t)


async def test_outside_symlink_directory_is_rejected_before_native_navigation():
    p, t, d, c, data, calls, writes = await setup()
    try:
        c.directories.blocked.add("escape-dir")
        with pytest.raises(ValueError, match="directory_scope_denied"):
            await c.listing(REF, directory="escape-dir")
        assert not calls and not c._observed and not writes
    finally:
        await finish(p, t)


async def test_directory_replaced_while_native_lists_never_publishes_metadata():
    p, t, d, c, data, calls, writes = await setup()
    original = t.client._transport
    try:

        def replaced(request):
            response = original.handler(request)
            if request.url.path == "/api/fs/list":
                c.directories.generation += 1
            return response

        t.client._transport = httpx.MockTransport(replaced)
        with pytest.raises(ValueError, match="physical_directory_boundary_changed"):
            await c.listing(REF)
        assert len(calls) == 1 and not c._observed and not writes
    finally:
        await finish(p, t)


async def test_search_parent_scope_is_checked_before_repeating_and_publishing():
    p, t, d, c, data, calls, writes = await setup()
    try:
        c.directories.blocked.add("reports")
        listing = await c.listing(REF, query="report")
        assert not listing.entries and listing.hidden_count == 1 and c.current(listing)
        assert len(calls) == 2 and not writes
    finally:
        await finish(p, t)


async def test_second_search_read_must_match_the_exact_first_native_response():
    p, t, d, c, data, calls, writes = await setup()
    original = t.client._transport
    try:

        def changes(request):
            if request.url.path == "/api/fs/find" and any(
                r.url.path == "/api/fs/find" for r in calls
            ):
                data["find"]["data"][0]["path"] = "reports/changed.html"
            return original.handler(request)

        t.client._transport = httpx.MockTransport(changes)
        with pytest.raises(ValueError, match="search_changed_during_parent_check"):
            await c.listing(REF, query="report")
        assert len(calls) == 2 and not c._observed and not writes
    finally:
        await finish(p, t)


async def test_search_directory_identity_changes_are_not_just_name_comparisons():
    p, t, d, c, data, calls, writes = await setup()
    try:

        async def change(paths, number):
            if number == 3:
                c.directories.generation += 1

        c.directories.hook = change
        with pytest.raises(ValueError, match="physical_directory_boundary_changed"):
            await c.listing(REF, query="report")
        assert len(calls) == 2 and not c._observed and not writes
    finally:
        await finish(p, t)


async def test_catalog_current_also_requires_the_original_physical_directory_observation():
    p, t, d, c, data, calls, writes = await setup()
    try:
        listing = await c.listing(REF)
        assert c.current(listing)
        c.directories.enabled = False
        assert not c.current(listing)
        assert not writes
    finally:
        await finish(p, t)


async def test_mixed_native_search_keeps_only_fresh_physically_verified_parents():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [
            {"path": "reports/ok.html", "type": "file"},
            {"path": "escape/foreign.html", "type": "file"},
        ]
        c.directories.blocked.add("escape")
        listing = await c.listing(REF, query="html")
        assert [e.path for e in listing.entries] == ["reports/ok.html"]
        assert listing.hidden_count == 1 and c.current(listing)
        assert c._observed[id(listing)].directory_scope.directories == ("reports",)
        assert len(calls) == 2 and not writes
    finally:
        await finish(p, t)


async def test_no_directory_service_cannot_be_reported_as_an_empty_search():
    p, t, d, c, data, calls, writes = await setup()
    try:

        async def unavailable(paths, number):
            if number > 1:
                raise ValueError("synthetic service unavailable")

        c.directories.hook = unavailable
        with pytest.raises(ValueError):
            await c.listing(REF, query="html")
        assert len(calls) == 1 and not c._observed and not writes
    finally:
        await finish(p, t)


async def test_parent_probe_root_change_rejects_the_whole_search_instead_of_hiding_it():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [
            {"path": "reports/ok.html", "type": "file"},
            {"path": "escape/foreign.html", "type": "file"},
        ]
        c.directories.blocked.add("escape")

        async def change(paths, number):
            if paths == ("reports",):
                c.directories.generation += 1

        c.directories.hook = change
        with pytest.raises(ValueError, match="physical_root_changed"):
            await c.listing(REF, query="html")
        assert not c._observed and not writes
    finally:
        await finish(p, t)


async def test_unprovable_wide_search_requires_refinement_without_unbounded_rpc_retry():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [{"path": f"parent{x}/file.html", "type": "file"} for x in range(33)]
        c.directories.blocked.add("parent0")
        with pytest.raises(ValueError, match="refine_unprovable_parent_scope"):
            await c.listing(REF, query="html")
        assert len(c.directories.calls) == 1 and len(calls) == 1 and not c._observed
    finally:
        await finish(p, t)


async def test_filtered_search_still_rejects_changed_raw_native_results():
    p, t, d, c, data, calls, writes = await setup()
    original = t.client._transport
    try:
        data["find"]["data"] = [
            {"path": "reports/ok.html", "type": "file"},
            {"path": "escape/foreign.html", "type": "file"},
        ]
        c.directories.blocked.add("escape")

        def changed(request):
            if request.url.path == "/api/fs/find" and any(
                r.url.path == "/api/fs/find" for r in calls
            ):
                data["find"]["data"][1]["path"] = "escape/changed-foreign.html"
            return original.handler(request)

        t.client._transport = httpx.MockTransport(changed)
        with pytest.raises(ValueError, match="search_changed_during_parent_check"):
            await c.listing(REF, query="html")
        assert len(calls) == 2 and not c._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("probe", [False, True])
async def test_search_keeps_native_rank_so_lexical_order_cannot_drop_the_best_match(probe):
    p, t, d, c, data, calls, writes = await setup()
    try:
        ranked = ["reports/繁體最佳符合.html"]
        ranked += (
            [f"reports/f{x:04}.txt" for x in range(1000)]
            if probe
            else ["reports/z-second.txt", "reports/a-third.txt"]
        )
        data["find"]["data"] = [{"path": path, "type": "file"} for path in ranked]
        result = await c.listing(REF, query="繁體")
        assert [entry.path for entry in result.entries] == ranked[:1000]
        assert result.complete is not probe and c.current(result)
        assert len(calls) == 2 and not writes
    finally:
        await finish(p, t)


async def test_changed_native_search_rank_changes_the_menu_snapshot():
    p, t, d, c, data, calls, writes = await setup()
    try:
        data["find"]["data"] = [
            {"path": "reports/z-best.txt", "type": "file"},
            {"path": "reports/a-next.txt", "type": "file"},
        ]
        original = await c.listing(REF, query="reports")
        data["find"]["data"].reverse()
        changed = await c.listing(REF, query="reports")
        assert original.sha256 != changed.sha256
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["list", "find", "diff"])
async def test_catalog_read_scope_never_borrows_or_restores_mutation_watch(monkeypatch, kind):
    p, t, data, catalog, payload, calls, writes = await setup()
    p.revoke_watch(REF)
    monkeypatch.setattr(catalog.client, "qualified_snapshot", AsyncMock(side_effect=AssertionError))
    monkeypatch.setattr(p, "watch", AsyncMock(side_effect=AssertionError))
    try:
        value = (
            await catalog.diff(REF)
            if kind == "diff"
            else await catalog.listing(REF, query="報表" if kind == "find" else "")
        )
        assert catalog.current(value) and not catalog.current(value.model_copy())
        assert p.certified_epoch(REF, t.profile.sha256) is None and not p._watched
        assert calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("drift", ["owner", "feed", "index", "task", "attestation", "generation"])
async def test_catalog_read_scope_checks_object_boundaries_even_with_same_epoch(drift):
    tasks = []

    def hook(kind, payload, proofs, data):
        if drift == "owner":
            proofs.feed.owner.read.return_value = SimpleNamespace(owner_epoch="f" * 64)
        elif drift == "feed":
            proofs.feed = copy.copy(proofs.feed)
        elif drift == "index":
            proofs.feed.index = copy.copy(proofs.feed.index)
        elif drift == "task":
            tasks.append(proofs.feed.task)
            proofs.feed.task = asyncio.create_task(asyncio.Event().wait())
        elif drift == "attestation":
            proofs.feed.transport.attestation = replace(proofs.feed.transport.attestation)
        else:
            proofs.feed.index.connection_epoch = "f" * 64

    p, t, data, catalog, payload, calls, writes = await setup(hook=hook)
    p.revoke_watch(REF)
    try:
        with pytest.raises((ValueError, KeyError)):
            await catalog.listing(REF)
        assert not catalog._observed and not writes and not p._watched
    finally:
        await finish(p, t)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def test_catalog_slow_second_scope_cannot_restart_first_five_second_deadline(monkeypatch):
    clock = [0.0]

    def hook(*_):
        clock[0] += 6

    p, t, data, catalog, payload, calls, writes = await setup(hook=hook)
    p.revoke_watch(REF)
    clock[0] = time.time()
    monkeypatch.setattr(
        "jt_oz_bridge.adapters.opencode.workspace_catalog.time.time", lambda: clock[0]
    )
    try:
        with pytest.raises(ValueError):
            await catalog.listing(REF)
        assert not catalog._observed and not writes and not p._watched
    finally:
        await finish(p, t)


@pytest.mark.parametrize("changed", ["feed", "index", "task", "attestation"])
async def test_fresh_catalog_scope_cannot_resurrect_observation_from_replaced_context(changed):
    p, t, data, catalog, payload, calls, writes = await setup()
    old_task = None
    p.revoke_watch(REF)
    try:
        previous = await catalog.listing(REF)
        if changed == "feed":
            p.feed = copy.copy(p.feed)
        elif changed == "index":
            p.feed.index = copy.copy(p.feed.index)
        elif changed == "task":
            old_task = p.feed.task
            p.feed.task = asyncio.create_task(asyncio.Event().wait())
        else:
            t.attestation = replace(t.attestation)
        fresh = await catalog.listing(REF)
        assert catalog.current(fresh) and not catalog.current(previous)
        assert not writes and not p._watched
        assert p.certified_epoch(REF, t.profile.sha256) is None
    finally:
        await finish(p, t)
        if old_task is not None:
            old_task.cancel()
            await asyncio.gather(old_task, return_exceptions=True)


def test_installed_contract_has_no_native_file_content_search_to_qualify():
    """File content search stays unimplemented on the pinned 2.0.32 contract.

    `fs.find` ranks entry names (path/type only) and `fs.read` returns one file.
    The untyped plugin `rpc.call`, shell/PTY execution and web search are not a
    workspace content-search capability. A future contract adding one must fail
    here and be qualified explicitly instead of being emulated by the Bridge.
    """
    path = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == INSTALLED_SCHEMA
    contract = json.loads(raw)
    operations = {
        operation["operationId"]: operation
        for methods in contract["paths"].values()
        for operation in methods.values()
    }
    filesystem = {name for name in operations if name.split(".")[-2:-1] == ["fs"]}
    assert filesystem == {"fs.read", "fs.list", "fs.find", "experimental.fs.write"}
    find = operations["fs.find"]
    assert {item["name"] for item in find["parameters"]} == {"location", "query", "type", "limit"}
    entry = contract["components"]["schemas"]["FileSystem.Entry"]
    assert set(entry["properties"]) == {"path", "type"}
    words = ("search", "find", "grep", "query")
    assert {
        name
        for name, operation in operations.items()
        if any(
            word
            in " ".join(
                (name, operation.get("summary", ""), operation.get("description", ""))
            ).lower()
            for word in words
        )
    } == {"fs.find", "websearch.providers", "websearch.query"}
    assert contract["components"]["schemas"]["Rpc.Input"]["properties"] == {"input": {}}
