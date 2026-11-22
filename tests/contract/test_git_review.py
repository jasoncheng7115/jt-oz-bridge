"""Installed-schema synthetic review routes; no live Git or installed qualification."""

import copy
import time
from dataclasses import replace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.git_review import (
    REVIEW_OPERATIONS,
    REVIEW_SEMANTICS,
    GitReviewAttestation,
    V2NativeGitReview,
)
from jt_oz_bridge.domain.git_review import NativeGitReview
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.contract.test_public_live_feed import REAL
from tests.support_directory_scope import SyntheticDirectoryScope


async def prepared(hook=None):
    p, t, d, guard, client, _, writes = await policy_setup()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | REVIEW_OPERATIONS
    )
    root = REF.canonical_directory
    raw = {
        "location": {
            "directory": root,
            "project": {"id": "global", "directory": root, "canonical": root},
        },
        "worktrees": [
            {"directory": root},
            {"directory": root + "/feature", "strategy": "saved"},
            {"directory": "/outside/secret-name"},
            {"directory": root + "/.ssh/private-name"},
        ],
        "info": {"provider": "git", "branch": {"current": "feature/original", "default": "main"}},
        "branches": ["feature/original", "main"],
        "base": {"name": "main", "ref": "refs/heads/main", "source": "reflog"},
        "diff": [
            {
                "file": "src/a.py",
                "patch": "@@ -1 +1 @@\n-old\n+unique-private-patch-text\n",
                "additions": 1,
                "deletions": 1,
                "status": "modified",
            },
            {
                "file": ".env",
                "patch": "-private-secret\n",
                "additions": 0,
                "deletions": 1,
                "status": "deleted",
            },
        ],
    }
    routes = {
        "/api/location": "location",
        "/api/worktree": "worktrees",
        "/api/vcs": "info",
        "/api/vcs/branch": "branches",
        "/api/vcs/base": "base",
        "/api/vcs/diff": "diff",
    }
    calls = []
    delegate = t.client._transport

    def handle(request):
        kind = routes.get(request.url.path)
        if kind is None:
            return delegate.handler(request)
        assert request.method == "GET"
        calls.append((kind, request))
        value = copy.deepcopy(raw[kind])
        if kind not in {"location", "worktrees"}:
            value = {"location": {"directory": root}, "data": value}
        if hook:
            hook(kind, sum(k == kind for k, _ in calls), value, p, t, d, raw)
        return httpx.Response(200, json=value)

    t.client._transport = httpx.MockTransport(handle)
    p.revoke_watch(REF)
    physical = SyntheticDirectoryScope(REF)
    a = GitReviewAttestation(
        REF,
        t.profile.sha256,
        guard.enrollments[REF].fingerprint_sha256,
        REVIEW_SEMANTICS,
        "a" * 64,
        REVIEW_OPERATIONS,
    )
    reader = V2NativeGitReview(client, {REF: a}, directories=physical)
    return p, t, d, reader, raw, calls, writes, physical


async def test_saved_inventory_base_and_summary_preserve_original_scope_without_mutation_authority():
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        assert p.certified_epoch(REF, t.profile.sha256) is None
        view = await c.read(REF)
        assert c.current(view)
        assert p.certified_epoch(REF, t.profile.sha256) is None
        with pytest.raises(ValueError):
            await p.prove(REF, t.profile.sha256, "0" * 64)
        assert view.current_branch == "feature/original" and view.default_branch == "main"
        assert [r.relative_directory for r in view.saved_worktrees] == ["", "feature"]
        assert view.hidden_worktrees == 2 and view.hidden_files == 1
        assert [f.path for f in view.files] == ["src/a.py"]
        assert view.inferred_base.ref == "refs/heads/main"
        text = view.model_dump_json()
        assert all(
            value not in text
            for value in [
                "secret-name",
                "private-name",
                "unique-private-patch-text",
                "private-secret",
                '"patch":',
            ]
        )
        assert not any(
            getattr(view, name)
            for name in [
                "full_diff_display",
                "index_verified",
                "head_verified",
                "remote_verified",
                "clean_verified",
                "worktree_switch_usable",
                "mutation_confirmation_usable",
            ]
        )
        assert not c.current(view.model_copy())
        assert not c.current(NativeGitReview.model_validate_json(text))
        assert len(calls) == 12 and not writes
        for kind, request in calls:
            params = dict(request.url.params)
            if kind == "worktrees":
                assert params == {"projectID": "global"}
            elif kind == "branches":
                assert params == {
                    "location[directory]": REF.canonical_directory,
                    "search": "",
                    "limit": "51",
                }
            elif kind == "diff":
                assert params == {"location[directory]": REF.canonical_directory, "mode": "working"}
            else:
                assert params == {"location[directory]": REF.canonical_directory}
    finally:
        await finish(p, t)


@pytest.mark.parametrize("operation", sorted(REVIEW_OPERATIONS))
async def test_each_unqualified_rpc_rejects_before_any_review_rpc(operation):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        t.attestation = replace(
            t.attestation, verified_operations=t.attestation.verified_operations - {operation}
        )
        assert not c.qualified(REF)
        with pytest.raises(ValueError):
            await c.read(REF)
        assert not calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "location",
        "project",
        "branch",
        "base",
        "diff",
        "worktrees",
        "owner",
        "attestation",
        "fence",
        "disconnect",
        "policy",
        "shell-root",
    ],
)
async def test_original_root_owner_policy_or_repeated_git_change_rejects(fault):
    def hook(kind, count, value, p, t, d, raw):
        if count != 2:
            return
        if fault == "location" and kind == "location":
            value["directory"] = "/foreign"
        elif fault == "project" and kind == "location":
            value["project"]["id"] = "foreign"
        elif fault == "branch" and kind == "info":
            value["data"]["branch"]["current"] = "changed"
        elif fault == "base" and kind == "base":
            value["data"]["ref"] = "changed"
        elif fault == "diff" and kind == "diff":
            value["data"][0]["patch"] += "changed"
        elif fault == "worktrees" and kind == "worktrees":
            value.pop()
        elif kind == "diff":
            if fault == "owner":
                p.feed.owner.read.side_effect = ValueError("owner-lost")
            elif fault == "attestation":
                t.attestation = replace(t.attestation)
            elif fault == "fence":
                p.feed.index._notice_arrival(REAL[0])
            elif fault == "disconnect":
                p.feed.index.invalidate("synthetic-disconnected")
            elif fault == "policy":
                d["session.get"]["data"]["permissions"] = []
            elif fault == "shell-root":
                d["session.get"]["data"]["parentID"] = "foreign"

    p, t, d, c, raw, calls, writes, physical = await prepared(hook)
    try:
        with pytest.raises(ValueError):
            await c.read(REF)
        assert not c._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "traversal",
        "absolute",
        "duplicate-diff",
        "duplicate-worktree",
        "noncanonical-worktree",
        "worktree-capacity",
        "diff-capacity",
        "branch-capacity",
        "duplicate-branch",
        "patch-capacity-hidden",
        "control-branch",
        "physical-capacity",
    ],
)
async def test_untrusted_native_rows_cannot_bypass_bounds_or_protected_names(fault):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        if fault in {"traversal", "absolute"}:
            raw["diff"][0]["file"] = "../escape" if fault == "traversal" else "/etc/shadow"
        elif fault == "duplicate-diff":
            raw["diff"].append(copy.deepcopy(raw["diff"][0]))
        elif fault == "duplicate-worktree":
            raw["worktrees"].append(copy.deepcopy(raw["worktrees"][0]))
        elif fault == "noncanonical-worktree":
            raw["worktrees"][0]["directory"] += "/../escape"
        elif fault == "worktree-capacity":
            raw["worktrees"] = [{"directory": f"/outside/{i}"} for i in range(129)]
        elif fault == "diff-capacity":
            raw["diff"] = [{**raw["diff"][0], "file": f"f{i}"} for i in range(1001)]
        elif fault == "branch-capacity":
            raw["branches"] = [f"b{i}" for i in range(52)]
        elif fault == "duplicate-branch":
            raw["branches"] = ["main", "main"]
        elif fault == "patch-capacity-hidden":
            raw["diff"][1]["patch"] = "x" * (1024**2 + 1)
        elif fault == "control-branch":
            raw["branches"] = ["untrusted\nname"]
        elif fault == "physical-capacity":
            raw["worktrees"] = [
                {"directory": REF.canonical_directory + f"/d{i}"} for i in range(32)
            ]
        with pytest.raises(ValueError):
            await c.read(REF)
        assert not c._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["physical-before", "physical-after", "blocked", "deadline"])
async def test_physical_root_and_parent_boundary_and_original_deadline_survive_all_later_awaits(
    fault, monkeypatch
):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    clock = time.time()

    async def hook(paths, count):
        if fault == "physical-before" and count == 2 or fault == "physical-after" and count == 3:
            physical.generation += 1
        if fault == "deadline" and count == 3:
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.git_review.time.time", lambda: clock + 6
            )

    physical.hook = hook
    if fault == "blocked":
        physical.blocked.add("feature")
    try:
        with pytest.raises(ValueError):
            await c.read(REF)
        assert not c._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("mode", ["branch", "committed"])
async def test_explicit_comparison_and_null_base_remain_read_only_and_do_not_invent_a_default(mode):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        raw["base"] = None
        raw["branches"] = ["rank-1", "rank-2", "rank-3"]
        raw["diff"] = []
        view = await c.read(REF, mode=mode, base="refs/heads/review", search="rank", limit=2)
        assert view.inferred_base is None and view.requested_base == "refs/heads/review"
        assert not view.clean_verified and not view.full_diff_display
        assert view.branches == ("rank-1", "rank-2") and not view.branches_complete
        assert all(
            request.url.params["base"] == "refs/heads/review"
            for kind, request in calls
            if kind == "diff"
        )
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "query",
    [
        {"mode": "branch"},
        {"mode": "committed"},
        {"base": "main"},
        {"mode": "unknown"},
        {"mode": "branch", "base": "-evil"},
        {"mode": "branch", "base": "main; touch /tmp/x"},
        {"limit": True},
        {"limit": 51},
        {"search": "x" * 129},
    ],
)
async def test_bad_queries_are_rejected_before_review_or_policy_reads(query):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        with pytest.raises(ValueError):
            await c.read(REF, **query)
        assert not calls and not writes and not physical.calls
    finally:
        await finish(p, t)


async def test_current_requires_original_view_current_feed_attestation_fence_and_nonexpired_scope(
    monkeypatch,
):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        view = await c.read(REF)
        assert c.current(view)
        physical.enabled = False
        assert not c.current(view)
        physical.enabled = True
        context = c._observed[id(view)]
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.git_review.time.time", lambda: context.deadline
        )
        assert not c.current(view)
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "attestation",
        "fence",
        "disconnect",
        "owner-feed",
        "physical",
        "root",
        "semantics",
        "evidence",
        "missing-physical",
    ],
)
async def test_current_context_cannot_survive_scope_policy_feed_or_attestation_drift(fault):
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        view = await c.read(REF)
        assert c.current(view)
        if fault == "attestation":
            t.attestation = replace(t.attestation)
        elif fault == "fence":
            p.feed.index._notice_arrival(REAL[0])
        elif fault == "disconnect":
            p.feed.index.invalidate("synthetic-disconnect")
        elif fault == "owner-feed":
            p.feed.index.owner_epoch = "changed"
        elif fault == "physical":
            physical.enabled = False
        elif fault == "root":
            foreign = REF.model_copy(update={"canonical_directory": "/foreign"})
            assert not c.current(view.model_copy(update={"reference": foreign}))
            return
        elif fault in {"semantics", "evidence"}:
            from types import MappingProxyType

            field = "semantics_sha256" if fault == "semantics" else "installed_evidence_sha256"
            c.attestations = MappingProxyType({REF: replace(c.attestations[REF], **{field: "bad"})})
        elif fault == "missing-physical":
            c.directories = None
        assert not c.current(view)
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    ["no-attestation", "schema", "semantics", "evidence", "policy", "physical", "foreign-ref"],
)
async def test_root_qualification_cannot_be_inferred_from_schema_presence_or_names(fault):
    from types import MappingProxyType

    p, t, d, c, raw, calls, writes, physical = await prepared()
    ref = REF
    try:
        if fault == "no-attestation":
            c.attestations = MappingProxyType({})
        elif fault in {"schema", "semantics", "evidence", "policy"}:
            field = {
                "schema": "schema_sha256",
                "semantics": "semantics_sha256",
                "evidence": "installed_evidence_sha256",
                "policy": "native_policy_sha256",
            }[fault]
            c.attestations = MappingProxyType(
                {
                    REF: replace(
                        c.attestations[REF], **{field: "0" * 64 if fault != "evidence" else "bad"}
                    )
                }
            )
        elif fault == "physical":
            physical.enabled = False
        else:
            ref = REF.model_copy(update={"upstream_session_id": "ses_foreign"})
        assert not c.qualified(ref)
        with pytest.raises(ValueError):
            await c.read(ref)
        assert not calls and not writes and not physical.calls
    finally:
        await finish(p, t)


async def test_transport_read_allowlist_additions_do_not_grant_mutation_operations():
    from jt_oz_bridge.adapters.opencode.transport import MUTATION_OPERATIONS, READ_OPERATIONS

    assert {"vcs.base", "vcs.branch.list"} <= READ_OPERATIONS
    assert not REVIEW_OPERATIONS & MUTATION_OPERATIONS
    p, t, d, c, raw, calls, writes, physical = await prepared()
    try:
        with pytest.raises(ValueError):
            await t.request(
                "vcs.branch.remove", query={"location": {"directory": REF.canonical_directory}}
            )
        assert not writes and not calls
    finally:
        await finish(p, t)


async def test_read_metadata_remains_possible_without_claiming_busy_original_root_is_idle(
    monkeypatch,
):
    p, t, d, c, raw, calls, writes, physical = await prepared()

    async def forbidden_mutation_capture(*args, **kwargs):
        raise AssertionError("read-only review must never request a mutation/resource proof")

    monkeypatch.setattr(p, "capture", forbidden_mutation_capture)
    # No current Idle boundary; the read-only API does not need to invent one.
    d["session.get"]["data"]["time"].pop("idle")
    d["session.get"]["data"].pop("outcome")
    try:
        view = await c.read(REF)
        assert c.current(view) and not view.clean_verified
        assert p.certified_epoch(REF, t.profile.sha256) is None
        assert not writes
    finally:
        await finish(p, t)
