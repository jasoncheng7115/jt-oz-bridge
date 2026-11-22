"""Synthetic complete metadata trees, not live/resource/adoption qualification."""

import copy
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.existing_session_graph import (
    MAX_GRAPH_DEPTH,
    V2ExistingSessionGraphObserver,
    graph_identity,
)
from jt_oz_bridge.adapters.opencode.existing_sessions import V2ExistingSessionObserver
from jt_oz_bridge.domain.existing_sessions import ExistingSessionGraphObservation
from tests.contract.test_existing_sessions import TARGET
from tests.contract.test_existing_sessions import setup as session_setup
from tests.contract.test_leaf_resources import REF, finish

CHILD = TARGET.model_copy(update={"upstream_session_id": "ses_original_child"})
GRANDCHILD = TARGET.model_copy(update={"upstream_session_id": "ses_original_grandchild"})
SIBLING = TARGET.model_copy(update={"upstream_session_id": "ses_original_sibling"})


async def setup():
    p, t, data, observer, original_state, calls, writes, _ = await session_setup()
    observer = V2ExistingSessionObserver(
        observer.anchor,
        replace(observer.protocol, operations=observer.protocol.operations | {"session.list"}),
        REF,
    )
    rows = {TARGET: original_state["info"]}
    for reference, parent, created in (
        (CHILD, TARGET, 20),
        (GRANDCHILD, CHILD, 30),
        (SIBLING, TARGET, 21),
    ):
        info = copy.deepcopy(original_state["info"])
        info.update(
            id=reference.upstream_session_id, parentID=parent.upstream_session_id, agent="task"
        )
        info["time"]["created"] = created
        rows[reference] = info
    state = {
        "rows": rows,
        "edges": {TARGET: [CHILD, SIBLING], CHILD: [GRANDCHILD]},
        "hook": None,
        "list_calls": [],
    }
    original = t.client._transport

    def handle(request):
        assert request.method == "GET"
        if state["hook"] is not None:
            response = state["hook"](request, state)
            if response is not None:
                return response
        if request.url.path == "/api/session":
            query = dict(request.url.params)
            assert set(query) in (
                {"parentID", "limit", "order"},
                {"parentID", "limit", "order", "cursor"},
            )
            assert query["limit"] == "100" and query["order"] == "asc"
            parent = TARGET.model_copy(update={"upstream_session_id": query["parentID"]})
            state["list_calls"].append(parent)
            children = state["edges"].get(parent, [])
            # Two pages on the Root prove continuation rather than first-page
            # inference. Other nodes always return their exact unfiltered list.
            if parent == TARGET and len(children) == 2:
                chosen = children[1:] if query.get("cursor") == "second" else children[:1]
                cursor = {} if query.get("cursor") == "second" else {"next": "second"}
            else:
                chosen, cursor = children, {}
            return httpx.Response(
                200, json={"data": [copy.deepcopy(rows[ref]) for ref in chosen], "cursor": cursor}
            )
        for reference, info in rows.items():
            if request.url.path == "/api/session/" + reference.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(info)})
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handle)
    graph = V2ExistingSessionGraphObserver(observer)
    return p, t, graph, state, calls, writes


async def test_two_complete_paginated_walks_preserve_original_tree_policy_and_no_execution():
    p, t, graph, state, calls, writes = await setup()
    try:
        feed_refs, index, task = p.feed.references, p.feed.index, p.feed.task
        value = await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert graph.current(value) and len(value.nodes) == 4
        assert value.reference == TARGET and value.nodes[0].parent_reference is None
        assert {node.reference: node.parent_reference for node in value.nodes} == {
            TARGET: None,
            CHILD: TARGET,
            SIBLING: TARGET,
            GRANDCHILD: CHILD,
        }
        assert value.graph_sha256 == graph_identity(tuple(reversed(value.nodes)))
        assert value.expires_at <= min(node.expires_at for node in value.nodes)
        assert not value.registered_for_execution and not value.starts_execution
        assert state["list_calls"].count(TARGET) == 4
        assert state["list_calls"].count(CHILD) == 2
        assert p.feed.references is feed_refs and p.feed.index is index and p.feed.task is task
        assert set(graph.observer.anchor.enrollments) == {REF} and not writes
        assert not any(r.url.path == "/api/session/active" for r in calls)
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    ["foreign_project", "foreign_directory", "wrong_parent", "archived", "duplicate", "cycle"],
)
async def test_unfiltered_children_cannot_hide_foreign_archived_duplicate_or_cyclic_nodes(fault):
    p, t, graph, state, calls, writes = await setup()
    if fault == "foreign_project":
        state["rows"][CHILD]["projectID"] = "other"
    elif fault == "foreign_directory":
        state["rows"][CHILD]["location"] = {"directory": "/other/project"}
    elif fault == "wrong_parent":
        state["rows"][CHILD]["parentID"] = SIBLING.upstream_session_id
    elif fault == "archived":
        state["rows"][CHILD]["time"]["archived"] = 100
    elif fault == "duplicate":
        state["edges"][TARGET] = [CHILD, CHILD]
    else:
        state["edges"][CHILD] = [TARGET]
    try:
        with pytest.raises(ContractError):
            await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert not graph._graphs and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change", ["child_added", "child_removed", "policy", "recreated", "reparented"]
)
async def test_complete_walks_reject_graph_or_original_policy_changes(change):
    p, t, graph, state, calls, writes = await setup()
    root_lists = 0

    def hook(request, state):
        nonlocal root_lists
        if (
            request.url.path == "/api/session"
            and request.url.params.get("parentID") == TARGET.upstream_session_id
            and "cursor" not in request.url.params
        ):
            root_lists += 1
            if root_lists == 2:
                if change == "child_added":
                    extra = TARGET.model_copy(
                        update={"upstream_session_id": "ses_original_new_child"}
                    )
                    row = copy.deepcopy(state["rows"][SIBLING])
                    row["id"] = extra.upstream_session_id
                    row["time"]["created"] = 40
                    state["rows"][extra] = row
                    state["edges"][TARGET].append(extra)
                elif change == "child_removed":
                    state["edges"][CHILD] = []
                elif change == "policy":
                    state["rows"][CHILD]["permissions"] = []
                elif change == "recreated":
                    state["rows"][CHILD]["time"]["created"] += 1
                else:
                    state["edges"][TARGET] = [CHILD]
                    state["edges"][GRANDCHILD] = [SIBLING]
                    state["rows"][SIBLING]["parentID"] = GRANDCHILD.upstream_session_id

    state["hook"] = hook
    try:
        with pytest.raises(ContractError):
            await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert not graph._graphs and not writes
    finally:
        await finish(p, t)


async def test_list_get_replacement_is_not_treated_as_same_original_session():
    p, t, graph, state, calls, writes = await setup()
    first = True

    def hook(request, state):
        nonlocal first
        if first and request.url.path == "/api/session/" + CHILD.upstream_session_id:
            first = False
            state["rows"][CHILD]["time"]["created"] += 1

    state["hook"] = hook
    try:
        with pytest.raises(ContractError, match="list_get_origin_changed"):
            await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert not graph._graphs and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["repeated", "empty", "too_long", "too_many_rows", "too_many_nodes"]
)
async def test_pagination_is_bounded_and_never_silently_truncates(fault):
    p, t, graph, state, calls, writes = await setup()
    page_calls = 0

    def hook(request, state):
        nonlocal page_calls
        if request.url.path == "/api/session":
            page_calls += 1
            if fault == "too_many_nodes":
                return httpx.Response(
                    200, json={"data": [state["rows"][CHILD], state["rows"][SIBLING]], "cursor": {}}
                )
            if fault == "too_many_rows":
                rows = []
                for index in range(101):
                    row = copy.deepcopy(state["rows"][CHILD])
                    row["id"] = f"ses_page_{index}"
                    rows.append(row)
                return httpx.Response(200, json={"data": rows, "cursor": {}})
            cursor = "" if fault == "empty" else "x" * 8193 if fault == "too_long" else "repeat"
            return httpx.Response(200, json={"data": [], "cursor": {"next": cursor}})

    state["hook"] = hook
    try:
        with pytest.raises(ContractError):
            await graph.children(TARGET, authorize=AsyncMock(return_value=True), remaining=1)
        assert page_calls <= 2 and not writes
    finally:
        await finish(p, t)


async def test_authority_revoked_after_page_prevents_using_its_child_entries():
    p, t, graph, state, calls, writes = await setup()
    allowed = True

    def hook(request, state):
        nonlocal allowed
        if request.url.path == "/api/session":
            allowed = False

    async def authorize():
        return allowed

    state["hook"] = hook
    try:
        with pytest.raises(ContractError, match="authority_required"):
            await graph.observe(TARGET, authorize=authorize)
        assert not graph._graphs and not writes
        assert not any(r.url.path == "/api/session/" + CHILD.upstream_session_id for r in calls)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["copy", "json", "node_copy", "observer", "node_revoked"])
async def test_graph_capability_requires_original_nodes_and_runtime_observer(change):
    p, t, graph, state, calls, writes = await setup()
    try:
        value = await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        if change == "copy":
            value = value.model_copy()
        elif change == "json":
            value = ExistingSessionGraphObservation.model_validate_json(value.model_dump_json())
        elif change == "node_copy":
            value = value.model_copy(
                update={"nodes": tuple(node.model_copy() for node in value.nodes)}
            )
        elif change == "observer":
            graph.observer = copy.copy(graph.observer)
        else:
            graph.observer._observed.pop(id(value.nodes[-1]))
        assert not graph.current(value) and not writes
    finally:
        await finish(p, t)


async def test_missing_backend_scoped_list_qualification_cannot_be_inferred_from_anchor():
    p, t, graph, state, calls, writes = await setup()
    try:
        observer = V2ExistingSessionObserver(
            graph.observer.anchor,
            replace(
                graph.observer.protocol,
                operations=graph.observer.protocol.operations - {"session.list"},
            ),
            REF,
        )
        with pytest.raises(ContractError, match="explicit_backend_list_contract"):
            V2ExistingSessionGraphObserver(observer)
        assert not state["list_calls"] and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate",
        "missing_parent",
        "cycle",
        "parent_recreated",
        "second_root",
        "foreign_owner",
        "extended_deadline",
        "execution",
    ],
)
async def test_graph_dto_enforces_complete_single_root_tree_and_original_deadline(fault):
    p, t, graph, state, calls, writes = await setup()
    try:
        value = await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        payload = value.model_dump()
        nodes = payload["nodes"] = list(payload["nodes"])
        child = next(n for n in nodes if n["reference"] == CHILD.model_dump())
        grandchild = next(n for n in nodes if n["reference"] == GRANDCHILD.model_dump())
        if fault == "duplicate":
            nodes.append(copy.deepcopy(child))
        elif fault == "missing_parent":
            nodes.remove(child)
        elif fault == "cycle":
            child["parent_reference"] = GRANDCHILD.model_dump()
            child["parent_created_at"] = grandchild["native_created_at"]
        elif fault == "parent_recreated":
            child["parent_created_at"] += 1
        elif fault == "second_root":
            child.update(parent_reference=None, parent_created_at=None)
        elif fault == "foreign_owner":
            child["owner_epoch"] = "b" * 64 if value.owner_epoch != "b" * 64 else "c" * 64
        elif fault == "extended_deadline":
            payload["expires_at"] = payload["observed_at"] + 6
        else:
            payload["starts_execution"] = True
        with pytest.raises(ValidationError):
            ExistingSessionGraphObservation.model_validate(payload)
        assert not writes
    finally:
        await finish(p, t)


async def test_metadata_graph_accepts_1000_deep_original_nodes_without_recursion():
    p, t, graph, state, calls, writes = await setup()
    try:
        value = await graph.observe(TARGET, authorize=AsyncMock(return_value=True))
        root = value.nodes[0].model_dump()
        root["expires_at"] = value.expires_at
        payload = value.model_dump() | {"nodes": [root]}
        parent_ref, parent_created = TARGET.model_dump(), root["native_created_at"]
        for index in range(1, 1000):
            row = copy.deepcopy(root)
            row["reference"]["upstream_session_id"] = f"ses_depth_{index}"
            row.update(
                native_created_at=100 + index,
                parent_reference=parent_ref,
                parent_created_at=parent_created,
            )
            parent_ref, parent_created = row["reference"], row["native_created_at"]
            payload["nodes"].append(row)
        typed = ExistingSessionGraphObservation.model_validate(payload)
        assert len(typed.nodes) == 1000 and not graph.current(typed)
        payload["nodes"].append(copy.deepcopy(payload["nodes"][-1]))
        with pytest.raises(ValidationError):
            ExistingSessionGraphObservation.model_validate(payload)
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("depth", [MAX_GRAPH_DEPTH, MAX_GRAPH_DEPTH + 1])
async def test_subagent_chain_deeper_than_the_bound_is_refused_not_truncated(depth):
    p, t, graph, state, calls, writes = await setup()
    try:
        state["edges"] = {}
        parent = TARGET
        for index in range(1, depth + 1):
            node = TARGET.model_copy(update={"upstream_session_id": f"ses_nested_{index}"})
            info = copy.deepcopy(state["rows"][CHILD])
            info.update(id=node.upstream_session_id, parentID=parent.upstream_session_id)
            info["time"]["created"] = 40 + index
            state["rows"][node] = info
            state["edges"][parent] = [node]
            parent = node
        authorize = AsyncMock(return_value=True)
        if depth > MAX_GRAPH_DEPTH:
            with pytest.raises(ContractError, match="depth_exceeded"):
                await graph.observe(TARGET, authorize=authorize)
        else:
            value = await graph.observe(TARGET, authorize=authorize)
            assert len(value.nodes) == depth + 1 and graph.current(value)
        assert not writes
    finally:
        await finish(p, t)


async def test_cursor_only_pages_cannot_evade_absolute_page_bound():
    p, t, graph, state, calls, writes = await setup()
    count = 0

    def hook(request, state):
        nonlocal count
        if request.url.path == "/api/session":
            count += 1
            return httpx.Response(200, json={"data": [], "cursor": {"next": f"cursor{count}"}})

    state["hook"] = hook
    try:
        with pytest.raises(ContractError, match="page_capacity_exceeded"):
            await graph.children(TARGET, authorize=AsyncMock(return_value=True), remaining=999)
        assert count == 1000 and not writes
    finally:
        await finish(p, t)
