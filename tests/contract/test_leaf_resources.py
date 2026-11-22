"""Synthetic resource orchestration plus installed benign pending shapes."""

import asyncio
import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed, VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    READS,
    V2LeafResourceProofs,
    root_state,
)
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_public_live_feed import (
    CONNECTED,
    OWNER,
    PROFILE,
    REAL,
    REF,
    frame,
    text_delta,
)
from tests.contract.test_v2_catalog import native

SCOPE = ProjectScope(**REF.model_dump(exclude={"upstream_session_id"}))


def fixture_data():
    info = native(
        id=REF.upstream_session_id,
        projectID="global",
        location={"directory": REF.canonical_directory},
        outcome="succeeded",
        time={"created": 1, "updated": 2, "idle": 3},
    )
    idle = {"id": "msg_idle", "type": "idle", "time": {"created": 3}, "outcome": "succeeded"}
    return {
        "session.get": {"data": info},
        "session.active": {"data": {}},
        "session.inbox.list": {"data": []},
        "session.permission.list": {"data": []},
        "session.form.list": {"data": []},
        "session.message.list": {"data": [idle], "cursor": {}},
        "session.list": {"data": [], "cursor": {}},
        "shell.list": {"location": {"directory": REF.canonical_directory}, "data": []},
    }


async def setup(data=None, hook=None, *, title_patches=None):
    data = fixture_data() if data is None else data
    calls = []

    def handler(request):
        path = request.url.path
        if request.method == "PATCH" and title_patches is not None:
            assert path == "/api/session/" + REF.upstream_session_id
            body = json.loads(request.content)
            assert set(body) == {"title"}
            title_patches.append(body)
            data["session.get"]["data"]["title"] = body["title"]
            data["session.get"]["data"]["time"]["updated"] += 1
            return httpx.Response(204)
        if path.endswith("/interrupt"):
            assert request.method == "POST" and request.content == b""
            assert dict(request.url.params) == {"resume": "false"}
            calls.append(("session.interrupt", str(request.url)))
            return httpx.Response(200, json={"interrupted": True})
        op = (
            "shell.list"
            if path == "/api/shell"
            else "session.list"
            if path == "/api/session"
            else "session.active"
            if path == "/api/session/active"
            else "session.get"
        )
        for suffix, name in [
            ("inbox", "session.inbox.list"),
            ("permission", "session.permission.list"),
            ("form", "session.form.list"),
            ("message", "session.message.list"),
        ]:
            if path.endswith("/" + suffix):
                op = name
        calls.append((op, str(request.url)))
        if hook:
            hook(op, len(calls), data)
        return httpx.Response(200, json=data[op])

    t = V2HTTPTransport(
        "http://127.0.0.1:4096",
        PROFILE,
        attestation=ContractAttestation(PROFILE.sha256, REF.backend_identity, "2.0.32", READS),
        transport=httpx.MockTransport(handler),
        verify_identity=AsyncMock(return_value=True),
    )
    proof = SimpleNamespace(owner_epoch=OWNER, model_dump=lambda **kwargs: {"fixture_owner": OWNER})
    owner = SimpleNamespace(
        enrollment=SimpleNamespace(
            backend_id=REF.backend_id,
            backend_identity=REF.backend_identity,
            version="2.0.32",
            url="http://127.0.0.1:4096",
        ),
        read=AsyncMock(return_value=proof),
    )
    f = V2PublicFeed(t, owner, (REF,))
    f.index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    f.index.accept(frame(CONNECTED))
    f.task = asyncio.create_task(asyncio.Event().wait())
    projects = {REF.project_id: V2CatalogProject(SCOPE, "global")}
    p = V2LeafResourceProofs(f, projects)
    return p, t, data, calls


async def finish(p, t):
    await p.feed.close()
    await t.close()


async def test_explicit_watch_then_double_resource_proof_matches_installed_execution_client():
    p, t, d, calls = await setup()
    try:
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        w = await p.watch(REF)
        assert w.state == ExecutionState.IDLE and w.last_outcome == "succeeded"
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(d["session.get"]["data"]))
        assert proof.reference == REF and proof.descendants == ()
        assert proof.cursor == "resource-sha256:" + w.resources_sha256
        assert proof.expires_at - proof.issued_at == 5
        client = V2ExecutionClient(t, p.projects, proofs=p)
        snapshot = await client.snapshot(REF)
        assert snapshot.state == ExecutionState.IDLE and snapshot.reconciled
        child_calls = [url for op, url in calls if op == "session.list"]
        assert child_calls and all(
            "parentID=" + REF.upstream_session_id in u
            and "directory" not in u
            and "project=" not in u
            for u in child_calls
        )
    finally:
        await finish(p, t)


async def test_stale_retained_outcome_never_overrides_positive_active_root():
    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    try:
        w = await p.watch(REF)
        assert w.state == ExecutionState.RUNNING and w.last_outcome == "succeeded"
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["running", "permission", "form"])
async def test_positive_active_state_is_provable_during_continuous_ephemeral_text(kind):
    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    expected = ExecutionState.RUNNING
    if kind != "running":
        e = next(
            e
            for e in REAL
            if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
        )
        raw = e["data"] if kind == "permission" else e["data"]["form"]
        d["session." + kind + ".list"]["data"] = [raw]
        expected = (
            ExecutionState.WAITING_PERMISSION
            if kind == "permission"
            else ExecutionState.WAITING_INPUT
        )
    original = p.bundle
    fragments = 0

    async def streaming(ref):
        nonlocal fragments
        result = await original(ref)
        fragments += 1
        p.feed.index.accept(frame(text_delta(f"evt_fragment_{fragments}")))
        return result

    p.bundle = streaming
    try:
        witness = await p.watch(REF)
        assert witness.state == expected and witness.state_only_fence
        client = V2ExecutionClient(t, p.projects, proofs=p)
        snapshot, proof = await client.qualified_snapshot(REF)
        assert snapshot.reconciled and snapshot.state == expected
        # A stream fragment after capture does not conceal changed authority.
        p.feed.index.accept(frame(text_delta("evt_after_capture")))
        client.current(REF, proof)
        assert p.valid_fence(REF, proof.resource_fence)
        assert proof.resource_fence != p.fence(REF)
        p.feed.index.accept(frame(REAL[0]))
        assert not p.valid_fence(REF, proof.resource_fence)
        with pytest.raises(ContractError):
            client.current(REF, proof)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("state", ["idle", "queued"])
async def test_ephemeral_text_never_relaxes_idle_or_queue_proofs(state):
    p, t, d, _ = await setup()
    if state == "queued":
        d["session.inbox.list"]["data"] = [
            {
                "id": "msg_queued",
                "sessionID": REF.upstream_session_id,
                "type": "user",
                "payload": {"text": "queued"},
                "delivery": "queue",
                "time": {"created": 4},
            }
        ]
    original = p.bundle

    async def changing(ref):
        result = await original(ref)
        p.feed.index.accept(frame(text_delta("evt_one_delta")))
        return result

    p.bundle = changing
    try:
        with pytest.raises(ContractError, match="boundary_changed"):
            await p.watch(REF)
    finally:
        await finish(p, t)


async def test_state_mode_fence_requires_a_current_positive_active_witness():
    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    try:
        witness = await p.watch(REF)
        assert p.valid_fence(REF, witness.resource_fence)
        p.witnesses.clear()
        assert not p.valid_fence(REF, witness.resource_fence)
    finally:
        await finish(p, t)


async def test_interrupt_uses_one_original_rpc_while_text_fragments_continue():
    from tests.contract.test_v2_execution import payload

    p, t, d, calls = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    t.attestation = replace(t.attestation, verified_operations=READS | {"session.interrupt"})
    original = p.bundle
    count = 0

    async def streaming(ref):
        nonlocal count
        result = await original(ref)
        count += 1
        p.feed.index.accept(frame(text_delta(f"evt_interrupt_fragment_{count}")))
        return result

    p.bundle = streaming
    try:
        await p.watch(REF)
        client = V2ExecutionClient(t, p.projects, proofs=p)
        request = payload("interrupt", reference=REF.model_dump(mode="json"))
        result = await client.submit(REF, request, "synthetic-stop-during-stream")
        sent = [(op, url) for op, url in calls if op == "session.interrupt"]
        assert len(sent) == 1 and REF.upstream_session_id in sent[0][1]
        assert result.status == "completed" and result.details["interrupted"] is True
        assert result.details["turn_completed"] is False
        assert result.details["children_verified_stopped"] is False
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["resource", "text_end", "permission", "owner", "disconnect"])
async def test_active_stream_tolerance_preserves_real_resource_and_authority_boundaries(change):
    from tests.contract.test_public_live_feed import ROOT

    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    original = p.bundle
    count = 0

    async def changing(ref):
        nonlocal count
        result = await original(ref)
        count += 1
        p.feed.index.accept(frame(text_delta(f"evt_fragment_{count}")))
        if count == 1:
            if change == "resource":
                d["session.get"]["data"]["title"] = "a real resource change"
            elif change == "text_end":
                ended = next(
                    e
                    for e in json.loads((ROOT / "parsed-feed.json").read_text())["events"]
                    if e["type"] == "session.text.ended"
                )
                p.feed.index.accept(frame(ended))
            elif change == "permission":
                p.feed.index.accept(frame(next(e for e in REAL if e["type"] == "permission.asked")))
            elif change == "owner":
                p.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
            else:
                p.feed.index.invalidate("lost")
        return result

    p.bundle = changing
    try:
        with pytest.raises(ContractError):
            await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["permission", "form"])
async def test_real_pending_kind_is_indexed_from_catalog_not_guessed_id_prefix(kind):
    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    e = next(
        e
        for e in REAL
        if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
    )
    raw = e["data"] if kind == "permission" else e["data"]["form"]
    d["session." + kind + ".list"]["data"] = [raw]
    try:
        w = await p.watch(REF)
        assert w.state == (
            ExecutionState.WAITING_PERMISSION
            if kind == "permission"
            else ExecutionState.WAITING_INPUT
        )
        assert await p.interaction_kind(REF, raw["id"], w.connection_epoch) == kind
        assert await p.interaction_kind(REF, "per_unseen", w.connection_epoch) is None
    finally:
        await finish(p, t)


async def test_unpreviewable_pending_form_does_not_hide_waiting_state():
    p, t, d, _ = await setup()
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    form = copy.deepcopy(next(e["data"]["form"] for e in REAL if e["type"] == "form.created"))
    # Native wire accepts URL strings; bridge answer normalization refuses
    # unsupported external schemes. That must not hide a real pending request.
    form["fields"] = [{"key": "external", "type": "external", "url": "file:///etc/passwd"}]
    d["session.form.list"]["data"] = [form]
    try:
        assert (await p.watch(REF)).state == ExecutionState.WAITING_INPUT
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        "parent",
        "project",
        "directory",
        "identity",
        "child",
        "child_cursor",
        "shell_location",
        "empty_message_cursor",
        "many_messages",
        "pending_foreign",
        "pending_duplicate",
        "kind_conflict",
    ],
)
async def test_scope_and_resource_boundary_rejections(change):
    p, t, d, _ = await setup()
    if change == "parent":
        d["session.get"]["data"]["parentID"] = "ses_parent"
    elif change == "project":
        d["session.get"]["data"]["projectID"] = "other"
    elif change == "directory":
        d["session.get"]["data"]["location"]["directory"] = "/other"
    elif change == "identity":
        d["session.get"]["data"]["id"] = "ses_other"
    elif change == "child":
        d["session.list"]["data"] = [native(id="ses_child", parentID=REF.upstream_session_id)]
    elif change == "child_cursor":
        d["session.list"]["cursor"]["next"] = "opaque"
    elif change == "shell_location":
        d["shell.list"]["location"]["directory"] = "/other"
    elif change == "empty_message_cursor":
        d["session.message.list"] = {"data": [], "cursor": {"next": "opaque"}}
    elif change == "many_messages":
        d["session.message.list"]["data"] *= 2
    else:
        permission = copy.deepcopy(next(e["data"] for e in REAL if e["type"] == "permission.asked"))
        d["session.permission.list"]["data"] = [permission]
        if change == "pending_foreign":
            permission["sessionID"] = "ses_other"
        elif change == "pending_duplicate":
            d["session.permission.list"]["data"] *= 2
        else:
            form = copy.deepcopy(
                next(e["data"]["form"] for e in REAL if e["type"] == "form.created")
            )
            form["id"] = permission["id"]
            d["session.form.list"]["data"] = [form]
    try:
        with pytest.raises(ContractError):
            await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change", ["outcome", "idle_timestamp", "latest_type", "absent_idle", "absent_message"]
)
async def test_active_absence_does_not_prove_idle_without_matching_positive_resources(change):
    p, t, d, _ = await setup()
    if change == "outcome":
        d["session.get"]["data"]["outcome"] = "failed"
    elif change == "idle_timestamp":
        d["session.get"]["data"]["time"]["idle"] = 4
    elif change == "latest_type":
        d["session.message.list"]["data"] = [
            {"id": "msg_new", "type": "user", "time": {"created": 4}, "content": []}
        ]
    elif change == "absent_idle":
        d["session.get"]["data"]["time"].pop("idle")
    else:
        d["session.message.list"]["data"] = []
    try:
        with pytest.raises(ContractError):
            await p.watch(REF)
    finally:
        await finish(p, t)


async def test_pristine_state_needs_all_empty_resources_and_no_retained_outcome():
    p, t, d, _ = await setup()
    d["session.get"]["data"].pop("outcome")
    d["session.get"]["data"]["time"].pop("idle")
    d["session.message.list"]["data"] = []
    try:
        assert (await p.watch(REF)).state == ExecutionState.IDLE
    finally:
        await finish(p, t)


async def test_unresolved_running_shell_blocks_idle_without_claiming_it_was_stopped():
    p, t, d, _ = await setup()
    d["shell.list"]["data"] = [
        {
            "id": "sh_original",
            "status": "running",
            "command": "test",
            "cwd": REF.canonical_directory,
            "shell": "/bin/bash",
            "file": "/tmp/log",
            "metadata": {},
            "time": {"started": 1},
        }
    ]
    try:
        with pytest.raises(ContractError, match="background_work"):
            await p.watch(REF)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["info", "event", "owner", "attestation"])
async def test_resources_or_event_generation_changing_between_reads_fail_closed(change):
    p, t, d, calls = await setup()
    try:
        await p.watch(REF)
        expected = digest(d["session.get"]["data"])
        original = p.bundle
        count = 0

        async def changing(ref):
            nonlocal count
            result = await original(ref)
            count += 1
            if count == 1:
                if change == "info":
                    d["session.get"]["data"]["title"] = "changed"
                elif change == "event":
                    p.feed.index.accept(frame(REAL[0]))
                elif change == "owner":
                    p.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
                else:
                    t.attestation = None
            return result

        p.bundle = changing
        with pytest.raises(ContractError) as error:
            await p.prove(REF, INSTALLED_SCHEMA, expected)
        assert isinstance(error.value, SnapshotBoundaryChanged) == (change in {"info", "event"})
    finally:
        await finish(p, t)


@pytest.mark.parametrize("active", [False, True])
async def test_received_uncommitted_state_event_already_invalidates_prior_before_send_proof(active):
    p, t, d, _ = await setup()
    if active:
        d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    try:
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(d["session.get"]["data"]))
        client = V2ExecutionClient(t, p.projects, proofs=p)
        client.current(REF, proof)
        p.feed.index._notice_arrival(REAL[0])
        assert p.feed.index.pop() is None and p.feed.index.revision == 0
        assert not p.valid_fence(REF, proof.resource_fence)
        with pytest.raises(ContractError):
            client.current(REF, proof)
    finally:
        await finish(p, t)


async def test_new_scoped_event_invalidates_state_proof_without_changing_request_epoch():
    p, t, d, _ = await setup()
    try:
        w = await p.watch(REF)
        old = w.connection_epoch
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(d["session.get"]["data"]))
        client = V2ExecutionClient(t, p.projects, proofs=p)
        client.current(REF, proof)
        p.feed.index.accept(frame(REAL[0]))
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == old
        assert not p.valid_fence(REF, proof.resource_fence)
        with pytest.raises(ContractError):
            client.current(REF, proof)
        p.feed.index.invalidate("disconnected")
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


async def test_missing_read_attestation_wrong_contract_and_unwatched_reference_fail():
    p, t, d, _ = await setup()
    try:
        with pytest.raises(ContractError, match="not_watched"):
            await p.prove(REF, INSTALLED_SCHEMA, digest(d["session.get"]["data"]))
        t.attestation = ContractAttestation(
            PROFILE.sha256, REF.backend_identity, "2.0.32", READS - {"shell.list"}
        )
        with pytest.raises(ContractError):
            await p.watch(REF)
        assert p.certified_epoch(REF, "0" * 64) is None
        with pytest.raises(ContractError):
            await p.watch(REF.model_copy(update={"project_id": "other"}))
    finally:
        await finish(p, t)


def test_pure_root_classification_does_not_use_prior_outcome_as_current_state():
    base = {
        "active": True,
        "permissions": [],
        "forms": [],
        "inbox_ids": [],
        "running_shell_ids": [],
        "info": {"outcome": "failed", "time": {"idle": 1}},
        "latest": {"type": "idle", "time": {"created": 1}, "outcome": "failed"},
    }
    assert root_state(base) == ExecutionState.RUNNING
    base["active"] = False
    assert root_state(base) == ExecutionState.IDLE
    base["inbox_ids"] = ["msg_queued"]
    assert root_state(base) == ExecutionState.QUEUED


async def test_other_enrolled_session_events_do_not_invalidate_this_roots_state_fence():
    p, t, d, _ = await setup()
    other = REF.model_copy(update={"upstream_session_id": "ses_other"})
    p.feed.references = (REF, other)
    p.feed.index = VolatileFeedIndex(PROFILE, (REF, other), OWNER)
    p.feed.index.accept(frame(CONNECTED))
    try:
        w = await p.watch(REF)
        event = json.loads(
            json.dumps(REAL[0]).replace(REF.upstream_session_id, other.upstream_session_id)
        )
        p.feed.index.accept(frame(event))
        assert p.valid_fence(REF, w.resource_fence)
        assert p.feed.index.revision_for(REF) == 0
        assert p.feed.index.revision_for(other) == 1
    finally:
        await finish(p, t)


@pytest.mark.parametrize("guard", [None, lambda ref, fence: False, lambda ref, fence: 1])
async def test_resource_fenced_proof_requires_a_positive_strict_provider_guard(guard):
    p, t, d, _ = await setup()
    try:
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(d["session.get"]["data"]))
        client = V2ExecutionClient(t, p.projects, proofs=p)
        p.valid_fence = guard
        with pytest.raises(ContractError):
            client.current(REF, proof)
    finally:
        await finish(p, t)


def test_actual_no_message_cancel_resources_remain_unresolved_despite_prior_success():
    from pathlib import Path

    e = json.loads(
        Path(
            "tests/fixtures/installed/opencode-v2.0.32/live-native-cancel-20261017.json"
        ).read_text()
    )
    assert e["form_state"] == {"status": "cancelled"}
    assert not e["selected_active"] and e["retained_outcome"] == "succeeded"
    assert e["latest_message_fields"]["type"] == "assistant"
    assert e["session_time"]["idle"] < e["latest_message_fields"]["time"]["created"]
    bundle = {
        "active": e["selected_active"],
        "permissions": [],
        "forms": [],
        "inbox_ids": [],
        "running_shell_ids": [],
        "info": {"outcome": e["retained_outcome"], "time": e["session_time"]},
        "latest": e["latest_message_fields"],
    }
    with pytest.raises(ContractError, match="not_positively_reconciled"):
        root_state(bundle)


def test_actual_leaf_recovery_preserves_original_ref_and_native_event_positions():
    import hashlib
    from pathlib import Path

    root = Path("tests/fixtures/installed/opencode-v2.0.32")
    m = json.loads((root / "manifest.json").read_text())
    for f in (
        m["resource_source_files"]
        + [m["resource_recovery_capture"]]
        + m["resource_static_observations"]
    ):
        assert hashlib.sha256((root / f["path"]).read_bytes()).hexdigest() == f["sha256"]
    evidence = json.loads((root / "live-leaf-recovery-20261017.json").read_text())
    assert evidence["prior_unresolved_state_correctly_rejected"] and evidence["passed"]
    assert not evidence["automatic_retry"] and evidence["exact_new_assistant_marker"]
    # Offline replay uses an explicitly noncertified fixture backend identity.
    # Installed report identity is retained, never promoted to a live authority.
    assert evidence["reference"]["upstream_session_id"] == REF.upstream_session_id
    assert evidence["reference"]["canonical_directory"] == REF.canonical_directory
    assert evidence["final_snapshot"]["reference"] == evidence["reference"]
    assert evidence["final_snapshot"]["state"] == "idle"
    assert evidence["final_snapshot"]["cursor"].startswith("resource-sha256:")
    i = VolatileFeedIndex(PROFILE, (REF,), OWNER)
    i.accept(frame(CONNECTED))
    capture = json.loads((root / m["resource_recovery_capture"]["path"]).read_text())
    for e in capture["events"]:
        item = i.accept(frame(e))
        assert item.reference == REF
        assert item.native_seq == e.get("durable", {}).get("seq")
    assert i.observed_position(REF) == 83


async def test_rename_readback_settles_its_sse_fence_without_replaying_the_title_patch():
    from jt_oz_bridge.domain.execution import HumanMessage
    from jt_oz_bridge.domain.session_lifecycle import SessionRename, SessionRenameOutcome

    patches = []
    post_patch_info_reads = 0
    injected = False

    def hook(operation, count, data):
        nonlocal post_patch_info_reads, injected
        if patches and operation == "session.get":
            post_patch_info_reads += 1
            if post_patch_info_reads == 2:
                event = copy.deepcopy(next(e for e in REAL if "durable" in e))
                event.update(
                    id="evt_synthetic_title_change",
                    type="session.renamed",
                    data={"sessionID": REF.upstream_session_id, "title": "Changed title"},
                )
                p.feed.index.accept(frame(event))
                injected = True

    p, t, data, _ = await setup(hook=hook, title_patches=patches)
    data["session.get"]["data"]["title"] = "Original title"
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | {"session.update"}
    )
    guard = SimpleNamespace(
        enrolled=lambda ref, operation: ref == REF and operation == "session.rename",
        authorize=AsyncMock(return_value=object()),
        current=lambda *args: True,
    )
    client = V2ExecutionClient(t, p.projects, proofs=p, scope_guard=guard)
    change = SessionRename(previous_title="Original title", target_title="Changed title")
    source = HumanMessage(
        realm_id="synthetic",
        channel_id=4,
        topic="synthetic",
        message_id=1,
        revision=0,
        author_id=9,
        text="!oz rename Changed title",
    )
    try:
        await p.watch(REF)
        admission = await client.submit(
            REF,
            {
                "operation": "session.rename",
                "reference": REF.model_dump(mode="json"),
                "source": source.model_dump(mode="json"),
                "change": change.model_dump(mode="json"),
                "reply_locale": "en",
            },
            "synthetic-title-race",
        )
        outcome = SessionRenameOutcome.model_validate(admission.details)
        assert outcome.observed_title == "Changed title" and not outcome.starts_execution
        assert injected and post_patch_info_reads >= 6
        assert patches == [{"title": "Changed title"}]
    finally:
        await finish(p, t)


async def test_authorized_feed_append_preserves_original_fence_without_granting_new_execution():
    p, t, data, calls = await setup()
    new = REF.model_copy(update={"upstream_session_id": "ses_synthetic_new_root"})
    try:
        p.feed.index.accept(frame(REAL[0]))
        witness = await p.watch(REF)
        index = p.feed.index
        epoch = index.connection_epoch
        positions = dict(index._positions)
        seen = dict(index._seen)
        await p.feed.enroll_reference(new, authorize=AsyncMock(return_value=True))
        assert p.feed.index is index and index.connection_epoch == epoch
        assert dict(index._positions) == positions and dict(index._seen) == seen
        assert p.valid_fence(REF, witness.resource_fence)
        assert p.certified_epoch(new, INSTALLED_SCHEMA) is None
        changed = json.loads(
            json.dumps(REAL[0]).replace(REF.upstream_session_id, new.upstream_session_id)
        )
        changed["id"] = "evt_synthetic_new_root"
        observed = index.accept(frame(changed))
        assert observed.reference == new
        assert p.valid_fence(REF, witness.resource_fence)
        assert p.feed.references == (REF, new)
        before = len(index.references)
        await p.feed.enroll_reference(new, authorize=AsyncMock(return_value=True))
        assert len(index.references) == before
        # The synthetic server still returns the original Root: feed scope
        # expansion alone cannot promote it into a qualified new execution.
        with pytest.raises(ContractError, match="root_scope"):
            await p.watch(new)
        assert p.certified_epoch(new, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize("value", [False, 1, None])
async def test_feed_adoption_requires_strict_explicit_authority(value):
    p, t, data, calls = await setup()
    new = REF.model_copy(update={"upstream_session_id": "ses_synthetic_new_root"})
    try:
        with pytest.raises(ContractError, match="authority"):
            await p.feed.enroll_reference(new, authorize=AsyncMock(return_value=value))
        assert p.feed.references == (REF,)
        assert tuple(p.feed.index.references.values()) == (REF,)
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "field", ["backend_id", "backend_identity", "project_id", "canonical_directory"]
)
async def test_feed_adoption_cannot_expand_existing_project_or_directory(field):
    p, t, data, calls = await setup()
    new = REF.model_copy(
        update={field: "/foreign" if field == "canonical_directory" else "foreign"}
    )
    authorize = AsyncMock(return_value=True)
    try:
        with pytest.raises(ContractError, match="existing_project"):
            await p.feed.enroll_reference(new, authorize=authorize)
        assert not authorize.await_count
        assert p.feed.references == (REF,)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["owner", "attestation", "connection"])
async def test_feed_identity_change_across_authority_await_never_adds_a_reference(fault):
    p, t, data, calls = await setup()
    new = REF.model_copy(update={"upstream_session_id": "ses_synthetic_new_root"})

    async def authorize():
        if fault == "owner":
            p.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
        elif fault == "attestation":
            t.attestation = replace(t.attestation)
        else:
            p.feed.index.invalidate("synthetic_reconnect")
            replacement = VolatileFeedIndex(PROFILE, (REF,), OWNER)
            replacement.accept(frame({**CONNECTED, "id": "evt_synthetic_new_connection"}))
            p.feed.index = replacement
        return True

    try:
        with pytest.raises(ContractError):
            await p.feed.enroll_reference(new, authorize=authorize)
        assert p.feed.references == (REF,)
        assert new.upstream_session_id not in p.feed.index.references
    finally:
        await finish(p, t)


async def test_readonly_root_scope_before_mutation_watch_never_certifies_execution():
    from jt_oz_bridge.adapters.opencode.resources import ReadOnlyRootScope

    p, t, data, calls = await setup()
    client = V2ExecutionClient(t, p.projects, proofs=p)
    try:
        assert p.read_epoch(REF, INSTALLED_SCHEMA) is None
        scope = await p.read_scope(REF)
        assert isinstance(scope, ReadOnlyRootScope)
        assert scope.reference == REF and scope.native_project_id == "global"
        assert scope.owner_epoch == OWNER and scope.expires_at - scope.issued_at == 5
        assert scope.session_info_sha256 == digest(data["session.get"]["data"])
        assert p.read_epoch(REF, INSTALLED_SCHEMA) == scope.connection_epoch
        assert not hasattr(scope, "state") and not hasattr(scope, "cursor")
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None and not p._watched
        assert not p.witnesses
        assert [op for op, _url in calls] == ["session.get", "session.get"]
        assert t.verify_identity.await_count == 2
        with pytest.raises(ContractError, match="unavailable"):
            client.epoch(REF)
        with pytest.raises(ContractError, match="not_watched"):
            await p.prove(REF, INSTALLED_SCHEMA, scope.session_info_sha256)
        assert not any(cap.supported for cap in client.capabilities(REF).values())
        with pytest.raises(ContractError):
            await client.snapshot(REF)
        # The normal strict watch still works independently after actual Idle
        # reconciliation. Read enrollment was never substituted for it.
        await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == scope.connection_epoch
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "root",
        "project",
        "directory",
        "parent",
        "archive",
        "metadata",
        "owner",
        "feed-closed",
        "feed-replaced",
        "task",
        "attestation",
        "peer",
        "timeout",
    ],
)
async def test_readonly_scope_rejects_changed_scope_owner_feed_or_qualification(fault, monkeypatch):
    import jt_oz_bridge.adapters.opencode.resources as module

    p = None
    reads = 0
    clock = [1000.0]

    def change(op, _count, data):
        nonlocal reads
        if op != "session.get":
            return
        reads += 1
        info = data["session.get"]["data"]
        if reads == 1:
            if fault == "owner":
                p.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
            elif fault == "feed-closed":
                p.feed.index.invalidate("synthetic lost feed")
            elif fault == "feed-replaced":
                index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
                index.accept(frame(CONNECTED))  # Same epoch cannot hide replacement.
                p.feed.index = index
            elif fault == "task":
                p.feed.task.cancel()
            elif fault == "attestation":
                t.attestation = replace(t.attestation)
            elif fault == "timeout":
                clock[0] += 5
        if fault == "metadata" and reads == 2:
            info["title"] = "Changed original metadata"
        if fault == "root":
            info["id"] = "ses_foreign"
        elif fault == "project":
            info["projectID"] = "foreign"
        elif fault == "directory":
            info["location"]["directory"] = "/foreign"
        elif fault == "parent":
            info["parentID"] = "ses_parent"
        elif fault == "archive":
            info["time"]["archived"] = 4

    p, t, data, calls = await setup(hook=change)
    if fault == "peer":
        t.verify_identity.side_effect = [True, False]
    if fault == "timeout":
        monkeypatch.setattr(module.time, "time", lambda: clock[0])
    try:
        with pytest.raises(ContractError):
            await p.read_scope(REF)
        assert p.read_epoch(REF, INSTALLED_SCHEMA) is None
        assert not p._watched and not p._read_watched and not p.witnesses
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["expired", "future", "schema", "owner", "feed", "task", "attestation"]
)
async def test_read_epoch_requires_current_readonly_scope_without_promoting_mutation(
    fault, monkeypatch
):
    import jt_oz_bridge.adapters.opencode.resources as module

    p, t, data, calls = await setup()
    try:
        scope = await p.read_scope(REF)
        contract = INSTALLED_SCHEMA
        if fault == "expired":
            monkeypatch.setattr(module.time, "time", lambda: scope.expires_at)
        elif fault == "future":
            monkeypatch.setattr(module.time, "time", lambda: scope.issued_at - 0.01)
        elif fault == "schema":
            contract = "a" * 64
        elif fault == "owner":
            p.feed.index.owner_epoch = "b" * 64
        elif fault == "attestation":
            t.attestation = replace(t.attestation)
        elif fault == "feed":
            index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
            index.accept(frame(CONNECTED))
            p.feed.index = index
        else:
            p.feed.task.cancel()
            await asyncio.sleep(0)
        assert p.read_epoch(REF, contract) is None
        assert not p._watched and not p.witnesses
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


async def test_failed_readonly_refresh_does_not_borrow_a_previous_or_mutation_watch():
    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        original_epoch = p.certified_epoch(REF, INSTALLED_SCHEMA)
        await p.read_scope(REF)
        t.verify_identity.return_value = False
        with pytest.raises(ContractError, match="identity_unverified"):
            await p.read_scope(REF)
        assert p.read_epoch(REF, INSTALLED_SCHEMA) is None
        # It is an independently established mutation watch, not a fallback
        # granted by the failed read. Its validation rules are unchanged.
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == original_epoch
    finally:
        await finish(p, t)


async def test_readonly_scope_rejects_owner_provider_not_matching_captured_feed_owner():
    p, t, data, calls = await setup()
    changed = SimpleNamespace(
        owner_epoch="b" * 64, model_dump=lambda **kwargs: {"fixture_owner": "b" * 64}
    )
    p.feed.current_owner = AsyncMock(return_value=changed)
    try:
        # Even a trusted-provider integration mistake cannot create a returned
        # scope for an owner different from the captured original feed.
        with pytest.raises(ContractError, match="owner_or_feed_boundary"):
            await p.read_scope(REF)
        assert not p._read_watched and not p._watched and not p.witnesses
    finally:
        await finish(p, t)


def background_shell(identity="sh_original"):
    return {
        "id": identity,
        "status": "running",
        "command": "test",
        "cwd": REF.canonical_directory,
        "shell": "/bin/bash",
        "file": "/private/not-read",
        "metadata": {"sessionID": REF.upstream_session_id, "background": True},
        "time": {"started": 1},
    }


async def test_background_report_requires_two_complete_stable_bundles_and_never_idle():
    from jt_oz_bridge.adapters.opencode.resources import BackgroundRootWork

    p, t, data, calls = await setup()
    data["shell.list"]["data"] = [background_shell("sh_z"), background_shell("sh_a")]
    try:
        with pytest.raises(BackgroundRootWork) as caught:
            await p.watch(REF)
        work = caught.value
        assert work.reference == REF and work.contract_sha256 == INSTALLED_SCHEMA
        assert work.running_shell_ids == ("sh_a", "sh_z")
        assert work.owner_epoch == OWNER
        assert work.connection_epoch == p.generation(REF)
        assert work.session_info_sha256 == digest(data["session.get"]["data"])
        assert work.resources_sha256 == digest(await p.bundle(REF))
        assert work.resource_fence == p.fence(REF)
        assert work.expires_at - work.issued_at == 5
        assert not hasattr(work, "state") and not hasattr(work, "cursor")
        assert p.is_current_background(work)
        assert sum(op == "session.get" for op, _url in calls) == 3
        assert not p.witnesses and not p._watched
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        # Independent read scope is permitted without approving these shells.
        await p.read_scope(REF)
        assert p.read_epoch(REF, INSTALLED_SCHEMA)
        assert p.is_current_background(work)
        assert not p._watched
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "metadata",
        "shell-id",
        "shell-metadata",
        "event",
        "owner",
        "feed",
        "attestation",
        "expected-info",
        "timeout",
    ],
)
async def test_background_shape_never_hides_unvalidated_resource_or_owner_drift(fault, monkeypatch):
    import jt_oz_bridge.adapters.opencode.resources as module
    from jt_oz_bridge.adapters.opencode.resources import BackgroundRootWork

    p, t, data, calls = await setup()
    data["shell.list"]["data"] = [background_shell()]
    original = p.bundle
    count = 0
    clock = [1000.0]
    if fault == "timeout":
        monkeypatch.setattr(module.time, "time", lambda: clock[0])

    async def changing(ref):
        nonlocal count
        result = await original(ref)
        count += 1
        if count == 1:
            if fault == "metadata":
                data["session.get"]["data"]["title"] = "Changed metadata"
            elif fault == "shell-id":
                data["shell.list"]["data"][0]["id"] = "sh_changed"
            elif fault == "shell-metadata":
                # Same id is not a complete stable shell resource.
                data["shell.list"]["data"][0]["command"] = "changed command"
            elif fault == "event":
                p.feed.index.accept(frame(text_delta("evt_background_delta")))
            elif fault == "owner":
                p.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
            elif fault == "feed":
                index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
                index.accept(frame(CONNECTED))
                p.feed.index = index
            elif fault == "attestation":
                t.attestation = replace(t.attestation)
            elif fault == "timeout":
                clock[0] += 5
        return result

    p.bundle = changing
    try:
        with pytest.raises(ContractError) as caught:
            await p.capture(REF, "f" * 64 if fault == "expected-info" else None)
        assert not isinstance(caught.value, BackgroundRootWork)
        assert not p._background_work and not p._watched and not p.witnesses
    finally:
        await finish(p, t)


@pytest.mark.parametrize("stage", ["second-bundle", "last-owner"])
@pytest.mark.parametrize("elapsed", [4.9, 5.0, 6.0, -0.01])
async def test_idle_capture_uses_first_observation_clock_not_completion(
    stage, elapsed, monkeypatch
):
    import jt_oz_bridge.adapters.opencode.resources as module

    p, t, _data, _calls = await setup()
    started = module.time.time()
    clock = [started]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    original = p.bundle if stage == "second-bundle" else p.feed.current_owner
    calls = 0

    async def delayed(*args, **kwargs):
        nonlocal calls
        result = await original(*args, **kwargs)
        calls += 1
        if calls == 2:
            clock[0] += elapsed
        return result

    if stage == "second-bundle":
        p.bundle = delayed
    else:
        p.feed.current_owner = delayed
    try:
        if 0 <= elapsed < 5:
            witness = await p.watch(REF, require_idle=True)
            assert witness.state == ExecutionState.IDLE
            assert witness.issued_at == started
            # Its remaining lifetime is0.1s, never a new full5s from completion.
            assert witness.issued_at + 5 - clock[0] == pytest.approx(0.1)
        else:
            with pytest.raises(ContractError, match="leaf_resource_boundary_expired"):
                await p.watch(REF, require_idle=True)
            assert not p._watched and not p.witnesses and not p._idle_anchors
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["expired", "mutated", "forged", "event", "feed", "owner", "attestation"]
)
async def test_background_report_is_minted_current_evidence_not_a_reusable_claim(
    fault, monkeypatch
):
    import jt_oz_bridge.adapters.opencode.resources as module
    from jt_oz_bridge.adapters.opencode.resources import BackgroundRootWork

    p, t, data, calls = await setup()
    data["shell.list"]["data"] = [background_shell()]
    try:
        with pytest.raises(BackgroundRootWork) as caught:
            await p.watch(REF)
        work = caught.value
        assert p.is_current_background(work)
        if fault == "expired":
            monkeypatch.setattr(module.time, "time", lambda: work.expires_at)
        elif fault == "mutated":
            work.running_shell_ids = ("sh_foreign",)
        elif fault == "forged":
            work = BackgroundRootWork(**vars(work))
        elif fault == "event":
            p.feed.index.accept(frame(text_delta("evt_background_changed")))
        elif fault == "feed":
            index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
            index.accept(frame(CONNECTED))
            p.feed.index = index
        elif fault == "owner":
            p.feed.index.owner_epoch = "b" * 64
        else:
            t.attestation = replace(t.attestation)
        assert not p.is_current_background(work)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


@pytest.mark.parametrize("same_epoch", [False, True])
async def test_mutation_watch_does_not_adopt_a_new_feed_generation(same_epoch):
    p, t, data, calls = await setup()
    try:
        witness = await p.watch(REF)
        old_epoch = witness.connection_epoch
        index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
        index.accept(
            frame(CONNECTED if same_epoch else {**CONNECTED, "id": "evt_other_generation"})
        )
        p.feed.index = index
        assert (p.generation(REF) == old_epoch) is same_epoch
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        assert not p.valid_fence(REF, witness.resource_fence)
        assert not p._watched and not p.witnesses
        with pytest.raises(ContractError, match="not_watched"):
            await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        # Only a new actual strict watch can certify the new feed.
        fresh = await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == fresh.connection_epoch
    finally:
        await finish(p, t)


async def test_idle_required_promotion_checks_before_committing_watch_membership():
    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        with pytest.raises(ContractError, match="idle_required"):
            await p.watch(REF, require_idle=True)
        assert not p._watched and not p.witnesses
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        data["session.active"]["data"].clear()
        witness = await p.watch(REF, require_idle=True)
        assert witness.state == ExecutionState.IDLE
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == witness.connection_epoch
    finally:
        await finish(p, t)


async def test_failed_watch_revokes_only_its_root_and_preserves_other_root_and_read_scope():
    p, t, data, calls = await setup()
    other = REF.model_copy(update={"upstream_session_id": "ses_sibling_root"})
    await p.feed.enroll_reference(other, authorize=AsyncMock(return_value=True))
    delegate = t.client._transport
    broken = False

    def scoped(request):
        response = delegate.handler(request)
        if request.url.path == "/api/session/" + other.upstream_session_id:
            raw = response.json()
            raw["data"]["id"] = other.upstream_session_id
            return httpx.Response(200, json=raw)
        if request.url.path == "/api/session/" + REF.upstream_session_id and broken:
            raw = response.json()
            raw["data"]["id"] = "ses_wrong_original"
            return httpx.Response(200, json=raw)
        return response

    t.client._transport = httpx.MockTransport(scoped)
    try:
        await p.watch(REF)
        sibling = await p.watch(other)
        await p.read_scope(REF)
        broken = True
        with pytest.raises(ContractError, match="root_scope_changed"):
            await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        assert REF not in p._watched and REF not in p.witnesses
        assert p.certified_epoch(other, INSTALLED_SCHEMA) == sibling.connection_epoch
        assert p.valid_fence(other, sibling.resource_fence)
        assert other in p._watched and other in p.witnesses
        assert p.read_epoch(REF, INSTALLED_SCHEMA)  # Independent read cache remains.
        p.revoke_watch(other)
        assert not p._watched and not p.witnesses
        assert p.read_epoch(REF, INSTALLED_SCHEMA)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("state", ["running", "queued"])
async def test_positive_idle_required_is_only_fully_verified_nonidle_without_watch(state):
    from jt_oz_bridge.adapters.opencode.resources import PositiveIdleRequired

    p, t, data, calls = await setup()
    expected = ExecutionState.RUNNING
    if state == "running":
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    else:
        expected = ExecutionState.QUEUED
        data["session.inbox.list"]["data"] = [
            {
                "id": "msg_pending",
                "sessionID": REF.upstream_session_id,
                "type": "user",
                "payload": {"text": "pending"},
                "delivery": "queue",
                "time": {"created": 4},
            }
        ]
    try:
        with pytest.raises(PositiveIdleRequired) as caught:
            await p.watch(REF, require_idle=True)
        witness = caught.value.witness
        assert witness.state == expected
        assert witness.reference == REF and witness.owner_epoch == OWNER
        assert witness.session_info_sha256 == digest(data["session.get"]["data"])
        assert witness.resources_sha256 == digest(await p.bundle(REF))
        assert not p._watched and not p.witnesses
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
    finally:
        await finish(p, t)


async def test_nonidle_shape_with_unstable_resources_never_raises_positive_idle_required():
    from jt_oz_bridge.adapters.opencode.resources import PositiveIdleRequired

    p, t, data, calls = await setup()
    data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    original = p.bundle
    count = 0

    async def changing(ref):
        nonlocal count
        result = await original(ref)
        count += 1
        if count == 1:
            data["session.get"]["data"]["title"] = "Changed scope metadata"
        return result

    p.bundle = changing
    try:
        with pytest.raises(ContractError) as caught:
            await p.watch(REF, require_idle=True)
        assert isinstance(caught.value, SnapshotBoundaryChanged)
        assert not isinstance(caught.value, PositiveIdleRequired)
        assert not p._watched and not p.witnesses
    finally:
        await finish(p, t)


async def test_dispatch_owner_epoch_comes_from_exact_current_idle_proof_without_io():
    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        before = (len(calls), p.feed.owner.read.await_count, t.verify_identity.await_count)
        witness = p.witnesses[REF]
        assert p.dispatch_owner_epoch(REF, proof) == OWNER
        assert p.witnesses[REF] is witness
        assert before == (len(calls), p.feed.owner.read.await_count, t.verify_identity.await_count)
        assert proof.state == ExecutionState.IDLE
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "reference",
        "schema",
        "connection",
        "owner-evidence",
        "session-info",
        "resource-fence",
        "cursor",
        "issued",
        "expires",
        "state",
        "descendants",
        "revoked",
        "feed",
        "owner",
        "expired",
        "future",
        "changed-witness",
        "pending",
        "read-scope",
    ],
)
async def test_dispatch_owner_epoch_rejects_stale_foreign_or_readonly_evidence(fault, monkeypatch):
    import jt_oz_bridge.adapters.opencode.resources as module

    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        if fault == "reference":
            proof = proof.model_copy(
                update={"reference": REF.model_copy(update={"upstream_session_id": "ses_foreign"})}
            )
        elif fault == "schema":
            proof = proof.model_copy(update={"contract_sha256": "b" * 64})
        elif fault == "connection":
            proof = proof.model_copy(update={"connection_epoch": "foreign-generation"})
        elif fault == "owner-evidence":
            proof = proof.model_copy(update={"ownership_evidence_sha256": "b" * 64})
        elif fault == "session-info":
            proof = proof.model_copy(update={"session_info_sha256": "b" * 64})
        elif fault == "resource-fence":
            proof = proof.model_copy(update={"resource_fence": "b" * 64})
        elif fault == "cursor":
            proof = proof.model_copy(update={"cursor": "resource-sha256:" + "b" * 64})
        elif fault == "issued":
            proof = proof.model_copy(update={"issued_at": proof.issued_at - 0.001})
        elif fault == "expires":
            proof = proof.model_copy(update={"expires_at": proof.expires_at + 0.001})
        elif fault == "state":
            proof = proof.model_copy(update={"state": ExecutionState.RUNNING})
        elif fault == "descendants":
            proof = proof.model_copy(
                update={
                    "descendants": (REF.model_copy(update={"upstream_session_id": "ses_child"}),)
                }
            )
        elif fault == "revoked":
            p.revoke_watch(REF)
        elif fault == "feed":
            index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
            index.accept(frame(CONNECTED))
            p.feed.index = index
        elif fault == "owner":
            p.feed.index.owner_epoch = "b" * 64
        elif fault == "expired":
            monkeypatch.setattr(module.time, "time", lambda: proof.expires_at)
        elif fault == "future":
            monkeypatch.setattr(module.time, "time", lambda: proof.issued_at - 0.001)
        elif fault == "changed-witness":
            p.witnesses[REF] = replace(p.witnesses[REF], resources_sha256="b" * 64)
        elif fault == "pending":
            p.witnesses[REF] = replace(
                p.witnesses[REF], pending=(("per_unexpected", "permission"),)
            )
        elif fault == "read-scope":
            proof = await p.read_scope(REF)
        with pytest.raises(ContractError, match="dispatch_owner_epoch_unqualified"):
            p.dispatch_owner_epoch(REF, proof)
    finally:
        await finish(p, t)


async def test_dispatch_owner_epoch_requires_current_full_idle_fence_and_not_active_proof():
    p, t, data, calls = await setup()
    try:
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        assert proof.state == ExecutionState.RUNNING
        with pytest.raises(ContractError, match="dispatch_owner_epoch_unqualified"):
            p.dispatch_owner_epoch(REF, proof)
        data["session.active"]["data"].clear()
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        assert p.dispatch_owner_epoch(REF, proof) == OWNER
        p.feed.index.accept(frame(text_delta("evt_after_dispatch_idle_proof")))
        with pytest.raises(ContractError, match="dispatch_owner_epoch_unqualified"):
            p.dispatch_owner_epoch(REF, proof)
    finally:
        await finish(p, t)


async def test_dispatch_positive_idle_anchor_uses_actual_latest_hash_and_native_idle():
    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        before = len(calls)
        anchor = p.dispatch_idle_anchor(REF, proof)
        assert anchor.reference == REF and not anchor.pristine
        assert anchor.idle.id == "msg_idle" and anchor.idle.created_at == 3
        assert anchor.idle.outcome == "succeeded"
        assert anchor.head.id == "msg_idle"
        assert anchor.head.sha256 == digest({"latest": data["session.message.list"]["data"][0]})
        assert len(calls) == before
        p.feed.index.accept(frame(text_delta("evt_anchor_proof_changed")))
        with pytest.raises(ContractError):
            p.dispatch_idle_anchor(REF, proof)
    finally:
        await finish(p, t)


async def test_read_scope_and_missing_positive_boundary_cannot_provide_dispatch_idle_anchor():
    p, t, data, calls = await setup()
    try:
        scope = await p.read_scope(REF)
        with pytest.raises(ContractError):
            p.dispatch_idle_anchor(REF, scope)
        await p.watch(REF)
        proof = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        p._idle_anchors.clear()
        with pytest.raises(ContractError, match="positive_idle_anchor_unavailable"):
            p.dispatch_idle_anchor(REF, proof)
        p.revoke_watch(REF)
        assert not p._idle_anchors
    finally:
        await finish(p, t)


@pytest.mark.parametrize("added_reads", [frozenset(), frozenset({"fs.read"})])
async def test_replaced_attestation_read_scope_cannot_restore_original_mutation_watch(added_reads):
    p, t, data, calls = await setup()
    try:
        await p.watch(REF)
        original = await p.prove(REF, INSTALLED_SCHEMA, digest(data["session.get"]["data"]))
        client = V2ExecutionClient(t, p.projects, proofs=p)
        t.attestation = replace(
            t.attestation, verified_operations=t.attestation.verified_operations | added_reads
        )
        scope = await p.read_scope(REF)
        assert p.read_epoch(REF, INSTALLED_SCHEMA) == scope.connection_epoch
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) is None
        assert not p._watched and not p.witnesses and not p._idle_anchors
        with pytest.raises(ContractError):
            client.current(REF, original)
        with pytest.raises(ContractError, match="original_execution_proof_unavailable"):
            await client.qualified_snapshot(REF)
        with pytest.raises(ContractError, match="not_watched"):
            await p.prove(REF, INSTALLED_SCHEMA, scope.session_info_sha256)
        # Only a new complete watch can qualify the replacement contract.
        fresh = await p.watch(REF)
        assert p.certified_epoch(REF, INSTALLED_SCHEMA) == fresh.connection_epoch
        assert p.read_epoch(REF, INSTALLED_SCHEMA) == scope.connection_epoch
        assert not any(op == "session.interrupt" for op, _url in calls)
    finally:
        await finish(p, t)
