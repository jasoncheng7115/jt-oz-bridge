"""Real read-only owner/HTTP graph -> original command -> encrypted return journal.

All Native/Source/owner/Zulip peers are synthetic. This is not installed or Human
qualification, and the running original check is never interrupted or promoted.
"""

import copy
import re
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.files import (
    FILE_FEATURES,
    FILE_SEMANTICS,
    BinaryReadAttestation,
    V2NativeFileReader,
)
from jt_oz_bridge.adapters.opencode.project_policy import (
    GUARDED_OPERATIONS,
    PERMISSION_SOURCE,
    POLICY_READS,
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.workspace_catalog import (
    CATALOG_SEMANTICS,
    V2WorkspaceCatalog,
    WorkspaceCatalogAttestation,
)
from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.bindings import topic_key
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_menus import FileMenus
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.contract.test_leaf_resources import finish
from tests.contract.test_native_project_policy import fingerprint
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.integration.test_file_returns import all_rows
from tests.integration.test_file_returns import setup as upload_setup
from tests.integration.test_router import Source, message
from tests.integration.test_runtime_enrollment import startup_check_graph
from tests.support_directory_scope import SyntheticDirectoryScope


@asynccontextmanager
async def workspace(db, tmp_path):
    body = b"original readonly bytes\r\n\x00\xff"
    # File-return plans require a canonical UUID; keep other helper callers'
    # enrollment-only binding identifier unchanged through its default.
    graph = await startup_check_graph(db, binding_id="00000000-0000-4000-8000-000000000001")
    # startup_check_graph exercises owned-check recovery directly and therefore
    # has no router topic index. This composed fixture uses the real router:
    # supply its existing binding's canonical index, never a fallback lookup.
    async with db.sessions.begin() as session:
        saved = await session.get(Binding, graph.binding.id)
        assert saved is not None and saved.topic_key is None
        assert (saved.realm_id, saved.channel_id, saved.topic) == ("realm", 4, "original")
        saved.topic_key = topic_key(saved.realm_id, saved.channel_id, saved.topic)
    seed, transport, policy_data, _, _, _, _ = await policy_setup()
    try:
        for operation in ("agent.get", "plugin.list", "permission.saved.list", "mcp.list"):
            graph.data[operation] = copy.deepcopy(policy_data[operation])
        for key in ("agent", "permissions"):
            graph.data["session.get"]["data"][key] = policy_data["session.get"]["data"][key]
    finally:
        await finish(seed, transport)
    original = graph.transport.client._transport
    routes = {
        "/api/agent/build": "agent.get",
        "/api/plugin": "plugin.list",
        "/api/permission/saved": "permission.saved.list",
        "/api/mcp": "mcp.list",
    }
    state = SimpleNamespace(body=body, byte_reads=0)

    def handle(request):
        assert request.method == "GET", "a read-only command must never mutate Native"
        operation = routes.get(request.url.path)
        if operation:
            return httpx.Response(200, json=copy.deepcopy(graph.data[operation]))
        if request.url.path in {"/api/fs/list", "/api/fs/find"}:
            assert request.url.params["location[directory]"] == graph.ref.canonical_directory
            return httpx.Response(
                200,
                json={
                    "location": {"directory": graph.ref.canonical_directory},
                    "data": [{"path": "report.bin", "type": "file"}],
                },
            )
        if request.url.path == "/api/fs/read/report.bin":
            assert request.url.params["location[directory]"] == graph.ref.canonical_directory
            state.byte_reads += 1
            return httpx.Response(
                200,
                content=state.body,
                headers={
                    "content-type": "application/octet-stream",
                    "content-length": str(len(state.body)),
                    "etag": '"original"',
                },
            )
        return original.handler(request)

    graph.transport.client._transport = httpx.MockTransport(handle)
    operations = frozenset({"fs.read", "fs.list", "fs.find"})
    graph.transport.attestation = replace(
        graph.transport.attestation,
        verified_operations=graph.transport.attestation.verified_operations
        | POLICY_READS
        | operations,
    )
    enrollment = NativePolicyEnrollment(
        format="native-project-policy-v1",
        reference=graph.ref,
        native_project_id="global",
        contract_sha256=INSTALLED_SCHEMA,
        permission_source_sha256=PERMISSION_SOURCE,
        fingerprint_sha256=fingerprint(graph.data),
        operations=GUARDED_OPERATIONS,
    )
    graph.client.scope_guard = V2ProjectPolicyGuard(graph.proofs, {graph.ref: enrollment})
    reader = V2NativeFileReader(
        graph.client,
        attestation=BinaryReadAttestation(
            graph.ref,
            INSTALLED_SCHEMA,
            FILE_SEMANTICS,
            "a" * 64,
            enrollment.fingerprint_sha256,
            FILE_FEATURES,
        ),
    )
    catalog = V2WorkspaceCatalog(
        graph.client,
        {
            graph.ref: WorkspaceCatalogAttestation(
                graph.ref,
                INSTALLED_SCHEMA,
                enrollment.fingerprint_sha256,
                CATALOG_SEMANTICS,
                "b" * 64,
                frozenset({"fs.list", "fs.find"}),
            )
        },
        directories=SyntheticDirectoryScope(graph.ref),
    )
    try:
        await graph.observer.start()
        assert graph.observer.mode == "readonly-owned-check"
        async with upload_setup(
            db,
            tmp_path / "upload",
            body=body,
            path="report.bin",
            mime="application/octet-stream",
            initial_artifact=False,
        ) as upload:
            # Reuse the fixture's one actual current consumer lease; do not
            # synthesize another holder while its live lease is still owned.
            fence = upload.store.fence
            assert fence is not None
            store = ArtifactService(
                graph.bindings,
                LocalArtifactFiles(tmp_path / "workspace"),
                db.cipher,
                reserve_free_bytes=0,
                fence=fence,
            )
            source = Source()
            journal = FileReturnJournal(
                store,
                source,
                Outbox(graph.bindings, 11, fence=fence),
                upload.uploader,
                upload.downloader,
                {graph.ref: reader},
                message_limit=1000,
                topic_limit=60,
            )
            menus = FileMenus(
                graph.bindings,
                source,
                TokenService(db, fence=fence),
                {graph.ref: catalog},
                message_limit=1000,
            )
            commands = FileCommands(journal, {graph.ref: reader}, choices=menus.choices)
            inbox = CommandInbox(db, fence.holder, fence.fencing)
            router = CommandRouter(graph.bindings, source, inbox, files=commands, file_menus=menus)
            try:
                yield SimpleNamespace(
                    graph=graph,
                    source=source,
                    reader=reader,
                    catalog=catalog,
                    store=store,
                    commands=commands,
                    journal=journal,
                    inbox=inbox,
                    router=router,
                    upload=upload,
                    state=state,
                )
            finally:
                store.files.close()
    finally:
        await finish(graph.proofs, graph.transport)


def human(v, text, number):
    item = message(text, number, channel_id=4, topic="original")
    v.source.messages[number] = item
    return item


async def choose(v):
    menu = await v.router.route(human(v, "!oz files", 102))
    assert (menu.state, menu.binding_id, menu.binding_revision) == (
        "reply",
        v.graph.binding.id,
        v.graph.binding.revision,
    ), menu
    selected = re.search(r"file:[A-Za-z0-9_-]{32}", menu.text)
    assert selected is not None, menu.text
    return human(v, "!oz file " + selected[0], 103)


def still_readonly(v):
    assert v.graph.observer.mode == "readonly-owned-check"
    assert v.graph.proofs.certified_epoch(v.graph.ref, INSTALLED_SCHEMA) is None
    assert not v.graph.proofs._watched and not v.graph.proofs.witnesses
    assert not any(cap.supported for cap in v.graph.client.capabilities(v.graph.ref).values())


@pytest.mark.parametrize("unroutable", ["missing-topic-key", "different-topic"])
async def test_owned_check_fixture_requires_exact_canonical_router_index(db, tmp_path, unroutable):
    async with workspace(db, tmp_path) as v:
        source = human(v, "!oz files", 102)
        bound = await v.router.binding_for(source)
        assert bound is not None and bound.id == v.graph.binding.id
        if unroutable == "missing-topic-key":
            async with db.sessions.begin() as session:
                saved = await session.get(Binding, v.graph.binding.id)
                assert saved is not None and saved.topic_key == topic_key("realm", 4, "original")
                saved.topic_key = None
        else:
            source = source.model_copy(update={"topic": "other original topic"})
            v.source.messages[source.message_id] = source
        assert await v.router.binding_for(source) is None
        routed = await v.router.route(source)
        assert routed.state == "ignore" and routed.text == ""
        assert v.state.byte_reads == v.upload.remote.posts == 0
        assert not await all_rows(db, ControlToken)
        assert not await all_rows(db, FileTransfer) and not await all_rows(db, Artifact)
        actions = await all_rows(db, Action)
        assert len(actions) == 1 and actions[0].id == "a" and actions[0].state == "running"
        still_readonly(v)


async def test_running_owned_check_keeps_menu_capture_upload_and_original_topic_readonly(
    db, tmp_path
):
    async with workspace(db, tmp_path) as v:
        source = await choose(v)
        result = await v.router.route(source)
        assert result.state == "reply" and v.state.byte_reads == 2
        transfers = await all_rows(db, FileTransfer)
        assert len(transfers) == 1, result.text
        row = transfers[0]
        plan = (await v.journal.load(row.id))[1]
        assert plan.source == source and plan.reference == v.graph.ref
        assert plan.native.expires_at - plan.native.observed_at == 5
        assert plan.native.semantics_sha256 == FILE_SEMANTICS
        assert (await v.store.read(row.artifact_id, "realm", 7)).content == v.state.body
        assert await v.router.route(source) == result and v.state.byte_reads == 2
        for state in ("uploaded", "verified", "queued"):
            assert await v.journal.advance(row.id) == state
        assert v.upload.remote.posts == 1
        actions = await all_rows(db, Action)
        assert len(actions) == 1 and actions[0].id == "a" and actions[0].state == "running"
        still_readonly(v)


@pytest.mark.parametrize("failure", ["source", "actor", "grant", "fence", "token"])
async def test_readonly_menu_does_not_bypass_human_authority_before_binary_get(
    db, tmp_path, failure
):
    async with workspace(db, tmp_path) as v:
        source = await choose(v)
        claim = await v.inbox.claim(
            source,
            "file",
            binding_id=v.graph.binding.id,
            binding_revision=1,
        )
        if failure == "source":
            v.source.messages[source.message_id] = source.model_copy(update={"revision": 1})
        elif failure == "actor":
            source = source.model_copy(update={"author_id": 8})
            v.source.messages[source.message_id] = source
        else:
            async with db.sessions.begin() as session:
                if failure == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                elif failure == "fence":
                    await session.execute(update(WorkerLease).values(fencing=999))
                else:
                    await session.execute(update(ControlToken).values(expires_at=0))
        with pytest.raises(ValueError):
            await v.commands.capture(v.graph.binding, source, claim, locale="en")
        assert v.state.byte_reads == v.upload.remote.posts == 0
        assert not await all_rows(db, FileTransfer) and not await all_rows(db, Artifact)
        still_readonly(v)


@pytest.mark.parametrize("changed", [False, True], ids=("same-bytes", "changed-bytes"))
async def test_slow_encryption_allows_only_one_exact_byte_reobservation(
    db,
    tmp_path,
    monkeypatch,
    changed,
):
    async with workspace(db, tmp_path) as v:
        source = await choose(v)
        clock = [time.time()]
        monkeypatch.setattr(time, "time", lambda: clock[0])
        original = v.store.create

        async def slow_storage(*args, **kwargs):
            value = await original(*args, **kwargs)
            clock[0] += 6
            if changed:
                v.state.body = b"different bytes"
            return value

        v.store.create = slow_storage
        claim = await v.inbox.claim(
            source, "file", binding_id=v.graph.binding.id, binding_revision=1
        )
        if changed:
            with pytest.raises(ValueError):
                await v.commands.capture(v.graph.binding, source, claim, locale="en")
            assert not await all_rows(db, FileTransfer)
        else:
            identity = await v.commands.capture(v.graph.binding, source, claim, locale="en")
            row, plan = await v.journal.load(identity)
            assert plan.native.observed_at == clock[0]
            assert plan.native.expires_at == clock[0] + 5
            assert len(await all_rows(db, Artifact)) == 1
            assert (await v.store.read(row.artifact_id, "realm", 7)).content == v.state.body
        assert v.state.byte_reads == 4 and v.upload.remote.posts == 0
        still_readonly(v)


@pytest.mark.parametrize("changed", ["session", "project", "directory", "backend"])
async def test_owned_check_read_certificate_cannot_be_inherited_by_another_full_root(
    db,
    tmp_path,
    changed,
):
    async with workspace(db, tmp_path) as v:
        field, value = {
            "session": ("upstream_session_id", "ses_other_original"),
            "project": ("project_id", "other-project"),
            "directory": ("canonical_directory", "/workspace/other"),
            "backend": ("backend_identity", "other-enrolled-native"),
        }[changed]
        foreign = v.graph.ref.model_copy(update={field: value})
        with pytest.raises(ValueError):
            await v.reader.read(foreign, "report.bin")
        with pytest.raises(ValueError):
            await v.catalog.listing(foreign)
        assert v.state.byte_reads == 0
        assert v.reader.current(await v.reader.read(v.graph.ref, "report.bin"))
        assert v.state.byte_reads == 2
        still_readonly(v)


@pytest.mark.parametrize("changed", ["client-proofs", "client-policy", "policy-proofs"])
async def test_workspace_readers_reject_replaced_original_dependency_graph(db, tmp_path, changed):
    async with workspace(db, tmp_path) as v:
        original = await v.reader.read(v.graph.ref, "report.bin")
        listing = await v.catalog.listing(v.graph.ref)
        assert v.reader.current(original) and v.catalog.current(listing)
        if changed == "client-proofs":
            v.graph.client.proofs = copy.copy(v.graph.proofs)
        elif changed == "client-policy":
            v.graph.client.scope_guard = copy.copy(v.graph.client.scope_guard)
        else:
            v.graph.client.scope_guard.proofs = copy.copy(v.graph.proofs)
        assert not v.reader.current(original) and not v.catalog.current(listing)
        with pytest.raises(ValueError):
            await v.reader.read(v.graph.ref, "report.bin")
        with pytest.raises(ValueError):
            await v.catalog.listing(v.graph.ref)
        assert v.state.byte_reads == 2 and v.upload.remote.posts == 0
        assert not await all_rows(db, Artifact) and not await all_rows(db, FileTransfer)
