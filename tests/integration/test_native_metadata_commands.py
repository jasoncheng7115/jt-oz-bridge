"""Synthetic Human/Native fixtures + real own DB/outbox; no live user acceptance."""

import asyncio
import re
from dataclasses import replace
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.native_metadata import (
    AgentMetadata,
    CommandMetadata,
    McpMetadata,
    NativeMetadataSnapshot,
    NativeUsage,
    SkillMetadata,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.native_metadata_commands import NativeMetadataCommands
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_router import Source, message, send
from tests.support import bound


class Catalog:
    def __init__(self, ref, contract):
        self.ref, self.contract, self.live = ref, contract, True
        self.hook, self.calls = None, []
        entries = {
            "agents": tuple(
                AgentMetadata(native_id=f"Agent/{i}", name=f"Agent-{i:02d}", mode="primary")
                for i in range(23)
            ),
            "commands": (CommandMetadata(native_id="Review/Exact", name="Review/Exact"),),
            "skills": (SkillMetadata(native_id="skill", name="Skill-00"),),
            "mcp": (McpMetadata(native_id="mcp", name="Native-MCP", status="needs_auth"),),
        }
        self.snapshots = {
            kind: NativeMetadataSnapshot(
                reference=ref, contract_sha256=contract, kind=kind, items=items
            )
            for kind, items in entries.items()
        }
        self.snapshots["usage"] = NativeMetadataSnapshot(
            reference=ref,
            contract_sha256=contract,
            kind="usage",
            usage=NativeUsage(
                cost_usd=0.0125, input=100, output=20, reasoning=7, cache_read=30, cache_write=40
            ),
        )
        self.kinds = frozenset(self.snapshots)

    def contract_for(self, ref):
        assert ref == self.ref
        return self.contract

    def available_kinds(self, ref):
        assert ref == self.ref
        return self.kinds

    async def read(self, ref, kind):
        assert ref == self.ref
        self.calls.append(kind)
        if self.hook:
            await self.hook()
        return self.snapshots[kind]

    def current(self, snapshot):
        return self.live and self.snapshots.get(snapshot.kind) is snapshot


async def setup(db, maximum=10000):
    bindings, binding, control, audience = await bound(db)
    fencing = await DurableStore(db).acquire_lease("metadata", ttl=120)
    inbox, source = CommandInbox(db, "metadata", fencing), Source()
    tokens = TokenService(db, fence=inbox.fence)
    ref = reference(binding)
    catalog = Catalog(ref, control.contract_hash)
    commands = NativeMetadataCommands(
        bindings, {ref: catalog}, tokens, source, message_limit=maximum
    )
    router = CommandRouter(bindings, source, inbox, metadata=commands)
    return router, binding, source, catalog, commands, audience


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


def token(text, command="agents"):
    return re.search(r"!oz " + command + r" ([A-Za-z0-9_-]{32})`", text)[1]


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("agents", "Agent-00"),
        ("commands", "Review/Exact"),
        ("skills", "Skill-00"),
        ("mcp", "needs authentication"),
        ("usage", "0.0125"),
    ],
)
async def test_commands_use_native_metadata_without_creating_an_action(db, kind, expected):
    router, binding, source, catalog, commands, audience = await setup(db)
    first = await send(router, source, message("!oz " + kind))
    assert expected in unescape(first.text)
    assert await router.route(source.messages[101]) == first
    assert catalog.calls == [kind] and not await rows(db, Action)
    if kind == "usage":
        assert all(str(v) in unescape(first.text) for v in (100, 20, 7, 30, 40))
        assert "197" not in first.text and "not a bill" in first.text


async def test_page_is_actor_kind_revision_and_catalog_bound_and_consumed_once(db):
    router, binding, source, catalog, commands, audience = await setup(db)
    menu = await send(router, source, message("!oz agents"))
    page = token(menu.text)
    assert "Agent-08" in unescape(menu.text) and "Agent-09" not in unescape(menu.text)
    for mid, kind, actor in ((102, "agents", 8), (103, "commands", 7)):
        denied = await send(
            router, source, message("!oz " + kind + " " + page, mid, author_id=actor)
        )
        assert "expired" in denied.text
    second = await send(router, source, message("!oz agents " + page, 104))
    assert "Agent-09" in unescape(second.text) and "Agent-17" in unescape(second.text)
    again = await send(router, source, message("!oz agents " + page, 105))
    assert "expired" in again.text
    final = await send(router, source, message("!oz agents " + token(second.text), 106))
    assert "Agent-22" in unescape(final.text) and not re.search(
        r"!oz agents [A-Za-z0-9_-]{32}", final.text
    )
    assert not await rows(db, Action)


async def test_same_page_race_emits_at_most_one_successful_page(db):
    router, binding, source, catalog, commands, audience = await setup(db)
    menu = await send(router, source, message("!oz agents"))
    page = token(menu.text)
    results = await asyncio.gather(
        *(send(router, source, message("!oz agents " + page, mid)) for mid in (102, 103))
    )
    assert sum("Agent-09" in unescape(x.text) for x in results) == 1
    assert sum("expired" in x.text for x in results) == 1
    assert not await rows(db, Action)


@pytest.mark.parametrize(
    "failure", ["items", "reference", "contract", "not-current", "missing-usage"]
)
async def test_changed_or_invalid_native_view_is_not_displayed(db, failure):
    router, binding, source, catalog, commands, audience = await setup(db)
    menu = await send(router, source, message("!oz agents"))
    page = token(menu.text)
    old = catalog.snapshots["agents"]
    if failure == "items":
        catalog.snapshots["agents"] = old.model_copy(update={"items": old.items[1:]})
    elif failure == "reference":
        catalog.snapshots["agents"] = old.model_copy(
            update={"reference": old.reference.model_copy(update={"upstream_session_id": "other"})}
        )
    elif failure == "contract":
        catalog.snapshots["agents"] = old.model_copy(update={"contract_sha256": "b" * 64})
    elif failure == "not-current":
        catalog.live = False
    else:
        catalog.snapshots["usage"] = catalog.snapshots["usage"].model_copy(update={"usage": None})
    item = message("!oz usage" if failure == "missing-usage" else "!oz agents " + page, 102)
    denied = await send(router, source, item)
    assert "expired" in denied.text and "Agent-" not in denied.text and "USD" not in denied.text
    assert not await rows(db, Action)


@pytest.mark.parametrize(
    "failure", ["source-edit", "grant-revoked", "binding-revised", "public-audience"]
)
async def test_read_rechecks_original_human_and_authorization_after_native_await(db, failure):
    router, binding, source, catalog, commands, audience = await setup(db)
    item = message("!oz agents")
    source.messages[item.message_id] = item

    async def change():
        if failure == "source-edit":
            source.messages[101] = item.model_copy(update={"revision": 1})
        elif failure == "public-audience":
            audience.private = False
        else:
            async with db.sessions.begin() as session:
                if failure == "grant-revoked":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                else:
                    await session.execute(
                        update(Binding)
                        .where(Binding.id == binding.id)
                        .values(revision=binding.revision + 1)
                    )

    catalog.hook = change
    with pytest.raises((Conflict, AccessDenied)):
        await commands.route(binding, item, "en", "agents", "")
    assert not await rows(db, Action) and not await rows(db, ControlToken)


@pytest.mark.parametrize("maximum", [512, 700, 1200])
async def test_hostile_long_names_remain_bounded_and_do_not_become_controls(db, maximum):
    router, binding, source, catalog, commands, audience = await setup(db, maximum)
    old = catalog.snapshots["agents"]
    name = "@**all** !oz stop " + ("*[]()#|" * 100) + "\x1b[31m"
    catalog.snapshots["agents"] = old.model_copy(
        update={"items": tuple(x.model_copy(update={"name": name}) for x in old.items)}
    )
    result = await send(router, source, message("!oz agents"))
    assert (
        len(result.text) <= maximum - 100
        and "@**all**" not in result.text
        and "\x1b" not in result.text
    )
    assert re.search(r"!oz agents [A-Za-z0-9_-]{32}", result.text)
    assert not await rows(db, Action)


async def test_unqualified_kind_and_execution_commands_remain_local(db):
    router, binding, source, catalog, commands, audience = await setup(db)
    catalog.kinds = frozenset({"usage"})
    reply = await send(router, source, message("!oz agents"))
    assert "available for this conversation" in reply.text and not catalog.calls
    for mid, text in enumerate(
        ("!oz mcp restart anything", "!oz run any -- arguments", "!oz agent any"), 102
    ):
        await send(router, source, message(text, mid))
    assert not await rows(db, Action)


async def test_runtime_whole_graph_delivers_read_only_catalog_and_ignores_bot_echo(db):
    from tests.integration.test_consumer_runtime import post_containing
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, native, results, binding, pulse = await graph_setup(db)
    ref = reference(binding)
    backend = previous.backends[ref.backend_id]
    catalog = Catalog(ref, backend.registered.contract_sha256)
    backend = replace(backend, metadata={ref: catalog})
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {ref.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz skills", 101)
        reply = await post_containing(server, "Skill-00")
        assert reply["sender_id"] == 11 and reply["subject"] == binding.topic
        await asyncio.sleep(0.1)
        assert runtime.healthy and not native.submitted and not await rows(db, Action)
        assert catalog.calls == ["skills"]
    finally:
        await runtime.close()


async def test_runtime_rejects_foreign_metadata_scope_and_contract_and_freezes_mapping(db):
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, native, results, binding, pulse = await graph_setup(db)
    ref = reference(binding)
    backend = previous.backends[ref.backend_id]
    catalog = Catalog(ref, backend.registered.contract_sha256)
    readers = {ref: catalog}
    candidate = replace(backend, metadata=readers)
    readers.clear()
    assert candidate.metadata[ref] is catalog
    with pytest.raises(TypeError):
        candidate.metadata[ref] = catalog
    foreign = ref.model_copy(update={"upstream_session_id": "another-original-root"})
    with pytest.raises(ValueError, match="runtime_native_metadata_scope_or_contract_changed"):
        replace(backend, metadata={foreign: catalog})
    catalog.contract = "a" * 64
    with pytest.raises(ValueError, match="runtime_native_metadata_scope_or_contract_changed"):
        replace(backend, metadata={ref: catalog})
