"""Synthetic original-session user-turn controls, not Native/Human qualification."""

import copy
from dataclasses import replace

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.workspace_catalog import WorkspaceTurn
from jt_oz_bridge.services.file_menus import FileMenuState
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_workspace_catalog import setup as native_setup
from tests.integration.test_file_menus import send, setup, token
from tests.integration.test_file_returns import all_rows
from tests.integration.test_router import message

OPS = frozenset({"session.diff", "session.message.list", "session.message.get"})
USER = {"id": "msg_original", "type": "user", "time": {"created": 1}, "text": "NEVER_PREVIEW"}


async def native(*, operations=OPS, hook=None):
    p, t, d, reader, payload, calls, writes = await native_setup(operations=operations)
    original = t.client._transport
    reads = []
    rows = [copy.deepcopy(USER)]

    def handle(req):
        if req.url.path.endswith("/message") and req.url.params.get("type") == "user":
            reads.append(req)
            result = {
                "data": copy.deepcopy(rows),
                "cursor": {} if "cursor" in req.url.params else {"next": "opaque:older"},
            }
        elif req.url.path.endswith("/message/msg_original"):
            reads.append(req)
            result = {"data": copy.deepcopy(rows[0])}
        else:
            return original.handler(req)
        if hook:
            hook(req, result, len(reads), p, t)
        return httpx.Response(200, json=result)

    t.client._transport = httpx.MockTransport(handle)
    return p, t, d, reader, rows, reads, calls, writes


async def test_native_turn_filter_cursor_and_exact_from_never_grant_mutation_watch():
    p, t, d, reader, rows, reads, calls, writes = await native()
    try:
        p.revoke_watch(REF)
        first = await reader.turns(REF)
        assert first.entries[0].native_id == USER["id"] and reader.current(first)
        assert "NEVER_PREVIEW" not in first.model_dump_json()
        assert reads[-1].url.params["type"] == "user" and reads[-1].url.params["order"] == "desc"
        await reader.turns(REF, cursor=first.next_cursor)
        assert (
            reads[-1].url.params["cursor"] == "opaque:older" and "order" not in reads[-1].url.params
        )
        changes = await reader.diff(REF, from_message=USER["id"], turn_sha256=digest(USER))
        assert changes.from_message == USER["id"] and reader.current(changes)
        assert not reader.current(changes.model_copy())
        assert calls[-1].url.params["from"] == USER["id"] and "to" not in calls[-1].url.params
        assert sum(r.url.path.endswith("/message/msg_original") for r in reads) == 2
        assert p.certified_epoch(REF, t.profile.sha256) is None and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change", ["id", "type", "text", "deleted", "owner", "physical", "attestation"]
)
async def test_selected_turn_identity_or_boundary_change_cannot_return_a_patch(change):
    def mutate(req, result, number, p, t):
        if not req.url.path.endswith("/message/msg_original"):
            return
        if change == "id":
            result["data"]["id"] = "msg_foreign"
        elif change == "type":
            result["data"] = {"id": "msg_original", "type": "idle", "time": {"created": 1}}
        elif change == "text" and number == 2:
            result["data"]["text"] = "edited"
        elif change == "deleted":
            result["data"]["id"] = "msg_deleted"
        elif change == "owner":
            p.feed.index.owner_epoch = "other"
        elif change == "attestation":
            t.attestation = replace(t.attestation)

    p, t, d, reader, rows, reads, calls, writes = await native(hook=mutate)
    try:
        if change == "physical":

            async def move(paths, number):
                if number == 2:
                    reader.directories.generation += 1

            reader.directories.hook = move
        with pytest.raises(ValueError):
            await reader.diff(REF, from_message=USER["id"], turn_sha256=digest(USER))
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("missing", ["session.message.list", "session.message.get", "session.diff"])
async def test_turn_operations_need_independent_explicit_qualification_before_get(missing):
    p, t, d, reader, rows, reads, calls, writes = await native(operations=OPS - {missing})
    try:
        with pytest.raises(ValueError):
            if missing == "session.message.list":
                await reader.turns(REF)
            else:
                await reader.diff(REF, from_message=USER["id"], turn_sha256=digest(USER))
        assert not reads and not calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("limit", [512, 1000])
async def test_router_chosen_turn_survives_new_default_and_every_patch_page(
    db, tmp_path, locale, limit
):
    async with setup(db, tmp_path, limit=limit) as v:
        await send(v, "!oz lang " + locale, 100)
        v.catalog.changes = (v.catalog.changes[0].model_copy(update={"patch": "+line\n" * 150}),)
        _, menu = await send(v, "!oz diff turns")
        assert "NEVER_PREVIEW" not in menu.text
        assert "1." in menu.text and "Native created=" not in menu.text
        selected = token(menu, "turn")
        # A new newest Native user must not change the original selected from.
        v.catalog.turn_entries = (
            WorkspaceTurn(native_id="msg_newest", created=2, message_sha256="b" * 64),
            *v.catalog.turn_entries,
        )
        _, summary = await send(v, "!oz diff " + selected, 103)
        from html import unescape

        assert "msg_original" in unescape(summary.text), summary.text
        _, page = await send(v, "!oz diff " + token(summary, "diff"), 104)
        assert page.state == "reply" and len(page.text) <= limit - 100
        for number in range(105, 200):
            import re

            found = re.search(r"diffpage:[A-Za-z0-9_-]{32}", page.text)
            if found is None:
                break
            _, page = await send(v, "!oz diff " + found[0], number)
            assert page.state == "reply" and len(page.text) <= limit - 100
        else:
            pytest.fail("bounded patch pages never completed")
        assert all(x == ("msg_original", "a" * 64) for x in v.catalog.diff_reads)
        assert v.reads == v.remote.posts == 0 and not await all_rows(db, Action)


@pytest.mark.parametrize(
    "failure",
    [
        "actor",
        "issuer",
        "edited-source",
        "binding",
        "grant",
        "fence",
        "expiry",
        "turn",
        "qualification",
        "audience",
        "topic",
        "realm",
    ],
)
async def test_stolen_stale_or_revoked_turn_never_publishes_diff(db, tmp_path, failure):
    async with setup(db, tmp_path) as v:
        issuer, menu = await send(v, "!oz diff turns")
        selected = token(menu, "turn")
        human = message(
            "!oz diff " + selected, 103, **({"author_id": 8} if failure == "actor" else {})
        )
        v.source.messages[103] = human
        if failure == "issuer":
            v.source.messages[issuer.message_id] = issuer.model_copy(update={"deleted": True})
        elif failure == "edited-source":
            v.source.messages[103] = human.model_copy(update={"revision": 1})
        elif failure in {"topic", "realm"}:
            human = human.model_copy(
                update={"topic" if failure == "topic" else "realm_id": "other"}
            )
            v.source.messages[103] = human
        elif failure == "turn":
            v.catalog.turn_entries = ()
        elif failure == "qualification":
            v.catalog.turn_enabled = False
        else:
            async with db.sessions.begin() as session:
                if failure == "binding":
                    await session.execute(update(Binding).values(revision=2))
                elif failure in {"grant", "audience"}:
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == (7 if failure == "grant" else 8))
                        .values(active=False)
                    )
                elif failure == "fence":
                    await session.execute(update(WorkerLease).values(fencing=99))
                elif failure == "expiry":
                    await session.execute(update(ControlToken).values(expires_at=0))
        if failure == "qualification":
            text = await v.menus.route(v.binding, human, "en", "diff", selected)
            assert "available for this conversation" in text
        else:
            with pytest.raises(ValueError):
                await v.menus.route(v.binding, human, "en", "diff", selected)
        assert not await all_rows(db, Action) and v.remote.posts == 0


async def test_turn_menu_pages_are_opaque_bounded_and_reject_changed_original_page(db, tmp_path):
    async with setup(db, tmp_path, limit=512) as v:
        v.catalog.turn_entries = tuple(
            WorkspaceTurn(native_id=f"msg_{n}", created=n, message_sha256=digest(n))
            for n in range(10)
        )
        _, first = await send(v, "!oz diff turns")
        continuation = token(first, "turns")
        v.catalog.turn_entries = v.catalog.turn_entries[:-1]
        human = message("!oz diff " + continuation, 103)
        v.source.messages[103] = human
        with pytest.raises(Conflict, match="original_page_changed"):
            await v.menus.route(v.binding, human, "en", "diff", continuation)


@pytest.mark.parametrize(
    "from_message,turn_sha256", [(None, "a" * 64), ("msg_a", None), ("../msg_a", "a" * 64)]
)
def test_turn_control_cannot_separate_or_reinterpret_original_identity(from_message, turn_sha256):
    from tests.support import REF as MENU_REF

    with pytest.raises(ValueError):
        FileMenuState(
            mode="turn",
            reference=MENU_REF,
            from_message=from_message,
            turn_sha256=turn_sha256,
            issuer=message("!oz diff turns"),
            snapshot_sha256="a" * 64,
            message_limit=512,
        )


@pytest.mark.parametrize(
    "change", ["duplicate", "assistant", "empty-cursor", "repeated-cursor", "capacity", "expired"]
)
async def test_user_turn_list_rejects_invalid_native_page_and_never_mints_fresh_deadline(
    change, monkeypatch
):
    import time

    initial = time.time()

    def mutate(req, result, number, p, t):
        if change == "duplicate":
            result["data"] *= 2
        elif change == "assistant":
            result["data"] = [{"id": "msg_idle", "type": "idle", "time": {"created": 1}}]
        elif change == "empty-cursor":
            result["cursor"]["next"] = ""
        elif change == "repeated-cursor":
            result["cursor"]["next"] = "opaque:same"
        elif change == "capacity":
            result["data"] = [{**USER, "id": f"msg_{n}"} for n in range(11)]
        else:
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.workspace_catalog.time.time", lambda: initial + 20
            )

    p, t, d, reader, rows, reads, calls, writes = await native(hook=mutate)
    try:
        with pytest.raises(ValueError):
            await reader.turns(REF, cursor="opaque:same" if change == "repeated-cursor" else None)
        assert not reader._observed and not writes
    finally:
        await finish(p, t)


async def test_selected_turn_patch_change_after_first_page_rejects_continuation(db, tmp_path):
    async with setup(db, tmp_path, limit=512) as v:
        v.catalog.changes = (v.catalog.changes[0].model_copy(update={"patch": "+line\n" * 100}),)
        _, turns = await send(v, "!oz diff turns")
        _, changes = await send(v, "!oz diff " + token(turns, "turn"), 103)
        _, first = await send(v, "!oz diff " + token(changes, "diff"), 104)
        selected = token(first, "diffpage")
        v.catalog.changes = ()
        human = message("!oz diff " + selected, 105)
        v.source.messages[105] = human
        with pytest.raises(Conflict, match="original_snapshot_changed"):
            await v.menus.route(v.binding, human, "en", "diff", selected)
        assert not await all_rows(db, Action)


async def test_other_root_cannot_inherit_selected_turn_certificate_or_gets():
    p, t, d, reader, rows, reads, calls, writes = await native()
    try:
        other = REF.model_copy(update={"upstream_session_id": "ses_other"})
        with pytest.raises(ValueError):
            await reader.diff(other, from_message=USER["id"], turn_sha256=digest(USER))
        assert not reads and not calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["audience", "lease"])
async def test_selected_diff_rechecks_sql_after_native_read_before_output(db, tmp_path, change):
    async with setup(db, tmp_path) as v:
        _, menu = await send(v, "!oz diff turns")
        chosen = token(menu, "turn")
        original = v.catalog.diff

        async def read(*args, **kwargs):
            result = await original(*args, **kwargs)
            async with db.sessions.begin() as session:
                if change == "audience":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 8).values(active=False)
                    )
                else:
                    await session.execute(update(WorkerLease).values(fencing=99))
            return result

        v.catalog.diff = read
        human = message("!oz diff " + chosen, 103)
        v.source.messages[103] = human
        with pytest.raises(ValueError):
            await v.menus.route(v.binding, human, "en", "diff", chosen)
        assert not await all_rows(db, Action) and v.remote.posts == 0


async def test_owned_running_root_real_http_to_router_selected_turn_stays_readonly(db, tmp_path):
    from jt_oz_bridge.adapters.opencode.workspace_catalog import V2WorkspaceCatalog
    from jt_oz_bridge.services.file_menus import FileMenus
    from jt_oz_bridge.services.router import CommandRouter
    from tests.integration.test_workspace_read_recovery import human, still_readonly, workspace

    async with workspace(db, tmp_path) as v:
        graph = v.graph
        original = graph.transport.client._transport
        reads = []

        def handle(req):
            assert req.method == "GET"
            if req.url.path.endswith("/message") and req.url.params.get("type") == "user":
                result = {"data": [USER], "cursor": {}}
            elif req.url.path.endswith("/message/msg_original"):
                result = {"data": USER}
            elif req.url.path == f"/api/session/{graph.ref.upstream_session_id}/diff":
                assert req.url.params["from"] == "msg_original"
                result = {
                    "data": [
                        {
                            "file": "report.bin",
                            "patch": "+original change\n",
                            "additions": 1,
                            "deletions": 0,
                            "status": "added",
                        }
                    ]
                }
            else:
                return original.handler(req)
            reads.append(req)
            return httpx.Response(200, json=copy.deepcopy(result))

        graph.transport.client._transport = httpx.MockTransport(handle)
        graph.transport.attestation = replace(
            graph.transport.attestation,
            verified_operations=graph.transport.attestation.verified_operations | OPS,
        )
        prior = v.catalog.attestations[graph.ref]
        catalog = V2WorkspaceCatalog(
            graph.client,
            {graph.ref: replace(prior, operations=prior.operations | OPS)},
            directories=v.catalog.directories,
        )
        menus = FileMenus(
            graph.bindings,
            v.source,
            v.router.file_menus.tokens,
            {graph.ref: catalog},
            message_limit=1000,
        )
        v.commands.choices = menus.choices
        router = CommandRouter(
            graph.bindings, v.source, v.inbox, files=v.commands, file_menus=menus
        )
        first = await router.route(human(v, "!oz diff turns", 102))
        assert first.state == "reply", first.text
        selected = token(first, "turn")
        changes = await router.route(human(v, "!oz diff " + selected, 103))
        assert changes.state == "reply", changes.text
        page = await router.route(human(v, "!oz diff " + token(changes, "diff"), 104))
        assert page.state == "reply" and "+original change" in page.text, page.text
        assert sum(req.url.path.endswith("/diff") for req in reads) == 2
        assert sum(req.url.path.endswith("/message/msg_original") for req in reads) == 4
        assert (
            len(await all_rows(db, Action)) == 1
            and v.state.byte_reads == v.upload.remote.posts == 0
        )
        still_readonly(v)
