"""Synthetic original-command menus, file bytes, replay and disclosure boundaries."""

import re
from contextlib import asynccontextmanager
from html import unescape

import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.workspace_catalog import (
    WorkspaceChanges,
    WorkspaceDiff,
    WorkspaceEntry,
    WorkspaceListing,
    WorkspaceTurn,
    WorkspaceTurns,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.services.file_choices import verify_file_use
from jt_oz_bridge.services.file_menus import FileMenus
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, Grant
from tests.integration.test_file_commands import claim, commands
from tests.integration.test_file_returns import all_rows
from tests.integration.test_router import message
from tests.support import REF


class Catalog:
    """Identity-aware synthetic catalog, never an installed certificate."""

    def __init__(self, path):
        self.entries = (WorkspaceEntry(path=path, kind="file"),)
        self.changes = (
            WorkspaceDiff(
                path=path,
                patch="@@ -1 +1 @@\n-old\n+new\n",
                additions=1,
                deletions=1,
                status="modified",
            ),
        )
        self.observed, self.reads, self.enabled = [], [], True
        self.complete, self.hidden, self.hook = True, 0, None
        self.turn_entries = (
            WorkspaceTurn(native_id="msg_original", created=1, message_sha256="a" * 64),
        )
        self.diff_reads, self.turn_reads = [], []
        self.turn_enabled = True
        self.next_cursor = None

    def qualified(self, ref, kind):
        return (
            self.enabled
            and ref == REF
            and (kind not in {"turns", "turn-diff"} or self.turn_enabled)
        )

    async def listing(self, ref, *, directory="", query=""):
        assert ref == REF
        self.reads.append((directory, query))
        entries = tuple(
            e
            for e in self.entries
            if (query in e.path if query else e.path.rpartition("/")[0] == directory)
        )
        value = WorkspaceListing(
            reference=ref,
            directory=directory,
            query=query,
            entries=entries,
            complete=self.complete,
            hidden_count=self.hidden,
        )
        self.observed.append(value)
        if self.hook:
            await self.hook()
        return value

    async def turns(self, ref, *, cursor=None):
        assert ref == REF
        self.turn_reads.append(cursor)
        value = WorkspaceTurns(
            reference=ref, cursor=cursor, next_cursor=self.next_cursor, entries=self.turn_entries
        )
        self.observed.append(value)
        return value

    async def diff(self, ref, *, from_message=None, turn_sha256=None):
        assert ref == REF
        self.diff_reads.append((from_message, turn_sha256))
        if from_message is not None and not any(
            e.native_id == from_message and e.message_sha256 == turn_sha256
            for e in self.turn_entries
        ):
            raise Conflict("original_user_turn_changed")
        value = WorkspaceChanges(
            reference=ref,
            from_message=from_message,
            turn_sha256=turn_sha256,
            files=self.changes,
            hidden_count=self.hidden,
        )
        self.observed.append(value)
        return value

    def current(self, value):
        return self.enabled and any(value is original for original in self.observed)


@asynccontextmanager
async def setup(db, tmp_path, *, limit=1000, **options):
    async with commands(db, tmp_path, path="report.html", **options) as v:
        v.catalog = Catalog("report.html")
        v.tokens = TokenService(db, fence=v.store.fence)
        v.menus = FileMenus(
            v.store.bindings, v.source, v.tokens, {REF: v.catalog}, message_limit=limit
        )
        v.commands.choices = v.menus.choices
        v.router = CommandRouter(
            v.store.bindings, v.source, v.inbox, files=v.commands, file_menus=v.menus
        )
        yield v


async def send(v, text, number=102, **changes):
    value = message(text, number, **changes)
    v.source.messages[number] = value
    return value, await v.router.route(value)


def token(reply, prefix="file"):
    return re.search(r"\b" + prefix + r":[A-Za-z0-9_-]{32}(?![A-Za-z0-9_-])", reply.text)[0]


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_selection_keeps_real_human_command_and_original_bytes_through_upload_journal(
    db, tmp_path, locale
):
    async with setup(db, tmp_path, body=b"<html>original\r\n\x00</html>") as v:
        await send(v, "!oz lang " + locale, 100)
        menu_source, menu = await send(v, "!oz files")
        selected = token(menu)
        v.human, result = await send(v, "!oz file " + selected, 103)
        assert result.state == "reply" and v.reads == 1
        row, plan = await v.service.load((await all_rows(db, FileTransfer))[0].id)
        assert plan.selection and plan.source == v.human and plan.locale == locale
        assert plan.source.text == "!oz file " + selected
        assert (
            plan.native.relative_path == "report.html"
            and plan.format == "original-file-choice-return-v1"
        )
        await verify_file_use(v.store.bindings, v.human, plan.selection)
        assert (await v.store.read(row.artifact_id, "realm", 7)).content == v.file.content
        assert (await v.router.route(v.human)) == result and v.reads == 1
        # The listing is historical metadata. Later menu changes cannot replace already captured bytes.
        v.catalog.entries = ()
        for expected in ("uploaded", "verified", "queued"):
            assert await v.service.advance(row.id) == expected
        assert v.remote.posts == 1 and not await all_rows(db, Action)
        _, repeated = await send(v, "!oz file " + selected, 104)
        assert repeated.text == Translator().render("router.stale", locale) and v.reads == 1


@pytest.mark.parametrize(
    "failure",
    [
        "actor",
        "realm",
        "topic",
        "source",
        "issuer",
        "binding",
        "expired",
        "operator",
        "audience",
        "listing",
        "unqualified",
        "fence",
    ],
)
async def test_stale_stolen_or_revoked_file_choice_never_reads_native_bytes(db, tmp_path, failure):
    async with setup(db, tmp_path) as v:
        issuer, menu = await send(v, "!oz files")
        selected = token(menu)
        v.human = message("!oz file " + selected, 103)
        v.source.messages[103] = v.human
        c = await claim(v)
        if failure == "actor":
            v.human = v.human.model_copy(update={"author_id": 8})
            v.source.messages[103] = v.human
        elif failure in {"realm", "topic"}:
            v.human = v.human.model_copy(
                update={failure + "_id" if failure == "realm" else failure: "other"}
            )
            v.source.messages[103] = v.human
        elif failure == "source":
            v.source.messages[103] = v.human.model_copy(update={"revision": 1})
        elif failure == "issuer":
            v.source.messages[issuer.message_id] = issuer.model_copy(update={"deleted": True})
        elif failure == "listing":
            v.catalog.entries = ()
        elif failure == "unqualified":
            v.catalog.enabled = False
        else:
            async with db.sessions.begin() as session:
                if failure == "binding":
                    await session.execute(update(Binding).values(revision=2))
                elif failure == "expired":
                    await session.execute(update(ControlToken).values(expires_at=0))
                elif failure in {"operator", "audience"}:
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == (7 if failure == "operator" else 8))
                        .values(active=False)
                    )
                else:
                    from jt_oz_bridge.storage.models import WorkerLease

                    await session.execute(update(WorkerLease).values(fencing=99))
        with pytest.raises(ValueError):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert v.reads == v.remote.posts == 0
        assert not await all_rows(db, Artifact) and not await all_rows(db, FileTransfer)


async def test_consumed_receipt_tampering_cannot_reauthorize_an_upload(db, tmp_path):
    async with setup(db, tmp_path) as v:
        _, menu = await send(v, "!oz files")
        v.human, _ = await send(v, "!oz file " + token(menu), 103)
        row = (await all_rows(db, FileTransfer))[0]
        async with db.sessions.begin() as session:
            await session.execute(update(ControlToken).values(context_hash="0" * 64))
        with pytest.raises(ValueError):
            await v.service.current((await v.service.load(row.id))[1])
        assert v.remote.posts == 0


@pytest.mark.parametrize("limit", [512, 1000, 10000])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_listing_pages_and_search_work_with_small_mobile_message_limits(
    db, tmp_path, limit, locale
):
    async with setup(db, tmp_path, limit=limit) as v:
        v.catalog.entries = tuple(
            WorkspaceEntry(path=f"檔案_{x:03}.html", kind="file") for x in range(25)
        )
        v.catalog.complete, v.catalog.hidden = False, 3
        source = message("!oz files", 102)
        v.source.messages[102] = source
        text = await v.menus.route(v.binding, source, locale, "files", "")
        seen = []
        for number in range(103, 140):
            assert len(text) <= limit - 100
            seen.extend(re.findall("檔案_[0-9]+.html", unescape(text)))
            match = re.search(r"page:[A-Za-z0-9_-]{32}", text)
            if match is None:
                break
            source = message("!oz files " + match[0], number)
            v.source.messages[number] = source
            text = await v.menus.route(v.binding, source, locale, "files", match[0])
        assert len(set(seen)) == 25 and len(seen) == 25
        assert v.reads == v.remote.posts == 0
        _, found = await send(v, "!oz files 024", 150)
        assert "檔案_024.html" in unescape(found.text) and "檔案_023.html" not in unescape(
            found.text
        )
        assert v.catalog.reads[-1] == ("", "024")


async def test_directory_selection_and_modified_listing_page_fail_closed(db, tmp_path):
    async with setup(db, tmp_path) as v:
        v.catalog.entries = (
            WorkspaceEntry(path="reports", kind="directory"),
            WorkspaceEntry(path="reports/child.html", kind="file"),
        )
        _, menu = await send(v, "!oz files")
        _, child = await send(v, "!oz files " + token(menu, "dir"), 103)
        assert "reports/child.html" in unescape(child.text) and v.catalog.reads[-1] == (
            "reports",
            "",
        )
        v.catalog.entries = tuple(WorkspaceEntry(path=f"f{x}.html", kind="file") for x in range(15))
        _, first = await send(v, "!oz files", 104)
        page = token(first, "page")
        v.catalog.entries = v.catalog.entries[:-1]
        _, rejected = await send(v, "!oz files " + page, 105)
        assert "expired" in rejected.text and "f10.html" not in unescape(rejected.text)


@pytest.mark.parametrize("limit", [512, 1000])
async def test_diff_page_sanitizes_secrets_and_mentions_and_rejects_changed_snapshot(
    db, tmp_path, limit
):
    async with setup(db, tmp_path, limit=limit) as v:
        patch = "+password=VERY_PRIVATE_SECRET\n+@**all** \x1b[31m\n" + (
            "+a long line to paginate\n" * 80
        )
        v.catalog.changes = (
            WorkspaceDiff(
                path="report.html", patch=patch, additions=82, deletions=0, status="added"
            ),
        )
        _, summary = await send(v, "!oz diff")
        chosen = token(summary, "diff")
        _, first = await send(v, "!oz diff " + chosen, 103)
        assert first.state == "reply"
        assert "VERY_PRIVATE_SECRET" not in first.text and "\x1b" not in first.text
        assert len(first.text) <= limit - 100
        next_page = token(first, "diffpage")
        _, second = await send(v, "!oz diff " + next_page, 104)
        assert second.state == "reply" and len(second.text) <= limit - 100
        last_token = token(second, "diffpage")
        v.catalog.changes = ()
        _, stale = await send(v, "!oz diff " + last_token, 105)
        assert "expired" in stale.text and v.reads == v.remote.posts == 0
        assert not await all_rows(db, Action)


async def test_unqualified_menu_commands_stay_controls_and_do_not_turn_into_prompts(db, tmp_path):
    async with setup(db, tmp_path) as v:
        v.catalog.enabled = False
        for n, text in enumerate(("!oz files", "!oz diff"), 102):
            _, reply = await send(v, text, n)
            assert "available for this conversation" in reply.text
        assert not v.catalog.reads and v.reads == v.remote.posts == 0
        assert not await all_rows(db, Action)


@pytest.mark.parametrize(
    "path",
    [
        ".jt-oz-incoming-id/input.html",
        ".jt-oz-preview-id/report.html",
        "x/.ENV.production",
        ".ssh/id_ed25519",
        "secret.KEY",
    ],
)
async def test_managed_staging_and_sensitive_names_cannot_bypass_return_scope(db, tmp_path, path):
    with pytest.raises(AccessDenied):
        disclosed_path(path)
    async with setup(db, tmp_path) as v:
        v.human, reply = await send(v, "!oz file " + path)
        assert v.reads == v.remote.posts == 0 and not await all_rows(db, Artifact)


async def test_exact_owned_command_resumes_consumed_choice_after_prepare_failure(
    db, tmp_path, monkeypatch
):
    from unittest.mock import AsyncMock

    async with setup(db, tmp_path) as v:
        _, menu = await send(v, "!oz files")
        v.human = message("!oz file " + token(menu), 103)
        v.source.messages[103] = v.human
        c = await claim(v)
        original = v.service.prepare
        monkeypatch.setattr(
            v.service, "prepare", AsyncMock(side_effect=Conflict("before plan commit"))
        )
        with pytest.raises(Conflict):
            await v.commands.capture(v.binding, v.human, c, locale="en")
        assert len(await all_rows(db, Artifact)) == 1
        assert not await all_rows(db, FileTransfer)
        monkeypatch.setattr(v.service, "prepare", original)
        identity = await v.commands.capture(v.binding, v.human, c, locale="en")
        assert identity and len(await all_rows(db, Artifact)) == 1
        assert len(await all_rows(db, FileTransfer)) == 1 and v.reads == 2
        assert v.remote.posts == 0


@pytest.mark.parametrize("limit", [512, 1000])
async def test_adversarial_long_path_still_has_bounded_selectable_label(db, tmp_path, limit):
    from jt_oz_bridge.services.file_menus import visible_path

    path = "@" * 240 + ".html"
    assert len(visible_path(path)) <= 96
    async with setup(db, tmp_path, limit=limit) as v:
        v.catalog.entries = (WorkspaceEntry(path=path, kind="file"),)
        _, reply = await send(v, "!oz files")
        assert token(reply) and len(reply.text) <= limit - 100


async def test_operator_revocation_inside_token_commit_cannot_consume_page(
    db, tmp_path, monkeypatch
):
    import jt_oz_bridge.services.file_choices as module
    from jt_oz_bridge.security.admin import token_hash

    async with setup(db, tmp_path) as v:
        v.catalog.entries = tuple(WorkspaceEntry(path=f"f{x}.html", kind="file") for x in range(20))
        _, first = await send(v, "!oz files")
        page = token(first, "page")
        original = module.lock_output_scope

        async def revoke(bindings, session, binding):
            await original(bindings, session, binding)
            await session.execute(
                update(Grant)
                .where(Grant.user_id == 7, Grant.role.in_(("operator", "administrator")))
                .values(active=False)
            )

        monkeypatch.setattr(module, "lock_output_scope", revoke)
        _, reply = await send(v, "!oz files " + page, 103)
        assert reply.text == Translator().render("permission.denied", "en")
        async with db.sessions() as session:
            assert not (await session.get(ControlToken, token_hash(page.split(":")[1]))).used
        assert v.reads == v.remote.posts == 0


async def test_another_authorized_operator_cannot_use_the_issuers_choice(db, tmp_path):
    async with setup(db, tmp_path) as v:
        _, menu = await send(v, "!oz files")
        from jt_oz_bridge.security.policy import Permission

        await v.store.bindings.get(v.binding.id, "realm", 8, Permission.OPERATE)
        _, rejected = await send(v, "!oz file " + token(menu), 103, author_id=8)
        assert rejected.text == Translator().render("router.stale", "en")
        assert v.reads == v.remote.posts == 0
        assert not await all_rows(db, Artifact)


async def test_change_list_paginates_every_file_without_omission(db, tmp_path):
    async with setup(db, tmp_path, limit=512) as v:
        v.catalog.changes = tuple(
            WorkspaceDiff(
                path=f"change{x:02}.html", patch="+x\n", additions=1, deletions=0, status="added"
            )
            for x in range(25)
        )
        _, reply = await send(v, "!oz diff")
        seen = []
        for number in range(103, 140):
            assert len(reply.text) <= 412
            seen.extend(re.findall(r"change[0-9]+\.html", unescape(reply.text)))
            more = re.search(r"diffs:[A-Za-z0-9_-]{32}", reply.text)
            if not more:
                break
            _, reply = await send(v, "!oz diff " + more[0], number)
        assert len(seen) == len(set(seen)) == 25
        assert v.reads == v.remote.posts == 0


async def test_a_live_catalog_view_keeps_roots_registered_after_startup(db, tmp_path):
    # Roots created from chat join through a live view; FileMenus must not freeze it.
    from jt_oz_bridge.domain.enrollment_views import EnrollmentView

    async with setup(db, tmp_path) as v:
        later: dict = {}
        menus = FileMenus(
            v.store.bindings,
            v.source,
            v.tokens,
            EnrollmentView(lambda: {REF: v.catalog, **later}),
            message_limit=1000,
        )
        other = REF.model_copy(update={"upstream_session_id": "ses_created"})
        assert set(menus.catalogs) == {REF}
        later[other] = v.catalog
        assert set(menus.catalogs) == {REF, other} and set(menus.choices.catalogs) == {REF, other}
