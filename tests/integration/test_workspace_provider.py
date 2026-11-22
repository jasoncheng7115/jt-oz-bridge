"""Real own encrypted journal/files and synthetic source/Native batch authority."""

import gc
import time
import weakref
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.native_workspace import NativeWorkspaceBatch
from jt_oz_bridge.domain.attachments import WorkspaceAttachmentManifest
from jt_oz_bridge.domain.workspace_attachments import (
    PreparedWorkspaceAttachments,
    workspace_projection,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.workspace_journal import WorkspaceJournal
from jt_oz_bridge.services.workspace_provider import ArtifactWorkspaceAttachmentProvider
from jt_oz_bridge.services.workspace_routes import WorkspaceProviderRoutes
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.workspace_files import WorkspaceFiles, WorkspaceNamespace
from jt_oz_bridge.storage.workspace_models import WorkspacePublication
from tests.integration.test_workspace_journal import finish
from tests.integration.test_workspace_journal import setup as journal_setup
from tests.support import REF


class SyntheticSharedHost:
    """Deliberate test authority; does not qualify a shared Native host."""

    def __init__(self, journal):
        self.files = journal.files
        self.namespace_sha256 = journal.namespace_sha256
        self.reader = SimpleNamespace(require=lambda ref: SimpleNamespace(contract_sha256="a" * 64))
        self.proofs = []
        self.active = True
        self.hook = None

    def qualified(self, ref, schema):
        return self.active and ref == REF and schema == "a" * 64

    async def prove(self, ref, files):
        result = NativeWorkspaceBatch(ref, files, "b" * 64)
        self.proofs.append(result)
        if self.hook:
            await self.hook()
        return result

    def current(self, proof):
        return (
            self.active
            and any(proof is item for item in self.proofs)
            and all(self.files.unchanged(f) for f in proof.files)
        )


async def setup(db, tmp_path, **options):
    parts, old, source, manifest = await journal_setup(db, tmp_path, **options)
    old.files.close()
    path = old.files.namespace.path
    renamed = path.with_name(".jt-oz-incoming-fixture")
    path.rename(renamed)
    stat = renamed.stat()
    files = WorkspaceFiles(
        WorkspaceNamespace(renamed, stat.st_dev, stat.st_ino, stat.st_uid, stat.st_gid),
        reserve_free_bytes=0,
    )
    journal = WorkspaceJournal(parts[0], files)
    host = SyntheticSharedHost(journal)
    provider = ArtifactWorkspaceAttachmentProvider(
        parts[0],
        parts[4],
        realm_id=source.realm_id,
        realm_url=parts[6].url,
        journals={REF: journal},
        hosts={REF: host},
        associations=parts[8].associations,
    )
    return parts, journal, source, manifest, host, provider


async def test_exact_source_stages_ordinary_files_with_metadata_only_projection_and_fresh_association(
    db, tmp_path
):
    parts, journal, source, manifest, host, provider = await setup(db, tmp_path)
    try:
        async with db.sessions() as session:
            before = await session.get(Action, parts[5])
        prepared = await provider.prepare(REF, parts[5], source, manifest, before.payload["text"])
        assert provider.current(REF, parts[5], prepared)
        text = prepared.checked(REF, parts[5], source, manifest, before.payload["text"])
        assert text.startswith(before.payload["text"] + "\n\n[jt-oz-bridge workspace inputs v1]\n")
        assert "model_interpretation" in text and "unverified" in text
        assert "data:" not in text and "PRIVATE-SIGNED" not in text
        assert [f.original.sha256 for f in host.proofs[-1].files] == [
            f.sha256 for f in manifest.files
        ]
        assert all(
            (journal.files.namespace.path / f.storage_name).read_bytes() == bytes(22)
            for f in host.proofs[-1].files
        )
        assert len(parts[-1]) == 4  # initial synthetic import only, no extra downloads/POST
        assert (
            parts[8].associations.calls[-2:]
            == [
                (
                    source.message_id,
                    tuple(f.source_upload.removeprefix("/user_uploads/") for f in manifest.files),
                )
            ]
            * 2
        )
        async with db.sessions() as session:
            after = await session.get(Action, parts[5])
        assert (after.payload, after.operation_digest, after.version, after.state) == (
            before.payload,
            before.operation_digest,
            before.version,
            before.state,
        )
        assert not provider.current(REF, parts[5], replace(prepared))
        assert not provider.current(REF, "another-action", prepared)
        held = weakref.ref(prepared)
        del prepared
        gc.collect()
        assert held() is None
    finally:
        await provider.close()
        await finish(parts, journal)


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "realm",
        "reference",
        "text",
        "grant",
        "association",
        "descriptor",
        "host",
        "closed",
    ],
)
async def test_original_scope_or_authority_change_rejects_before_plaintext_staging(
    db, tmp_path, change
):
    parts, journal, source, manifest, host, provider = await setup(db, tmp_path)
    selected = REF
    async with db.sessions() as session:
        text = (await session.get(Action, parts[5])).payload["text"]
    try:
        if change == "source":
            parts[4].messages[source.message_id] = source.model_copy(
                update={"revision": source.revision + 1}
            )
        if change == "realm":
            provider.realm_id = "foreign"
        if change == "reference":
            selected = REF.model_copy(update={"upstream_session_id": "other"})
        if change == "text":
            text += " altered"
        if change == "grant":
            async with db.sessions.begin() as session:
                for grant in (await session.scalars(select(Grant))).all():
                    grant.active = False
        if change == "association":
            parts[8].associations.active = False
        if change == "descriptor":
            parts[8].associations.size += 1
        if change == "host":
            host.active = False
        if change == "closed":
            await provider.close()
        with pytest.raises((Conflict, AccessDenied, ValueError)):
            await provider.prepare(selected, parts[5], source, manifest, text)
        assert not list(journal.files.namespace.path.iterdir())
        async with db.sessions() as session:
            assert not (await session.scalars(select(WorkspacePublication))).all()
    finally:
        await provider.close()
        await finish(parts, journal)


@pytest.mark.parametrize("change", ["source", "grant", "action", "association", "host", "file"])
async def test_change_during_native_batch_never_issues_prepared_authority(db, tmp_path, change):
    parts, journal, source, manifest, host, provider = await setup(db, tmp_path)
    async with db.sessions() as session:
        original_text = (await session.get(Action, parts[5])).payload["text"]

    async def mutate():
        if change == "source":
            parts[4].messages[source.message_id] = source.model_copy(
                update={"revision": source.revision + 1}
            )
        if change in {"action", "grant"}:
            async with db.sessions.begin() as session:
                if change == "action":
                    (await session.get(Action, parts[5])).version += 1
                else:
                    for grant in (await session.scalars(select(Grant))).all():
                        grant.active = False
        if change == "association":
            parts[8].associations.active = False
        if change == "host":
            host.active = False
        if change == "file":
            f = host.proofs[-1].files[0]
            (journal.files.namespace.path / f.storage_name).write_bytes(b"changed")

    host.hook = mutate
    try:
        with pytest.raises((Conflict, AccessDenied, ValueError)):
            await provider.prepare(REF, parts[5], source, manifest, original_text)
        assert not provider._issued
        assert len(list(journal.files.namespace.path.iterdir())) == 2
    finally:
        await provider.close()
        await finish(parts, journal)


@pytest.mark.parametrize("change", ["expired", "association", "host", "close"])
async def test_issued_preparation_expires_and_revokes_without_rehydrating_authority(
    db, tmp_path, monkeypatch, change
):
    parts, journal, source, manifest, host, provider = await setup(db, tmp_path)
    async with db.sessions() as session:
        original_text = (await session.get(Action, parts[5])).payload["text"]
    try:
        prepared = await provider.prepare(REF, parts[5], source, manifest, original_text)
        if change == "expired":
            now = time.monotonic()
            monkeypatch.setattr(
                "jt_oz_bridge.services.workspace_provider.time.monotonic", lambda: now + 6
            )
        elif change == "association":
            parts[8].associations.active = False
        elif change == "host":
            host.active = False
        else:
            await provider.close()
        assert not provider.current(REF, parts[5], prepared)
        assert not provider.current(REF, parts[5], replace(prepared))
    finally:
        await provider.close()
        await finish(parts, journal)


class RealmProvider:
    def __init__(self):
        self.prepared = None
        self.hook = None

    def qualified(self, ref, schema):
        return ref == REF and schema == "a" * 64

    async def prepare(self, ref, action, source, manifest, text):
        self.prepared = PreparedWorkspaceAttachments(
            ref,
            action,
            source.realm_id,
            digest(source.model_dump(mode="json")),
            "d" * 64,
            workspace_projection(ref, action, text, manifest, ".jt-oz-incoming-fixture", "b" * 64),
        )
        if self.hook:
            self.hook()
        return self.prepared

    def current(self, ref, action, prepared):
        return prepared is self.prepared


async def test_realm_routes_keep_original_registration_identity_and_do_not_resurrect_reissued_objects():
    from uuid import uuid4

    from tests.integration.test_workspace_attachment_imports import receipts

    source, files = receipts(count=1, size=0)
    manifest = WorkspaceAttachmentManifest(files=files)
    routes = WorkspaceProviderRoutes()
    one, two = RealmProvider(), RealmProvider()
    first = routes.register(source.realm_id, one)
    second = routes.register("second", two)
    assert routes.qualified(REF, "a" * 64)
    prepared = await routes.prepare(REF, str(uuid4()), source, manifest, source.text)
    assert routes.current(REF, prepared.action_id, prepared)
    assert two.prepared is None
    routes.unregister(first)
    routes.register(source.realm_id, one)
    assert not routes.current(REF, prepared.action_id, prepared)
    with pytest.raises(ValueError):
        routes.unregister(first)
    with pytest.raises(ValueError):
        routes.register("second", two)
    routes.unregister(second)


async def test_realm_removed_during_preparation_cannot_publish_cross_registration_authority():
    from uuid import uuid4

    from tests.integration.test_workspace_attachment_imports import receipts

    source, files = receipts(count=1, size=0)
    routes, one = WorkspaceProviderRoutes(), RealmProvider()
    registration = routes.register(source.realm_id, one)
    one.hook = lambda: routes.unregister(registration)
    with pytest.raises(Conflict, match="registration_changed"):
        await routes.prepare(
            REF, str(uuid4()), source, WorkspaceAttachmentManifest(files=files), source.text
        )
    assert not routes._prepared
