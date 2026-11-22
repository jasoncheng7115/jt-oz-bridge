"""Synthetic Root certificates + real isolated namespace; no live qualification."""

import copy
import json
import os
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode import native_workspace
from jt_oz_bridge.domain.workspace_attachments import WORKSPACE_SEMANTICS
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.services import upload_associations
from jt_oz_bridge.services.file_enrollment import component_sha
from jt_oz_bridge.services.upload_associations import SSHAssociationConfig, SSHUploadAssociations
from jt_oz_bridge.services.workspace_enrollment import REVIEW, SOURCE_NEGATIVES
from jt_oz_bridge.storage import workspace_files
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.integration.test_file_enrollment import files as files
from tests.integration.test_runtime_enrollment import enrolled as enrolled


@pytest.fixture
def workspace(files, tmp_path):
    project = tmp_path.resolve() / "native-project"
    project.mkdir(mode=0o700)
    directory = project / ".jt-oz-incoming-fixture"
    directory.mkdir(mode=0o2750)
    directory.chmod(0o2750)
    st = directory.stat()
    b = files.manifest["backends"][0]
    ref = copy.deepcopy(files.ref)
    ref["canonical_directory"] = str(project)
    files.ref = ref
    b["reference"] = ref
    files.settings.projects[0].workspace_root = str(project)
    owner = json.loads(files.documents[Path(b["owner"]["path"])])
    owner["client_uid"] = os.geteuid()
    b["owner"] = files.pin("owner-v4.json", owner)
    policy = json.loads(files.documents[Path(b["policy"]["path"])])
    policy["reference"] = ref
    b["policy"] = files.pin("policy-v4.json", policy)
    model = json.loads(files.documents[Path(b["model_evidence"]["path"])])
    model["reference"] = ref
    b["model_evidence"] = files.pin("model-v4.json", model)
    outcome = json.loads(files.documents[Path(b["outcome_evidence"][0]["path"])])
    outcome["evidence"]["correlation"]["reference"] = ref
    b["outcome_evidence"] = [files.pin("outcome-v4.json", outcome)]
    files.native["native_read"]["reference"] = ref
    files.save_files()
    files.manifest["format"] = "qualified-consumer-runtime-v4"
    files.settings.runtime.workspace_inputs_enabled = True
    source_config = dict(
        format="jt-oz-upload-association-v1",
        realm_id="2",
        realm_url="https://chat.invalid",
        channel_ids=[4],
        host="zulip.invalid",
        user="claim-reader",
        key_file="/etc/jtoz-synthetic/claim-key",
        key_sha256="a" * 64,
        known_hosts_file="/etc/jtoz-synthetic/known-hosts",
        known_hosts_sha256="b" * 64,
        helper_sha256="c" * 64,
        remote_policy_sha256="d" * 64,
        installed_evidence_sha256="e" * 64,
    )
    namespace = dict(
        format="qualified-original-workspace-v1",
        operator_review=REVIEW,
        reference=ref,
        namespace=dict(
            path=str(directory),
            device=st.st_dev,
            inode=st.st_ino,
            owner_uid=st.st_uid,
            reader_gid=st.st_gid,
        ),
        contract_sha256=b["schema_file"]["sha256"],
        native_policy_sha256=policy["fingerprint_sha256"],
        executable_sha256=owner["executable_sha256"],
        native_uid=owner["native_uid"],
        workspace_component_sha256=component_sha(native_workspace),
        storage_component_sha256=component_sha(workspace_files),
        workspace_semantics_sha256=WORKSPACE_SEMANTICS,
        observation=dict(
            files=10,
            bytes_each=20 * 1024**2,
            aggregate_original_object_current=True,
            namespace_identity_preserved=True,
            controlled_files_removed=True,
            namespace_retained=True,
            native_database_bytes_read=False,
            native_mutations=0,
            zulip_requests=0,
            evidence_sha256="f" * 64,
        ),
    )
    source = dict(
        format="qualified-original-source-uploads-v1",
        operator_review=REVIEW,
        realm_id="2",
        realm_url="https://chat.invalid",
        bot_user_id=11,
        config_sha256="0" * 64,
        transport_component_sha256=component_sha(upload_associations),
        helper_sha256=source_config["helper_sha256"],
        remote_policy_sha256=source_config["remote_policy_sha256"],
        installed_evidence_sha256=source_config["installed_evidence_sha256"],
        positive=dict(
            author_id=8,
            channel_id=4,
            message_id=123,
            upload_count=1,
            mode="human-source",
            is_bot=False,
            transaction_read_only=True,
            original_association_current=True,
            source_sha256="a" * 64,
        ),
        negatives={key: True for key in SOURCE_NEGATIVES},
    )

    def save():
        files.manifest["realm"]["source_uploads"] = files.pin(
            "source-config-v4.json", source_config
        )
        source["config_sha256"] = files.manifest["realm"]["source_uploads"]["sha256"]
        files.manifest["realm"]["source_evidence"] = files.pin("source-evidence-v4.json", source)
        b["workspace"] = files.pin("namespace-v4.json", namespace)
        files.save()

    files.save_workspace = save
    files.namespace_doc = namespace
    files.source_doc = source
    files.source_config = source_config
    files.namespace_path = directory
    save()
    return files


def test_v4_root_read_is_inert_and_does_not_read_source_key_or_open_workspace(
    workspace, monkeypatch
):
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("credential read during inert enrollment")
    )
    monkeypatch.setattr(
        runtime,
        "WorkspaceFiles",
        lambda *_args, **_kwargs: pytest.fail("filesystem opened during inert enrollment"),
    )
    value, sha = runtime.read_enrollment(workspace.settings)
    assert value.format.endswith("v4") and value.realm.source_uploads and len(sha) == 64
    assert not workspace.settings.app.state_dir.exists()


@pytest.mark.parametrize(
    "path,value",
    [
        (("reference", "upstream_session_id"), "foreign"),
        (("namespace", "inode"), 0),
        (("namespace", "owner_uid"), 99999),
        (("namespace", "path"), "/other/.jt-oz-incoming-fixture"),
        (("contract_sha256",), "f" * 64),
        (("native_policy_sha256",), "f" * 64),
        (("executable_sha256",), "f" * 64),
        (("workspace_component_sha256",), "f" * 64),
        (("storage_component_sha256",), "f" * 64),
        (("workspace_semantics_sha256",), "f" * 64),
        (("native_uid",), False),
        (("observation", "files"), 9),
        (("observation", "bytes_each"), 1024),
        (("observation", "namespace_retained"), False),
        (("observation", "controlled_files_removed"), False),
        (("observation", "aggregate_original_object_current"), False),
        (("observation", "native_mutations"), 1),
        (("observation", "native_database_bytes_read"), True),
    ],
)
def test_rehashed_namespace_certificate_cannot_change_original_scope_or_case_boundaries(
    workspace, path, value
):
    doc = workspace.namespace_doc
    for key in path[:-1]:
        doc = doc[key]
    doc[path[-1]] = value
    workspace.save_workspace()
    with pytest.raises(ValueError):
        runtime.read_enrollment(workspace.settings)


@pytest.mark.parametrize(
    "path,value",
    [
        (("realm_id",), "foreign"),
        (("realm_url",), "https://foreign.invalid"),
        (("bot_user_id",), 12),
        (("helper_sha256",), "f" * 64),
        (("remote_policy_sha256",), "f" * 64),
        (("installed_evidence_sha256",), "f" * 64),
        (("transport_component_sha256",), "f" * 64),
        (("positive", "author_id"), 11),
        (("positive", "channel_id"), 99),
        (("positive", "message_id"), False),
        (("positive", "is_bot"), True),
        (("positive", "transaction_read_only"), False),
        (("positive", "original_association_current"), False),
        (("positive", "upload_count"), 11),
        (("negatives", "unlinked-upload"), False),
    ],
)
def test_rehashed_source_certificate_requires_true_original_human_and_denial_coverage(
    workspace, path, value
):
    doc = workspace.source_doc
    for key in path[:-1]:
        doc = doc[key]
    doc[path[-1]] = value
    workspace.save_workspace()
    with pytest.raises(ValueError):
        runtime.read_enrollment(workspace.settings)


@pytest.mark.parametrize(
    "change",
    ["v3", "missing-source", "missing-proof", "missing-workspace", "flag-v3", "requires-files"],
)
def test_capabilities_cannot_leak_into_old_manifests_or_enable_without_files(workspace, change):
    if change == "v3":
        workspace.manifest["format"] = "qualified-consumer-runtime-v3"
    elif change == "missing-source":
        workspace.manifest["realm"].pop("source_uploads")
    elif change == "missing-proof":
        workspace.manifest["realm"].pop("source_evidence")
    elif change == "missing-workspace":
        workspace.manifest["backends"][0].pop("workspace")
    elif change == "flag-v3":
        workspace.manifest["format"] = "qualified-consumer-runtime-v3"
        workspace.manifest["realm"].pop("source_uploads")
        workspace.manifest["realm"].pop("source_evidence")
        workspace.manifest["backends"][0].pop("workspace")
    else:
        from jt_oz_bridge.config import Settings

        data = workspace.settings.model_dump(mode="json")
        data["runtime"]["file_returns_enabled"] = False
        with pytest.raises(ValueError):
            Settings.model_validate(data)
        return
    workspace.save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(workspace.settings)


async def compose(workspace, db):
    value, sha = runtime.read_enrollment(workspace.settings)
    lease = await DurableStore(db).acquire_lease("workspace-enrollment", ttl=120)
    return runtime.build_pipeline(
        workspace.settings, value, sha, db, ConsumerFence("workspace-enrollment", lease)
    )


async def close(pipeline):
    await pipeline.close_files()
    await pipeline.scope.client.close()
    for backend in pipeline.backends.values():
        for resource in backend.resources:
            await resource.close()


async def test_v4_composition_shares_exact_source_store_client_readers_fence_and_cleanup(
    workspace, db, monkeypatch
):
    opened = []

    def config(self):
        opened.append(True)
        return SSHAssociationConfig.model_validate(workspace.source_config)

    monkeypatch.setattr(SSHUploadAssociations, "configuration", config)
    pipeline = await compose(workspace, db)
    incoming = pipeline.incoming
    try:
        assert incoming and incoming.files is pipeline.files
        importer = incoming.imports.importer
        assert importer.artifacts is pipeline.files.journal.artifacts
        assert importer.source is pipeline.source and importer.zulip is pipeline.scope.client
        assert importer.downloader is pipeline.files.journal.downloader
        assert incoming.imports is pipeline.dispatcher.attachment_imports
        assert incoming.imports.fence == pipeline.fence
        assert not opened
        await incoming.start()
        assert opened == [True]
        for ref, host in incoming.hosts.items():
            assert host.reader is pipeline.files.readers[ref]
            assert incoming.qualified(ref, pipeline.registry.contract_for(ref))
            assert host.reader.client.workspace_attachments is not None
        names = [resource.name for resource in pipeline.runtime().resources]
        assert (
            names.index("file-returns")
            < names.index("workspace-inputs")
            < next(i for i, n in enumerate(names) if n.startswith("native:"))
        )
        await incoming.prune_once()
    finally:
        await close(pipeline)
    assert all(j.files._fd == -1 for j in incoming.journals.values())
    assert pipeline.files.journal.artifacts.files._fd == -1
    assert pipeline.files.journal.downloader.client.is_closed


async def test_preloaded_v4_certificates_do_not_enable_incoming_without_flag(workspace, db):
    workspace.settings.runtime.workspace_inputs_enabled = False
    pipeline = await compose(workspace, db)
    try:
        assert pipeline.incoming is None and pipeline.dispatcher.attachment_imports is None
        assert not any(r.name == "workspace-inputs" for r in pipeline.runtime().resources)
        assert all(
            reader.client.workspace_attachments is None
            for reader in pipeline.files.readers.values()
        )
    finally:
        await close(pipeline)


async def test_namespace_inode_replacement_rejected_during_composition(workspace, db):
    workspace.namespace_path.rename(workspace.namespace_path.with_name("retained-original"))
    workspace.namespace_path.mkdir(mode=0o2750)
    workspace.namespace_path.chmod(0o2750)
    with pytest.raises(ValueError, match="namespace_pin_rejected"):
        await compose(workspace, db)


async def test_current_source_configuration_failure_releases_every_local_namespace(
    workspace, db, monkeypatch
):
    def unavailable(_self):
        raise ValueError("synthetic source credential mismatch")

    monkeypatch.setattr(SSHUploadAssociations, "configuration", unavailable)
    pipeline = await compose(workspace, db)
    incoming = pipeline.incoming
    try:
        with pytest.raises(ValueError):
            await incoming.start()
        assert all(j.files._fd == -1 for j in incoming.journals.values())
        assert not incoming._installed
    finally:
        await close(pipeline)


async def test_early_native_startup_failure_still_closes_preconstructed_input_and_artifact_fds(
    workspace, db, monkeypatch
):
    from dataclasses import replace
    from types import MappingProxyType

    from jt_oz_bridge.services.runtime import RuntimeResource

    async def fail():
        raise RuntimeError("synthetic original owner unavailable")

    async def done():
        pass

    monkeypatch.setattr(
        SSHUploadAssociations,
        "configuration",
        lambda _: SSHAssociationConfig.model_validate(workspace.source_config),
    )
    pipeline = await compose(workspace, db)
    pipeline.backends = MappingProxyType(
        {
            key: replace(backend, resources=(RuntimeResource("native:synthetic", fail, done),))
            for key, backend in pipeline.backends.items()
        }
    )
    live = pipeline.runtime()
    try:
        with pytest.raises(RuntimeError, match="runtime_start_failed"):
            await live.start()
        assert all(j.files._fd == -1 for j in pipeline.incoming.journals.values())
        assert pipeline.files.journal.artifacts.files._fd == -1
        assert pipeline.files.journal.downloader.client.is_closed
        assert live.failure_detail.component == "native"
    finally:
        await live.close()
        await close(pipeline)


async def test_two_original_roots_share_one_namespace_journal_and_prune_it_once(
    workspace, db, monkeypatch
):
    from unittest.mock import AsyncMock

    one = workspace.manifest["backends"][0]
    two = copy.deepcopy(one)
    newref = {**one["reference"], "upstream_session_id": "ses_synthetic_second"}
    two["reference"] = newref
    for field in ("policy", "model_evidence", "file_read", "workspace"):
        doc = json.loads(workspace.documents[Path(one[field]["path"])])
        if field == "file_read":
            doc["native_read"]["reference"] = newref
        else:
            doc["reference"] = newref
        two[field] = workspace.pin("second-" + field + ".json", doc)
    doc = json.loads(workspace.documents[Path(one["outcome_evidence"][0]["path"])])
    doc["evidence"]["correlation"]["reference"] = newref
    two["outcome_evidence"] = [workspace.pin("second-outcome.json", doc)]
    workspace.manifest["backends"].append(two)
    workspace.save()
    monkeypatch.setattr(
        SSHUploadAssociations,
        "configuration",
        lambda _: SSHAssociationConfig.model_validate(workspace.source_config),
    )
    pipeline = await compose(workspace, db)
    try:
        journals = pipeline.incoming.journals
        assert len(journals) == 2 and len({id(j) for j in journals.values()}) == 1
        journal = next(iter(journals.values()))
        journal.prune_expired = AsyncMock(return_value=0)
        await pipeline.incoming.start()
        await pipeline.incoming.prune_once()
        await pipeline.incoming.prune_once()
        journal.prune_expired.assert_awaited_once_with(limit=10)
    finally:
        await close(pipeline)


def scoped_workspace(workspace):
    """Two synthetic Roots; only the first has an incoming namespace certificate."""
    from tests.integration.test_catalog_enrollment import configure_catalogs
    from tests.integration.test_runtime_enrollment import add_second_root

    second = add_second_root(workspace)
    second.pop("workspace", None)
    configure_catalogs(workspace)
    workspace.manifest["format"] = "qualified-consumer-runtime-v7"
    workspace.manifest["workspace_roots"] = [copy.deepcopy(workspace.ref)]
    workspace.manifest["generated_roots"] = []
    workspace.save_catalogs()
    return second


async def test_v7_scoped_incoming_composes_only_the_selected_root(workspace, db, monkeypatch):
    second = scoped_workspace(workspace)
    monkeypatch.setattr(
        SSHUploadAssociations,
        "configuration",
        lambda _: SSHAssociationConfig.model_validate(workspace.source_config),
    )
    pipeline = await compose(workspace, db)
    try:
        from jt_oz_bridge.domain.models import SessionRef

        selected = SessionRef.model_validate(workspace.ref)
        other = SessionRef.model_validate(second["reference"])
        incoming = pipeline.incoming
        assert set(incoming.journals) == {selected}
        assert set(pipeline.files.readers) == {selected, other}
        await incoming.start()
        contract = pipeline.registry.contract_for(selected)
        assert incoming.qualified(selected, contract) and not incoming.qualified(other, contract)
        assert pipeline.dispatcher.workspace_scope(selected) is True
        assert pipeline.dispatcher.workspace_scope(other) is False
        assert pipeline.files.readers[other].client.workspace_attachments is None
    finally:
        await close(pipeline)


@pytest.mark.parametrize("change", ["empty", "both", "foreign", "extra-cert", "missing-source"])
def test_v7_incoming_scope_must_equal_certified_roots(workspace, change):
    second = scoped_workspace(workspace)
    if change == "empty":
        workspace.manifest["workspace_roots"] = []
    elif change == "both":
        workspace.manifest["workspace_roots"].append(second["reference"])
    elif change == "foreign":
        workspace.manifest["workspace_roots"][0]["upstream_session_id"] = "ses_foreign"
    elif change == "extra-cert":
        second["workspace"] = copy.deepcopy(workspace.manifest["backends"][0]["workspace"])
    else:
        workspace.manifest["realm"].pop("source_evidence")
    workspace.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(workspace.settings)


@pytest.mark.parametrize("version", ["v4", "v5", "v6"])
def test_legacy_format_rejects_incoming_scope_field(workspace, version):
    from tests.integration.test_catalog_enrollment import configure_catalogs

    configure_catalogs(workspace)
    workspace.manifest["format"] = "qualified-consumer-runtime-" + version
    workspace.manifest["workspace_roots"] = [workspace.ref]
    workspace.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(workspace.settings)
