"""Synthetic Root documents + isolated own DB; never installed certification."""

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode import directory_scope, workspace_catalog
from jt_oz_bridge.adapters.opencode.directory_scope import DirectoryScopeEnrollment
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.domain.enrollment_views import EnrollmentView
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.services.catalog_enrollment import CATALOG_CHECKS, catalog_qualification
from jt_oz_bridge.services.file_enrollment import component_sha
from jt_oz_bridge.services.runtime import SupervisedRuntime
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.integration.test_file_enrollment import files as files
from tests.integration.test_runtime_enrollment import add_second_root
from tests.integration.test_runtime_enrollment import enrolled as enrolled
from tests.integration.test_workspace_enrollment import workspace as workspace


def configure_catalogs(files):
    files.manifest["format"] = "qualified-consumer-runtime-v5"
    files.settings.runtime.workspace_menus_enabled = True
    b = files.manifest["backends"][0]
    owner = json.loads(files.documents[Path(b["owner"]["path"])])
    roots = {}
    for b in files.manifest["backends"]:
        ref = SessionRef.model_validate(b["reference"])
        key = directory_project_key(ref)
        roots[key] = dict(
            project_key=key,
            directory=ref.canonical_directory,
            device=11,
            inode=22,
            uid=owner["native_uid"],
            gid=owner["native_uid"],
            mode=0o700,
        )
        b["verified_operations"] = sorted(set(b["verified_operations"]) | {"fs.list", "fs.find"})
        # This entire module is synthetic, including its second reader evidence.
        native = copy.deepcopy(files.native)
        native["native_read"]["reference"] = b["reference"]
        b["file_read"] = files.pin("read-catalog-" + ref.upstream_session_id + ".json", native)
    files.directory_doc = dict(
        config_sha256="a" * 64,
        implementation_sha256="b" * 64,
        server_uid=owner["native_uid"],
        client_uid=owner["client_uid"],
        roots=list(roots.values()),
    )
    files.manifest["directory_scope"] = files.pin("directory-v5.json", files.directory_doc)
    files.manifest["directory_socket"] = "/run/jtoz-synthetic/directory.sock"
    documents = {}
    for b in files.manifest["backends"]:
        ref = SessionRef.model_validate(b["reference"])
        policy = json.loads(files.documents[Path(b["policy"]["path"])])
        documents[ref.upstream_session_id] = dict(
            format="qualified-original-workspace-catalog-v2",
            operator_review="installed-evidence-reviewed-for-development-runtime",
            reference=b["reference"],
            contract_sha256=b["schema_file"]["sha256"],
            native_policy_sha256=policy["fingerprint_sha256"],
            executable_sha256=owner["executable_sha256"],
            catalog_component_sha256=component_sha(workspace_catalog),
            directory_component_sha256=component_sha(directory_scope),
            semantics_sha256=workspace_catalog.CATALOG_SEMANTICS,
            directory_enrollment_sha256=files.manifest["directory_scope"]["sha256"],
            directory_config_sha256=files.directory_doc["config_sha256"],
            directory_implementation_sha256=files.directory_doc["implementation_sha256"],
            physical_root=roots[directory_project_key(ref)],
            operations=["fs.list", "fs.find"],
            observation=dict(
                passed=True,
                native_database_bytes_read=False,
                native_http_mutations=0,
                zulip_http_mutations=0,
                original_processes_unchanged=True,
                live_bridge_counts_unchanged=True,
                controlled_probe_cleanup_complete=True,
                evidence_sha256="c" * 64,
                checks={
                    op: dict.fromkeys(CATALOG_CHECKS[op], True) for op in ("fs.list", "fs.find")
                },
            ),
        )
    files.catalog_docs = documents
    files.catalog_doc = documents[files.ref["upstream_session_id"]]

    def save():
        files.manifest["directory_scope"] = files.pin("directory-v5.json", files.directory_doc)
        for b in files.manifest["backends"]:
            name = b["reference"]["upstream_session_id"]
            b["workspace_catalog"] = files.pin(
                "catalog-" + name + ".json", files.catalog_docs[name]
            )
        files.save()

    files.save_catalogs = save
    save()
    return files


@pytest.fixture
def catalogs(files):
    return configure_catalogs(files)


def test_v5_catalog_enrollment_is_inert_and_does_not_need_source_uploads(catalogs, monkeypatch):
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("no credentials during read")
    )
    monkeypatch.setattr(
        runtime, "LinuxDirectoryScopeGuard", lambda *_: pytest.fail("no socket client during read")
    )
    value, sha = runtime.read_enrollment(catalogs.settings)
    assert value.format.endswith("v5") and len(sha) == 64
    assert (
        value.realm.source_uploads is None
        and not catalogs.settings.runtime.workspace_inputs_enabled
    )
    assert not catalogs.settings.app.state_dir.exists()


@pytest.mark.parametrize(
    "field",
    [
        "format",
        "operator_review",
        "reference",
        "contract_sha256",
        "native_policy_sha256",
        "executable_sha256",
        "catalog_component_sha256",
        "directory_component_sha256",
        "semantics_sha256",
        "directory_enrollment_sha256",
        "directory_config_sha256",
        "directory_implementation_sha256",
        "physical_root",
    ],
)
def test_rehashed_catalog_cannot_change_original_scope_or_components(catalogs, field):
    if field == "reference":
        catalogs.catalog_doc[field] = {**catalogs.ref, "upstream_session_id": "other"}
    elif field == "physical_root":
        catalogs.catalog_doc[field] = {**catalogs.catalog_doc[field], "inode": 23}
    else:
        catalogs.catalog_doc[field] = "unqualified"
    catalogs.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(catalogs.settings)


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("native_database_bytes_read", True),
        ("native_http_mutations", 1),
        ("native_http_mutations", False),
        ("zulip_http_mutations", True),
        ("original_processes_unchanged", False),
        ("live_bridge_counts_unchanged", False),
        ("controlled_probe_cleanup_complete", False),
        ("evidence_sha256", "invalid"),
    ],
)
def test_catalog_requires_actual_readonly_cleaned_observation(catalogs, field, value):
    catalogs.catalog_doc["observation"][field] = value
    catalogs.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(catalogs.settings)


@pytest.mark.parametrize(
    "operation,case",
    [(op, case) for op in ("fs.list", "fs.find") for case in sorted(CATALOG_CHECKS[op])],
)
def test_every_catalog_boundary_and_rank_case_is_required(catalogs, operation, case):
    catalogs.catalog_doc["observation"]["checks"][operation][case] = False
    catalogs.save_catalogs()
    with pytest.raises(ValueError, match="complete_operation_checks"):
        runtime.read_enrollment(catalogs.settings)


@pytest.mark.parametrize(
    "change",
    [
        "missing-catalog",
        "missing-directories",
        "missing-socket",
        "relative-socket",
        "extra-project",
        "wrong-root",
        "wrong-server",
        "wrong-client",
        "root-owner",
        "list-only",
        "duplicate-op",
        "undeclared-diff",
        "extra-evidence",
        "missing-find-transport",
        "legacy-v3",
        "enable-inputs",
    ],
)
def test_partial_or_widened_v5_configuration_fails_closed(catalogs, change):
    b = catalogs.manifest["backends"][0]
    if change == "missing-catalog":
        catalogs.save_catalogs()
        b.pop("workspace_catalog")
        catalogs.save()
    elif change == "missing-directories":
        catalogs.save_catalogs()
        catalogs.manifest.pop("directory_scope")
        catalogs.save()
    elif change == "missing-socket":
        catalogs.manifest.pop("directory_socket")
        catalogs.save_catalogs()
    elif change == "relative-socket":
        catalogs.manifest["directory_socket"] = "relative.sock"
        catalogs.save_catalogs()
    elif change == "extra-project":
        catalogs.directory_doc["roots"].append(
            {**catalogs.directory_doc["roots"][0], "project_key": "f" * 64}
        )
        catalogs.save_catalogs()
    elif change in {"wrong-root", "root-owner"}:
        catalogs.directory_doc["roots"][0]["directory" if change == "wrong-root" else "uid"] = (
            "/different" if change == "wrong-root" else 123
        )
        catalogs.save_catalogs()
    elif change in {"wrong-server", "wrong-client"}:
        catalogs.directory_doc["server_uid" if change == "wrong-server" else "client_uid"] = 123
        catalogs.save_catalogs()
    elif change in {"list-only", "duplicate-op", "undeclared-diff"}:
        catalogs.catalog_doc["operations"] = {
            "list-only": ["fs.list"],
            "duplicate-op": ["fs.list", "fs.find", "fs.find"],
            "undeclared-diff": ["fs.list", "fs.find", "session.diff"],
        }[change]
        catalogs.save_catalogs()
    elif change == "extra-evidence":
        catalogs.catalog_doc["observation"]["checks"]["session.diff"] = {}
        catalogs.save_catalogs()
    elif change == "missing-find-transport":
        b["verified_operations"].remove("fs.find")
        catalogs.save_catalogs()
    elif change == "legacy-v3":
        catalogs.manifest["format"] = "qualified-consumer-runtime-v3"
        catalogs.save_catalogs()
    else:
        catalogs.settings.runtime.workspace_inputs_enabled = True
    with pytest.raises(ValueError):
        runtime.read_enrollment(catalogs.settings)


def test_empty_diff_does_not_qualify_nonempty_session_diff(catalogs):
    catalogs.catalog_doc["operations"].append("session.diff")
    catalogs.catalog_doc["observation"]["checks"]["session.diff"] = {"empty_diff": True}
    catalogs.save_catalogs()
    with pytest.raises(ValueError, match="complete_operation_checks"):
        runtime.read_enrollment(catalogs.settings)


async def close_pipeline(pipe):
    await pipe.close_files()
    await pipe.scope.client.close()
    for backend in pipe.backends.values():
        for resource in reversed(backend.resources):
            await resource.close()


@pytest.mark.parametrize("enabled", [False, True])
async def test_v5_pipeline_shares_original_readers_source_tokens_and_fence(catalogs, db, enabled):
    catalogs.settings.runtime.workspace_menus_enabled = enabled
    value, sha = runtime.read_enrollment(catalogs.settings)
    pipe = runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert pipe.files is not None and pipe.incoming is None
        if enabled:
            menus = pipe.file_menus
            assert menus is not None and menus.source is pipe.source and menus.tokens is pipe.tokens
            assert menus.bindings is pipe.bindings and menus.fence == pipe.fence
            assert pipe.files.choices is menus.choices
            assert set(menus.catalogs) == set(pipe.files.readers)
            # Live views: a Root created from chat later adds its own reader here.
            assert isinstance(pipe.files.readers, EnrollmentView)
            assert isinstance(menus.catalogs, EnrollmentView)
            for ref, reader in menus.catalogs.items():
                assert reader.client is pipe.files.readers[ref].client
                assert reader.client is pipe.backends[ref.backend_id].metadata[ref].client
                assert reader.attestations[ref].operations == frozenset({"fs.list", "fs.find"})
                assert not reader.qualified(ref, "diff")
            assert any(r.name.startswith("workspace-catalog:") for r in pipe.runtime().resources)
        else:
            assert pipe.file_menus is None and pipe.files.choices is None
            assert not any(
                r.name.startswith("workspace-catalog:") for r in pipe.runtime().resources
            )
    finally:
        await close_pipeline(pipe)


async def test_two_roots_share_metadata_helper_but_keep_distinct_catalog_attestations(files, db):
    add_second_root(files)
    configure_catalogs(files)
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        readers = list(pipe.file_menus.catalogs.values())
        assert len(readers) == 2 and readers[0].directories is readers[1].directories
        assert readers[0].client is not readers[1].client
        assert readers[0].client.transport is readers[1].client.transport
        assert readers[0].attestations != readers[1].attestations
        assert len(readers[0].directories.enrollment.roots) == 1
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("present", [True, False])
def test_v5_optional_workspace_certificates_are_all_or_nothing(workspace, present):
    configure_catalogs(workspace)
    if not present:
        workspace.manifest["realm"].pop("source_evidence")
        workspace.save_catalogs()
    if present:
        value, _ = runtime.read_enrollment(workspace.settings)
        assert value.realm.source_uploads is not None and value.backends[0].workspace is not None
    else:
        with pytest.raises(ValueError):
            runtime.read_enrollment(workspace.settings)


def test_catalog_document_hash_must_match_actual_bytes(catalogs):
    b = runtime.RuntimeEnrollment.model_validate(catalogs.manifest).backends[0]
    directories = DirectoryScopeEnrollment.model_validate(catalogs.directory_doc)
    raw = catalogs.documents[b.workspace_catalog.path]
    owner = runtime.HostOwnerEnrollment.model_validate(json.loads(catalogs.documents[b.owner.path]))
    with pytest.raises(ValueError):
        catalog_qualification(
            raw,
            reference=b.reference,
            contract_sha256=b.schema_file.sha256,
            native_policy_sha256="b" * 64,
            owner=owner,
            directories=directories,
            directory_enrollment_sha256=catalogs.manifest["directory_scope"]["sha256"],
            evidence_sha256=hashlib.sha256(raw + b" ").hexdigest(),
        )


@pytest.mark.parametrize("failure", ["unavailable", "expired"])
async def test_metadata_startup_failure_closes_files_before_any_zulip_worker(
    catalogs, db, monkeypatch, caplog, failure
):
    lease = await DurableStore(db).acquire_lease("catalog-startup")
    value, sha = runtime.read_enrollment(catalogs.settings)
    pipe = runtime.build_pipeline(
        catalogs.settings, value, sha, db, ConsumerFence("catalog-startup", lease)
    )
    reader = next(iter(pipe.file_menus.catalogs.values()))
    guard = reader.directories
    observed = (
        AsyncMock(side_effect=PermissionError("PRIVATE_NATIVE_METADATA"))
        if failure == "unavailable"
        else AsyncMock(return_value=object())
    )
    monkeypatch.setattr(guard, "observe", observed)
    monkeypatch.setattr(guard, "current", lambda *_: False)
    resources = tuple(
        replace(r, start=AsyncMock()) if r.name.startswith("native:") else r
        for r in pipe.runtime().resources
    )
    consumer = AsyncMock(side_effect=AssertionError("must not start consumer"))
    resources = tuple(
        replace(r, start=consumer) if r.name == "zulip-consumer" else r for r in resources
    )
    service = SupervisedRuntime(db, pipe.fence, resources, pipe.runtime().workers)
    try:
        with pytest.raises(RuntimeError, match="runtime_start_failed"):
            await service.start()
        assert observed.await_count == 1 and consumer.await_count == 0
        assert pipe.files.journal.artifacts.files._fd == -1
        assert pipe.files.journal.downloader.client.is_closed
        assert service.failure_detail.component == "workspace-catalog"
        assert "PRIVATE" not in caplog.text
    finally:
        await service.close()
        await close_pipeline(pipe)


async def test_directory_startup_checks_each_original_root(files, db, monkeypatch):
    add_second_root(files)
    configure_catalogs(files)
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    reader = next(iter(pipe.file_menus.catalogs.values()))
    guard = reader.directories
    observe = AsyncMock(return_value=object())
    monkeypatch.setattr(guard, "observe", observe)
    monkeypatch.setattr(guard, "current", lambda *_: True)
    try:
        resource = next(
            r for r in pipe.runtime().resources if r.name.startswith("workspace-catalog:")
        )
        await resource.start()
        assert [call.args for call in observe.await_args_list] == [
            (q.reference, ("",)) for q in value.backends
        ]
    finally:
        await close_pipeline(pipe)


def test_changed_catalog_pin_is_rechecked_before_secrets_or_local_artifacts(
    catalogs, db, monkeypatch
):
    value, sha = runtime.read_enrollment(catalogs.settings)
    b = value.backends[0]
    catalogs.documents[b.workspace_catalog.path] += b" "
    monkeypatch.setattr(
        runtime, "resolve_secret", lambda _: pytest.fail("secret resolved after drift")
    )
    with pytest.raises(ValueError):
        runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    assert not catalogs.settings.app.state_dir.exists()


def test_menu_optin_on_legacy_manifest_requires_v5_even_without_extra_fields(files):
    files.settings.runtime.workspace_menus_enabled = True
    with pytest.raises(ValueError, match="menus_require_v5"):
        runtime.read_enrollment(files.settings)


async def test_direct_builder_rechecks_menu_file_runtime_dependency(catalogs, db, monkeypatch):
    value, sha = runtime.read_enrollment(catalogs.settings)
    catalogs.settings.runtime.file_returns_enabled = False
    monkeypatch.setattr(runtime, "resolve_secret", lambda _: pytest.fail("credential read"))
    with pytest.raises(ValueError, match="menus_require_original_file_runtime"):
        runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    assert not catalogs.settings.app.state_dir.exists()


@pytest.mark.parametrize("operations", [[], "fs.list", ["fs.read"]])
def test_catalog_operations_cannot_be_inferred_or_borrowed_from_other_capabilities(
    catalogs, operations
):
    catalogs.catalog_doc["operations"] = operations
    catalogs.save_catalogs()
    with pytest.raises(ValueError, match="explicit_operations"):
        runtime.read_enrollment(catalogs.settings)


async def test_diff_requires_its_own_complete_original_root_certificate(catalogs, db, monkeypatch):
    catalogs.catalog_doc["operations"].append("session.diff")
    catalogs.catalog_doc["observation"]["checks"]["session.diff"] = dict.fromkeys(
        CATALOG_CHECKS["session.diff"], True
    )
    b = catalogs.manifest["backends"][0]
    b["verified_operations"] = sorted(set(b["verified_operations"]) | {"session.diff"})
    catalogs.save_catalogs()
    value, sha = runtime.read_enrollment(catalogs.settings)
    pipe = runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        ref, reader = next(iter(pipe.file_menus.catalogs.items()))
        monkeypatch.setattr(reader.directories, "qualified", lambda _: True)
        assert reader.qualified(ref, "diff")
        assert reader.attestations[ref].operations == frozenset(
            {"fs.list", "fs.find", "session.diff"}
        )
    finally:
        await close_pipeline(pipe)


async def test_valid_v5_with_both_file_features_disabled_opens_no_file_store(catalogs, db):
    catalogs.settings.runtime.workspace_menus_enabled = False
    catalogs.settings.runtime.file_returns_enabled = False
    value, sha = runtime.read_enrollment(catalogs.settings)
    pipe = runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert pipe.files is None and pipe.file_menus is None
        assert not catalogs.settings.app.state_dir.exists()
        assert not any(r.name.startswith("workspace-catalog:") for r in pipe.runtime().resources)
    finally:
        await close_pipeline(pipe)


def test_one_original_root_cannot_borrow_another_roots_catalog_certificate(files):
    add_second_root(files)
    configure_catalogs(files)
    first, second = files.manifest["backends"]
    second["workspace_catalog"] = first["workspace_catalog"]
    files.save()
    with pytest.raises(ValueError, match="scope_or_component"):
        runtime.read_enrollment(files.settings)


async def test_v5_menus_and_incoming_share_the_same_original_file_graph(workspace, db, monkeypatch):
    from jt_oz_bridge.services.upload_associations import (
        SSHAssociationConfig,
        SSHUploadAssociations,
    )
    from tests.integration.test_workspace_enrollment import compose

    configure_catalogs(workspace)
    monkeypatch.setattr(
        SSHUploadAssociations,
        "configuration",
        lambda _: SSHAssociationConfig.model_validate(workspace.source_config),
    )
    pipe = await compose(workspace, db)
    try:
        incoming, menus = pipe.incoming, pipe.file_menus
        assert incoming is not None and menus is not None
        assert incoming.files is pipe.files and pipe.files.choices is menus.choices
        assert incoming.imports.importer.source is menus.source
        assert incoming.imports.importer.artifacts is pipe.files.journal.artifacts
        await incoming.start()
        for ref, reader in menus.catalogs.items():
            assert reader.client is incoming.hosts[ref].reader.client
            assert incoming.qualified(ref, pipe.registry.contract_for(ref))
        names = [r.name for r in pipe.runtime().resources]
        assert names.index("file-returns") < names.index("workspace-inputs")
        assert (
            names.index("workspace-inputs")
            < next(i for i, name in enumerate(names) if name.startswith("native:"))
            < next(i for i, name in enumerate(names) if name.startswith("workspace-catalog:"))
        )
    finally:
        await close_pipeline(pipe)
    assert all(journal.files._fd == -1 for journal in incoming.journals.values())


async def test_actual_pipeline_receives_current_database_backed_draft_policy(
    catalogs, db, monkeypatch
):
    original = runtime.ConsumerPipeline
    seen = []

    def build(*args, **kwargs):
        seen.append(kwargs["draft_interval_resolver"])
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime, "ConsumerPipeline", build)
    value, sha = runtime.read_enrollment(catalogs.settings)
    pipe = runtime.build_pipeline(catalogs.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert (
            len(seen) == 1
            and seen[0].__self__.db is db
            and seen[0].__self__.settings is catalogs.settings
        )
        async with db.sessions() as session:
            assert (
                await seen[0](session)
                == catalogs.settings.rendering.stream_update_min_interval_ms / 1000
            )
    finally:
        for backend in pipe.backends.values():
            for resource in reversed(backend.resources):
                await resource.close()


def test_legacy_catalog_format_cannot_borrow_new_read_scope_semantics(catalogs):
    catalogs.catalog_doc["format"] = "qualified-original-workspace-catalog-v1"
    catalogs.save_catalogs()
    with pytest.raises(ValueError):
        runtime.read_enrollment(catalogs.settings)


@pytest.mark.parametrize("missing", [None, "session.message.list", "session.message.get"])
def test_explicit_turn_catalog_requires_separate_operation_checks_and_transport(catalogs, missing):
    backend = catalogs.manifest["backends"][0]
    operations = [
        "fs.list",
        "fs.find",
        "session.diff",
        "session.message.list",
        "session.message.get",
    ]
    catalogs.catalog_doc["operations"] = operations
    catalogs.catalog_doc["observation"]["checks"] = {
        op: dict.fromkeys(CATALOG_CHECKS[op], True) for op in operations
    }
    backend["verified_operations"] = sorted(set(backend["verified_operations"]) | set(operations))
    if missing is not None:
        catalogs.catalog_doc["observation"]["checks"][missing] = {}
    catalogs.save_catalogs()
    if missing is not None:
        with pytest.raises(ValueError, match="complete_operation_checks"):
            runtime.read_enrollment(catalogs.settings)
    else:
        value, _ = runtime.read_enrollment(catalogs.settings)
        assert len(value.backends) == 1
