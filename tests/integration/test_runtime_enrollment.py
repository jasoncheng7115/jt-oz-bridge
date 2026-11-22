"""Synthetic root documents + real own DB enrollment, no installed certification."""

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.model_settings import MODEL_SETTING_SEMANTICS
from jt_oz_bridge.adapters.opencode.project_policy import PERMISSION_SOURCE, POLICY_READS
from jt_oz_bridge.adapters.opencode.resources import READS
from jt_oz_bridge.config import Settings
from jt_oz_bridge.services import runtime_enrollment as module
from jt_oz_bridge.services.runtime import RuntimeResource
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Grant
from tests.contract.test_host_owner import CONFIG


def adoption_enrollment(enrolled, *, lineage=None):
    """Synthetic operator pins, not installed semantic qualification."""
    from jt_oz_bridge.domain.existing_sessions import (
        ExistingSessionGraphObservation,
        ExistingSessionObservation,
    )
    from jt_oz_bridge.domain.models import SessionRef
    from jt_oz_bridge.domain.session_adoption import SessionAdoptionPolicy
    from jt_oz_bridge.storage.durable import digest

    manifest = enrolled.manifest
    manifest["format"] = "qualified-consumer-runtime-v2"
    native = manifest["backends"][0]
    native["protocol_scope"] = "backend"
    anchor = module.NativeQualification.model_validate(native)
    policy = SessionAdoptionPolicy(
        anchor=anchor.reference,
        contract_sha256=anchor.schema_file.sha256,
        installed_protocol_evidence_sha256=module.adoption_protocol_sha256(anchor),
        protocol_scope="backend",
        operations=frozenset({"prompt"}),
    )
    entry = {
        "anchor": copy.deepcopy(enrolled.ref),
        "policy": enrolled.pin("adoption-policy.json", policy.model_dump(mode="json")),
    }
    observed = None
    if lineage is not None:
        ref = SessionRef.model_validate(enrolled.ref)
        root_origin = {
            "reference": ref.model_dump(mode="json"),
            "native_project_id": "global",
            "created_at": 1,
            "parent_id": None,
        }
        root = ExistingSessionObservation(
            reference=ref,
            native_project_id="global",
            native_created_at=1,
            origin_sha256=digest(root_origin),
            policy_sha256="b" * 64,
            session_info_sha256="c" * 64,
            owner_epoch="a" * 64,
            observed_at=0,
            expires_at=5,
        )
        nodes = (root,)
        if lineage == "tree":
            child = ref.model_copy(update={"upstream_session_id": "ses_synthetic_original_child"})
            origin = {
                "reference": child.model_dump(mode="json"),
                "native_project_id": "global",
                "created_at": 2,
                "parent_id": ref.upstream_session_id,
                "parent_origin_sha256": digest(root_origin),
                "parent_created_at": 1,
            }
            nodes += (
                ExistingSessionObservation(
                    reference=child,
                    native_project_id="global",
                    native_created_at=2,
                    parent_reference=ref,
                    parent_created_at=1,
                    origin_sha256=digest(origin),
                    policy_sha256="b" * 64,
                    session_info_sha256="c" * 64,
                    owner_epoch="a" * 64,
                    observed_at=0,
                    expires_at=5,
                ),
            )
        graph = ExistingSessionGraphObservation(
            reference=ref,
            nodes=nodes,
            graph_sha256=module.graph_identity(nodes),
            owner_epoch="a" * 64,
            observed_at=0,
            expires_at=5,
        )
        owner = json.loads(enrolled.documents[Path(native["owner"]["path"])])
        observed = {
            "format": "installed-original-lineage-resource-observation-v1",
            "backend_id": ref.backend_id,
            "backend_identity": ref.backend_identity,
            "contract_sha256": anchor.schema_file.sha256,
            "executable_sha256": owner["executable_sha256"],
            "upstream_version": owner["version"],
            "semantics": module.LINEAGE_SEMANTICS,
            "qualification_scope": lineage,
            "graph": graph.model_dump(mode="json"),
            "checks": {key: True for key in sorted(module.LINEAGE_CHECKS)},
            "requests": [
                {"operation": op, "method": "GET", "status": 200, "response_sha256": "d" * 64}
                for op in sorted(READS)
            ],
            "native_http_mutations": 0,
            "native_database_bytes_read": False,
        }
        envelope = {
            "format": "qualified-original-session-lineage-v1",
            "operator_review": "installed-evidence-reviewed-for-development-runtime",
            "observation": enrolled.pin("lineage-observation.json", observed),
        }
        entry["lineage"] = enrolled.pin("lineage-pin.json", envelope)
    manifest["adoption_projects"] = [entry]
    enrolled.save()
    return entry, policy.model_dump(mode="json"), observed


@pytest.mark.parametrize("lineage", [None, "leaf", "tree"])
def test_adoption_pins_require_explicit_backend_scope_and_independent_lineage(
    enrolled, monkeypatch, lineage
):
    entry, policy, observed = adoption_enrollment(enrolled, lineage=lineage)
    monkeypatch.setattr(
        module, "resolve_secret", lambda _: pytest.fail("credentials during pin validation")
    )
    value, _ = module.read_enrollment(enrolled.settings)
    actual, semantics = module.adoption_pins(value)[enrolled.ref["project_id"]]
    assert actual.model_dump(mode="json") == policy
    if lineage is None:
        assert semantics is None  # A missing pin cannot silently certify a tree.
    else:
        assert semantics.qualification_scope == lineage
        assert semantics.contract_sha256 == actual.contract_sha256
        assert semantics.operations == READS
        assert len(observed["graph"]["nodes"]) == (2 if lineage == "tree" else 1)


@pytest.mark.parametrize(
    "fault",
    [
        "legacy",
        "session_scope",
        "duplicate",
        "foreign_anchor",
        "policy_anchor",
        "contract",
        "protocol",
        "operation_widening",
        "check",
        "missing_read",
        "root_file_changed",
    ],
)
def test_adoption_rejects_unreviewed_or_widened_backend_scope_before_credentials(
    enrolled, monkeypatch, fault
):
    entry, policy, _ = adoption_enrollment(enrolled)
    anchor = enrolled.manifest["backends"][0]
    if fault == "legacy":
        enrolled.manifest["format"] = "qualified-consumer-runtime-v1"
    elif fault == "session_scope":
        anchor["protocol_scope"] = "session"
    elif fault == "duplicate":
        enrolled.manifest["adoption_projects"].append(copy.deepcopy(entry))
    elif fault == "foreign_anchor":
        entry["anchor"]["upstream_session_id"] = "ses_not_enrolled"
    elif fault == "missing_read":
        anchor["verified_operations"].remove(sorted(READS)[0])
    elif fault == "root_file_changed":
        enrolled.documents[Path(entry["policy"]["path"])] = b"tampered"
    else:
        if fault == "policy_anchor":
            policy["anchor"]["upstream_session_id"] = "ses_other_original"
        elif fault == "contract":
            policy["contract_sha256"] = "f" * 64
        elif fault == "protocol":
            policy["installed_protocol_evidence_sha256"] = "f" * 64
        else:
            policy["operations"] = ["check.run" if fault == "check" else "unsupported"]
        entry["policy"] = enrolled.pin("changed-adoption-policy.json", policy)
    enrolled.save()
    monkeypatch.setattr(
        module, "resolve_secret", lambda _: pytest.fail("credentials during invalid pin validation")
    )
    with pytest.raises(ValueError):
        module.read_enrollment(enrolled.settings)


@pytest.mark.parametrize(
    "fault",
    [
        "foreign_backend",
        "binary",
        "schema",
        "metadata_only",
        "missing_child",
        "wrong_scope",
        "false_check",
        "unknown_check",
        "wire_mutation",
        "boolean_status",
        "missing_rpc",
        "native_mutations",
        "native_database",
        "wrong_native_project",
    ],
)
def test_lineage_pin_cannot_borrow_metadata_leaf_or_another_binary_as_tree_semantics(
    enrolled, fault
):
    entry, policy, observed = adoption_enrollment(enrolled, lineage="tree")
    if fault == "foreign_backend":
        observed["backend_identity"] = "replacement"
    elif fault == "binary":
        observed["executable_sha256"] = "f" * 64
    elif fault == "schema":
        observed["contract_sha256"] = "f" * 64
    elif fault == "metadata_only":
        observed["checks"] = {}
    elif fault == "missing_child":
        observed["graph"]["nodes"] = observed["graph"]["nodes"][:1]
    elif fault == "wrong_scope":
        observed["qualification_scope"] = "leaf"
    elif fault == "false_check":
        observed["checks"]["queued_and_pending_kinds"] = False
    elif fault == "unknown_check":
        observed["checks"].pop("queued_and_pending_kinds")
        observed["checks"]["metadata_is_enough"] = True
    elif fault == "wire_mutation":
        observed["requests"][0]["method"] = "POST"
    elif fault == "boolean_status":
        observed["requests"][0]["status"] = True
    elif fault == "missing_rpc":
        observed["requests"] = observed["requests"][1:]
    elif fault == "native_mutations":
        observed["native_http_mutations"] = 1
    elif fault == "native_database":
        observed["native_database_bytes_read"] = True
    else:
        for node in observed["graph"]["nodes"]:
            node["native_project_id"] = "other-native-project"
    envelope = {
        "format": "qualified-original-session-lineage-v1",
        "operator_review": "installed-evidence-reviewed-for-development-runtime",
        "observation": enrolled.pin("changed-lineage-observation.json", observed),
    }
    entry["lineage"] = enrolled.pin("changed-lineage-pin.json", envelope)
    enrolled.save()
    with pytest.raises(ValueError):
        module.read_enrollment(enrolled.settings)


@pytest.mark.parametrize("lineage", [None, "tree"])
async def test_reviewed_adoption_is_composed_into_real_pipeline_without_starting_or_prompting_native(
    enrolled, db, lineage
):
    adoption_enrollment(enrolled, lineage=lineage)
    value, sha = module.read_enrollment(enrolled.settings)
    store = DurableStore(db)
    epoch = await store.acquire_lease("adoption-compose", ttl=120)
    pipeline = module.build_pipeline(
        enrolled.settings, value, sha, db, module.ConsumerFence("adoption-compose", epoch)
    )
    try:
        assert pipeline.adoption is not None
        factory = pipeline.adoption.factories[enrolled.ref["project_id"]]
        assert (
            factory.registry
            is pipeline.backends[factory.policy.anchor.backend_id].registered.client
        )
        assert pipeline.router.unbound.confirmations.adoption is pipeline.adoption
        resources = [resource.name for resource in pipeline.runtime().resources]
        assert resources.index("original-session-restoration") < resources.index("zulip-consumer")
        assert (
            factory.lineage is None
            if lineage is None
            else factory.lineage.qualification_scope == "tree"
        )
    finally:
        await pipeline.scope.client.close()
        for backend in pipeline.backends.values():
            for resource in reversed(backend.resources):
                await resource.close()
        await store.release_lease("adoption-compose", epoch)


@pytest.fixture
def enrolled(monkeypatch):
    documents = {}

    def pin(name, document):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        path = Path("/etc/jtoz-synthetic") / name
        documents[path] = raw
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

    observation = json.loads(
        Path(
            "tests/fixtures/installed/opencode-v2.0.32/operator-resource-observation.json"
        ).read_text()
    )
    ref = observation["evidence"]["correlation"]["reference"]
    owner = {**CONFIG, "backend_id": ref["backend_id"], "backend_identity": ref["backend_identity"]}
    schema = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json").read_bytes()
    schema_pin = pin("schema.json", schema)
    owner_pin = pin("owner.json", owner)
    policy = {
        "format": "native-project-policy-v1",
        "reference": ref,
        "native_project_id": "global",
        "contract_sha256": schema_pin["sha256"],
        "permission_source_sha256": PERMISSION_SOURCE,
        "fingerprint_sha256": "b" * 64,
        "operations": ["prompt"],
    }
    manifest = {
        "format": "qualified-consumer-runtime-v1",
        "operator_review": "installed-evidence-reviewed-for-development-runtime",
        "realm": {
            "realm_id": "2",
            "url": "https://chat.invalid",
            "bot_email": "bot@chat.invalid",
            "bot_user_id": 11,
            "bot_owner_id": 8,
            "zulip_version": "12.3",
            "feature_level": 500,
            "message_limit": 10000,
            "topic_limit": 60,
            "evidence": [pin("zulip.json", {"scope": "synthetic enrollment test"})],
        },
        "backends": [
            {
                "reference": ref,
                "native_project_id": "global",
                "owner": owner_pin,
                "owner_socket": "/run/jtoz-synthetic/status.sock",
                "schema_file": schema_pin,
                "policy": pin("policy.json", policy),
                "model_evidence": pin(
                    "models.json",
                    {"passed": True, "reference": ref, "semantics_sha256": MODEL_SETTING_SEMANTICS},
                ),
                "outcome_evidence": [pin("result.json", observation)],
                "operation_evidence": [pin("operations.json", {"scope": "synthetic only"})],
                "verified_operations": sorted(
                    READS | MODEL_READS | POLICY_READS | {"session.prompt", "event.subscribe"}
                ),
            }
        ],
        "grants": [
            {"project_id": ref["project_id"], "user_id": user, "roles": ["administrator"]}
            for user in (8, 9)
        ],
    }
    enrollment_path = Path("/etc/jtoz-synthetic/runtime.json")

    def save():
        documents[enrollment_path] = json.dumps(manifest).encode()

    save()
    settings = Settings.model_validate(
        {
            "runtime": {"enabled": True, "enrollment_file": str(enrollment_path)},
            "zulip_realms": [
                {
                    "id": "2",
                    "enabled": True,
                    "url": "https://chat.invalid",
                    "bot_email": "bot@chat.invalid",
                    "api_key_ref": "env:SYNTHETIC_ZULIP_KEY",
                    "allowed_user_ids": [8, 9],
                    "allowed_channel_ids": [4],
                }
            ],
            "opencode_backends": [
                {
                    "id": ref["backend_id"],
                    "enabled": True,
                    "base_url": owner["url"],
                    "credential_ref": "env:SYNTHETIC_NATIVE_KEY",
                }
            ],
            "projects": [
                {
                    "id": ref["project_id"],
                    "enabled": True,
                    "backend_id": ref["backend_id"],
                    "realm_id": "2",
                    "workspace_root": ref["canonical_directory"],
                }
            ],
        }
    )

    def read(path, **kwargs):
        return documents[path]

    monkeypatch.setattr(module, "root_bytes", read)
    monkeypatch.setattr("jt_oz_bridge.security.root_files.root_bytes", read)
    monkeypatch.setenv("SYNTHETIC_ZULIP_KEY", "synthetic-only")
    monkeypatch.setenv("SYNTHETIC_NATIVE_KEY", "synthetic-only")
    return SimpleNamespace(
        settings=settings, manifest=manifest, documents=documents, pin=pin, save=save, ref=ref
    )


def test_exact_root_reviewed_pins_load_without_network_or_credentials(enrolled, monkeypatch):
    monkeypatch.setattr(
        module, "resolve_secret", lambda ref: pytest.fail("not resolved during enrollment read")
    )
    value, digest = module.read_enrollment(enrolled.settings)
    assert value.backends[0].reference.model_dump(mode="json") == enrolled.ref and len(digest) == 64


@pytest.mark.parametrize(
    "change",
    [
        "directory",
        "identity",
        "policy",
        "model",
        "outcome",
        "grant",
        "pin",
        "realm_url",
        "bot_email",
    ],
)
def test_qualification_drift_is_rejected(enrolled, change):
    m = enrolled.manifest
    b = m["backends"][0]
    if change == "realm_url":
        enrolled.settings.zulip_realms[0].url = "https://different.invalid"
    elif change == "bot_email":
        enrolled.settings.zulip_realms[0].bot_email = "different@chat.invalid"
    elif change == "directory":
        enrolled.settings.projects[0].workspace_root = "/different"
    elif change == "identity":
        doc = json.loads(enrolled.documents[Path(b["owner"]["path"])])
        doc["backend_identity"] = "different"
        b["owner"] = enrolled.pin("owner.json", doc)
    elif change == "policy":
        doc = json.loads(enrolled.documents[Path(b["policy"]["path"])])
        doc["reference"]["project_id"] = "different"
        b["policy"] = enrolled.pin("policy.json", doc)
    elif change == "model":
        doc = json.loads(enrolled.documents[Path(b["model_evidence"]["path"])])
        doc["reference"]["upstream_session_id"] = "different"
        b["model_evidence"] = enrolled.pin("models.json", doc)
    elif change == "outcome":
        doc = json.loads(enrolled.documents[Path(b["outcome_evidence"][0]["path"])])
        doc["evidence"]["semantics_sha256"] = "0" * 64
        b["outcome_evidence"][0] = enrolled.pin("result.json", doc)
    elif change == "grant":
        m["grants"][0]["user_id"] = 999
    else:
        enrolled.documents[Path(b["operation_evidence"][0]["path"])] = b"changed certificate"
    enrolled.save()
    with pytest.raises(ValueError):
        module.read_enrollment(enrolled.settings)


def test_factory_reloads_manifest_and_refuses_changed_scope(enrolled, db):
    factory = module.runtime_factory(enrolled.settings)
    enrolled.manifest["grants"][0]["roles"] = ["viewer"]
    enrolled.save()
    from jt_oz_bridge.storage.fencing import ConsumerFence

    with pytest.raises(ValueError, match="changed_before_start"):
        factory(db, ConsumerFence("unused", 1))


async def test_builder_uses_same_original_reference_and_explicit_adapters_without_starting(
    enrolled, db
):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    e, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, e, sha, db, ConsumerFence("unused", 1))
    assert not pipeline.consumer.queue_id
    assert (
        pipeline.registry.selected(e.backends[0].reference).identity
        == enrolled.ref["backend_identity"]
    )
    try:
        assert all(b.references == (e.backends[0].reference,) for b in pipeline.backends.values())
        assert pipeline.router.inbox.fence == pipeline.fence
    finally:
        for b in pipeline.backends.values():
            for resource in b.resources:
                await resource.close()
        await pipeline.scope.client.close()


@pytest.mark.parametrize("enabled", [True, False])
async def test_zulip_format_instructions_wrap_only_the_dispatcher_and_follow_the_flag(
    enrolled, db, enabled
):
    from jt_oz_bridge.config import Runtime
    from jt_oz_bridge.services.format_instructions import FormattedExecution
    from jt_oz_bridge.storage.fencing import ConsumerFence

    assert Runtime().zulip_format_instructions_enabled is True
    enrolled.settings.runtime.zulip_format_instructions_enabled = enabled
    e, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, e, sha, db, ConsumerFence("unused", 1))
    try:
        client = pipeline.dispatcher.client
        if not enabled:
            assert client is pipeline.registry
            return
        assert type(client) is FormattedExecution and client.client is pipeline.registry
        ref = e.backends[0].reference
        execution = pipeline.registry.selected(ref).client.selected(ref).execution
        # The same contract-checked transport, with no write verified unless enrolled.
        assert client.instructions.clients[ref.backend_id].transport is execution.transport
        assert client.instructions.clients[ref.backend_id].writable() is False
    finally:
        for b in pipeline.backends.values():
            for resource in b.resources:
                await resource.close()
        await pipeline.scope.client.close()


async def stub_composition(enrolled, monkeypatch, *, extra_member=None):
    opened, closed = AsyncMock(), AsyncMock()

    def make(settings, enrollment, sha, db, fence):
        scope = SimpleNamespace(
            identity=AsyncMock(),
            channel=AsyncMock(
                return_value={
                    "invite_only": True,
                    "is_web_public": False,
                    "history_public_to_subscribers": False,
                }
            ),
            members=AsyncMock(return_value=(8, 9, 11) + ((extra_member,) if extra_member else ())),
            client=SimpleNamespace(close=AsyncMock()),
        )

        async def user(uid):
            return {"user_id": uid, "is_bot": uid == 11, "is_active": True}

        scope.user = user
        return SimpleNamespace(
            db=db,
            fence=fence,
            scope=scope,
            backends={
                "native": SimpleNamespace(resources=(RuntimeResource("native", opened, closed),))
            },
        )

    monkeypatch.setattr(module, "build_pipeline", make)
    return opened, closed


async def count(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


async def test_explicit_enrollment_is_atomic_idempotent_and_never_overrides_revocation(
    enrolled, db, monkeypatch
):
    opened, closed = await stub_composition(enrolled, monkeypatch)
    await module.enroll_runtime(enrolled.settings, db)
    await module.enroll_runtime(enrolled.settings, db)
    assert len(await count(db, EnrolledBackend)) == 1 and len(await count(db, EnrolledProject)) == 1
    grants = await count(db, Grant)
    assert len(grants) == 2 and all(g.active for g in grants)
    async with db.sessions.begin() as session:
        target = await session.get(Grant, grants[0].id)
        target.active = False
    with pytest.raises(ValueError, match="revoked"):
        await module.enroll_runtime(enrolled.settings, db)
    assert sum(g.active for g in await count(db, Grant)) == 1
    assert opened.await_count == 3 and closed.await_count == 3
    assert await DurableStore(db).acquire_lease("next-process")


async def test_unapproved_channel_member_prevents_all_enrollment_writes(enrolled, db, monkeypatch):
    opened, closed = await stub_composition(enrolled, monkeypatch, extra_member=99)
    with pytest.raises(ValueError, match="unapproved"):
        await module.enroll_runtime(enrolled.settings, db)
    assert not await count(db, EnrolledBackend) and not await count(db, Grant)
    opened.assert_awaited_once()
    closed.assert_awaited_once()


async def test_failed_file_cleanup_still_closes_client_and_releases_enrollment_lease(
    enrolled, db, monkeypatch
):
    await stub_composition(enrolled, monkeypatch)
    original = module.build_pipeline
    pipelines = []

    def build(*args):
        pipeline = original(*args)
        pipeline.files = object()
        pipeline.close_files = AsyncMock(side_effect=RuntimeError("synthetic file close failed"))
        pipelines.append(pipeline)
        return pipeline

    monkeypatch.setattr(module, "build_pipeline", build)
    with pytest.raises(RuntimeError, match="file close failed"):
        await module.enroll_runtime(enrolled.settings, db)
    pipelines[0].scope.client.close.assert_awaited_once()
    assert await DurableStore(db).acquire_lease("after-file-close-failure")


async def test_running_bridge_lease_prevents_enrollment_before_opening_adapters(
    enrolled, db, monkeypatch
):
    await DurableStore(db).acquire_lease("already-serving")
    build = AsyncMock()
    monkeypatch.setattr(module, "build_pipeline", build)
    with pytest.raises(ValueError, match="stop_bridge"):
        await module.enroll_runtime(enrolled.settings, db)
    build.assert_not_called()


async def test_runtime_identity_coalesces_only_metadata_and_refreshes_after_one_second(
    enrolled, monkeypatch
):
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    qualification = module.RuntimeEnrollment.model_validate(enrolled.manifest).realm
    user = {"user_id": 11, "bot_owner_id": 8, "is_bot": True, "role": 400}
    client = SimpleNamespace(
        request=AsyncMock(side_effect=lambda *args: dict(user)),
        server_settings=AsyncMock(
            return_value={
                "realm_url": qualification.url,
                "zulip_version": "12.3",
                "zulip_feature_level": 500,
            }
        ),
    )
    identity = module.ZulipRuntimeIdentity(client, qualification)
    assert await identity() and await identity()
    assert client.request.await_count == 1
    user["bot_owner_id"] = 99
    clock[0] = 101.1
    assert not await identity() and client.request.await_count == 2
    assert not await identity() and client.request.await_count == 3  # No cached failure.


def add_second_root(enrolled):
    m = enrolled.manifest
    m["format"] = "qualified-consumer-runtime-v2"
    second = copy.deepcopy(m["backends"][0])
    second["reference"]["upstream_session_id"] = "ses_second_explicit_root"
    second["protocol_scope"] = "backend"
    policy = json.loads(enrolled.documents[Path(second["policy"]["path"])])
    policy["reference"] = second["reference"]
    second["policy"] = enrolled.pin("second-policy.json", policy)
    m["backends"].append(second)
    enrolled.save()
    return second


def test_v2_multiple_roots_share_backend_codec_but_each_needs_exact_policy_and_enrollment(enrolled):
    second = add_second_root(enrolled)
    value, sha = module.read_enrollment(enrolled.settings)
    assert (
        len(value.backends) == 2
        and value.backends[1].reference.upstream_session_id
        == second["reference"]["upstream_session_id"]
    )
    assert value.backends[1].protocol_scope == "backend"
    # The real observation remains from the first Root, never rewritten to fake a second test.
    pin = value.backends[1].model_evidence
    assert json.loads(enrolled.documents[pin.path])["reference"] == enrolled.ref


@pytest.mark.parametrize(
    "change",
    [
        "legacy_format",
        "duplicate_native",
        "owner",
        "contract",
        "socket",
        "operations",
        "project_directory",
        "missing_policy",
        "wrong_observation_backend",
    ],
)
def test_multi_root_qualification_rejects_alias_drift_or_unqualified_protocol_scope(
    enrolled, change
):
    second = add_second_root(enrolled)
    if change == "legacy_format":
        enrolled.manifest["format"] = "qualified-consumer-runtime-v1"
    elif change == "duplicate_native":
        second["reference"]["upstream_session_id"] = enrolled.ref["upstream_session_id"]
    elif change == "owner":
        second["reference"]["backend_identity"] = "other"
    elif change == "contract":
        second["schema_file"]["sha256"] = "b" * 64
    elif change == "socket":
        second["owner_socket"] = "/run/different/status.sock"
    elif change == "operations":
        second["verified_operations"].append("unreviewed.operation")
    elif change == "project_directory":
        second["reference"]["canonical_directory"] = "/different"
    elif change == "missing_policy":
        second["policy"] = enrolled.manifest["backends"][0]["policy"]
    else:
        doc = json.loads(enrolled.documents[Path(second["model_evidence"]["path"])])
        doc["reference"]["backend_identity"] = "another-installed-instance"
        second["model_evidence"] = enrolled.pin("wrong-models.json", doc)
    enrolled.save()
    with pytest.raises(ValueError):
        module.read_enrollment(enrolled.settings)


async def test_multi_root_builder_has_one_feed_and_independent_policy_proof_result_objects(
    enrolled, db
):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    add_second_root(enrolled)
    value, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, value, sha, db, ConsumerFence("unused", 1))
    backend = next(iter(pipeline.backends.values()))
    registry = backend.registered.client
    first, second = (registry.selected(q.reference) for q in value.backends)
    try:
        assert len(backend.resources) == 1 and len(backend.references) == 2
        assert first.execution.proofs is not second.execution.proofs
        assert first.execution.scope_guard is not second.execution.scope_guard
        assert first.results is not second.results
        assert first.execution.transport is second.execution.transport
        assert first.execution.proofs.feed is second.execution.proofs.feed
        assert second.execution.proofs.model_settings.qualification_scope == "backend"
        assert second.execution.proofs.model_settings.reference == first.reference
        assert tuple(registry.projects) == (first.reference.project_id,)
    finally:
        for resource in backend.resources:
            await resource.close()
        await pipeline.scope.client.close()


async def test_multi_root_enrollment_keeps_one_backend_project_and_existing_grants(
    enrolled, db, monkeypatch
):
    add_second_root(enrolled)
    await stub_composition(enrolled, monkeypatch)
    await module.enroll_runtime(enrolled.settings, db)
    assert len(await count(db, EnrolledBackend)) == len(await count(db, EnrolledProject)) == 1
    assert len(await count(db, Grant)) == 2


def creation_enrollment(enrolled):
    """Synthetic pinned operator RPC, never a Human or installed certificate."""
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate
    from jt_oz_bridge.storage.durable import digest

    manifest = enrolled.manifest
    manifest["format"] = "qualified-consumer-runtime-v2"
    anchor = manifest["backends"][0]
    anchor["protocol_scope"] = "backend"
    anchor["verified_operations"] += ["session.create", "session.get"]
    source = json.loads(enrolled.documents[Path(anchor["policy"]["path"])])
    template = {
        "format": "native-root-creation-policy-v1",
        "source": source,
        "creation": {
            "scope": {k: v for k, v in enrolled.ref.items() if k != "upstream_session_id"},
            "native_project_id": "global",
            "agent_id": "build",
            "permissions": [{"action": "*", "resource": "*", "effect": "deny"}],
        },
        "operations": ["prompt"],
    }
    policy = CreationPolicyTemplate.model_validate(template)
    sid = "ses_jtoz_" + "e" * 32
    intent = {
        "operator_not_human": True,
        "reference_scope": copy.deepcopy(template["creation"]["scope"]),
        "native_project_id": "global",
        "owner_epoch": "a" * 64,
        "source_policy_sha256": source["fingerprint_sha256"],
        "requested_session_id": sid,
    }
    body = {
        "id": sid,
        "location": {"directory": enrolled.ref["canonical_directory"]},
        "agent": "build",
        "permissions": copy.deepcopy(template["creation"]["permissions"]),
        "metadata": {"synthetic_operator": {"nonce": "e" * 32}},
    }
    request = {
        "body": body,
        "intent": intent,
        "body_sha256": digest(body),
        "intent_sha256": digest(intent),
    }
    observation = {
        "passed": True,
        "rpc_shape_and_readback_verified": True,
        "stable_double_get": True,
        "owner_unchanged": True,
        "native_post_attempts": 1,
        "create_http_status": 200,
        "human_acceptance": False,
        "normal_creation_workflow_qualified": False,
        "request_body_sha256": digest(body),
        "requested_session_id": sid,
        "returned_session_id": sid,
        "created_session_id": sid,
    }
    owner = json.loads(enrolled.documents[Path(anchor["owner"]["path"])])
    certificate = {
        "format": "installed-root-creation-rpc-v1",
        "passed": True,
        "evidence_scope": "operator-rpc-only-not-human-acceptance",
        "reference": enrolled.ref,
        "contract_sha256": anchor["schema_file"]["sha256"],
        "executable_sha256": owner["executable_sha256"],
        "upstream_version": "2.0.32",
        "owner_epoch": intent["owner_epoch"],
        "policy_template_sha256": policy.checksum(),
        "operations": ["session.create", "session.get"],
        "observation": enrolled.pin("create-observation.json", observation),
        "request_record": enrolled.pin("create-request.json", request),
        "response_record": enrolled.pin(
            "create-response.json", {"data": {**body, "projectID": "global"}}
        ),
    }
    qualification = {
        "anchor": enrolled.ref,
        "policy_template": enrolled.pin("creation-policy.json", template),
        "rpc_evidence": enrolled.pin("creation-rpc.json", certificate),
    }
    manifest["creation_projects"] = [qualification]
    enrolled.settings.runtime.session_creation_enabled = True
    enrolled.save()
    return SimpleNamespace(
        qualification=qualification,
        certificate=certificate,
        template=template,
        request=request,
        observation=observation,
    )


def test_creation_setting_requires_enrolled_runtime_and_defaults_off():
    assert not Settings().runtime.session_creation_enabled
    with pytest.raises(ValueError, match="session_creation_requires_enabled"):
        Settings.model_validate({"runtime": {"session_creation_enabled": True}})


def test_creation_pins_are_root_reviewed_not_network_or_live_credentials(enrolled, monkeypatch):
    creation_enrollment(enrolled)
    monkeypatch.setattr(module, "resolve_secret", lambda _: pytest.fail("unexpected credential"))
    value, _ = module.read_enrollment(enrolled.settings)
    projects = module.creation_pins(value)
    project, policy = projects[enrolled.ref["project_id"]]
    assert project.template == policy.creation and project.owner_epoch == "a" * 64
    assert project.policy_template_sha256 == policy.checksum()


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "legacy",
        "session_scope",
        "duplicate",
        "foreign_anchor",
        "wire_operations",
        "source_policy",
        "template_directory",
        "template_operations",
        "contract",
        "executable",
        "version",
        "template_hash",
        "rpc_reference",
        "scope_claim",
        "missing_observation",
        "observation_hash",
        "passed",
        "human_claim",
        "workflow_claim",
        "post_count",
        "status",
        "owner",
        "request_hash",
        "body_permissions",
        "body_path",
        "body_agent",
        "extra_body",
        "response",
        "intent_owner",
        "intent_source",
        "intent_scope",
        "stable_readback",
    ],
)
def test_creation_enrollment_rejects_unqualified_or_relabelled_evidence(enrolled, change):
    c = creation_enrollment(enrolled)
    b = enrolled.manifest["backends"][0]
    if change == "missing":
        enrolled.manifest["creation_projects"] = []
    elif change == "legacy":
        enrolled.manifest["format"] = "qualified-consumer-runtime-v1"
    elif change == "session_scope":
        b["protocol_scope"] = "session"
    elif change == "duplicate":
        enrolled.manifest["creation_projects"].append(copy.deepcopy(c.qualification))
    elif change == "foreign_anchor":
        c.qualification["anchor"] = {**enrolled.ref, "upstream_session_id": "ses_foreign"}
    elif change == "wire_operations":
        b["verified_operations"].remove("session.create")
    elif change.startswith("template_") or change == "source_policy":
        if change == "source_policy":
            c.template["source"]["fingerprint_sha256"] = "0" * 64
        elif change == "template_directory":
            c.template["creation"]["scope"]["canonical_directory"] = "/foreign"
        elif change == "template_operations":
            c.template["operations"] = ["abort"]
        else:
            c.certificate["policy_template_sha256"] = "0" * 64
        c.qualification["policy_template"] = enrolled.pin("creation-policy.json", c.template)
    elif change in {"contract", "executable", "version", "rpc_reference", "scope_claim"}:
        key, value = {
            "contract": ("contract_sha256", "0" * 64),
            "executable": ("executable_sha256", "0" * 64),
            "version": ("upstream_version", "2.0.99"),
            "rpc_reference": ("reference", {**enrolled.ref, "project_id": "foreign"}),
            "scope_claim": ("evidence_scope", "normal-human-accepted"),
        }[change]
        c.certificate[key] = value
    elif change == "missing_observation":
        del enrolled.documents[Path(c.certificate["observation"]["path"])]
    elif change == "observation_hash":
        enrolled.documents[Path(c.certificate["observation"]["path"])] = b"changed"
    elif change in {
        "passed",
        "human_claim",
        "workflow_claim",
        "post_count",
        "status",
        "owner",
        "stable_readback",
    }:
        key, value = {
            "passed": ("passed", False),
            "human_claim": ("human_acceptance", True),
            "workflow_claim": ("normal_creation_workflow_qualified", True),
            "post_count": ("native_post_attempts", True),
            "status": ("create_http_status", 201),
            "owner": ("owner_unchanged", False),
            "stable_readback": ("stable_double_get", False),
        }[change]
        c.observation[key] = value
        c.certificate["observation"] = enrolled.pin("create-observation.json", c.observation)
    elif change == "response":
        raw = {**c.request["body"], "projectID": "foreign"}
        c.certificate["response_record"] = enrolled.pin("create-response.json", {"data": raw})
    else:
        if change == "request_hash":
            c.request["body_sha256"] = "0" * 64
        elif change == "body_permissions":
            c.request["body"]["permissions"][0]["effect"] = "allow"
        elif change == "body_path":
            c.request["body"]["location"]["directory"] = "/foreign"
        elif change == "body_agent":
            c.request["body"]["agent"] = "foreign"
        elif change == "extra_body":
            c.request["body"]["parentID"] = "ses_existing"
        elif change == "intent_owner":
            c.request["intent"]["owner_epoch"] = "0" * 64
        elif change == "intent_source":
            c.request["intent"]["source_policy_sha256"] = "0" * 64
        elif change == "intent_scope":
            c.request["intent"]["reference_scope"]["project_id"] = "foreign"
        # A self-consistent rehashed forgery must still fail semantic scope checks.
        from jt_oz_bridge.storage.durable import digest

        if change != "request_hash":
            c.request["body_sha256"] = digest(c.request["body"])
        c.request["intent_sha256"] = digest(c.request["intent"])
        c.observation["request_body_sha256"] = digest(c.request["body"])
        c.certificate["observation"] = enrolled.pin("create-observation.json", c.observation)
        c.certificate["response_record"] = enrolled.pin(
            "create-response.json", {"data": {**c.request["body"], "projectID": "global"}}
        )
        c.certificate["request_record"] = enrolled.pin("create-request.json", c.request)
    c.qualification["rpc_evidence"] = enrolled.pin("creation-rpc.json", c.certificate)
    enrolled.save()
    with pytest.raises((ValueError, KeyError)):
        module.read_enrollment(enrolled.settings)


@pytest.mark.parametrize("enabled", [False, True])
async def test_creation_composition_uses_exact_original_graph_and_explicit_switch(
    enrolled, db, enabled
):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    creation_enrollment(enrolled)
    enrolled.settings.runtime.session_creation_enabled = enabled
    value, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, value, sha, db, ConsumerFence("unused", 1))
    try:
        assert not pipeline.consumer.queue_id
        if not enabled:
            assert pipeline.creation is None
            return
        coordinator = pipeline.creation
        project_id = enrolled.ref["project_id"]
        factory = coordinator.factories[project_id]
        backend = pipeline.backends[value.backends[0].reference.backend_id]
        registry = backend.registered.client
        assert factory.registry is registry
        assert coordinator.journal.bindings is pipeline.bindings
        assert coordinator.journal.reader is pipeline.source
        assert coordinator.replies is pipeline.bound_replies
        assert factory.creator.transport is factory.anchor.execution.transport
        assert factory.creator.owner is factory.feed.owner
        assert factory.policies.anchor is factory.anchor.execution.scope_guard
        assert backend.transcripts is registry.transcripts
        assert backend.metadata is registry.metadata
        assert backend.reference_provider.__self__ is registry
        assert len(registry.sessions) == 1  # No session POST, fake enrollment or binding.
    finally:
        for backend in pipeline.backends.values():
            for resource in backend.resources:
                await resource.close()
        await pipeline.scope.client.close()


def test_creation_pin_edits_are_reloaded_before_runtime_start(enrolled, db):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    creation_enrollment(enrolled)
    factory = module.runtime_factory(enrolled.settings)
    enrolled.documents[Path(enrolled.manifest["creation_projects"][0]["rpc_evidence"]["path"])] = (
        b"changed"
    )
    with pytest.raises(ValueError):
        factory(db, ConsumerFence("unused", 1))


async def test_creation_anchor_is_explicit_with_two_original_roots(enrolled, db):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    creation_enrollment(enrolled)
    second = add_second_root(enrolled)
    value, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, value, sha, db, ConsumerFence("unused", 1))
    try:
        factory = pipeline.creation.factories[enrolled.ref["project_id"]]
        assert len(factory.registry.sessions) == 2
        assert factory.anchor.reference.model_dump(mode="json") == enrolled.ref
        sibling = factory.registry.selected(module.SessionRef.model_validate(second["reference"]))
        assert sibling.execution.transport is factory.creator.transport
        assert sibling.execution.scope_guard is not factory.policies.anchor
        assert factory.policies.template.source.reference == factory.anchor.reference
    finally:
        for backend in pipeline.backends.values():
            for resource in backend.resources:
                await resource.close()
        await pipeline.scope.client.close()


def test_disabled_creation_pins_still_reject_tampering(enrolled):
    c = creation_enrollment(enrolled)
    enrolled.settings.runtime.session_creation_enabled = False
    c.observation["human_acceptance"] = True
    c.certificate["observation"] = enrolled.pin("create-observation.json", c.observation)
    c.qualification["rpc_evidence"] = enrolled.pin("creation-rpc.json", c.certificate)
    enrolled.save()
    with pytest.raises(ValueError, match="observed_template_or_rpc_changed"):
        module.read_enrollment(enrolled.settings)


def approved_checks(enrolled):
    from jt_oz_bridge.adapters.opencode.checks import CHECK_READS, CHECK_SEMANTICS
    from jt_oz_bridge.domain.checks import ApprovedCheck, CheckCatalog
    from jt_oz_bridge.domain.models import SessionRef

    backend = enrolled.manifest["backends"][0]
    catalog = CheckCatalog(
        reference=SessionRef.model_validate(enrolled.ref),
        contract_sha256=backend["schema_file"]["sha256"],
        checks=(
            ApprovedCheck(
                id="unit", title="Explicit administrator check", command="python -m pytest tests"
            ),
        ),
    )
    document = {
        "format": "native-approved-checks-v1",
        "passed": True,
        "catalog": catalog.model_dump(mode="json"),
        "semantics_sha256": CHECK_SEMANTICS,
        "installed_evidence_sha256": "c" * 64,
    }
    policy = json.loads(enrolled.documents[Path(backend["policy"]["path"])])
    policy["operations"].append("check.run")
    backend["policy"] = enrolled.pin("policy-with-checks.json", policy)
    backend["verified_operations"] = sorted(
        set(backend["verified_operations"]) | CHECK_READS | {"session.shell"}
    )
    backend["checks"] = enrolled.pin("checks.json", document)
    return backend, document


async def test_root_pinned_check_catalog_builds_same_original_reader_without_starting_native(
    enrolled, db
):
    from jt_oz_bridge.storage.fencing import ConsumerFence

    backend, document = approved_checks(enrolled)
    enrolled.save()
    value, sha = module.read_enrollment(enrolled.settings)
    pipeline = module.build_pipeline(enrolled.settings, value, sha, db, ConsumerFence("unused", 1))
    try:
        root = value.backends[0].reference
        reader = pipeline.backends[root.backend_id].checks[root]
        assert reader.catalog(root).checks[0].command == "python -m pytest tests"
        assert reader.client is pipeline.registry.selected(root).client.selected(root).execution
        group = pipeline.backends[root.backend_id].resources[0].start.__self__
        observer = next(item for item in group.roots if item.ref == root)
        journal = observer.recovery.owner_for.__self__
        from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords

        assert isinstance(journal, CheckDispatchRecords)
        assert journal.bindings is pipeline.bindings and journal.fence is pipeline.fence
        assert observer.proofs.check_tail.original.__self__ is journal
        assert not pipeline.consumer.queue_id
    finally:
        for provider in pipeline.backends.values():
            for resource in provider.resources:
                await resource.close()
        await pipeline.scope.client.close()


@pytest.mark.parametrize(
    "change",
    [
        "format",
        "passed",
        "semantics",
        "evidence",
        "foreign-root",
        "duplicate-check",
        "unapproved-operation",
        "missing-rpc",
    ],
)
def test_missing_or_foreign_check_qualification_is_not_enabled(enrolled, change):
    backend, document = approved_checks(enrolled)
    if change == "format":
        document["format"] = "some-other-api"
    if change == "passed":
        document["passed"] = False
    if change == "semantics":
        document["semantics_sha256"] = "f" * 64
    if change == "evidence":
        document["installed_evidence_sha256"] = "not-an-evidence-hash"
    if change == "foreign-root":
        document["catalog"]["reference"]["upstream_session_id"] = "ses_other"
    if change == "duplicate-check":
        document["catalog"]["checks"] *= 2
    if change == "missing-rpc":
        backend["verified_operations"].remove("session.shell")
    if change == "unapproved-operation":
        policy = json.loads(enrolled.documents[Path(backend["policy"]["path"])])
        policy["operations"].remove("check.run")
        backend["policy"] = enrolled.pin("policy-without-checks.json", policy)
    backend["checks"] = enrolled.pin("checks.json", document)
    enrolled.save()
    with pytest.raises(ValueError):
        module.read_enrollment(enrolled.settings)


async def startup_check_graph(db, *, binding_id="original-check-binding"):
    """Real resource/HTTP and own encrypted DB; synthetic owner evidence only."""
    import time

    import httpx

    from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
    from jt_oz_bridge.domain.checks import CheckSelection, check_message_id
    from jt_oz_bridge.domain.execution import Admission, HumanMessage
    from jt_oz_bridge.security.admin import token_hash
    from jt_oz_bridge.services.bindings import BindingService
    from jt_oz_bridge.services.check_recovery import OwnedCheckRecovery
    from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
    from jt_oz_bridge.storage.control_models import Binding
    from jt_oz_bridge.storage.durable import digest
    from jt_oz_bridge.storage.models import Action
    from tests.contract.test_native_checks import CHECK, leaf_tail_fixture
    from tests.support import SyntheticAudience

    proofs, transport, data, client, ref = await leaf_tail_fixture(running=True)
    # A Bridge reconnect has a new volatile generation, same authenticated owner.
    old_epoch = proofs.generation(ref)
    proofs.feed.index.connection_epoch = "b" * 64
    assert proofs.certified_epoch(ref, transport.profile.sha256) is None
    proofs.feed.start = AsyncMock()
    qualification = client.checks.attestations[ref]
    selection = CheckSelection(
        reference=ref,
        check=CHECK,
        catalog_sha256=digest(qualification.catalog.model_dump(mode="json")),
        qualification_sha256=qualification.enrollment_sha256,
    )
    source = HumanMessage(
        realm_id="realm",
        channel_id=4,
        topic="original",
        message_id=12,
        revision=0,
        author_id=7,
        text="!oz check " + "x" * 32,
    )
    payload = {
        "operation": "check.run",
        "reference": ref.model_dump(mode="json"),
        "source": source.model_dump(mode="json"),
        "selection": selection.model_dump(mode="json"),
        "selection_token_sha256": token_hash("x" * 32),
        "choice_expires_at": time.time() - 100,
        "reply_locale": "en",
    }
    receipt = ExecutionReceipt(
        action_id="a",
        operation_digest=digest(payload),
        reference=ref,
        contract_sha256=transport.profile.sha256,
        admission=Admission(status="admitted", upstream_id=check_message_id("a")),
    )
    binding = Binding(
        id=binding_id,
        realm_id="realm",
        channel_id=4,
        topic="original",
        backend_id=ref.backend_id,
        backend_identity=ref.backend_identity,
        session_id=ref.upstream_session_id,
        project_id=ref.project_id,
        canonical_directory=ref.canonical_directory,
        title="Original Root",
        owner_id=7,
        audience_revision="audience:1",
        audience_user_ids=[7, 8],
        observed_cursor="original",
    )
    action = Action(
        id="a",
        dedupe_key="original-a",
        binding_id=binding.id,
        binding_revision=1,
        actor_id=7,
        operation_digest=digest(payload),
        payload=payload,
        operation="check.run",
        state="running",
        admission=receipt.model_dump(mode="json"),
        upstream_id=check_message_id("a"),
        owner="opencode",
    )
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=ref.backend_id,
                identity=ref.backend_identity,
                contract_hash=transport.profile.sha256,
                enabled=True,
                verified=True,
                version="synthetic",
            )
        )
        session.add(
            EnrolledProject(
                id=ref.project_id,
                backend_id=ref.backend_id,
                realm_id="realm",
                canonical_directory=ref.canonical_directory,
                enabled=True,
            )
        )
        session.add(binding)
        session.add(action)
        for user in (7, 8):
            session.add(
                Grant(
                    realm_id="realm", user_id=user, project_id=ref.project_id, role="administrator"
                )
            )
    owner_record = CheckDispatchPreflight(
        binding_id=binding.id,
        binding_revision=1,
        ownership_evidence_sha256="c" * 64,
        issued_at=100.0,
        expires_at=105.0,
        action_id="a",
        operation_digest=action.operation_digest,
        reference=ref,
        qualification_sha256=qualification.enrollment_sha256,
        contract_sha256=transport.profile.sha256,
        message_id=check_message_id("a"),
        state="idle",
        owner_epoch="a" * 64,
        connection_epoch=old_epoch,
    )
    owner_for = AsyncMock(return_value=owner_record)
    recovery = OwnedCheckRecovery(db, proofs, client.checks, owner_for=owner_for)
    observer = module.OriginalRuntimeObserver(proofs.feed, proofs, ref, recovery)
    calls = []
    delegate = transport.client._transport

    def handle(request):
        calls.append(request.method)
        return delegate.handler(request)

    transport.client._transport = httpx.MockTransport(handle)
    return SimpleNamespace(
        proofs=proofs,
        transport=transport,
        data=data,
        client=client,
        ref=ref,
        recovery=recovery,
        observer=observer,
        owner_record=owner_record,
        owner_for=owner_for,
        action=action,
        binding=binding,
        calls=calls,
        bindings=BindingService(db, client, SyntheticAudience()),
    )


async def test_restart_owned_running_check_collects_readonly_and_promotes_only_strict_idle(db):
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
    from jt_oz_bridge.services.check_results import CheckResultCollector
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from tests.contract.test_leaf_resources import finish

    graph = await startup_check_graph(db)
    try:
        await graph.observer.start()
        assert graph.observer.mode == "readonly-owned-check"
        assert graph.proofs.certified_epoch(graph.ref, INSTALLED_SCHEMA) is None
        assert not any(cap.supported for cap in graph.client.capabilities(graph.ref).values())
        lease = await DurableStore(db).acquire_lease("readonly-recovery", ttl=120)
        collector = CheckResultCollector(
            graph.bindings,
            {graph.ref: graph.client.checks},
            ConsumerFence("readonly-recovery", lease),
        )
        assert not await collector.collect("a", "realm")
        assert graph.proofs.certified_epoch(graph.ref, INSTALLED_SCHEMA) is None
        # A result observation alone does not promote the Root.
        graph.client.checks.observe = AsyncMock(wraps=graph.client.checks.observe)
        await graph.observer.retry_recovery()
        assert graph.observer.mode == "readonly-owned-check"
        # Complete, positively idle resources are required, including real tail proof.
        graph.data["shell.list"]["data"].clear()
        graph.data["session.message.list"]["data"] = graph.data["check_tail_rows"][-1:]
        await graph.observer.retry_recovery()
        assert graph.observer.mode == "strict"
        assert graph.proofs.certified_epoch(graph.ref, INSTALLED_SCHEMA) is not None
        assert graph.calls and set(graph.calls) == {"GET"}
    finally:
        await finish(graph.proofs, graph.transport)


@pytest.mark.parametrize(
    "failure", ["missing-owner-journal", "owner", "queued", "payload", "foreign-shell"]
)
async def test_unknown_or_unowned_background_never_degrades_startup(db, failure):
    from sqlalchemy import update

    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.storage.models import Action
    from tests.contract.test_leaf_resources import finish

    graph = await startup_check_graph(db)
    if failure == "missing-owner-journal":
        graph.recovery.owner_for = None
    elif failure == "owner":
        graph.owner_for.return_value = graph.owner_record.model_copy(
            update={"owner_epoch": "c" * 64}
        )
    elif failure == "queued":
        async with db.sessions.begin() as session:
            await session.execute(update(Action).where(Action.id == "a").values(state="queued"))
    elif failure == "payload":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action).where(Action.id == "a").values(payload={"forged": True})
            )
    else:
        foreign = copy.deepcopy(graph.data["shell.list"]["data"][0])
        foreign["id"] = "sh_foreign"
        graph.data["shell.list"]["data"].append(foreign)
    try:
        with pytest.raises((ContractError, ValueError, module.Conflict)):
            await graph.observer.start()
        assert graph.observer.mode == "unstarted" and not graph.proofs._watched
        assert "POST" not in graph.calls
    finally:
        await finish(graph.proofs, graph.transport)


async def test_validated_nonidle_resources_stay_readonly_and_owner_change_is_fatal(db):
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from tests.contract.test_leaf_resources import finish

    graph = await startup_check_graph(db)
    try:
        await graph.observer.start()
        graph.data["shell.list"]["data"].clear()
        graph.data["session.active"]["data"][graph.ref.upstream_session_id] = {"type": "running"}
        await graph.observer.retry_recovery()
        assert graph.observer.mode == "readonly-awaiting-idle" and not graph.proofs._watched
        graph.proofs.feed.owner.read.return_value = SimpleNamespace(owner_epoch="d" * 64)
        with pytest.raises((ContractError, ValueError)):
            await graph.observer.retry_recovery()
        assert not graph.proofs._watched and "POST" not in graph.calls
    finally:
        await finish(graph.proofs, graph.transport)


async def test_backend_recovery_retry_is_bounded_and_fair_without_restarting_other_roots(
    monkeypatch,
):
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    feed = SimpleNamespace(current_owner=AsyncMock(), index=SimpleNamespace(pop=lambda: None))
    roots = tuple(
        SimpleNamespace(
            ref=f"root-{index}",
            mode="readonly-owned-check",
            retry_at=0,
            retry_recovery=AsyncMock(),
            lost_watch=lambda: False,
        )
        for index in range(3)
    )
    group = module.BackendRuntimeObserver(feed, roots)
    for count in range(6):
        await group.pulse()
        assert sum(root.retry_recovery.await_count for root in roots) == count + 1
    assert [root.retry_recovery.await_count for root in roots] == [2, 2, 2]
    roots[0].mode = "strict"
    roots[1].retry_at = roots[2].retry_at = 102
    await group.pulse()
    assert sum(root.retry_recovery.await_count for root in roots) == 6
    assert group.readiness()[0] == ("root-0", "strict")


async def test_backend_pulse_restores_a_strict_root_that_lost_its_watch():
    feed = SimpleNamespace(current_owner=AsyncMock(), index=SimpleNamespace(pop=lambda: None))
    healthy = SimpleNamespace(
        ref="healthy",
        mode="strict",
        retry_at=0,
        lost_watch=lambda: False,
        restore_watch=AsyncMock(),
    )
    lost = SimpleNamespace(
        ref="lost", mode="strict", retry_at=0, lost_watch=lambda: True, restore_watch=AsyncMock()
    )
    group = module.BackendRuntimeObserver(feed, (healthy, lost))
    await group.pulse()
    lost.restore_watch.assert_awaited_once()
    healthy.restore_watch.assert_not_awaited()


async def test_one_owned_check_root_degrades_while_same_backend_other_project_stays_usable(db):
    import asyncio
    from dataclasses import replace

    import httpx

    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.domain.control import ExecutionState
    from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from tests.contract.test_leaf_resources import fixture_data
    from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame

    graph = await startup_check_graph(db)
    second = graph.ref.model_copy(
        update={
            "upstream_session_id": "ses_independent_project",
            "project_id": "independent-project",
            "canonical_directory": "/workspace/independent",
        }
    )
    feed = graph.proofs.feed
    feed.references = (graph.ref, second)
    feed.index = VolatileFeedIndex(PROFILE, feed.references, OWNER)
    feed.index.accept(frame({**CONNECTED, "id": "new_restarted_bridge_feed"}))
    peer_data = fixture_data()
    peer_data["session.get"]["data"].update(
        {
            "id": second.upstream_session_id,
            "projectID": "independent-native-project",
            "location": {"directory": second.canonical_directory},
        }
    )
    delegate = graph.transport.client._transport

    def handle(request):
        if request.url.path == "/api/shell":
            location = {"directory": request.url.params["location[directory]"]}
            if location["directory"] == second.canonical_directory:
                graph.calls.append(request.method)
                return httpx.Response(200, json={"location": location, "data": []})
        prefix = "/api/session/" + second.upstream_session_id
        if request.url.path == prefix:
            value = peer_data["session.get"]
        elif request.url.path.startswith(prefix + "/"):
            suffix = request.url.path.rsplit("/", 1)[1]
            operation = {
                "message": "session.message.list",
                "inbox": "session.inbox.list",
                "permission": "session.permission.list",
                "form": "session.form.list",
            }[suffix]
            value = peer_data[operation]
        else:
            return delegate.handler(request)
        graph.calls.append(request.method)
        return httpx.Response(200, json=value)

    graph.transport.client._transport = httpx.MockTransport(handle)
    graph.transport.attestation = replace(
        graph.transport.attestation,
        verified_operations=graph.transport.attestation.verified_operations | {"session.prompt"},
    )
    peer_proofs = V2LeafResourceProofs(
        feed,
        {
            second.project_id: V2CatalogProject(
                ProjectScope(**second.model_dump(exclude={"upstream_session_id"})),
                "independent-native-project",
            )
        },
    )
    peer_client = V2ExecutionClient(
        graph.transport,
        peer_proofs.projects,
        proofs=peer_proofs,
        scope_guard=SimpleNamespace(enrolled=lambda ref, operation: True),
    )
    peer = module.OriginalRuntimeObserver(feed, peer_proofs, second)
    group = module.BackendRuntimeObserver(feed, (graph.observer, peer))
    lease = await DurableStore(db).acquire_lease("root-readiness", ttl=120)
    runtime = SupervisedRuntime(
        db,
        ConsumerFence("root-readiness", lease),
        (RuntimeResource("native:synthetic", group.start, group.close),),
        (RuntimeWorker("native-results", asyncio.Event().wait),),
    )
    try:
        await runtime.start()
        assert runtime.healthy
        assert group.readiness() == ((graph.ref, "readonly-owned-check"), (second, "strict"))
        assert not any(cap.supported for cap in graph.client.capabilities(graph.ref).values())
        snapshot = await peer_client.snapshot(second)
        assert snapshot.reconciled and snapshot.state == ExecutionState.IDLE
        assert peer_client.capabilities(second)["prompt"].supported
        # Read observations are per full Root even on the same backend/feed.
        # The owned running check does not borrow the peer's strict watch, and
        # reading either Root cannot downgrade/promote the other's authority.
        own_read = await graph.proofs.read_scope(graph.ref)
        peer_read = await peer_proofs.read_scope(second)
        assert own_read.reference == graph.ref and peer_read.reference == second
        assert graph.proofs.read_epoch(graph.ref, graph.transport.profile.sha256)
        assert peer_proofs.read_epoch(second, graph.transport.profile.sha256)
        assert graph.proofs.certified_epoch(graph.ref, graph.transport.profile.sha256) is None
        assert peer_proofs.certified_epoch(second, graph.transport.profile.sha256)
        for proofs, foreign in ((graph.proofs, second), (peer_proofs, graph.ref)):
            with pytest.raises(ValueError):
                await proofs.read_scope(foreign)
        assert group.readiness() == ((graph.ref, "readonly-owned-check"), (second, "strict"))
        feed.start.assert_awaited_once()
        assert set(graph.calls) == {"GET"}
    finally:
        await runtime.close()


@pytest.mark.parametrize(
    "failure", ["root", "project", "directory", "parent", "archived", "schema", "owner"]
)
async def test_startup_scope_errors_are_never_reclassified_as_owned_background(db, failure):
    from dataclasses import replace

    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from tests.contract.test_leaf_resources import finish

    graph = await startup_check_graph(db)
    classify = AsyncMock(wraps=graph.recovery.classify)
    graph.recovery.classify = classify
    info = graph.data["session.get"]["data"]
    if failure == "root":
        info["id"] = "ses_foreign"
    elif failure == "project":
        info["projectID"] = "foreign-project"
    elif failure == "directory":
        info["location"]["directory"] = "/workspace/foreign"
    elif failure == "parent":
        info["parentID"] = "ses_other_parent"
    elif failure == "archived":
        info["time"]["archived"] = 22
    elif failure == "schema":
        graph.transport.attestation = replace(graph.transport.attestation, schema_sha256="e" * 64)
    else:
        graph.proofs.feed.owner.read.return_value = SimpleNamespace(owner_epoch="e" * 64)
    try:
        with pytest.raises((ContractError, ValueError)):
            await graph.observer.start()
        classify.assert_not_awaited()
        assert graph.observer.mode == "unstarted" and not graph.proofs._watched
        assert "POST" not in graph.calls
    finally:
        await finish(graph.proofs, graph.transport)


@pytest.mark.parametrize("failure", ["qualification", "metadata", "owner", "fence"])
async def test_recovery_rechecks_identity_after_original_shell_observation(db, failure):
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from tests.contract.test_leaf_resources import finish

    graph = await startup_check_graph(db)
    observe = graph.client.checks.observe

    async def changing(*args):
        value = await observe(*args)
        if failure == "qualification":
            graph.client.checks.attestations = {}
        elif failure == "metadata":
            graph.data["session.get"]["data"]["title"] = "changed during observation"
        elif failure == "owner":
            graph.proofs.feed.owner.read.return_value = SimpleNamespace(owner_epoch="f" * 64)
        else:
            index = graph.proofs.feed.index
            key = graph.ref.upstream_session_id
            index._arrival_revisions[key] = index._arrival_revisions.get(key, 0) + 1
        return value

    graph.client.checks.observe = changing
    try:
        with pytest.raises((ContractError, ValueError)):
            await graph.observer.start()
        assert graph.observer.mode == "unstarted" and not graph.proofs._watched
        assert "POST" not in graph.calls
    finally:
        await finish(graph.proofs, graph.transport)


async def configured_anchor_startup_peer(enrolled, db, monkeypatch, *, lineage="tree"):
    """Actual composition/feed/resources + synthetic HTTP, encrypted own DB only."""
    import asyncio
    import time

    import httpx

    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence
    from tests.contract.test_host_owner import evidence
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_native_project_policy import setup as policy_setup
    from tests.contract.test_public_live_feed import CONNECTED, REF

    proofs, old_transport, data, guard, _, _, writes = await policy_setup()
    peer = old_transport.client._transport
    from jt_oz_bridge.adapters.opencode.project_policy import policy_fingerprint
    from jt_oz_bridge.domain.models import SessionRef

    policy = guard.enrollments[REF]
    REF = SessionRef.model_validate(enrolled.ref)
    policy = policy.model_copy(
        update={
            "reference": REF,
            "fingerprint_sha256": policy_fingerprint(
                REF,
                "global",
                data["session.get"]["data"],
                data["agent.get"],
                data["plugin.list"],
                data["permission.saved.list"],
                data["mcp.list"],
            ),
            "operations": frozenset({"prompt"}),
        }
    )
    await finish(proofs, old_transport)
    native = enrolled.manifest["backends"][0]
    native["policy"] = enrolled.pin("policy.json", policy.model_dump(mode="json"))
    adoption_enrollment(enrolled, lineage=lineage)
    value, sha = module.read_enrollment(enrolled.settings)
    child = REF.model_copy(update={"upstream_session_id": "ses_offline_configured_child"})
    child_info = copy.deepcopy(data["session.get"]["data"])
    child_info.update(id=child.upstream_session_id, parentID=REF.upstream_session_id, agent="task")
    child_info["time"]["created"] = 2
    child_agent = copy.deepcopy(data["agent.get"])
    child_agent["data"].update(id="task", mode="subagent")
    state = {"child": False, "owner": False, "calls": [], "streams": []}

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield ("event: message\ndata: " + json.dumps(CONNECTED) + "\n\n").encode()
            await asyncio.Event().wait()

    def handle(request):
        state["calls"].append(request)
        assert request.method == "GET", "startup must never mutate Native"
        if request.url.path == "/api/event":
            state["streams"].append(request)
            return httpx.Response(
                200, headers={"content-type": "text/event-stream"}, stream=Stream()
            )
        if request.url.path == "/api/session":
            parent = request.url.params["parentID"]
            rows = [child_info] if state["child"] and parent == REF.upstream_session_id else []
            return httpx.Response(200, json={"data": copy.deepcopy(rows), "cursor": {}})
        if request.url.path == "/api/session/" + child.upstream_session_id:
            return httpx.Response(200, json={"data": copy.deepcopy(child_info)})
        if request.url.path == "/api/agent/task":
            return httpx.Response(200, json=copy.deepcopy(child_agent))
        return peer.handler(request)

    original_transport = module.V2HTTPTransport

    def transport(*args, **kwargs):
        return original_transport(*args, **kwargs, transport=httpx.MockTransport(handle))

    def owner(enrollment, socket):
        def read():
            raw = evidence(
                backend_id=REF.backend_id,
                backend_identity=REF.backend_identity,
                pid=124 if state["owner"] else 123,
            )
            raw["observed_at"] = time.time()
            return HostOwnerEvidence.model_validate(raw)

        return SimpleNamespace(enrollment=enrollment, read=AsyncMock(side_effect=read))

    monkeypatch.setattr(module, "V2HTTPTransport", transport)
    monkeypatch.setattr(module, "LinuxHostOwnerProbe", owner)
    holder = "configured-anchor-startup"
    store = DurableStore(db)
    epoch = await store.acquire_lease(holder, ttl=120)
    fence = module.ConsumerFence(holder, epoch)
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=REF.backend_id,
                identity=REF.backend_identity,
                contract_hash=value.backends[0].schema_file.sha256,
                enabled=True,
                verified=True,
                version="2.0.32",
            )
        )
        session.add(
            EnrolledProject(
                id=REF.project_id,
                backend_id=REF.backend_id,
                realm_id="2",
                canonical_directory=REF.canonical_directory,
                enabled=True,
            )
        )
        session.add(Grant(realm_id="2", user_id=8, project_id=REF.project_id, role="administrator"))

    def build():
        return module.build_pipeline(enrolled.settings, value, sha, db, fence)

    async def close(pipeline):
        for resource in reversed(pipeline.runtime().resources):
            await resource.close()

    async def start(pipeline, *, before=None):
        names = []
        # Exercise exactly the real composed resource start order; the final
        # consumer boundary is observed without registering a fake live queue.
        for resource in pipeline.runtime().resources:
            if before is not None:
                await before(resource.name, pipeline)
            names.append(resource.name)
            if resource.name == "zulip-consumer":
                break
            await resource.start()
        return names

    return SimpleNamespace(
        build=build,
        close=close,
        start=start,
        state=state,
        root=REF,
        child=child,
        writes=writes,
        data=data,
        store=store,
        holder=holder,
        epoch=epoch,
    )


async def test_actual_configured_tree_startup_restores_offline_child_before_original_watch(
    enrolled, db, monkeypatch
):
    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    first = graph.build()
    second = None
    try:
        await graph.start(first)
        saved = await first.adoption.journal.recovery_records(
            "2",
            graph.root.project_id,
            lock_authority=first.graph_authority(graph.root.project_id)[1],
            current=lambda: True,
        )
        assert len(saved) == 1 and saved[0].state == "active" and len(saved[0].record.nodes) == 1
        await graph.close(first)
        graph.state["child"] = True
        second = graph.build()
        factory = second.adoption.factory(graph.root)
        original = factory.registry.selected(graph.root)
        markers = (
            original.execution,
            original.execution.proofs,
            original.execution.scope_guard,
            original.models,
            original.results,
            original.transcript,
            original.metadata,
            original.execution.proofs.model_settings,
        )
        names = await graph.start(second)
        assert names.index("original-session-restoration") < names.index("zulip-consumer")
        generation = factory.registry.publication.generation(graph.root)
        assert generation.record is not None and generation.context is not None
        assert set(generation.entries) == {graph.root, graph.child}
        assert factory.registry.selected(graph.root) is original
        assert markers == (
            original.execution,
            original.execution.proofs,
            original.execution.scope_guard,
            original.models,
            original.results,
            original.transcript,
            original.metadata,
            original.execution.proofs.model_settings,
        )
        snapshot, proof = await original.execution.qualified_snapshot(graph.root)
        assert snapshot.reconciled and snapshot.descendants == (graph.child,)
        original.execution.current(graph.root, proof)
        assert original.execution.scope_guard.enrollments[graph.root].operations == frozenset(
            {"prompt"}
        )
        assert graph.data["session.get"]["data"]["permissions"] == [
            {"action": "*", "resource": "*", "effect": "deny"}
        ]
        assert not graph.writes and all(r.method == "GET" for r in graph.state["calls"])
    finally:
        await graph.close(second or first)
        await graph.store.release_lease(graph.holder, graph.epoch)


@pytest.mark.parametrize("qualification", [None, "leaf", "tree"])
async def test_actual_configured_startup_without_history_never_invents_child_baseline(
    enrolled, db, monkeypatch, qualification
):
    from jt_oz_bridge.adapters.opencode.contracts import ContractError

    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch, lineage=qualification)
    graph.state["child"] = True
    pipeline = graph.build()
    seen = []

    async def before(name, current):
        seen.append(name)

    try:
        with pytest.raises(ContractError, match="leaf_descendants_require_qualification"):
            await graph.start(pipeline, before=before)
        assert "zulip-consumer" not in seen
        backend = pipeline.backends[graph.root.backend_id]
        assert bool(backend.post_restoration_resources) is (qualification == "tree")
        generation = backend.registered.client.publication.generation(graph.root)
        assert generation.record is None and generation.context is None
        assert set(generation.entries) == {graph.root}
        assert not graph.writes
    finally:
        await graph.close(pipeline)
        await graph.store.release_lease(graph.holder, graph.epoch)


@pytest.mark.parametrize(
    "failure",
    [
        "owner",
        "grant",
        "fence",
        "qualification",
        "head",
        "grant-during-proof",
        "identity",
        "policy",
    ],
)
async def test_actual_configured_graph_startup_rechecks_original_authority_before_consumer(
    enrolled, db, monkeypatch, failure
):
    from dataclasses import replace

    from sqlalchemy import update

    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.durable import Conflict

    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    first = graph.build()
    second = None
    seen = []
    injected = False
    try:
        await graph.start(first)
        await graph.close(first)
        graph.state["child"] = True
        second = graph.build()
        factory = second.adoption.factory(graph.root)

        async def before(name, pipeline):
            nonlocal injected
            seen.append(name)
            stage = (
                "original-session-restoration"
                if failure in {"owner", "grant", "fence", "identity", "policy"}
                else "native-graph-activation:" + graph.root.backend_id
            )
            if name != stage:
                return
            injected = True
            if failure == "owner":
                graph.state["owner"] = True
            elif failure == "grant":
                async with db.sessions.begin() as session:
                    await session.execute(update(Grant).values(active=False))
            elif failure == "fence":
                await graph.store.release_lease(graph.holder, graph.epoch)
                await graph.store.acquire_lease("new-startup-owner", ttl=120)
            elif failure == "identity":
                graph.data["session.get"]["data"]["time"]["created"] += 1
            elif failure == "policy":
                graph.data["session.get"]["data"]["permissions"] = [
                    {"action": "*", "resource": "*", "effect": "allow"}
                ]
            elif failure == "qualification":
                factory.lineage = replace(factory.lineage, qualification_scope="leaf")
            elif failure == "grant-during-proof":
                execution = factory.registry.selected(graph.root).execution
                original_snapshot = execution.qualified_snapshot

                async def revoked_after_real_proof(ref):
                    result = await original_snapshot(ref)
                    async with db.sessions.begin() as session:
                        await session.execute(update(Grant).values(active=False))
                    return result

                execution.qualified_snapshot = revoked_after_real_proof
            else:
                generation = factory.registry.publication.generation(graph.root)
                await pipeline.adoption.journal.prepare(
                    "2",
                    generation.record,
                    lock_authority=pipeline.graph_authority(graph.root.project_id)[1],
                    current=lambda: factory.registry.publication.current(graph.root, generation),
                )

        with pytest.raises((ContractError, AccessDenied, Conflict)):
            await graph.start(second, before=before)
        assert injected and "zulip-consumer" not in seen
        if failure in {"owner", "grant", "fence", "identity", "policy"}:
            generation = factory.registry.publication.generation(graph.root)
            assert generation.record is None and generation.context is None
            assert set(generation.entries) == {graph.root}
        assert not graph.writes and all(r.method == "GET" for r in graph.state["calls"])
    finally:
        await graph.close(second or first)
        await graph.store.release_lease(graph.holder, graph.epoch)


async def test_actual_tree_owner_feed_precedes_restoration_and_original_activation(
    enrolled, db, monkeypatch
):
    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    pipeline = graph.build()
    backend = pipeline.backends[graph.root.backend_id]
    group = backend.resources[0].start.__self__
    try:
        await backend.resources[0].start()
        assert group.feed.index is not None and not group.feed.task.done()
        assert group.roots[0].mode == "unstarted"
        assert graph.state["calls"] and all(
            request.url.path == "/api/event" for request in graph.state["calls"]
        )
        assert len(backend.post_restoration_resources) == 1
        with pytest.raises(module.ContractError, match="startup_restoration_required"):
            await backend.post_restoration_resources[0].start()
        assert group.roots[0].mode == "unstarted"
        await pipeline.restore_adopted()
        assert group.roots[0].mode == "unstarted"
        await backend.post_restoration_resources[0].start()
        assert group.roots[0].mode == "strict"
        names = [r.name for r in pipeline.runtime().resources]
        assert (
            names.index("original-session-restoration")
            < names.index("native-graph-activation:" + graph.root.backend_id)
            < names.index("zulip-consumer")
        )
        assert not graph.writes
    finally:
        await graph.close(pipeline)
        await graph.store.release_lease(graph.holder, graph.epoch)


async def test_actual_graph_activation_cancel_cannot_start_consumer_or_rewrite_original_root(
    enrolled, db, monkeypatch
):
    import asyncio

    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    pipeline = graph.build()
    seen = []

    async def before(name, current):
        seen.append(name)
        if name == "native-graph-activation:" + graph.root.backend_id:
            asyncio.current_task().cancel()

    try:
        with pytest.raises(asyncio.CancelledError):
            await asyncio.create_task(graph.start(pipeline, before=before))
        assert "zulip-consumer" not in seen
        factory = pipeline.adoption.factory(graph.root)
        root = factory.registry.selected(graph.root)
        generation = factory.registry.publication.generation(graph.root)
        assert generation.entries[graph.root] is root
        assert generation.record is not None and generation.context is not None
        assert pipeline.backends[graph.root.backend_id].mode_snapshot()[0].mode == "unstarted"
        assert not graph.writes
    finally:
        await graph.close(pipeline)
        await graph.store.release_lease(graph.holder, graph.epoch)


async def test_explicit_enrollment_keeps_strict_leaf_resource_start_despite_tree_opt_in(
    enrolled, db, monkeypatch
):
    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    pipeline = graph.build()
    graph.state["child"] = True
    group = pipeline.backends[graph.root.backend_id].resources[0].start.__self__
    try:
        with pytest.raises(module.ContractError, match="leaf_descendants_require_qualification"):
            await group.start()
        assert group.roots[0].mode == "unstarted"
        assert (
            pipeline.adoption.factory(graph.root).registry.publication.generation(graph.root).record
            is None
        )
        assert not graph.writes
    finally:
        await graph.close(pipeline)
        await graph.store.release_lease(graph.holder, graph.epoch)
