"""Synthetic pinned Git review evidence and real own DB; not installed qualification."""

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode import directory_scope, git_review
from jt_oz_bridge.adapters.opencode.git_review import (
    PATCH_SEMANTICS,
    REVIEW_OPERATIONS,
    REVIEW_SEMANTICS,
    review_attestation_sha256,
)
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.services.file_enrollment import component_sha
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.contract.test_host_owner import evidence
from tests.integration.test_catalog_enrollment import close_pipeline, configure_catalogs
from tests.integration.test_file_enrollment import files as files
from tests.integration.test_runtime_enrollment import add_second_root
from tests.integration.test_runtime_enrollment import enrolled as enrolled


def configure_git_reviews(files, *, indices=(0,)):
    configure_catalogs(files)
    files.git_docs, files.git_observations = {}, {}
    for index in indices:
        b = files.manifest["backends"][index]
        ref = SessionRef.model_validate(b["reference"])
        policy = json.loads(files.documents[Path(b["policy"]["path"])])
        owner = json.loads(files.documents[Path(b["owner"]["path"])])
        owner_keys = (
            "backend_id",
            "backend_identity",
            "unit",
            "unit_sha256",
            "native_uid",
            "version",
            "url",
            "executable_sha256",
            "dataset_device",
            "dataset_inode",
        )
        observed_owner = evidence(**{key: owner[key] for key in owner_keys})
        observation = dict(
            format="installed-original-git-review-observation-v1",
            passed=True,
            reference=ref.model_dump(mode="json"),
            contract_sha256=b["schema_file"]["sha256"],
            native_policy_sha256=policy["fingerprint_sha256"],
            semantics_sha256=REVIEW_SEMANTICS,
            owners=[observed_owner, {**observed_owner, "observed_at": 101}],
            requests=[
                dict(
                    operation=operation,
                    method="GET",
                    status=200,
                    directory=None if operation == "worktree.list" else ref.canonical_directory,
                    native_project_id=b["native_project_id"]
                    if operation == "worktree.list"
                    else None,
                    response_sha256=digest({"operation": operation, "reference": ref.model_dump()}),
                )
                for _ in range(2)
                for operation in sorted(REVIEW_OPERATIONS)
            ],
            original_processes_unchanged=True,
            live_bridge_counts_unchanged=True,
            native_database_bytes_read=False,
            native_http_mutations=0,
            zulip_requests=0,
            repeated_bundle_equal=True,
            physical_boundary_unchanged=True,
            saved_inventory_only=True,
            mutation_proof_issued=False,
        )
        root = next(
            row
            for row in files.directory_doc["roots"]
            if row["directory"] == ref.canonical_directory
        )
        doc = dict(
            format="qualified-original-git-review-v1",
            operator_review="installed-evidence-reviewed-for-development-runtime",
            reference=ref.model_dump(mode="json"),
            native_project_id=b["native_project_id"],
            contract_sha256=b["schema_file"]["sha256"],
            native_policy_sha256=policy["fingerprint_sha256"],
            semantics_sha256=REVIEW_SEMANTICS,
            git_component_sha256=component_sha(git_review),
            directory_component_sha256=component_sha(directory_scope),
            directory_enrollment_sha256=files.manifest["directory_scope"]["sha256"],
            directory_config_sha256=files.directory_doc["config_sha256"],
            directory_implementation_sha256=files.directory_doc["implementation_sha256"],
            physical_root=copy.deepcopy(root),
            operations=sorted(REVIEW_OPERATIONS),
            observation=files.pin("git-observed-" + ref.upstream_session_id + ".json", observation),
        )
        b["verified_operations"] = sorted(set(b["verified_operations"]) | REVIEW_OPERATIONS)
        files.git_docs[index], files.git_observations[index] = doc, observation

    def save():
        files.save_catalogs()
        for index, doc in files.git_docs.items():
            b = files.manifest["backends"][index]
            sid = b["reference"]["upstream_session_id"]
            doc["observation"] = files.pin(
                "git-observed-" + sid + ".json", files.git_observations[index]
            )
            b["git_review"] = files.pin("git-review-" + sid + ".json", doc)
        files.save()

    # The transport contract is shared by one Native backend; Root disclosure
    # qualification remains per-ref and is never inherited from this op catalog.
    for backend in files.manifest["backends"]:
        backend["verified_operations"] = sorted(
            set(backend["verified_operations"]) | REVIEW_OPERATIONS
        )
    files.save_git_reviews = save
    save()
    return files


def synthetic_directory_composition(monkeypatch):
    class SyntheticEnrolledDirectories:
        """Only inert composition facts; never a live Linux metadata witness."""

        def __init__(self, enrollment, socket_path):
            self.enrollment, self.socket_path = enrollment, socket_path
            self.roots = {root.project_key: root for root in enrollment.roots}

        def qualified(self, reference):
            root = self.roots.get(directory_project_key(reference))
            return root is not None and root.directory == reference.canonical_directory

        async def observe(self, *_args, **_kwargs):
            pytest.fail("synthetic composition must not issue a live directory witness")

        def current(self, *_args, **_kwargs):
            return False

    monkeypatch.setattr(runtime, "LinuxDirectoryScopeGuard", SyntheticEnrolledDirectories)


@pytest.fixture
def reviews(files, monkeypatch):
    synthetic_directory_composition(monkeypatch)
    return configure_git_reviews(files)


def configure_patch(reviews):
    """Synthetic positive evidence; never an installed Native certification."""
    value, _ = runtime.read_enrollment(reviews.settings)
    q = value.backends[0]
    summary = runtime.git_review_pin(q, value.directory_scope)
    observed = dict(
        format="installed-original-git-patch-observation-v1",
        review=copy.deepcopy(reviews.git_observations[0]),
        mode="working",
        base=None,
        selected_file=dict(
            path="src/a.py",
            additions=1,
            deletions=0,
            status="added",
            patch_sha256="a" * 64,
            patch_bytes=16,
        ),
        original_patch_sha256="a" * 64,
        original_patch_bytes=16,
        exact_projection_verified=True,
    )
    for row in observed["review"]["requests"]:
        if row["operation"] == "vcs.diff":
            row.update(comparison_mode="working", comparison_base=None)
    doc = dict(
        format="qualified-original-git-patch-v1",
        operator_review="installed-evidence-reviewed-for-development-runtime",
        reference=q.reference.model_dump(mode="json"),
        review_attestation_sha256=review_attestation_sha256(summary),
        semantics_sha256=PATCH_SEMANTICS,
        git_component_sha256=component_sha(git_review),
        observations=[reviews.pin("git-patch-observed.json", observed)],
    )

    def save():
        doc["observations"] = [reviews.pin("git-patch-observed.json", observed)]
        reviews.manifest["backends"][0]["git_patch"] = reviews.pin("git-patch.json", doc)
        reviews.save()

    save()
    return doc, observed, save


@pytest.mark.parametrize("mode", ["branch", "committed"])
def test_patch_mode_requires_its_own_matching_positive_comparison_record(reviews, mode):
    doc, observed, save = configure_patch(reviews)
    comparison = copy.deepcopy(observed)
    comparison.update(mode=mode, base="main")
    for row in comparison["review"]["requests"]:
        if row["operation"] == "vcs.diff":
            row.update(comparison_mode=mode, comparison_base="main")
    doc["observations"].append(reviews.pin("patch-" + mode + ".json", comparison))
    reviews.manifest["backends"][0]["git_patch"] = reviews.pin("git-patch.json", doc)
    reviews.save()
    value, _ = runtime.read_enrollment(reviews.settings)
    pin = runtime.git_patch_pin(value.backends[0], value.directory_scope)
    assert pin.verified_modes == frozenset({"working", mode})


@pytest.mark.parametrize("fault", ["duplicate", "missing-mode", "wrong-base", "non-diff-mode"])
def test_patch_mode_labels_or_duplicate_evidence_cannot_expand_qualification(reviews, fault):
    doc, observed, save = configure_patch(reviews)
    if fault == "duplicate":
        doc["observations"].append(doc["observations"][0])
        reviews.manifest["backends"][0]["git_patch"] = reviews.pin("git-patch.json", doc)
        reviews.save()
    else:
        row = next(r for r in observed["review"]["requests"] if r["operation"] == "vcs.diff")
        if fault == "missing-mode":
            row.pop("comparison_mode")
        elif fault == "wrong-base":
            row["comparison_base"] = "main"
        else:
            observed["review"]["requests"][0]["comparison_mode"] = "working"
        save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


async def test_separate_patch_pin_composes_same_original_reader_but_never_inherits_to_other_root(
    reviews, db, monkeypatch
):
    doc, observed, _ = configure_patch(reviews)
    monkeypatch.setattr(
        runtime.V2HTTPTransport,
        "request",
        lambda *_args, **_kwargs: pytest.fail("composition is not Native observation"),
    )
    value, sha = runtime.read_enrollment(reviews.settings)
    pin = runtime.git_patch_pin(value.backends[0], value.directory_scope)
    assert pin.installed_evidence_sha256 == digest({"observations": doc["observations"]})
    assert pin.verified_modes == frozenset({"working"})
    pipe = runtime.build_pipeline(reviews.settings, value, sha, db, ConsumerFence("patch", 1))
    try:
        ref = value.backends[0].reference
        reader = pipe.router.git_review.readers[ref]
        assert reader is pipe.backends[ref.backend_id].git_reviews[ref]
        assert reader.patch_attestations[ref] == pin
        assert set(reader.patch_attestations) == {ref}
        assert not reader.proofs._watched
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize(
    "field",
    [
        "format",
        "reference",
        "operator_review",
        "review_attestation_sha256",
        "semantics_sha256",
        "git_component_sha256",
    ],
)
def test_patch_qualification_pin_drift_is_rejected_before_runtime(reviews, field):
    doc, observed, save = configure_patch(reviews)
    doc[field] = (
        {**reviews.ref, "upstream_session_id": "foreign"} if field == "reference" else "bad"
    )
    save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


@pytest.mark.parametrize(
    "fault",
    [
        "summary-removed",
        "empty",
        "oversized",
        "wrong-hash",
        "wrong-size",
        "not-exact",
        "integer-exact",
        "hidden-path",
        "wrong-root",
        "unknown-operation",
        "missing-request",
        "wrong-directory",
        "wrong-project",
        "unequal-bundle",
        "post",
        "owner",
        "branch-missing-base",
        "working-extra-base",
        "bad-base",
        "mutation",
    ],
)
def test_partial_or_wrong_patch_observation_never_enables_disclosure(reviews, fault):
    doc, observed, save = configure_patch(reviews)
    raw = observed["review"]
    if fault == "summary-removed":
        reviews.manifest["backends"][0].pop("git_review")
    elif fault == "empty":
        observed["selected_file"]["patch_bytes"] = observed["original_patch_bytes"] = 0
    elif fault == "oversized":
        observed["original_patch_bytes"] = 1024**2 + 1
    elif fault == "wrong-hash":
        observed["original_patch_sha256"] = "b" * 64
    elif fault == "wrong-size":
        observed["original_patch_bytes"] += 1
    elif fault == "not-exact":
        observed["exact_projection_verified"] = False
    elif fault == "integer-exact":
        observed["exact_projection_verified"] = 1
    elif fault == "hidden-path":
        observed["selected_file"]["path"] = ".env"
    elif fault == "wrong-root":
        raw["reference"]["upstream_session_id"] = "foreign"
    elif fault == "unknown-operation":
        raw["requests"][0]["operation"] = "foreign.get"
    elif fault == "missing-request":
        raw["requests"].pop()
    elif fault == "wrong-directory":
        next(r for r in raw["requests"] if r["operation"] != "worktree.list")["directory"] = (
            "/foreign"
        )
    elif fault == "wrong-project":
        next(r for r in raw["requests"] if r["operation"] == "worktree.list")[
            "native_project_id"
        ] = "foreign"
    elif fault == "unequal-bundle":
        raw["requests"][0]["response_sha256"] = "f" * 64
    elif fault == "post":
        raw["requests"][0]["method"] = "POST"
    elif fault == "owner":
        raw["owners"][0]["owner_epoch"] = "0" * 64
    elif fault == "branch-missing-base":
        observed["mode"] = "branch"
    elif fault == "working-extra-base":
        observed["base"] = "main"
    elif fault == "bad-base":
        observed.update(mode="committed", base="-evil")
    else:
        raw["native_http_mutations"] = 1
    save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


def test_git_review_load_is_explicit_inert_and_not_live_owner_or_mutation_proof(
    reviews, monkeypatch
):
    monkeypatch.setattr(
        runtime,
        "resolve_secret",
        lambda _: pytest.fail("no credential resolution during normalization"),
    )
    monkeypatch.setattr(
        runtime,
        "LinuxDirectoryScopeGuard",
        lambda *_: pytest.fail("no helper/socket during normalization"),
    )
    value, _ = runtime.read_enrollment(reviews.settings)
    q = value.backends[0]
    attestation = runtime.git_review_pin(q, value.directory_scope)
    assert attestation.reference == q.reference and attestation.operations == REVIEW_OPERATIONS
    assert attestation.installed_evidence_sha256 == reviews.git_docs[0]["observation"]["sha256"]
    assert not hasattr(attestation, "mutation_watch")


@pytest.mark.parametrize(
    "field",
    [
        "format",
        "operator_review",
        "reference",
        "native_project_id",
        "contract_sha256",
        "native_policy_sha256",
        "semantics_sha256",
        "git_component_sha256",
        "directory_component_sha256",
        "directory_enrollment_sha256",
        "directory_config_sha256",
        "directory_implementation_sha256",
        "physical_root",
    ],
)
def test_git_review_requires_exact_original_root_policy_schema_components_and_physical_pin(
    reviews, field
):
    doc = reviews.git_docs[0]
    if field == "reference":
        doc[field] = {**reviews.ref, "upstream_session_id": "foreign"}
    elif field == "physical_root":
        doc[field] = {**doc[field], "inode": 23}
    else:
        doc[field] = "unqualified"
    reviews.save_git_reviews()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-operation",
        "duplicate-operation",
        "mutation-operation",
        "missing-verified-operation",
        "missing-observation",
        "tampered-observation-bytes",
        "missing-physical",
        "legacy-format",
    ],
)
def test_git_review_cannot_be_qualified_from_schema_or_partial_evidence(reviews, fault):
    b = reviews.manifest["backends"][0]
    if fault == "missing-operation":
        reviews.git_docs[0]["operations"].pop()
    elif fault == "duplicate-operation":
        reviews.git_docs[0]["operations"][0] = reviews.git_docs[0]["operations"][1]
    elif fault == "mutation-operation":
        reviews.git_docs[0]["operations"][0] = "session.shell"
    elif fault == "missing-verified-operation":
        b["verified_operations"].remove("vcs.base")
    elif fault == "missing-observation":
        reviews.save_git_reviews()
        reviews.documents.pop(Path(reviews.git_docs[0]["observation"]["path"]))
        with pytest.raises((ValueError, KeyError)):
            runtime.read_enrollment(reviews.settings)
        return
    elif fault == "tampered-observation-bytes":
        reviews.save_git_reviews()
        reviews.documents[Path(reviews.git_docs[0]["observation"]["path"])] += b" "
        with pytest.raises(ValueError):
            runtime.read_enrollment(reviews.settings)
        return
    elif fault == "missing-physical":
        reviews.manifest.pop("directory_scope")
    else:
        reviews.manifest["format"] = "qualified-consumer-runtime-v1"
    if fault in {"missing-physical", "legacy-format"}:
        reviews.save()
    else:
        reviews.save_git_reviews()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("passed", 1),
        ("native_http_mutations", 1),
        ("native_http_mutations", False),
        ("zulip_requests", 1),
        ("native_database_bytes_read", True),
        ("mutation_proof_issued", True),
        ("original_processes_unchanged", False),
        ("live_bridge_counts_unchanged", False),
        ("repeated_bundle_equal", False),
        ("physical_boundary_unchanged", False),
        ("saved_inventory_only", False),
    ],
)
def test_git_review_historical_observation_must_record_readonly_preserved_boundaries(
    reviews, field, value
):
    reviews.git_observations[0][field] = value
    reviews.save_git_reviews()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


@pytest.mark.parametrize(
    "fault",
    [
        "foreign-ref",
        "wrong-schema",
        "wrong-policy",
        "wrong-semantics",
        "changed-owner",
        "wrong-owner-enrollment",
        "missing-request",
        "unknown-operation",
        "post",
        "bad-status",
        "wrong-directory",
        "wrong-project",
        "unequal-response",
    ],
)
def test_git_review_original_observation_and_two_get_bundles_are_independent_requirements(
    reviews, fault
):
    observation = reviews.git_observations[0]
    if fault == "foreign-ref":
        observation["reference"] = {**reviews.ref, "upstream_session_id": "foreign"}
    elif fault in {"wrong-schema", "wrong-policy", "wrong-semantics"}:
        field = {
            "wrong-schema": "contract_sha256",
            "wrong-policy": "native_policy_sha256",
            "wrong-semantics": "semantics_sha256",
        }[fault]
        observation[field] = "0" * 64
    elif fault in {"changed-owner", "wrong-owner-enrollment"}:
        original = observation["owners"][0]
        fields = {
            key: value
            for key, value in original.items()
            if key not in {"owner_epoch", "observed_at"}
        }
        if fault == "changed-owner":
            fields["pid"] += 1
        else:
            fields["dataset_inode"] += 1
        changed = {**fields, "owner_epoch": digest(fields), "observed_at": 101}
        observation["owners"][1] = changed
        if fault == "wrong-owner-enrollment":
            observation["owners"][0] = copy.deepcopy(changed)
    elif fault == "missing-request":
        observation["requests"].pop()
    elif fault == "unknown-operation":
        observation["requests"][0]["operation"] = "foreign.get"
    elif fault == "post":
        observation["requests"][0]["method"] = "POST"
    elif fault == "bad-status":
        observation["requests"][0]["status"] = 401
    elif fault == "wrong-directory":
        observation["requests"][0]["directory"] = "/foreign"
    elif fault == "wrong-project":
        row = next(row for row in observation["requests"] if row["operation"] == "worktree.list")
        row["native_project_id"] = "foreign"
    else:
        observation["requests"][0]["response_sha256"] = "0" * 64
    reviews.save_git_reviews()
    with pytest.raises(ValueError):
        runtime.read_enrollment(reviews.settings)


async def test_absent_git_pin_keeps_existing_v5_disabled_and_never_adds_native_get(
    files, db, monkeypatch
):
    configure_catalogs(files)
    monkeypatch.setattr(
        runtime.V2HTTPTransport,
        "request",
        lambda *_args, **_kwargs: pytest.fail("absent pin must not add Native GET"),
    )
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert all(not backend.git_reviews for backend in pipe.backends.values())
        assert not pipe.router.git_review.readers
        for backend in pipe.backends.values():
            for ref in backend.references:
                assert not backend.git_reviews
                reader = backend.metadata[ref]
                monkeypatch.setattr(
                    reader.client.transport,
                    "request",
                    lambda *_args, **_kwargs: pytest.fail("absent pin must not read Native"),
                )
        assert not any(b.git_review for b in value.backends)
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("menus", [False, True])
async def test_git_review_pipeline_shares_original_client_source_tokens_and_never_creates_watch(
    reviews, db, menus
):
    reviews.settings.runtime.workspace_menus_enabled = menus
    value, sha = runtime.read_enrollment(reviews.settings)
    pipe = runtime.build_pipeline(reviews.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        commands = pipe.router.git_review
        assert (
            commands.bindings is pipe.bindings
            and commands.tokens is pipe.tokens
            and commands.source is pipe.source
        )
        assert commands.fence == commands.tokens.fence == pipe.fence
        ref = value.backends[0].reference
        backend = pipe.backends[ref.backend_id]
        reader = backend.git_reviews[ref]
        assert reader.client is backend.metadata[ref].client
        assert reader is commands.readers[ref]
        assert reader.directories is not None and not reader.proofs._watched
        assert reader.proofs.certified_epoch(ref, reader.client.transport.profile.sha256) is None
        assert reader.attestations[ref].operations == REVIEW_OPERATIONS
        with pytest.raises(TypeError):
            backend.git_reviews[ref] = object()
        with pytest.raises(ValueError, match="runtime_git_review_scope_or_contract_changed"):
            replace(
                backend,
                git_reviews={ref.model_copy(update={"upstream_session_id": "foreign"}): reader},
            )
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("both", [False, True])
async def test_two_original_roots_never_inherit_other_root_git_review_qualification(
    files, db, both, monkeypatch
):
    synthetic_directory_composition(monkeypatch)
    add_second_root(files)
    configure_git_reviews(files, indices=(0, 1) if both else (0,))
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        readers = pipe.router.git_review.readers
        assert len(readers) == (2 if both else 1)
        if both:
            first, second = readers.values()
            assert (
                first.client is not second.client
                and first.client.transport is second.client.transport
            )
            assert first.directories is second.directories
            assert first.attestations != second.attestations
        else:
            assert value.backends[1].reference not in readers
    finally:
        await close_pipeline(pipe)


async def test_unavailable_physical_guard_still_rejects_even_with_valid_git_evidence(
    reviews, db, monkeypatch
):
    value, sha = runtime.read_enrollment(reviews.settings)
    pipe = runtime.build_pipeline(reviews.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        ref = value.backends[0].reference
        backend = pipe.backends[ref.backend_id]
        reader = backend.git_reviews[ref]
        monkeypatch.setattr(reader.directories, "qualified", lambda _ref: False)
        # Retain the real production constructor guard. No live witness is
        # fabricated, and all already-owned client/file resources are closed.
        with pytest.raises(ValueError, match="runtime_git_review_scope_or_contract_changed"):
            replace(backend)
        assert not reader.proofs._watched
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("ordering", ["adjacent-operation-pairs", "cross-boundary-duplicates"])
def test_two_matching_gets_per_operation_cannot_replace_two_complete_bundles(reviews, ordering):
    rows = reviews.git_observations[0]["requests"]
    if ordering == "adjacent-operation-pairs":
        rows[:] = sorted(rows, key=lambda row: row["operation"])
    else:
        rows[0], rows[7] = rows[7], rows[0]
    # Preserve the same twelve values, per-op pair hashes, owner and Root scope.
    # Only the claimed complete-bundle boundaries are invalid.
    assert all(
        sum(row["operation"] == operation for row in rows) == 2 for operation in REVIEW_OPERATIONS
    )
    reviews.save_git_reviews()
    with pytest.raises(ValueError, match="runtime_git_review_two_complete_get_bundles_required"):
        runtime.read_enrollment(reviews.settings)


def test_complete_bundles_allow_independent_within_bundle_record_order(reviews):
    rows = reviews.git_observations[0]["requests"]
    rows[:] = list(reversed(rows[:6])) + rows[7:] + rows[6:7]
    reviews.save_git_reviews()
    value, _ = runtime.read_enrollment(reviews.settings)
    assert runtime.git_review_pin(value.backends[0], value.directory_scope) is not None
