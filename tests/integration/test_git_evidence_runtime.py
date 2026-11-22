"""Synthetic pinned loader composition, not installed Git/Native qualification."""

from dataclasses import replace
from pathlib import Path

import pytest

from jt_oz_bridge.domain.checks import ApprovedCheck
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services import runtime_enrollment as runtime
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.integration.test_catalog_enrollment import close_pipeline, configure_catalogs
from tests.integration.test_file_enrollment import files as files
from tests.integration.test_git_review_enrollment import synthetic_directory_composition
from tests.integration.test_runtime_enrollment import approved_checks
from tests.integration.test_runtime_enrollment import enrolled as enrolled
from tests.unit.test_git_evidence import pin


def configured(files, monkeypatch):
    configure_catalogs(files)
    backend, doc = approved_checks(files)
    ref = SessionRef.model_validate(backend["reference"])
    scope = digest(ref.model_dump(mode="json"))
    check = ApprovedCheck(
        id="evidence",
        title="Synthetic original Git check",
        command="/usr/bin/python3 -I -B /opt/jt-oz-bridge/git-inspect225.py --scope " + scope,
    )
    doc["catalog"]["checks"] = [check.model_dump(mode="json")]
    backend["checks"] = files.pin("git-evidence-checks.json", doc)
    backend["git_evidence"] = files.pin("git-evidence-installed.json", {"synthetic": True})
    files.save_catalogs()
    calls = []

    def qualify(raw, **kwargs):
        assert raw == files.documents[Path(backend["git_evidence"]["path"])]
        assert kwargs["reference"] == ref and kwargs["catalog"].checks == (check,)
        assert kwargs["physical_root"].directory == ref.canonical_directory
        assert kwargs["owner"].native_uid == kwargs["physical_root"].uid
        calls.append(kwargs)
        return pin(
            reference=ref,
            scope_sha256=scope,
            check=check,
            catalog_sha256=digest(kwargs["catalog"].model_dump(mode="json")),
            contract_sha256=kwargs["contract_sha256"],
            qualification_sha256=kwargs["check_qualification_sha256"],
        )

    monkeypatch.setattr(runtime, "qualify_git_evidence", qualify)
    synthetic_directory_composition(monkeypatch)
    return backend, ref, calls


def test_absent_opt_in_keeps_legacy_serialization_and_zero_extra_asset_reads(enrolled, monkeypatch):
    q = runtime.NativeQualification.model_validate(enrolled.manifest["backends"][0])
    assert "git_evidence" not in q.model_dump(mode="json")
    assert runtime.NativeQualification.model_validate(q.model_dump(mode="json")) == q
    monkeypatch.setattr(runtime, "qualify_git_evidence", lambda *a, **k: pytest.fail("absent pin"))
    assert runtime.git_evidence_pin(q, None) is None


async def test_pipeline_uses_exact_root_original_reader_source_fence_and_shared_tokens(
    files, db, monkeypatch
):
    backend, ref, calls = configured(files, monkeypatch)
    monkeypatch.setattr(
        runtime.V2HTTPTransport,
        "request",
        lambda *a, **k: pytest.fail("composition must not read Native"),
    )
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert len(calls) >= 2
        graph = pipe.backends[ref.backend_id]
        commands = pipe.router.git_evidence
        assert commands.source is pipe.source and commands.bindings is pipe.bindings
        assert commands.tokens is pipe.tokens and commands.db is db and commands.fence == pipe.fence
        assert commands.results.readers[ref] is graph.checks[ref]
        assert commands.results.pins[ref] == graph.git_evidence[ref]
        assert set(graph.git_evidence) == {ref}
        with pytest.raises(TypeError):
            graph.git_evidence[ref] = pin()
        with pytest.raises(ValueError, match="git_evidence_original_check_scope_changed"):
            replace(
                graph,
                git_evidence={
                    ref: graph.git_evidence[ref].model_copy(update={"catalog_sha256": "0" * 64})
                },
            )
        child = ref.model_copy(update={"upstream_session_id": "ses_child"})
        with pytest.raises(ValueError, match="git_evidence_original_check_scope_changed"):
            replace(graph, git_evidence={child: graph.git_evidence[ref]})
    finally:
        await close_pipeline(pipe)


@pytest.mark.parametrize("fault", ["checks", "directory", "legacy", "bad_packet"])
def test_declared_pin_must_validate_even_when_menus_disabled(files, monkeypatch, fault):
    backend, ref, calls = configured(files, monkeypatch)
    files.settings.runtime.workspace_menus_enabled = False
    if fault == "checks":
        backend["checks"] = None
    elif fault == "directory":
        files.manifest["directory_scope"] = None
    elif fault == "legacy":
        files.manifest["format"] = "qualified-consumer-runtime-v1"
    else:

        def bad(*a, **k):
            raise ValueError("synthetic_invalid_installed_packet")

        monkeypatch.setattr(runtime, "qualify_git_evidence", bad)
    files.save()
    with pytest.raises(ValueError):
        runtime.read_enrollment(files.settings)


async def test_absent_pin_pipeline_stays_disabled_without_native_reads(files, db, monkeypatch):
    configure_catalogs(files)
    synthetic_directory_composition(monkeypatch)
    monkeypatch.setattr(
        runtime.V2HTTPTransport, "request", lambda *a, **k: pytest.fail("no added GET")
    )
    value, sha = runtime.read_enrollment(files.settings)
    pipe = runtime.build_pipeline(files.settings, value, sha, db, ConsumerFence("synthetic", 1))
    try:
        assert all(not b.git_evidence for b in pipe.backends.values())
        assert not pipe.router.git_evidence.results.pins
    finally:
        await close_pipeline(pipe)
