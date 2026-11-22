"""Offline checks of the creation certification tool's pure evidence builders.

Synthetic data only: no Native, socket, systemd or root file is touched, and
nothing here is installed, operator or Human qualification evidence.
"""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
from jt_oz_bridge.adapters.opencode.project_policy import PERMISSION_SOURCE, NativePolicyEnrollment
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.services.runtime_enrollment import (
    CreationRPCQualification,
    RuntimeEnrollment,
    creation_observation,
)
from jt_oz_bridge.storage.durable import digest
from tests.integration.test_runtime_enrollment import enrolled  # noqa: F401  (fixture)

TOOL = Path(__file__).resolve().parents[2] / "ops" / "server" / "certify_creation.py"
_spec = importlib.util.spec_from_file_location("certify_creation", TOOL)
assert _spec is not None and _spec.loader is not None
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

OUT = Path("/etc/jtoz-certify-test/creation-unit")
REF = {
    "backend_id": "server",
    "backend_identity": "server-installed",
    "project_id": "synthetic-project",
    "canonical_directory": "/home/opencode/workspaces/synthetic",
    "upstream_session_id": "ses_synthetic_anchor",
}
EPOCH = "c" * 64
SID = "ses_jtoz_" + "e" * 32
RULES = [
    {"action": "bash", "resource": "*", "effect": "ask"},
    {"action": "*", "resource": "*", "effect": "deny"},
]


def source_policy(ref=REF, operations=("prompt", "permission.reply", "session.rename")):
    return NativePolicyEnrollment.model_validate(
        {
            "format": "native-project-policy-v1",
            "reference": ref,
            "native_project_id": "global",
            "contract_sha256": INSTALLED_SCHEMA,
            "permission_source_sha256": PERMISSION_SOURCE,
            "fingerprint_sha256": "b" * 64,
            "operations": list(operations),
        }
    )


def owner_evidence(**changes):
    value = {
        "owner_epoch": EPOCH,
        "pid": 243,
        "process_start_ticks": 48236,
        "boot_id": "00000000-0000-4000-8000-000000000001",
        "executable_sha256": "d" * 64,
        "version": "2.0.32",
    }
    return value | changes


def scenario(source=None, *, owner=None, **worker_changes):
    source = source or source_policy()
    template = tool.build_template(source, agent_id="build", permissions=RULES)
    operator = tool.operator_source(
        tag="unit", intent_id="a" * 32, template_sha256=template.checksum()
    )
    intent = tool.build_intent(
        template,
        intent_id="a" * 32,
        native_session_id=SID,
        owner_epoch=EPOCH,
        source_sha256=digest(operator),
        title=tool.DEFAULT_TITLE,
    )
    body = tool.creation_body(template, intent)
    info = {
        **copy.deepcopy(body),
        "projectID": "global",
        "cost": 0,
        "tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        "time": {"created": 1, "updated": 1},
    }
    worker = {
        "operator_source": operator,
        "body": body,
        "post_attempts": 1,
        "create_status": 200,
        "create_info": info,
        "readbacks": [copy.deepcopy(info), copy.deepcopy(info)],
        "check_info_errors": [],
        "owner_before": owner_evidence(),
        "owner_after": owner_evidence(),
        "observed_at": 1.5,
    } | worker_changes
    anchor = SimpleNamespace(
        reference=source.reference, schema_file=SimpleNamespace(sha256=INSTALLED_SCHEMA)
    )
    owner = owner or SimpleNamespace(executable_sha256="d" * 64, version="2.0.32")
    return SimpleNamespace(
        template=template, intent=intent, worker=worker, anchor=anchor, owner=owner, info=info
    )


def assemble(s, manifest=None):
    return tool.assemble(
        anchor=s.anchor,
        owner_enrollment=s.owner,
        template=s.template,
        intent=s.intent,
        directory=OUT,
        worker=s.worker,
        tool_sha256="f" * 64,
        manifest=manifest,
    )


def repin(s, encoded):
    """Rebuild the certificate over (possibly forged) records, as a forger would."""
    encoded = dict(encoded)
    encoded["certificate"] = tool.dumps(
        tool.build_certificate(
            anchor=s.anchor,
            owner_enrollment=s.owner,
            template=s.template,
            owner_epoch=EPOCH,
            directory=OUT,
            encoded=encoded,
        )
    )
    return encoded


def test_produced_records_pass_creation_observation_and_certificate_model():
    s = scenario()
    encoded, failures = assemble(s)
    assert failures == [] and set(encoded) == set(tool.FILES)
    rpc = CreationRPCQualification.model_validate_json(encoded["certificate"])
    assert rpc.owner_epoch == EPOCH and rpc.operations == {"session.create", "session.get"}
    assert rpc.policy_template_sha256 == s.template.checksum()
    for name, pin in (
        ("observation", rpc.observation),
        ("request", rpc.request_record),
        ("response", rpc.response_record),
    ):
        assert pin.path == OUT / tool.FILES[name]
        assert pin.sha256 == tool.sha(encoded[name])
    files = {OUT / tool.FILES[name]: raw for name, raw in encoded.items()}
    with tool.memory_root_files(files):
        creation_observation(rpc, s.template)
    observation = json.loads(encoded["observation"])
    assert observation["passed"] is True and observation["human_acceptance"] is False
    assert observation["normal_creation_workflow_qualified"] is False
    assert observation["native_post_attempts"] == 1 and observation["create_http_status"] == 200
    request = json.loads(encoded["request"])
    assert request["intent"]["operator_not_human"] is True
    assert request["intent"]["requested_session_id"] == SID
    metadata = request["body"]["metadata"]["jt_oz_bridge"]
    assert metadata["intent_sha256"] == digest(s.intent.model_dump(mode="json"))
    assert request["intent"]["session_creation_intent_sha256"] == metadata["intent_sha256"]


def test_template_is_stable_exact_anchor_source_and_admin_ruleset():
    source = source_policy()
    template = tool.build_template(source, agent_id="build", permissions=RULES)
    again = tool.build_template(
        source,
        agent_id="build",
        permissions=RULES,
        operations=["session.rename", "prompt", "permission.reply"],
    )
    assert template.source == source and template.checksum() == again.checksum()
    assert "upstream_session_id" not in template.creation.scope.model_dump()
    assert [r.model_dump() for r in template.creation.permissions] == RULES  # order kept
    raw = tool.dumps(tool.template_document(template))
    assert raw == tool.dumps(tool.template_document(again))
    subset = tool.build_template(source, agent_id="build", permissions=RULES, operations=["prompt"])
    assert subset.operations == {"prompt"} and subset.checksum() != template.checksum()


@pytest.mark.parametrize(
    "permissions, operations",
    [
        ([], None),
        (None, None),
        ([{"action": "*", "resource": "*"}], None),
        ([{"action": "*", "resource": "*", "effect": "maybe"}], None),
        ([{"action": "*", "resource": "*", "effect": "deny", "extra": 1}], None),
        (RULES, ["worktree.create"]),
        (RULES, []),
    ],
)
def test_template_rejects_empty_malformed_or_widened_input(permissions, operations):
    with pytest.raises(ValueError):
        tool.build_template(
            source_policy(), agent_id="build", permissions=permissions, operations=operations
        )


def test_live_agent_requires_two_identical_reads_equal_to_pinned_fingerprint():
    facts = {"agent": {"id": "build", "mode": "primary", "permissions": []}, "mcp": []}
    source = source_policy().model_copy(update={"fingerprint_sha256": digest(facts)})
    assert tool.live_agent(facts, copy.deepcopy(facts), source) == "build"
    changed = copy.deepcopy(facts) | {"mcp": [{"name": "pve"}]}
    with pytest.raises(ValueError, match="unstable"):
        tool.live_agent(facts, changed, source)
    with pytest.raises(ValueError, match="drifted"):
        tool.live_agent(changed, copy.deepcopy(changed), source)


@pytest.mark.parametrize(
    "change, failure",
    [
        ({"post_attempts": 2}, "native_post_attempts"),
        ({"post_attempts": 0}, "native_post_attempts"),
        ({"post_attempts": True}, "native_post_attempts"),
        ({"create_status": 201}, "create_http_status"),
        ({"create_status": None}, "create_http_status"),
        ({"owner_after": owner_evidence(owner_epoch="9" * 64)}, "owner_unchanged"),
        ({"owner_after": owner_evidence(pid=244)}, "owner_unchanged"),
        ({"owner_before": owner_evidence(owner_epoch="9" * 64)}, "owner_unchanged"),
        ({"owner_after": None}, "owner_unchanged"),
        ({"check_info_errors": ["new_root_creation_or_readback_scope_changed"]}, "rpc_shape"),
        ({"create_info": None}, "returned_session_id"),
        ({"readbacks": []}, "stable_double_get"),
        ({"error": "TransportError:upstream_outcome_requires_reconciliation"}, "worker_error"),
    ],
)
def test_wrong_count_status_owner_or_shape_never_yields_a_certificate(change, failure):
    s = scenario(**change)
    encoded, failures = assemble(s)
    assert any(f.startswith(failure) for f in failures), failures
    assert "certificate" not in encoded
    observation = json.loads(encoded["observation"])
    assert observation["passed"] is False and observation["failures"] == failures


def test_native_choosing_another_id_or_unstable_readback_is_rejected():
    s = scenario()
    other = {**s.info, "id": "ses_" + "1" * 26}
    for change in (
        {"create_info": other},
        {"readbacks": [s.info, other]},
        {"readbacks": [s.info, {**s.info, "time": {"created": 1, "updated": 2}}]},
        {"readbacks": [{**s.info, "model": {"id": "m"}}, {**s.info, "model": {"id": "m"}}]},
    ):
        bad = scenario(**change)
        if "model" in str(change):
            # Pure checks cannot see `model`; the worker's check_info reports it.
            bad.worker["check_info_errors"] = ["new_root_creation_or_readback_scope_changed"]
        encoded, failures = assemble(bad)
        assert failures and "certificate" not in encoded


@pytest.mark.parametrize("bad", ["ses_" + "e" * 32, "ses_jtoz_" + "E" * 32, "ses_jtoz_short"])
def test_non_bridge_session_id_is_rejected_before_any_request(bad):
    s = scenario()
    with pytest.raises(ValueError):
        tool.build_intent(
            s.template,
            intent_id="a" * 32,
            native_session_id=bad,
            owner_epoch=EPOCH,
            source_sha256="0" * 64,
            title=None,
        )


@pytest.mark.parametrize(
    "document, mutate",
    [
        ("observation", lambda d: d.update(native_post_attempts=2)),
        ("observation", lambda d: d.update(create_http_status=201)),
        ("observation", lambda d: d.update(owner_unchanged=False)),
        ("observation", lambda d: d.update(human_acceptance=True)),
        ("request", lambda d: d["body"].update(id="ses_" + "e" * 37)),
        ("request", lambda d: d["intent"].update(owner_epoch="9" * 64)),
        ("response", lambda d: d["data"].update(id="ses_jtoz_" + "1" * 32)),
    ],
)
def test_forged_records_fail_the_runtime_validator(document, mutate):
    s = scenario()
    encoded, failures = assemble(s)
    assert not failures
    value = json.loads(encoded[document])
    mutate(value)
    forged = repin(s, encoded | {document: tool.dumps(value)})
    with pytest.raises(ValueError):
        tool.validate_in_memory(OUT, forged)


def creation_manifest(enrolled):  # noqa: F811
    manifest = enrolled.manifest
    manifest["format"] = "qualified-consumer-runtime-v2"
    manifest["backends"][0]["protocol_scope"] = "backend"
    enrolled.save()
    anchor = RuntimeEnrollment.model_validate(manifest).backends[0]
    source = NativePolicyEnrollment.model_validate_json(
        enrolled.documents[Path(manifest["backends"][0]["policy"]["path"])]
    )
    owner = HostOwnerEnrollment.model_validate_json(
        enrolled.documents[Path(manifest["backends"][0]["owner"]["path"])]
    )
    return manifest, anchor, source, owner


def test_candidate_manifest_passes_runtime_creation_pins(enrolled):  # noqa: F811
    manifest, anchor, source, owner = creation_manifest(enrolled)
    assert "session.create" not in anchor.verified_operations
    s = scenario(source, owner=owner)
    s.anchor = anchor
    encoded, failures = assemble(s, manifest=manifest)
    assert failures == [] and "certificate" in encoded
    entry = tool.manifest_entry(anchor, OUT, encoded)
    merged = tool.candidate_manifest(manifest, entry)
    assert {"session.create", "session.get"} <= set(merged["backends"][0]["verified_operations"])
    assert merged["creation_projects"] == [entry] and "creation_projects" not in manifest
    with pytest.raises(ValueError, match="already_present"):
        tool.candidate_manifest(merged, entry)


def test_candidate_manifest_rejects_foreign_executable(enrolled):  # noqa: F811
    manifest, anchor, source, owner = creation_manifest(enrolled)
    s = scenario(source, owner=SimpleNamespace(executable_sha256="0" * 64, version="2.0.32"))
    s.anchor = anchor
    encoded, failures = assemble(s, manifest=manifest)
    assert failures and failures[0].startswith("runtime_validation")
    assert "certificate" not in encoded


def test_select_anchor_is_explicit_and_backend_scoped():
    backend = SimpleNamespace(reference=SimpleNamespace(**REF), protocol_scope="backend")
    session = SimpleNamespace(
        reference=SimpleNamespace(**REF | {"project_id": "p2", "upstream_session_id": "ses_2"}),
        protocol_scope="session",
    )
    enrollment = SimpleNamespace(backends=(backend, session))
    assert tool.select_anchor(enrollment, project_id=REF["project_id"]) is backend
    assert tool.select_anchor(enrollment, session_id=REF["upstream_session_id"]) is backend
    for kwargs in (
        {},
        {"project_id": "p2"},
        {"project_id": "x"},
        {"project_id": "p2", "session_id": "s"},
    ):
        with pytest.raises(ValueError):
            tool.select_anchor(enrollment, **kwargs)


def test_certify_refuses_without_explicit_flag_before_any_io(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("worker launched"))
    monkeypatch.setattr(tool.os, "geteuid", lambda: pytest.fail("checked root before flag"))
    missing = str(tmp_path / "absent-spec.json")
    with pytest.raises(ValueError, match="explicit_permanent_session_flag_required"):
        tool.main(["certify", "--spec", missing, "--template-sha256", "0" * 64])
    with pytest.raises(ValueError, match="template_sha256_from_plan_required"):
        tool.main(["certify", "--spec", missing, tool.PERMANENT_FLAG])
    with pytest.raises(ValueError, match="explicit_permanent_session_flag_required"):
        tool.main(["worker", "--job", json.dumps({"mode": "certify"})])
    with pytest.raises(ValueError, match="explicit_permanent_session_flag_required"):
        tool.cmd_certify(SimpleNamespace(), "0" * 64, False)
    with pytest.raises(ValueError, match="plan_takes_no_permanent_session_flag"):
        spec = tmp_path / "spec.json"
        spec.write_text(json.dumps({"tag": "unit", "project_id": "p", "permissions": RULES}))
        tool.main(["plan", "--spec", str(spec), tool.PERMANENT_FLAG])


async def test_wire_allows_one_session_create_only_in_certify_mode():
    def request(method, path):
        return SimpleNamespace(method=method, url=SimpleNamespace(path=path))

    plan = tool.Wire(allow_create=False)
    await plan.request(request("GET", "/api/session/ses_x"))
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await plan.request(request("POST", "/api/session"))
    assert plan.post_attempts == 0
    certify = tool.Wire(allow_create=True)
    with pytest.raises(ValueError, match="unexpected_native_mutation"):
        await certify.request(request("POST", "/api/session/ses_x/prompt"))
    await certify.request(request("POST", "/api/session"))
    with pytest.raises(ValueError, match="second_native_post"):
        await certify.request(request("POST", "/api/session"))
    await certify.response(
        SimpleNamespace(request=request("POST", "/api/session"), status_code=200)
    )
    assert certify.create_status == 200 and certify.statuses == [["POST", "/api/session", 200]]


class FakeNative:
    """Mock Native for the worker path; httpx.MockTransport, never a socket."""

    def __init__(self, ref, *, echo_model=False, returned_id=None):
        self.ref, self.echo_model, self.returned_id = ref, echo_model, returned_id
        self.created = None
        self.posts = []
        location = {"directory": ref["canonical_directory"]}
        self.routes = {
            "/api/agent/build": {
                "location": location,
                "data": {
                    "id": "build",
                    "name": "Build",
                    "request": {"settings": {}, "headers": {}, "body": {}},
                    "mode": "primary",
                    "hidden": False,
                    "permissions": [{"action": "*", "resource": "*", "effect": "allow"}],
                },
            },
            "/api/plugin": {"location": location, "data": []},
            "/api/permission/saved": {"data": []},
            "/api/mcp": {"location": location, "data": []},
        }
        self.anchor = self.info(
            ref["upstream_session_id"],
            agent="build",
            permissions=[{"action": "*", "resource": "*", "effect": "deny"}],
        )

    def info(self, sid, **extra):
        return {
            "id": sid,
            "projectID": "global",
            "cost": 0,
            "tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}},
            "time": {"created": 1, "updated": 1},
            "location": {"directory": self.ref["canonical_directory"]},
            **extra,
        }

    def fingerprint(self):
        from jt_oz_bridge.adapters.opencode.project_policy import _policy_facts
        from jt_oz_bridge.domain.models import SessionRef

        r = self.routes
        return digest(
            _policy_facts(
                SessionRef.model_validate(self.ref),
                "global",
                self.anchor,
                r["/api/agent/build"],
                r["/api/plugin"],
                r["/api/permission/saved"],
                r["/api/mcp"],
            )
        )

    def __call__(self, request):
        import httpx

        path = request.url.path
        if request.method == "POST" and path == "/api/session":
            body = json.loads(request.content)
            self.posts.append(body)
            self.created = self.info(body["id"]) | body
            if self.returned_id is not None:  # Native ignoring the client-chosen id
                self.created["id"] = self.returned_id
            if self.echo_model:
                self.created["model"] = {"providerID": "example-provider", "id": "example-model-1"}
            return httpx.Response(200, json={"data": self.created})
        assert request.method == "GET", request
        if path == "/api/session/" + self.ref["upstream_session_id"]:
            return httpx.Response(200, json={"data": self.anchor})
        if self.created is not None and path == "/api/session/" + self.created["id"]:
            return httpx.Response(200, json={"data": self.created})
        if path in self.routes:
            return httpx.Response(200, json=copy.deepcopy(self.routes[path]))
        return httpx.Response(404, json={"_tag": "NotFound"})


def worker_setup(enrolled, monkeypatch, **native):  # noqa: F811
    import time as clock

    import httpx

    import jt_oz_bridge.adapters.opencode.host_owner as host_owner
    import jt_oz_bridge.adapters.opencode.transport as transport_module
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence
    from tests.contract.test_host_owner import evidence

    manifest, _, source, owner = creation_manifest(enrolled)
    fake = FakeNative(enrolled.ref, **native)
    policy = source.model_dump(mode="json") | {"fingerprint_sha256": fake.fingerprint()}
    manifest["backends"][0]["policy"] = enrolled.pin("policy-live.json", policy)
    enrolled.save()
    epochs = [evidence(backend_id=owner.backend_id, backend_identity=owner.backend_identity)]

    class Owner:
        def __init__(self, enrollment, socket_path):
            self.enrollment = enrollment

        async def read(self):
            return HostOwnerEvidence.model_validate(epochs[-1] | {"observed_at": clock.time()})

    class Transport(transport_module.V2HTTPTransport):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, transport=httpx.MockTransport(fake), **kwargs)

    monkeypatch.setattr(host_owner, "LinuxHostOwnerProbe", Owner)
    monkeypatch.setattr(transport_module, "V2HTTPTransport", Transport)
    monkeypatch.setattr(tool.os, "getuid", lambda: owner.client_uid)
    job = {
        "mode": "plan",
        "tag": "unit",
        "config": "/unused",
        "project_id": enrolled.ref["project_id"],
        "anchor_session_id": None,
        "permissions": RULES,
        "operations": None,
        "title": tool.DEFAULT_TITLE,
    }
    monkeypatch.setattr("jt_oz_bridge.config.load_settings", lambda _: enrolled.settings)
    return SimpleNamespace(fake=fake, job=job, manifest=manifest, owner=owner, epochs=epochs)


async def test_worker_plan_reads_only_and_certify_posts_once_with_valid_evidence(
    enrolled,  # noqa: F811
    monkeypatch,
):
    w = worker_setup(enrolled, monkeypatch)
    planned = await tool.worker_main(w.job, {})
    assert planned["error"] is None and planned["stage"] == "planned"
    assert planned["post_attempts"] == 0 and not w.fake.posts
    job = w.job | {
        "mode": "certify",
        "confirmed_permanent_session": True,
        "intent_id": "a" * 32,
        "native_session_id": SID,
        "expected_template_sha256": planned["template_sha256"],
    }
    result = await tool.worker_main(job, {})
    assert result["error"] is None and result["stage"] == "observed", result["error"]
    assert result["posted"] is True and len(w.fake.posts) == 1 and result["post_attempts"] == 1
    assert result["create_status"] == 200 and len(result["readbacks"]) == 2
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate
    from jt_oz_bridge.domain.session_creation import SessionCreationIntent

    s = SimpleNamespace(
        anchor=RuntimeEnrollment.model_validate(w.manifest).backends[0],
        owner=w.owner,
        template=CreationPolicyTemplate.model_validate(result["template"]),
        intent=SessionCreationIntent.model_validate(result["intent"]),
        worker=result,
    )
    encoded, failures = assemble(s, manifest=w.manifest)
    assert failures == [] and "certificate" in encoded


@pytest.mark.parametrize("native", [{"echo_model": True}, {"returned_id": "ses_" + "9" * 26}])
async def test_worker_post_then_unexpected_native_shape_is_reported_not_retried(
    enrolled,  # noqa: F811
    monkeypatch,
    native,
):
    w = worker_setup(enrolled, monkeypatch, **native)
    planned = await tool.worker_main(w.job, {})
    job = w.job | {
        "mode": "certify",
        "confirmed_permanent_session": True,
        "intent_id": "a" * 32,
        "native_session_id": SID,
        "expected_template_sha256": planned["template_sha256"],
    }
    result = await tool.worker_main(job, {})
    assert "new_root_creation_or_readback_scope_changed" in result["error"]
    assert result["posted"] is True and len(w.fake.posts) == 1 and result["post_attempts"] == 1
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate
    from jt_oz_bridge.domain.session_creation import SessionCreationIntent

    s = SimpleNamespace(
        anchor=RuntimeEnrollment.model_validate(w.manifest).backends[0],
        owner=w.owner,
        template=CreationPolicyTemplate.model_validate(result["template"]),
        intent=SessionCreationIntent.model_validate(result["intent"]),
        worker=result,
    )
    encoded, failures = assemble(s, manifest=w.manifest)
    assert "worker_error" in failures and "certificate" not in encoded
    assert json.loads(encoded["observation"])["passed"] is False


async def test_worker_refuses_template_drift_before_any_post(enrolled, monkeypatch):  # noqa: F811
    w = worker_setup(enrolled, monkeypatch)
    job = w.job | {
        "mode": "certify",
        "confirmed_permanent_session": True,
        "intent_id": "a" * 32,
        "native_session_id": SID,
        "expected_template_sha256": "0" * 64,
    }
    result = await tool.worker_main(job, {})
    assert "template_changed_since_plan" in result["error"] and result["posted"] is False
    assert not w.fake.posts and result["post_attempts"] == 0
