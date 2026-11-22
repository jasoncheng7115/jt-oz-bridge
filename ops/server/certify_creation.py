"""Issue the per-project pins that let the Bridge create new OpenCode Roots.

Production `!oz new` needs, per project, two root-owned files referenced from the
runtime manifest's ``creation_projects`` entry: a ``native-root-creation-policy-v1``
template and an ``installed-root-creation-rpc-v1`` operator certificate that pins
one real ``session.create`` transcript. This tool produces both for ONE enrolled
anchor Root, using the installed release's own adapters.

Run with the selected release's interpreter, as root:

    python -I -B certify_creation.py plan    --spec spec.json [--stage-template PATH]
    python -I -B certify_creation.py certify --spec spec.json --template-sha256 HEX \\
        --i-understand-this-creates-a-permanent-native-session

``plan`` (the default) is read-only: GET requests only, no Native POST, nothing
written except an optional staged template. ``certify`` sends exactly one
``session.create``; the created Native session is permanent and is never
retried, deleted or reused. Native access runs in a transient unit as the
enrolled Bridge client UID; root only reads pins and writes the outputs. The
Native database is never opened and Native is never restarted. The evidence is
operator RPC evidence, never Human acceptance.

spec.json::

    {
      "tag": "mcp-create01",
      "project_id": "example-project",          # or "anchor_session_id": "ses_..."
      "permissions": [{"action": "*", "resource": "*", "effect": "ask"}],
      "operations": ["prompt", "permission.reply"],   # optional, default all
      "title": "jt-oz-bridge creation qualification", # optional
      "config": "/etc/jt-oz-bridge/config.toml",      # optional
      "output": "/etc/jt-oz-bridge/creation-<tag>"    # optional, must not exist
    }
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

PERMANENT_FLAG = "--i-understand-this-creates-a-permanent-native-session"
WORKER_SECONDS = 150
DEFAULT_TITLE = "jt-oz-bridge creation qualification"
CREATION_OPERATIONS = ("session.create", "session.get")
SOURCE_FORMAT = "jt-oz-bridge-operator-creation-certification-v1"
OBSERVATION_FORMAT = "installed-root-creation-rpc-observation-v1"
FILES = {
    "template": "creation-policy.json",
    "request": "create-request.json",
    "response": "create-response.json",
    "observation": "create-observation.json",
    "certificate": "creation-rpc.json",
}
SESSION_ID = re.compile(r"^ses_jtoz_[0-9a-f]{32}$")


class CertifyError(ValueError):
    pass


def need(condition: object, code: str) -> None:
    if not condition:
        raise CertifyError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dumps(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


# --------------------------------------------------------------------------
# Pure functions: no file, socket or network I/O. The unit test drives these.
# --------------------------------------------------------------------------


def parse_permissions(value: object) -> list[dict[str, str]]:
    """Administrator ruleset; order is significant and kept exactly."""
    from jt_oz_bridge.domain.session_creation import NativePermissionRule

    need(isinstance(value, list) and 0 < len(value) <= 1000, "permissions_nonempty_list_required")
    assert isinstance(value, list)
    rules = []
    for item in value:
        need(
            isinstance(item, dict) and set(item) == {"action", "resource", "effect"},
            "permission_rule_requires_action_resource_effect",
        )
        rules.append(NativePermissionRule.model_validate(item).model_dump(mode="json"))
    return rules


def select_anchor(
    enrollment: Any, *, project_id: str | None = None, session_id: str | None = None
) -> Any:
    """One enrolled backend-scoped Root, chosen by project or anchor session id."""
    need((project_id is None) != (session_id is None), "exactly_one_anchor_selector_required")
    matches = [
        q
        for q in enrollment.backends
        if (project_id is not None and q.reference.project_id == project_id)
        or (session_id is not None and q.reference.upstream_session_id == session_id)
    ]
    need(len(matches) == 1, f"anchor_not_uniquely_enrolled:{len(matches)}")
    anchor = matches[0]
    need(anchor.protocol_scope == "backend", "anchor_must_be_backend_scoped")
    return anchor


def live_agent(first: dict[str, Any], second: dict[str, Any], source: Any) -> str:
    """Two live policy-fact reads must both equal the anchor's pinned fingerprint."""
    from jt_oz_bridge.storage.durable import digest

    need(digest(first) == digest(second), "anchor_policy_facts_unstable")
    need(
        digest(first) == source.fingerprint_sha256, "anchor_policy_drifted_from_pinned_fingerprint"
    )
    agent = first.get("agent", {}).get("id")
    need(isinstance(agent, str) and agent, "anchor_live_agent_missing")
    assert isinstance(agent, str)
    return agent


def build_template(
    source: Any,
    *,
    agent_id: str,
    permissions: list[dict[str, str]],
    operations: list[str] | None = None,
) -> Any:
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate

    selected = sorted(source.operations) if operations is None else sorted(set(operations))
    need(selected, "creation_operations_required")
    need(set(selected) <= source.operations, "creation_operations_must_subset_anchor_policy")
    return CreationPolicyTemplate.model_validate(
        {
            "format": "native-root-creation-policy-v1",
            "source": source.model_dump(mode="json"),
            "creation": {
                "scope": source.reference.model_dump(mode="json", exclude={"upstream_session_id"}),
                "native_project_id": source.native_project_id,
                "agent_id": agent_id,
                "permissions": parse_permissions(permissions),
            },
            "operations": selected,
        }
    )


def template_document(template: Any) -> dict[str, Any]:
    """Stable JSON; frozenset order otherwise differs between processes."""
    value: dict[str, Any] = template.model_dump(mode="json")
    value["operations"] = sorted(template.operations)
    value["source"]["operations"] = sorted(template.source.operations)
    return value


def operator_source(*, tag: str, intent_id: str, template_sha256: str) -> dict[str, Any]:
    """Stands in for the Zulip message an ordinary creation would digest."""
    return {
        "format": SOURCE_FORMAT,
        "tag": tag,
        "intent_id": intent_id,
        "policy_template_sha256": template_sha256,
        "operator_not_human": True,
    }


def build_intent(
    template: Any,
    *,
    intent_id: str,
    native_session_id: str,
    owner_epoch: str,
    source_sha256: str,
    title: str | None,
) -> Any:
    from jt_oz_bridge.domain.session_creation import SessionCreationIntent

    need(SESSION_ID.fullmatch(native_session_id), "bridge_owned_session_id_required")
    return SessionCreationIntent(
        intent_id=intent_id,
        scope=template.creation.scope,
        native_session_id=native_session_id,
        source_sha256=source_sha256,
        owner_epoch=owner_epoch,
        title=title,
    )


def creation_body(template: Any, intent: Any) -> dict[str, Any]:
    """Mirror of V2SessionCreation.body; the worker asserts equality before POST."""
    from jt_oz_bridge.storage.durable import digest

    body: dict[str, Any] = {
        "id": intent.native_session_id,
        "location": {"directory": intent.scope.canonical_directory},
        "agent": template.creation.agent_id,
        "permissions": [rule.model_dump() for rule in template.creation.permissions],
        "metadata": {
            "jt_oz_bridge": {
                "creation_id": intent.intent_id,
                "intent_sha256": digest(intent.model_dump(mode="json")),
            }
        },
    }
    if intent.title is not None:
        body["title"] = intent.title
    return body


def _info_matches(raw: object, body: dict[str, Any], native_project_id: str) -> bool:
    return (
        isinstance(raw, dict)
        and raw.get("projectID") == native_project_id
        and all(raw.get(key) == value for key, value in body.items())
        and "parentID" not in raw
        and "fork" not in raw
    )


def build_records(
    *,
    template: Any,
    intent: Any,
    source: dict[str, Any],
    body: dict[str, Any],
    post_attempts: int,
    create_status: int | None,
    create_info: dict[str, Any] | None,
    readbacks: list[dict[str, Any] | None],
    check_info_errors: list[str],
    owner_before: dict[str, Any] | None,
    owner_after: dict[str, Any] | None,
    tool_sha256: str,
    observed_at: float,
    worker_error: str | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Request/response/observation documents plus the list of failed checks.

    Every claim in the observation is computed here from raw values; a failed
    check is recorded as false (never omitted) so the files stay honest.
    """
    from jt_oz_bridge.storage.durable import digest

    sid = intent.native_session_id
    scope = template.creation.scope
    failures: list[str] = []
    if worker_error is not None:
        failures.append("worker_error")
    if body != creation_body(template, intent) or not SESSION_ID.fullmatch(str(body.get("id"))):
        failures.append("request_body_changed")
    if type(post_attempts) is not int or post_attempts != 1:
        failures.append("native_post_attempts")
    if type(create_status) is not int or create_status != 200:
        failures.append("create_http_status")
    returned = create_info.get("id") if isinstance(create_info, dict) else None
    if returned != sid:
        failures.append("returned_session_id")
    complete = len(readbacks) == 2 and all(isinstance(r, dict) for r in readbacks)
    stable = complete and digest(readbacks[0] or {}) == digest(readbacks[1] or {})
    if not stable:
        failures.append("stable_double_get")
    created = readbacks[-1].get("id") if complete and readbacks[-1] is not None else None
    if created != sid:
        failures.append("created_session_id")
    shape = (
        not check_info_errors
        and _info_matches(create_info, body, template.creation.native_project_id)
        and complete
        and all(_info_matches(r, body, template.creation.native_project_id) for r in readbacks)
    )
    if not shape:
        failures.append("rpc_shape_and_readback")
    owner_unchanged = (
        isinstance(owner_before, dict)
        and isinstance(owner_after, dict)
        and owner_before.get("owner_epoch") == owner_after.get("owner_epoch") == intent.owner_epoch
        and all(
            owner_before.get(key) == owner_after.get(key)
            for key in ("pid", "process_start_ticks", "boot_id", "executable_sha256")
        )
    )
    if not owner_unchanged:
        failures.append("owner_unchanged")
    intent_record = {
        "operator_not_human": True,
        "reference_scope": scope.model_dump(mode="json"),
        "native_project_id": template.creation.native_project_id,
        "owner_epoch": intent.owner_epoch,
        "source_policy_sha256": template.source.fingerprint_sha256,
        "requested_session_id": sid,
        "policy_template_sha256": template.checksum(),
        "session_creation_intent": intent.model_dump(mode="json"),
        "session_creation_intent_sha256": digest(intent.model_dump(mode="json")),
        "operator_source": source,
    }
    request = {
        "body": body,
        "intent": intent_record,
        "body_sha256": digest(body),
        "intent_sha256": digest(intent_record),
    }
    response = {"data": create_info, "readbacks": readbacks}
    observation = {
        "format": OBSERVATION_FORMAT,
        "passed": not failures,
        "rpc_shape_and_readback_verified": shape,
        "stable_double_get": stable,
        "owner_unchanged": owner_unchanged,
        "native_post_attempts": post_attempts,
        "create_http_status": create_status,
        "human_acceptance": False,
        "normal_creation_workflow_qualified": False,
        "request_body_sha256": digest(body),
        "requested_session_id": sid,
        "returned_session_id": returned,
        "created_session_id": created,
        "create_response_sha256": digest(create_info) if isinstance(create_info, dict) else None,
        "readback_sha256": [digest(r) if isinstance(r, dict) else None for r in readbacks],
        "check_info_errors": check_info_errors,
        "failures": failures,
        "worker_error": worker_error,
        "owner_before": owner_before,
        "owner_after": owner_after,
        "policy_template_sha256": template.checksum(),
        "certify_tool_sha256": tool_sha256,
        "native_database_bytes_read": False,
        "native_restart": False,
        "observed_at": observed_at,
    }
    return {"request": request, "response": response, "observation": observation}, failures


def root_file(directory: Path, name: str, raw: bytes) -> dict[str, str]:
    return {"path": str(directory / name), "sha256": sha(raw)}


def build_certificate(
    *,
    anchor: Any,
    owner_enrollment: Any,
    template: Any,
    owner_epoch: str,
    directory: Path,
    encoded: Mapping[str, bytes],
) -> dict[str, Any]:
    return {
        "format": "installed-root-creation-rpc-v1",
        "passed": True,
        "evidence_scope": "operator-rpc-only-not-human-acceptance",
        "reference": anchor.reference.model_dump(mode="json"),
        "contract_sha256": anchor.schema_file.sha256,
        "executable_sha256": owner_enrollment.executable_sha256,
        "upstream_version": owner_enrollment.version,
        "owner_epoch": owner_epoch,
        "policy_template_sha256": template.checksum(),
        "operations": sorted(CREATION_OPERATIONS),
        "observation": root_file(directory, FILES["observation"], encoded["observation"]),
        "request_record": root_file(directory, FILES["request"], encoded["request"]),
        "response_record": root_file(directory, FILES["response"], encoded["response"]),
    }


def manifest_entry(anchor: Any, directory: Path, encoded: Mapping[str, bytes]) -> dict[str, Any]:
    return {
        "anchor": anchor.reference.model_dump(mode="json"),
        "policy_template": root_file(directory, FILES["template"], encoded["template"]),
        "rpc_evidence": root_file(directory, FILES["certificate"], encoded["certificate"]),
    }


def candidate_manifest(manifest: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """Current manifest plus this entry, with the creation operations attested on
    every qualification of the anchor's backend (the runtime attests the group's
    first one). Other content is unchanged; nothing is written."""
    merged = copy.deepcopy(manifest)
    project = entry["anchor"]["project_id"]
    need(
        all(c["anchor"]["project_id"] != project for c in merged.get("creation_projects", [])),
        "creation_project_already_present_in_manifest",
    )
    merged["creation_projects"] = [*merged.get("creation_projects", []), entry]
    for backend in merged["backends"]:
        if backend["reference"]["backend_id"] == entry["anchor"]["backend_id"]:
            backend["verified_operations"] = sorted(
                set(backend["verified_operations"]) | set(CREATION_OPERATIONS)
            )
    return merged


@contextlib.contextmanager
def memory_root_files(files: Mapping[Path, bytes]) -> Iterator[None]:
    """Serve not-yet-written pins to the project's own validators; other paths
    still go through the real root-managed reader."""
    import jt_oz_bridge.security.root_files as root_files

    original = root_files.root_bytes

    def read(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
        if path in files:
            return files[path]
        return original(path, maximum=maximum)

    root_files.root_bytes = read
    try:
        yield
    finally:
        root_files.root_bytes = original


def validate_pins(
    template_raw: bytes, certificate_raw: bytes, *, manifest: dict[str, Any] | None = None
) -> tuple[Any, Any]:
    """The exact runtime checks: models, creation_observation and, given the
    current manifest, creation_pins on the candidate manifest."""
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.services.runtime_enrollment import (
        CreationRPCQualification,
        RuntimeEnrollment,
        creation_observation,
        creation_pins,
    )

    template = CreationPolicyTemplate.model_validate(strict_loads(template_raw))
    rpc = CreationRPCQualification.model_validate(strict_loads(certificate_raw))
    need(rpc.policy_template_sha256 == template.checksum(), "certificate_template_checksum")
    creation_observation(rpc, template)
    if manifest is not None:
        directory = rpc.observation.path.parent
        entry = {
            "anchor": rpc.reference.model_dump(mode="json"),
            "policy_template": root_file(directory, FILES["template"], template_raw),
            "rpc_evidence": root_file(directory, FILES["certificate"], certificate_raw),
        }
        enrollment = RuntimeEnrollment.model_validate(candidate_manifest(manifest, entry))
        projects = creation_pins(enrollment)
        need(rpc.reference.project_id in projects, "candidate_manifest_creation_pin_missing")
    return template, rpc


def validate_in_memory(
    directory: Path,
    encoded: Mapping[str, bytes],
    *,
    manifest: dict[str, Any] | None = None,
) -> tuple[Any, Any]:
    files = {directory / FILES[name]: raw for name, raw in encoded.items()}
    with memory_root_files(files):
        return validate_pins(encoded["template"], encoded["certificate"], manifest=manifest)


def assemble(
    *,
    anchor: Any,
    owner_enrollment: Any,
    template: Any,
    intent: Any,
    directory: Path,
    worker: dict[str, Any],
    tool_sha256: str,
    manifest: dict[str, Any] | None = None,
) -> tuple[dict[str, bytes], list[str]]:
    """Encode every evidence file; the certificate exists only if all checks and
    the in-memory runtime validation pass."""
    docs, failures = build_records(
        template=template,
        intent=intent,
        source=worker["operator_source"],
        body=worker["body"],
        post_attempts=worker["post_attempts"],
        create_status=worker["create_status"],
        create_info=worker["create_info"],
        readbacks=worker["readbacks"],
        check_info_errors=worker["check_info_errors"],
        owner_before=worker["owner_before"],
        owner_after=worker["owner_after"],
        tool_sha256=tool_sha256,
        observed_at=worker["observed_at"],
        worker_error=worker.get("error"),
    )
    encoded = {"template": dumps(template_document(template))}
    encoded.update({name: dumps(doc) for name, doc in docs.items()})
    if failures:
        return encoded, failures
    certificate = build_certificate(
        anchor=anchor,
        owner_enrollment=owner_enrollment,
        template=template,
        owner_epoch=intent.owner_epoch,
        directory=directory,
        encoded=encoded,
    )
    encoded["certificate"] = dumps(certificate)
    try:
        validate_in_memory(directory, encoded, manifest=manifest)
    except ValueError as error:  # pydantic ValidationError and CertifyError included
        encoded.pop("certificate")
        return encoded, [f"runtime_validation:{type(error).__name__}:{str(error)[:300]}"]
    return encoded, []


# --------------------------------------------------------------------------
# Native worker: runs as the enrolled Bridge client UID in a transient unit.
# --------------------------------------------------------------------------


class Wire:
    """Counts what actually reaches httpx; refuses anything but the allowed RPCs."""

    def __init__(self, allow_create: bool) -> None:
        self.allow_create = allow_create
        self.post_attempts = 0
        self.gets = 0
        self.create_status: int | None = None
        self.statuses: list[list[Any]] = []

    async def request(self, request: Any) -> None:
        if request.method == "GET":
            self.gets += 1
            need(self.gets <= 200, "bounded_native_gets")
            return
        need(
            self.allow_create and request.method == "POST" and request.url.path == "/api/session",
            "unexpected_native_mutation_refused",
        )
        self.post_attempts += 1
        need(self.post_attempts == 1, "second_native_post_refused")

    async def response(self, response: Any) -> None:
        request = response.request
        self.statuses.append([request.method, request.url.path, response.status_code])
        if request.method == "POST":
            self.create_status = response.status_code


async def worker_main(job: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Fills ``result`` in place so a timeout still reports what happened."""
    import httpx

    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
    from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, LinuxHostOwnerProbe
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from jt_oz_bridge.adapters.opencode.project_policy import (
        NativePolicyEnrollment,
        V2ProjectPolicyGuard,
    )
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.domain.execution import MutationNotSent
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.security.secrets import resolve_secret
    from jt_oz_bridge.services.runtime_enrollment import read_enrollment
    from jt_oz_bridge.storage.durable import digest

    certify = job["mode"] == "certify"
    if certify:
        need(job.get("confirmed_permanent_session") is True, "explicit_permanent_session_flag")
    settings = load_settings(Path(job["config"]))
    enrollment, _ = read_enrollment(settings)
    anchor = select_anchor(
        enrollment, project_id=job.get("project_id"), session_id=job.get("anchor_session_id")
    )
    ref = anchor.reference
    configured = next(b for b in settings.opencode_backends if b.id == ref.backend_id)
    owner_doc = HostOwnerEnrollment.model_validate(strict_loads(anchor.owner.read()))
    need(os.getuid() == owner_doc.client_uid, "enrolled_bridge_client_uid_required")
    owner = LinuxHostOwnerProbe(owner_doc, anchor.owner_socket)
    profile = OpenAPIProfile(anchor.schema_file.read())
    policy = NativePolicyEnrollment.model_validate(strict_loads(anchor.policy.read()))
    need(policy.reference == ref, "anchor_policy_reference")
    operations = frozenset(anchor.verified_operations)
    if certify:
        # This run is the operator RPC qualification itself; it attests the two
        # creation RPCs for this one process only and changes no pinned file.
        operations |= frozenset(CREATION_OPERATIONS)
    transport = V2HTTPTransport(
        configured.base_url,
        profile,
        auth=httpx.BasicAuth(
            "opencode", resolve_secret(configured.credential_ref).get_secret_value()
        ),
        attestation=ContractAttestation(
            profile.sha256, ref.backend_identity, owner_doc.version, operations
        ),
    )
    wire = Wire(allow_create=certify)
    transport.client.event_hooks["request"].append(wire.request)
    transport.client.event_hooks["response"].append(wire.response)
    # The feed is never started: the guard only needs its transport.
    feed = V2PublicFeed(transport, owner, (ref,), receipts=None, capture_text=False)
    projects = {
        ref.project_id: V2CatalogProject(
            ProjectScope(**ref.model_dump(exclude={"upstream_session_id"})),
            anchor.native_project_id,
        )
    }
    guard = V2ProjectPolicyGuard(V2LeafResourceProofs(feed, projects), {ref: policy})
    result.update(
        {
            "mode": job["mode"],
            "stage": "start",
            "error": None,
            "reference": ref.model_dump(mode="json"),
            "posted": False,
            "post_attempts": 0,
            "create_status": None,
            "create_info": None,
            "readbacks": [],
            "check_info_errors": [],
            "owner_before": None,
            "owner_after": None,
        }
    )
    native_request = transport.request
    try:
        result["owner_before"] = (await owner.read()).model_dump(mode="json")
        result["stage"] = "policy"
        first, _ = await guard._bundle_facts(ref)
        second, _ = await guard._bundle_facts(ref)
        agent = live_agent(first, second, policy)
        result["live"] = {
            "agent": first["agent"],
            "anchor_session_permissions": first["session_permissions"],
            "mcp": [m.get("name") for m in first["mcp"]],
            "plugins": len(first["plugins"]),
            "saved_permissions": len(first["saved_permissions"]),
            "policy_fingerprint_sha256": digest(first),
        }
        template = build_template(
            policy,
            agent_id=agent,
            permissions=job["permissions"],
            operations=job.get("operations"),
        )
        result["template"] = template_document(template)
        result["template_sha256"] = template.checksum()
        if not certify:
            result["owner_after"] = (await owner.read()).model_dump(mode="json")
            result["stage"] = "planned"
            return result
        need(template.checksum() == job["expected_template_sha256"], "template_changed_since_plan")
        epoch = result["owner_before"]["owner_epoch"]

        async def same_owner() -> bool:
            observed = await owner.read()
            return (
                observed.owner_epoch == epoch
                and observed.backend_identity == ref.backend_identity
                and observed.version == owner_doc.version
            )

        transport.verify_identity = same_owner
        creator = V2SessionCreation(transport, owner, {ref.project_id: template.creation})
        live_epoch = await creator.live_epoch(ref.project_id)
        need(live_epoch == epoch, "owner_changed_before_create")
        source = operator_source(
            tag=job["tag"], intent_id=job["intent_id"], template_sha256=template.checksum()
        )
        intent = build_intent(
            template,
            intent_id=job["intent_id"],
            native_session_id=job["native_session_id"],
            owner_epoch=live_epoch,
            source_sha256=digest(source),
            title=job.get("title"),
        )
        body = creator.body(intent)
        need(body == creation_body(template, intent), "tool_body_differs_from_adapter_body")
        result.update(
            operator_source=source, intent=intent.model_dump(mode="json"), body=copy.deepcopy(body)
        )

        async def capture(operation: str, **kwargs: Any) -> Any:
            value = await native_request(operation, **kwargs)
            if operation == "session.create" and isinstance(value, dict):
                result["create_info"] = copy.deepcopy(value.get("data"))
            return value

        transport.request = capture  # type: ignore[method-assign,assignment]

        def before_send() -> None:
            need(wire.post_attempts <= 1, "second_native_post_refused")

        result["stage"] = "create"
        try:
            await creator.create(intent, before_send=before_send)
        except MutationNotSent:
            result["posted"] = False  # the adapter proved nothing reached Native
            raise
        except BaseException:
            result["posted"] = wire.post_attempts > 0
            raise
        else:
            result["posted"] = True
        finally:
            transport.request = native_request  # type: ignore[method-assign]
        result["stage"] = "readback"
        for _ in range(2):
            raw = (
                await native_request("session.get", path={"sessionID": intent.native_session_id})
            )["data"]
            result["readbacks"].append(copy.deepcopy(raw))
            try:
                creator.check_info(intent, raw)
            except ValueError as error:
                result["check_info_errors"].append(str(error))
        result["owner_after"] = (await owner.read()).model_dump(mode="json")
        result["stage"] = "observed"
    except Exception as error:  # report everything; root decides what is written
        result["error"] = f"{type(error).__name__}:{error}"[:500]
        if certify and result["posted"] and len(result["readbacks"]) < 2:
            # The session may exist: record its state without ever re-POSTing.
            with contextlib.suppress(Exception):
                for _ in range(2 - len(result["readbacks"])):
                    raw = (
                        await native_request(
                            "session.get", path={"sessionID": job["native_session_id"]}
                        )
                    )["data"]
                    result["readbacks"].append(copy.deepcopy(raw))
        if result["owner_after"] is None:
            with contextlib.suppress(Exception):
                result["owner_after"] = (await owner.read()).model_dump(mode="json")
    finally:
        result["post_attempts"] = wire.post_attempts
        result["create_status"] = wire.create_status
        result["native_statuses"] = wire.statuses
        result["native_get_count"] = wire.gets
        result["observed_at"] = time.time()
        await transport.close()
    return result


def cmd_worker(job: dict[str, Any], confirmed: bool) -> None:
    need(job.get("mode") in {"plan", "certify"}, "worker_mode")
    if job["mode"] == "certify":
        need(confirmed, "explicit_permanent_session_flag_required")
        job["confirmed_permanent_session"] = True

    result: dict[str, Any] = {"mode": job["mode"], "posted": False, "post_attempts": 0}

    async def bounded() -> None:
        async with asyncio.timeout(WORKER_SECONDS - 20):
            await worker_main(job, result)

    try:
        asyncio.run(bounded())
    except BaseException as error:  # e.g. timeout: keep the partial transcript
        result["error"] = result.get("error") or f"{type(error).__name__}:{error}"[:500]
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, default=str))


# --------------------------------------------------------------------------
# Root wrapper: reads pins, launches the worker, writes root-owned outputs.
# --------------------------------------------------------------------------


class Spec:
    def __init__(self, path: Path) -> None:
        raw = json.loads(path.read_bytes())
        need(isinstance(raw, dict), "spec_object_required")
        self.tag: str = raw["tag"]
        need(re.fullmatch(r"[a-z0-9-]{1,40}", self.tag), "spec_tag")
        self.project_id: str | None = raw.get("project_id")
        self.anchor_session_id: str | None = raw.get("anchor_session_id")
        need(
            (self.project_id is None) != (self.anchor_session_id is None),
            "spec_requires_exactly_one_of_project_id_or_anchor_session_id",
        )
        self.permissions = parse_permissions(raw.get("permissions"))
        self.operations: list[str] | None = raw.get("operations")
        need(
            self.operations is None
            or isinstance(self.operations, list)
            and all(isinstance(x, str) for x in self.operations),
            "spec_operations_list",
        )
        self.title: str | None = raw.get("title", DEFAULT_TITLE)
        self.config = Path(raw.get("config", "/etc/jt-oz-bridge/config.toml"))
        self.output = Path(raw.get("output", f"/etc/jt-oz-bridge/creation-{self.tag}"))
        need(self.output.is_absolute() and ".." not in self.output.parts, "spec_output_absolute")

    def job(self, mode: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "tag": self.tag,
            "config": str(self.config),
            "project_id": self.project_id,
            "anchor_session_id": self.anchor_session_id,
            "permissions": self.permissions,
            "operations": self.operations,
            "title": self.title,
        }


def root_ancestry(path: Path) -> None:
    """Every existing ancestor root-owned and not group/other writable."""
    for directory in reversed(path.parents):
        info = directory.lstat()
        need(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            f"root_managed_ancestry_required:{directory}",
        )


def write_new(path: Path, raw: bytes, *, group: int = 0, mode: int = 0o640) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_anchor(spec: Spec) -> tuple[Any, Any, Any, dict[str, Any]]:
    from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
    from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyEnrollment
    from jt_oz_bridge.config import load_settings
    from jt_oz_bridge.security.json_data import strict_loads
    from jt_oz_bridge.security.root_files import root_bytes
    from jt_oz_bridge.services.runtime_enrollment import read_enrollment

    settings = load_settings(spec.config)
    enrollment, _ = read_enrollment(settings)
    assert settings.runtime.enrollment_file is not None
    manifest = strict_loads(root_bytes(settings.runtime.enrollment_file))
    anchor = select_anchor(
        enrollment, project_id=spec.project_id, session_id=spec.anchor_session_id
    )
    owner_doc = HostOwnerEnrollment.model_validate(strict_loads(anchor.owner.read()))
    policy = NativePolicyEnrollment.model_validate(strict_loads(anchor.policy.read()))
    return anchor, owner_doc, policy, manifest


def run_worker(job: dict[str, Any], client_uid: int, confirmed: bool) -> tuple[int, bytes, bytes]:
    """Transient unit as the enrolled client UID; the script travels on stdin."""
    account = pwd.getpwuid(client_uid)
    argv = [
        "systemd-run",
        "--unit",
        f"jt-oz-certify-{job['tag']}-{job['mode']}-{uuid.uuid4().hex[:8]}.service",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--service-type=exec",
        f"--property=User={account.pw_name}",
        f"--property=Group={account.pw_gid}",
        "--property=MemoryMax=750M",
        "--property=MemorySwapMax=0",
        f"--property=RuntimeMaxSec={WORKER_SECONDS}",
        "--property=KillMode=control-group",
        "--property=Nice=10",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--working-directory=/",
        sys.executable,
        "-I",
        "-B",
        "-",
        "worker",
        "--job",
        json.dumps(job, ensure_ascii=False, sort_keys=True),
    ]
    if confirmed:
        argv.append(PERMANENT_FLAG)
    done = subprocess.run(
        argv,
        input=Path(__file__).read_bytes(),
        capture_output=True,
        timeout=WORKER_SECONDS + 30,
        check=False,
    )
    return done.returncode, done.stdout, done.stderr


def last_json(stdout: bytes) -> dict[str, Any] | None:
    for line in reversed(stdout.decode(errors="replace").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def cmd_plan(spec: Spec, stage_template: Path | None) -> None:
    need(os.geteuid() == 0, "root_required")
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate

    anchor, owner_doc, policy, manifest = load_anchor(spec)
    code, stdout, stderr = run_worker(spec.job("plan"), owner_doc.client_uid, False)
    worker = last_json(stdout)
    if code != 0 or worker is None or worker.get("error") or worker.get("stage") != "planned":
        print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        raise CertifyError(f"plan_worker_failed:{code}:{(worker or {}).get('error')}")
    need(worker["post_attempts"] == 0, "plan_must_not_post")
    template = CreationPolicyTemplate.model_validate(worker["template"])
    rebuilt = build_template(
        policy,
        agent_id=worker["live"]["agent"]["id"],
        permissions=spec.permissions,
        operations=spec.operations,
    )
    need(template == rebuilt and template.checksum() == rebuilt.checksum(), "template_rebuild")
    need(
        worker["owner_before"]["owner_epoch"] == worker["owner_after"]["owner_epoch"],
        "owner_changed_during_plan",
    )
    existing = [
        c for c in manifest.get("creation_projects", []) if c["anchor"] == worker["reference"]
    ]
    missing = sorted(
        b["reference"]["upstream_session_id"]
        for b in manifest["backends"]
        if b["reference"]["backend_id"] == anchor.reference.backend_id
        and not set(CREATION_OPERATIONS) <= set(b["verified_operations"])
    )
    preview = {
        "id": "ses_jtoz_<32 hex chosen at certify>",
        "location": {"directory": template.creation.scope.canonical_directory},
        "agent": template.creation.agent_id,
        "permissions": [r.model_dump(mode="json") for r in template.creation.permissions],
        "metadata": {"jt_oz_bridge": {"creation_id": "<intent id>", "intent_sha256": "<...>"}},
    }
    if spec.title is not None:
        preview["title"] = spec.title
    if stage_template is not None:
        need(stage_template.is_absolute(), "stage_template_absolute")
        root_ancestry(stage_template)
        write_new(stage_template, dumps(template_document(template)), mode=0o640)
    print(
        json.dumps(
            {
                "planned": True,
                "native_posts": 0,
                "native_get_count": worker["native_get_count"],
                "anchor": worker["reference"],
                "native_project_id": template.creation.native_project_id,
                "manifest_format": manifest["format"],
                "live_policy": worker["live"],
                "owner_epoch": worker["owner_before"]["owner_epoch"],
                "would_create": preview,
                "template": template_document(template),
                "template_sha256": template.checksum(),
                "staged_template": str(stage_template) if stage_template else None,
                "output_directory": str(spec.output),
                "output_directory_exists": spec.output.exists(),
                "creation_project_already_in_manifest": bool(existing),
                "backend_qualifications_missing_creation_operations": missing,
                "next": f"certify --spec <spec> --template-sha256 {template.checksum()} "
                f"{PERMANENT_FLAG}",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_certify(spec: Spec, expected_template: str, confirmed: bool) -> None:
    need(confirmed, "explicit_permanent_session_flag_required")
    need(os.geteuid() == 0, "root_required")
    need(re.fullmatch(r"[0-9a-f]{64}", expected_template), "template_sha256_from_plan_required")
    from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate
    from jt_oz_bridge.domain.session_creation import SessionCreationIntent

    anchor, owner_doc, policy, manifest = load_anchor(spec)
    group = pwd.getpwuid(owner_doc.client_uid).pw_gid
    out = spec.output
    root_ancestry(out)
    need(not os.path.lexists(out), f"output_directory_exists_refused:{out}")
    out.mkdir(mode=0o750)
    os.chown(out, 0, group)
    os.chmod(out, 0o750)
    tool_sha = sha(Path(__file__).read_bytes())
    intent_id = uuid.uuid4().hex
    session_id = "ses_jtoz_" + uuid.uuid4().hex
    reservation = {
        "status": "reserved_before_single_native_post",
        "tag": spec.tag,
        "anchor": anchor.reference.model_dump(mode="json"),
        "intent_id": intent_id,
        "requested_session_id": session_id,
        "policy_template_sha256": expected_template,
        "certify_tool_sha256": tool_sha,
        "reserved_at": time.time(),
    }
    write_new(out / "reservation.json", dumps(reservation), mode=0o600)
    print(f"requested Native session id: {session_id}", file=sys.stderr, flush=True)
    job = spec.job("certify") | {
        "intent_id": intent_id,
        "native_session_id": session_id,
        "expected_template_sha256": expected_template,
    }
    code, stdout, stderr = run_worker(job, owner_doc.client_uid, True)
    write_new(out / "worker.stdout", stdout, mode=0o600)
    write_new(out / "worker.stderr", stderr, mode=0o600)
    worker = last_json(stdout)

    def fail(reason: str, posted: object, failures: list[str]) -> None:
        receipt = {
            "status": "failed",
            "reason": reason,
            "posted": posted,
            "requested_session_id": session_id,
            "worker_returncode": code,
            "worker_error": (worker or {}).get("error"),
            "failures": failures,
            "permanent_session_may_exist": posted is not False,
        }
        write_new(out / "FAILED.json", dumps(receipt), mode=0o600)
        if posted is not False:
            print(
                f"\n*** A permanent Native session may now exist: {session_id} ***\n"
                "*** Do not rerun certify for it; evidence kept in "
                f"{out} ***\n",
                file=sys.stderr,
            )
        print(stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        raise CertifyError(f"certify_failed:{reason}:{failures[:6]}")

    if worker is None:
        fail("worker_output_missing", "unknown", [])
    assert worker is not None
    posted = worker.get("posted")
    if "body" not in worker or "template" not in worker:
        fail(f"worker_stopped_before_body:{worker.get('stage')}", posted, [])
    template = CreationPolicyTemplate.model_validate(worker["template"])
    rebuilt = build_template(
        policy,
        agent_id=template.creation.agent_id,
        permissions=spec.permissions,
        operations=spec.operations,
    )
    if template != rebuilt or template.checksum() != expected_template:
        fail("template_changed", posted, ["template"])
    intent = SessionCreationIntent.model_validate(worker["intent"])
    if (intent.intent_id, intent.native_session_id) != (intent_id, session_id):
        fail("intent_identity_changed", posted, ["intent"])
    encoded, failures = assemble(
        anchor=anchor,
        owner_enrollment=owner_doc,
        template=template,
        intent=intent,
        directory=out,
        worker=worker,
        tool_sha256=tool_sha,
        manifest=manifest,
    )
    for name in ("template", "request", "response", "observation", "certificate"):
        if name in encoded:
            write_new(out / FILES[name], encoded[name], group=group)
    if failures or code != 0:
        fail("evidence_checks", posted, failures or [f"worker_returncode:{code}"])
    try:
        # Same checks again, now through the real root-managed file reader.
        validate_pins(
            (out / FILES["template"]).read_bytes(),
            (out / FILES["certificate"]).read_bytes(),
            manifest=manifest,
        )
    except ValueError as error:
        fail("disk_validation", posted, [f"{type(error).__name__}:{str(error)[:300]}"])
    entry = manifest_entry(anchor, out, encoded)
    write_new(out / "manifest-entry.json", dumps(entry), group=group)
    missing = sorted(
        b["reference"]["upstream_session_id"]
        for b in manifest["backends"]
        if b["reference"]["backend_id"] == anchor.reference.backend_id
        and not set(CREATION_OPERATIONS) <= set(b["verified_operations"])
    )
    print(
        json.dumps(
            {
                "certified": True,
                "created_session_id": session_id,
                "permanent_native_session": True,
                "human_acceptance": False,
                "output_directory": str(out),
                "creation_projects_entry": entry,
                "add_session_create_and_get_to_verified_operations_of": missing,
                "reminder": (
                    "Append creation_projects_entry to the runtime manifest's "
                    "creation_projects; every backend qualification on backend "
                    f"{anchor.reference.backend_id!r} must list session.create and "
                    "session.get in verified_operations; set "
                    "runtime.session_creation_enabled = true; repin the manifest "
                    "sha256 in the observer policy; full gate before switching."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("step", nargs="?", default="plan", choices=("plan", "certify", "worker"))
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--job")
    parser.add_argument("--stage-template", type=Path)
    parser.add_argument("--template-sha256")
    parser.add_argument(PERMANENT_FLAG, dest="confirmed", action="store_true")
    args = parser.parse_args(argv)
    if args.step == "certify":
        # Checked before reading anything, so a missing flag never touches Native.
        need(args.confirmed, "explicit_permanent_session_flag_required")
        need(args.template_sha256, "template_sha256_from_plan_required")
    if args.step == "worker":
        need(args.job, "worker_job_required")
        cmd_worker(json.loads(args.job), args.confirmed)
        return
    need(args.spec is not None, "spec_required")
    spec = Spec(args.spec)
    if args.step == "plan":
        need(not args.confirmed, "plan_takes_no_permanent_session_flag")
        cmd_plan(spec, args.stage_template)
    else:
        cmd_certify(spec, args.template_sha256, args.confirmed)


if __name__ == "__main__":
    main()
