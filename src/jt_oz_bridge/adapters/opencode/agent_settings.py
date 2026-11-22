"""Candidate Agent-definition/transition and mixed-setting-tail validators.

These pure validators issue no certificate, perform no HTTP/DB operation and
install no runtime capability. Agent switching can change effective permissions;
it must never borrow the existing model-only qualification or policy pin.
"""

import hashlib
import html
from pathlib import Path
from typing import Any

from pydantic import Field

from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head, reconcile_aborted_suffix
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.domain.agent_selection import (
    AgentCatalog,
    AgentDefinition,
    AgentPolicyEndpoint,
    AgentTransitionEnrollment,
    AgentTransitionPreview,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.markdown import literal, sanitize_controls
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.security.root_files import root_bytes
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

AGENT_SETTING_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"
AGENT_SETTING_SOURCES = {
    "session.ts": "53d67aef56a1a6b518fad623d51a15b26f071db25c7e5f1c71a21c36ac3a9d11",
    "info.ts": "d14557573746c0b2ed65f42f8a881012813f36235bb67d2f2a27661c017c80a6",
    "projector.ts": "b2145973cd8ae49fdbde760cb4277ed61113669447583805fcbd2669ced304b1",
    "message-updater.ts": "40d7a2ae2852db7b4c985ed0c2c8cfbebb92a91a3d60e3007b37b4f282703ee2",
    "permission.ts": "d69278896f9a541dac7cf46056c859834d840ecc16ac57a639cbabc1afdda9a5",
}
AGENT_SETTING_SEMANTICS = digest(
    {
        "format": "agent-and-model-setting-tail-v1",
        "version": "2.0.32",
        "sources": AGENT_SETTING_SOURCES,
    }
)


def _profile(profile: OpenAPIProfile) -> None:
    if profile.sha256 != AGENT_SETTING_SCHEMA:
        raise ContractError("native_agent_exact_installed_schema_required")


def _hash(value: dict[str, Any], maximum: int) -> str:
    try:
        raw = checked_json(value)
        if len(raw) > maximum:
            raise ValueError("capacity")
        return hashlib.sha256(raw).hexdigest()
    except ValueError:
        raise ContractError("native_agent_definition_invalid_or_oversized") from None


def _label(value: str) -> str:
    safe = sanitize_controls(value)[0].replace("\n", " ").replace("\t", " ")
    redacted, _ = redact_text(safe)
    # Keep complete entities and apply the DTO limit after serialization.
    output = ""
    for char in redacted[:120]:
        encoded = literal(char)
        if len(output) + len(encoded) > 511:
            return output + "…"
        output += encoded
    return output


def agent_definition(profile: OpenAPIProfile, raw: dict[str, Any]) -> AgentDefinition:
    """Hash every validated field, including model/request/system/permissions.

    Neither an identifier nor the old safe metadata projection freezes an Agent.
    Omitted optional fields and explicit empty values retain different hashes.
    """
    _profile(profile)
    try:
        fingerprint = _hash(raw, 1024 * 1024)
        profile.validate(
            "agent-selection-full-definition-v1", {"$ref": "#/components/schemas/Agent.Info"}, raw
        )
        return AgentDefinition(
            agent_id=raw["id"],
            label=_label(raw["name"]),
            mode=raw["mode"],
            hidden=raw["hidden"],
            definition_sha256=fingerprint,
            permissions_sha256=_hash({"rules": raw["permissions"]}, 1024 * 1024),
        )
    except ValueError:
        raise ContractError("native_agent_definition_invalid_or_oversized") from None


def agent_catalog(
    profile: OpenAPIProfile, reference: SessionRef, response: dict[str, Any]
) -> AgentCatalog:
    """Project a response already acquired under a separate original-owner proof."""
    _profile(profile)
    _hash(response, 4 * 1024 * 1024)
    profile.response("agent.list", 200, response)
    if response["location"] != {"directory": reference.canonical_directory}:
        raise ContractError("native_agent_catalog_location_changed")
    rows = response["data"]
    if len(rows) > 4096 or len({row["id"] for row in rows}) != len(rows):
        raise ContractError("native_agent_catalog_capacity_or_duplicate_identity")
    all_items = tuple(
        sorted((agent_definition(profile, row) for row in rows), key=lambda a: a.agent_id)
    )
    return AgentCatalog(
        reference=reference,
        contract_sha256=profile.sha256,
        # Hidden definition changes also invalidate the complete observation.
        catalog_sha256=digest(
            {"definitions": [item.model_dump(mode="json") for item in all_items]}
        ),
        items=tuple(item for item in all_items if not item.hidden),
    )


def agent_policy_endpoint(
    profile: OpenAPIProfile,
    reference: SessionRef,
    native_project_id: str,
    info: dict[str, Any],
    agent: dict[str, Any],
    plugins: dict[str, Any],
    saved: dict[str, Any],
    mcp: dict[str, Any],
) -> AgentPolicyEndpoint:
    # Keep these pure setting types importable by the future execution client;
    # the existing policy implementation itself depends on that client.
    from jt_oz_bridge.adapters.opencode.project_policy import policy_fingerprint

    _profile(profile)
    for operation, response in (
        ("session.get", {"data": info}),
        ("agent.get", agent),
        ("plugin.list", plugins),
        ("permission.saved.list", saved),
        ("mcp.list", mcp),
    ):
        _hash(response, 4 * 1024 * 1024)
        profile.response(operation, 200, response)
    # The existing policy projection verifies original Root/project/location,
    # plugin and saved/MCP inventory, plus ordered effective-permission inputs.
    policy = policy_fingerprint(reference, native_project_id, info, agent, plugins, saved, mcp)
    return AgentPolicyEndpoint(
        reference=reference,
        native_project_id=native_project_id,
        definition=agent_definition(profile, agent["data"]),
        policy_sha256=policy,
    )


def require_agent_transition(
    enrollment: AgentTransitionEnrollment,
    before: AgentPolicyEndpoint,
    after: AgentPolicyEndpoint,
    schema_sha256: str,
) -> None:
    if (
        schema_sha256 != AGENT_SETTING_SCHEMA
        or enrollment.contract_sha256 != schema_sha256
        or enrollment.permission_source_sha256 != AGENT_SETTING_SOURCES["permission.ts"]
        or not enrollment.matches(before, after)
    ):
        raise ContractError("native_agent_transition_not_exactly_enrolled")


def root_agent_transition(path: Path) -> AgentTransitionEnrollment:
    """Parse one root-owned, non-writable-ancestry file; never auto-install it."""
    try:
        value = AgentTransitionEnrollment.model_validate(
            strict_loads(root_bytes(path, maximum=65536))
        )
        require_agent_transition(value, value.before, value.after, value.contract_sha256)
        return value
    except (ValueError, OSError):
        raise ContractError("native_agent_root_transition_invalid") from None


def agent_transition_preview(enrollment: AgentTransitionEnrollment) -> AgentTransitionPreview:
    return AgentTransitionPreview(
        # Root-owned authority inputs can still contain untrusted display text.
        # Decode one existing literal layer before canonical serialization, so
        # labels issued by agent_definition remain stable rather than escaped twice.
        before_label=_label(html.unescape(enrollment.before.definition.label)),
        after_label=_label(html.unescape(enrollment.after.definition.label)),
        permissions_differ=(
            enrollment.before.definition.permissions_sha256
            != enrollment.after.definition.permissions_sha256
        ),
    )


class AgentSettingsAttestation(ControlModel):
    """Independent exact-Root evidence input; source hashes are not a certificate.

    Future composition must separately verify retained installed receipts for all
    three evidence hashes. This type alone grants no operation or policy change.
    No backend-wide or graph-wide qualification is accepted.
    """

    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    switch_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mixed_tail_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_transition_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def require(self, reference: SessionRef, schema_sha256: str) -> None:
        if (
            reference != self.reference
            or schema_sha256 != AGENT_SETTING_SCHEMA
            or self.contract_sha256 != schema_sha256
            or self.semantics_sha256 != AGENT_SETTING_SEMANTICS
        ):
            raise ContractError("native_agent_setting_semantics_unqualified")


def reconcile_agent_settings_tail(
    profile: OpenAPIProfile,
    reference: SessionRef,
    info: dict[str, Any],
    page: dict[str, Any],
    qualification: AgentSettingsAttestation | None,
) -> dict[str, Any]:
    """Check a bounded descending mixed chain ending at a positive Native idle.

    No pristine/created baseline is inferred. Original physical scope, owner,
    full-definition checks and the final resource boundary remain caller duties.
    This candidate is deliberately not installed in the existing proof reader.
    """
    _profile(profile)
    if not isinstance(qualification, AgentSettingsAttestation):
        raise ContractError("native_agent_independent_setting_qualification_required")
    qualification.require(reference, profile.sha256)
    _hash(info, 4 * 1024 * 1024)
    profile.response("session.get", 200, {"data": info})
    if (
        info["id"] != reference.upstream_session_id
        or info["projectID"] != qualification.native_project_id
        or info["location"] != {"directory": reference.canonical_directory}
    ):
        raise ContractError("native_agent_tail_original_session_changed")
    if "archived" in info["time"] or "revert" in info:
        raise ContractError("native_agent_tail_unqualified_session_state")
    _hash(page, 4 * 1024 * 1024)
    profile.response("session.message.list", 200, page)
    rows = page["data"]
    if (
        not 2 <= len(rows) <= 51
        or rows[0]["type"] not in {"agent-switched", "model-switched"}
        or len({row["id"] for row in rows}) != len(rows)
    ):
        raise ContractError("native_agent_tail_boundary_or_duplicate_identity")
    expected_agent = info.get("agent")
    expected_model = native_ref(info["model"]) if "model" in info else None
    newer_time = info["time"]["updated"]
    controls: list[dict[str, Any]] = []
    saw_agent = False
    for index, row in enumerate(rows):
        created = row["time"]["created"]
        if created > newer_time:
            raise ContractError("native_agent_tail_time_boundary_changed")
        if aborted_head(row):
            # Settings changed after a declined permission ended its turn
            # without a new idle; that exact tail must still reach one.
            if not saw_agent:
                raise ContractError("native_agent_tail_positive_idle_boundary_changed")
            turn = reconcile_aborted_suffix(info, rows[index:], page["cursor"], newer_time)
            if turn["idle"] is None:
                raise ContractError("native_agent_tail_positive_idle_not_found")
            return {
                "controls": controls,
                "idle": turn["idle"],
                "pristine": False,
                "aborted_turn": turn,
            }
        newer_time = created
        if row["type"] == "idle":
            if (
                not saw_agent
                or row["outcome"] != info.get("outcome")
                or created != info["time"].get("idle")
            ):
                raise ContractError("native_agent_tail_positive_idle_boundary_changed")
            return {
                "controls": controls,
                "idle": {
                    "id": row["id"],
                    "type": "idle",
                    "time": {"created": created},
                    "outcome": row["outcome"],
                },
                "pristine": False,
            }
        if len(controls) >= 50:
            raise ContractError("native_agent_tail_capacity")
        if row["type"] == "agent-switched":
            if row["agent"] != expected_agent:
                raise ContractError("native_agent_tail_selection_chain_changed")
            expected_agent = row.get("previous")
            saw_agent = True
            controls.append(
                {
                    "id": row["id"],
                    "type": row["type"],
                    "time": {"created": created},
                    "agent": row["agent"],
                    "previous": expected_agent,
                }
            )
        elif row["type"] == "model-switched":
            selected = native_ref(row["model"])
            if not selected.same_native_selection(expected_model):
                raise ContractError("native_agent_tail_model_chain_changed")
            expected_model = native_ref(row["previous"]) if "previous" in row else None
            controls.append(
                {
                    "id": row["id"],
                    "type": row["type"],
                    "time": {"created": created},
                    "model": selected.wire(),
                    "previous": expected_model.wire() if expected_model is not None else None,
                }
            )
        else:
            raise ContractError("native_agent_tail_intervening_execution_or_unknown_control")
    raise ContractError("native_agent_tail_positive_idle_not_found")
