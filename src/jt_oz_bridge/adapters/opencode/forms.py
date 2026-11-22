"""V2 source-qualified form/permission normalization, without executing any control."""

import hashlib
from typing import Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.config import validate_endpoint
from jt_oz_bridge.domain.control import (
    Choice,
    FieldCondition,
    InteractionSnapshot,
    PermissionDetails,
    QuestionField,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.redaction import RedactionError, canonical_json, redact_json
from jt_oz_bridge.storage.durable import digest


class UnsupportedForm(ContractError):
    pass


def normalize_field(raw: dict[str, Any]) -> QuestionField:
    kind = raw.get("type")
    options = tuple(
        Choice(id=item["value"], label=item["label"]) for item in raw.get("options", [])
    )
    if kind == "string":
        normalized = "single" if "options" in raw else "text"
    elif kind == "multiselect":
        normalized = "multi"
    elif kind in {"boolean", "integer", "number", "external"}:
        normalized = kind
    else:
        raise UnsupportedForm("unknown_form_field_type")
    if normalized == "external":
        validate_endpoint(raw["url"], allow_loopback=False)
    return QuestionField.model_validate(
        {
            "id": raw["key"],
            "label": raw.get("title", raw["key"]),
            "description": raw.get("description", ""),
            "kind": normalized,
            "required": True if normalized == "external" else raw.get("required", False),
            "choices": options,
            "allow_custom_text": raw.get("custom", False),
            "min_length": raw.get("minLength", 0),
            "max_length": raw.get("maxLength", 10000),
            "minimum": raw.get("minimum"),
            "maximum": raw.get("maximum"),
            "min_items": raw.get("minItems", 0),
            "max_items": raw.get("maxItems", 1000),
            "when": tuple(FieldCondition.model_validate(item) for item in raw.get("when", [])),
            "pattern": raw.get("pattern"),
            "format": raw.get("format"),
            "hidden": raw.get("hidden", False),
            "external_url": raw.get("url") if normalized == "external" else None,
        }
    )


PERMISSION_NORMALIZER_VERSION = "v2-permission-details-v1"


def generation(
    reference: SessionRef, request_id: str, epoch: str, *, normalizer: str | None = None
) -> str:
    if not epoch:
        raise ContractError("verified_connection_epoch_required")
    data = {"reference": reference.model_dump(), "request": request_id, "epoch": epoch}
    if normalizer is not None:
        data["normalizer"] = normalizer
    return digest(data)


def normalize_form(
    profile: OpenAPIProfile,
    reference: SessionRef,
    raw: dict[str, Any],
    epoch: str,
    *,
    pending_catalog: bool = False,
) -> InteractionSnapshot:
    component = "Form.Detail" if "state" in raw else "Form.Info"
    profile.validate("component:" + component, {"$ref": "#/components/schemas/" + component}, raw)
    if raw["sessionID"] != reference.upstream_session_id:
        raise ContractError("form_session_identity_mismatch")
    pending = raw["state"]["status"] == "pending" if "state" in raw else pending_catalog
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=raw["id"],
        generation=generation(reference, raw["id"], epoch),
        kind="form",
        pending=pending,
        description=raw["title"],
        fields=tuple(normalize_field(field) for field in raw["fields"]),
    )


def normalize_permission(
    profile: OpenAPIProfile,
    reference: SessionRef,
    raw: dict[str, Any],
    epoch: str,
    *,
    pending_catalog: bool = False,
) -> InteractionSnapshot:
    profile.validate(
        "component:Permission.Request", {"$ref": "#/components/schemas/Permission.Request"}, raw
    )
    if raw["sessionID"] != reference.upstream_session_id:
        raise ContractError("permission_session_identity_mismatch")
    try:
        source_digest = hashlib.sha256(canonical_json(raw, max_bytes=2 * 1024**2)).hexdigest()
        redacted = redact_json(raw)
        safe = redacted.value
        details = PermissionDetails(
            source_digest=source_digest,
            metadata_json=canonical_json(safe["metadata"], max_bytes=262144).decode()
            if "metadata" in safe
            else None,
            requester_json=canonical_json(safe["source"], max_bytes=8192).decode()
            if "source" in safe
            else None,
            redactions=redacted.redactions,
            control_escapes=redacted.control_escapes,
        )
    except RedactionError:
        raise ContractError("permission_details_not_safely_previewable") from None
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=raw["id"],
        generation=generation(
            reference, raw["id"], epoch, normalizer=PERMISSION_NORMALIZER_VERSION
        ),
        kind="permission",
        pending=pending_catalog,
        description=safe.get("message", safe["action"]),
        operation=safe["action"],
        resources=tuple(safe["resources"]),
        requested_scope=tuple(safe.get("save", [])),
        permission_details=details,
    )
