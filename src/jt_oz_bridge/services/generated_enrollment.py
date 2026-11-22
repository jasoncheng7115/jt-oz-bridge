"""Root-reviewed actual output evidence; live responses cannot enroll themselves.

v1 qualifies every output origin at the 20 MiB bound. v2 declares the exact
origins and the largest byte size its real cases observed; the runtime reader
then counts anything outside that scope as unsupported and refuses to read it.
"""

import hashlib
from pathlib import Path
from typing import Any

from jt_oz_bridge.adapters.opencode import generated_files as component
from jt_oz_bridge.adapters.opencode.generated_files import (
    BYTE_FEATURES,
    BYTE_SEMANTICS,
    FULL_SCOPE,
    GENERATED_ORIGINS,
    OUTPUT_FEATURES,
    OUTPUT_SEMANTICS,
    GeneratedByteEvidence,
    GeneratedBytesAttestation,
    GeneratedDiscoveryEvidence,
    GeneratedFileAttestation,
    GeneratedScope,
)
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.services.file_enrollment import object_data

FULL_FORMAT = "qualified-generated-outputs-v1"
SCOPED_FORMAT = "qualified-generated-outputs-v2"
NEGATIVE_CHECKS = frozenset(
    {
        "copied-and-expired-objects-rejected",
        "foreign-root-rejected",
        "changed-owner-rejected",
        "changed-output-rejected",
        "external-uri-not-fetched",
        "protected-path-not-disclosed",
    }
)


def declared_scope(value: Any) -> GeneratedScope:
    """The v2 ``scope`` object: exact keys, unique known origins, an int bound."""
    data = object_data(value)
    origins = data.get("origins")
    if set(data) != {"origins", "max_bytes"} or not isinstance(origins, list):
        raise ValueError("generated_qualification_declared_scope_invalid")
    pairs = []
    for item in origins:
        entry = object_data(item)
        if set(entry) != {"kind", "origin"} or not all(isinstance(v, str) for v in entry.values()):
            raise ValueError("generated_qualification_declared_scope_invalid")
        pairs.append((entry["kind"], entry["origin"]))
    if len(set(pairs)) != len(pairs) or not set(pairs) <= GENERATED_ORIGINS:
        raise ValueError("generated_qualification_declared_scope_invalid")
    return GeneratedScope(frozenset(pairs), data["max_bytes"])


def scope_document(scope: GeneratedScope) -> dict[str, Any]:
    return {
        "origins": [{"kind": k, "origin": o} for k, o in sorted(scope.origins)],
        "max_bytes": scope.max_bytes,
    }


def generated_qualification(
    raw: bytes,
    *,
    reference: SessionRef,
    contract_sha256: str,
    executable_sha256: str,
    evidence_sha256: str,
) -> tuple[GeneratedFileAttestation, GeneratedBytesAttestation]:
    bundle = object_data(strict_loads(raw))
    before, after = (
        object_data(bundle.get("native_before")),
        object_data(bundle.get("native_after")),
    )
    negatives = object_data(bundle.get("negative_checks"))
    if (
        bundle.get("format") not in (FULL_FORMAT, SCOPED_FORMAT)
        or bundle.get("operator_review") != "installed-evidence-reviewed-for-development-runtime"
        or bundle.get("actual_original_native_outputs") is not True
        or bundle.get("human_input_fabricated") is not False
        or bundle.get("backend_replaced") is not False
        or bundle.get("native_database_bytes_read") is not False
        or bundle.get("native_restarted") is not False
        or bundle.get("reference") != reference.model_dump(mode="json")
        or bundle.get("contract_sha256") != contract_sha256
        or bundle.get("metadata_semantics_sha256") != OUTPUT_SEMANTICS
        or bundle.get("byte_semantics_sha256") != BYTE_SEMANTICS
        or bundle.get("component_sha256")
        != hashlib.sha256(Path(component.__file__).read_bytes()).hexdigest()
        or bundle.get("metadata_features") != sorted(OUTPUT_FEATURES)
        or bundle.get("byte_features") != sorted(BYTE_FEATURES)
        or before != after
        or before.get("binary_sha256") != executable_sha256
        or type(before.get("pid")) is not int
        or before["pid"] <= 0
        or type(before.get("nrestarts")) is not int
        or before["nrestarts"] != 0
        or set(negatives) != NEGATIVE_CHECKS
        or any(x is not True for x in negatives.values())
    ):
        raise ValueError("generated_qualification_original_scope_or_component_changed")
    scoped = bundle["format"] == SCOPED_FORMAT
    if scoped != ("scope" in bundle):
        raise ValueError("generated_qualification_scope_requires_v2")
    scope = declared_scope(bundle["scope"]) if scoped else FULL_SCOPE
    inventories, byte_cases = bundle.get("inventories"), bundle.get("byte_cases")
    if (
        not isinstance(inventories, list)
        or not 2 <= len(inventories) <= 20
        or not isinstance(byte_cases, list)
        or not 5 <= len(byte_cases) <= 20
    ):
        raise ValueError("generated_qualification_complete_inventory_and_bytes_required")
    discoveries = [GeneratedDiscoveryEvidence.model_validate(value) for value in inventories]
    if not any(not d.files for d in discoveries) or not any(d.files for d in discoveries):
        raise ValueError("generated_qualification_actual_empty_and_nonempty_required")
    evidence = []
    for case in byte_cases:
        data = object_data(case)
        if any(
            data.get(k) is not True
            for k in (
                "original_object_current",
                "exact_native_bytes_verified",
                "no_direct_local_read",
            )
        ):
            raise ValueError("generated_qualification_actual_original_bytes_required")
        value = GeneratedByteEvidence.model_validate(data.get("evidence"))
        if value.discovery().stable_sha256 not in {d.stable_sha256 for d in discoveries}:
            raise ValueError("generated_qualification_same_original_inventory_required")
        evidence.append(value)
    for d in discoveries:
        if (
            d.turn.correlation.reference != reference
            or d.turn.owner_epoch != before.get("owner_epoch")
            or d.turn.contract_sha256 != contract_sha256
        ):
            raise ValueError("generated_qualification_actual_root_and_owner_required")
    observed = {(e.selection.kind, e.selection.origin) for e in evidence}
    if not scoped:
        if observed != GENERATED_ORIGINS or not all(
            any(
                e.selection.kind == kind and e.projection.size == MAX_ATTACHMENT_BYTES
                for e in evidence
            )
            for kind in ("workspace", "inline")
        ):
            raise ValueError("generated_qualification_complete_origins_and_twenty_mib_required")
    elif (
        observed != scope.origins
        or max(e.projection.size for e in evidence) != scope.max_bytes
        or len({e.stable_sha256 for e in evidence}) != len(evidence)
    ):
        # Exactly what distinct real cases covered: no unread origin, no unobserved
        # size, and no case counted twice toward the minimum.
        raise ValueError("generated_qualification_declared_scope_not_observed")
    return (
        GeneratedFileAttestation(
            reference, contract_sha256, OUTPUT_SEMANTICS, evidence_sha256, OUTPUT_FEATURES, scope
        ),
        GeneratedBytesAttestation(
            reference, contract_sha256, BYTE_SEMANTICS, evidence_sha256, BYTE_FEATURES, scope
        ),
    )
