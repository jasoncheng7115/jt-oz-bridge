"""Normalize Root-reviewed catalog evidence without opening a metadata socket.

Historical operation qualification never substitutes for live Human, owner,
policy, filesystem or consumer-fence checks. List/find and nonempty session
diff qualification remain separate capabilities.
"""

import hashlib
import re
from types import MappingProxyType

from jt_oz_bridge.adapters.opencode import directory_scope, workspace_catalog
from jt_oz_bridge.adapters.opencode.directory_scope import (
    DirectoryScopeEnrollment,
    DirectoryScopeRoot,
)
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
from jt_oz_bridge.adapters.opencode.workspace_catalog import WorkspaceCatalogAttestation
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.services.file_enrollment import component_sha, object_data, zero

CATALOG_CHECKS = MappingProxyType(
    {
        "fs.list": frozenset(
            {
                "directory_marker_and_immediate_children",
                "protected_and_managed_names_hidden",
                "original_object_only",
                "unicode_nested_root_relative_paths",
                "oversized_directory_rejected",
                "absolute_traversal_and_separators_rejected_before_http",
                "outside_directory_symlink_rejected",
                "five_second_original_observation_expires",
                "readonly_without_mutation_watch",
                "first_scope_deadline_preserved",
            }
        ),
        "fs.find": frozenset(
            {
                "unicode_and_empty_search",
                "thousand_entry_search_reports_truncation",
                "outside_search_descendants_absent",
                "native_rank_preserved_after_scope_filtering",
                "original_object_only",
                "five_second_original_observation_expires",
                "readonly_without_mutation_watch",
                "first_scope_deadline_preserved",
            }
        ),
        "session.message.list": frozenset(
            {
                "user_type_filter_before_cursor_pagination",
                "original_session_only",
                "bounded_ids_only_without_prompt_content",
                "first_scope_deadline_preserved",
                "readonly_without_mutation_watch",
            }
        ),
        "session.message.get": frozenset(
            {
                "exact_user_message_identity_before_and_after_diff",
                "changed_deleted_assistant_and_foreign_turn_rejected",
                "selected_turn_digest_preserved",
                "first_scope_deadline_preserved",
                "readonly_without_mutation_watch",
            }
        ),
        "session.diff": frozenset(
            {
                "nonempty_original_session_turn",
                "file_and_patch_pagination",
                "explicit_user_turn_from_preserved_through_pagination",
                "outside_diff_paths_rejected",
                "byte_and_entry_capacity",
                "original_object_only",
                "five_second_original_observation_expires",
                "readonly_without_mutation_watch",
                "first_scope_deadline_preserved",
            }
        ),
    }
)


def catalog_qualification(
    raw: bytes,
    *,
    reference: SessionRef,
    contract_sha256: str,
    native_policy_sha256: str,
    owner: HostOwnerEnrollment,
    directories: DirectoryScopeEnrollment,
    directory_enrollment_sha256: str,
    evidence_sha256: str,
) -> WorkspaceCatalogAttestation:
    doc = object_data(strict_loads(raw))
    observed = object_data(doc.get("observation"))
    physical = DirectoryScopeRoot.model_validate(doc.get("physical_root"))
    root = next(
        (r for r in directories.roots if r.project_key == directory_project_key(reference)), None
    )
    if (
        doc.get("format") != "qualified-original-workspace-catalog-v2"
        or doc.get("operator_review") != "installed-evidence-reviewed-for-development-runtime"
        or doc.get("reference") != reference.model_dump(mode="json")
        or doc.get("contract_sha256") != contract_sha256
        or doc.get("native_policy_sha256") != native_policy_sha256
        or doc.get("executable_sha256") != owner.executable_sha256
        or (owner.backend_id, owner.backend_identity)
        != (reference.backend_id, reference.backend_identity)
        or owner.version != "2.0.32"
        or doc.get("catalog_component_sha256") != component_sha(workspace_catalog)
        or doc.get("directory_component_sha256") != component_sha(directory_scope)
        or doc.get("semantics_sha256") != workspace_catalog.CATALOG_SEMANTICS
        or doc.get("directory_enrollment_sha256") != directory_enrollment_sha256
        or doc.get("directory_config_sha256") != directories.config_sha256
        or doc.get("directory_implementation_sha256") != directories.implementation_sha256
        or (directories.server_uid, directories.client_uid) != (owner.native_uid, owner.client_uid)
        or root is None
        or root.directory != reference.canonical_directory
        or root.uid != owner.native_uid
        or physical != root
        or hashlib.sha256(raw).hexdigest() != evidence_sha256
        or observed.get("passed") is not True
        or observed.get("native_database_bytes_read") is not False
        or not zero(observed.get("native_http_mutations"))
        or not zero(observed.get("zulip_http_mutations"))
        or observed.get("original_processes_unchanged") is not True
        or observed.get("live_bridge_counts_unchanged") is not True
        or observed.get("controlled_probe_cleanup_complete") is not True
        or not isinstance(observed.get("evidence_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", observed["evidence_sha256"]) is None
    ):
        raise ValueError("workspace_catalog_evidence_scope_or_component_changed")
    operations = doc.get("operations")
    if (
        not isinstance(operations, list)
        or not 1 <= len(operations) <= len(CATALOG_CHECKS)
        or any(type(op) is not str or op not in CATALOG_CHECKS for op in operations)
        or len(set(operations)) != len(operations)
    ):
        raise ValueError("workspace_catalog_explicit_operations_required")
    checks = object_data(observed.get("checks"))
    if set(checks) != set(operations):
        raise ValueError("workspace_catalog_operation_evidence_set_changed")
    for operation in operations:
        cases = object_data(checks[operation])
        if any(cases.get(case) is not True for case in CATALOG_CHECKS[operation]):
            raise ValueError("workspace_catalog_complete_operation_checks_required")
    return WorkspaceCatalogAttestation(
        reference,
        contract_sha256,
        native_policy_sha256,
        workspace_catalog.CATALOG_SEMANTICS,
        evidence_sha256,
        frozenset(operations),
    )
