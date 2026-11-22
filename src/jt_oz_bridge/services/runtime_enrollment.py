"""Root-reviewed installed qualification -> explicit operational composition.

The manifest is a deployment-operator trust input. Live responses do not issue
certificates, grant users, widen scope or enable unspecified Native operations.
"""

import asyncio
import hashlib
import logging
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import httpx
from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    StrictBool,
    StrictInt,
    field_validator,
    model_serializer,
    model_validator,
)
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode import directory_scope, git_review
from jt_oz_bridge.adapters.opencode.agent_configuration import AgentConfigurationCell
from jt_oz_bridge.adapters.opencode.agent_settings import AgentSettingsAttestation
from jt_oz_bridge.adapters.opencode.agent_switch import (
    V2AgentSettings,
    agent_settings_by_reference,
)
from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject, V2SessionCatalog
from jt_oz_bridge.adapters.opencode.check_idle_anchor import V2AnchoredCheckTailReader
from jt_oz_bridge.adapters.opencode.checks import (
    CHECK_READS,
    CheckExecutionAttestation,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate, V2CreationPolicy
from jt_oz_bridge.adapters.opencode.directory_scope import (
    DirectoryScopeEnrollment,
    DirectoryScopeRoot,
    LinuxDirectoryScopeGuard,
)
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.existing_session_graph import (
    V2ExistingSessionGraphObserver,
    graph_identity,
)
from jt_oz_bridge.adapters.opencode.existing_sessions import (
    ExistingSessionProtocol,
    V2ExistingSessionObserver,
)
from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
from jt_oz_bridge.adapters.opencode.generated_files import V2GeneratedFileReader
from jt_oz_bridge.adapters.opencode.git_review import (
    PATCH_SEMANTICS,
    REVIEW_OPERATIONS,
    REVIEW_SEMANTICS,
    GitPatchAttestation,
    GitReviewAttestation,
    V2NativeGitReview,
    review_attestation_sha256,
)
from jt_oz_bridge.adapters.opencode.graph_generation import GraphResourceContext
from jt_oz_bridge.adapters.opencode.host_owner import (
    HostOwnerEnrollment,
    HostOwnerEvidence,
    LinuxHostOwnerProbe,
)
from jt_oz_bridge.adapters.opencode.instructions import V2SessionInstructions
from jt_oz_bridge.adapters.opencode.lineage_resources import (
    LINEAGE_SEMANTICS,
    LineageResourceAttestation,
    V2LineageResourceProofs,
)
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.project_policy import (
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
    approve_observer_plugins,
)
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    READS,
    BackgroundRootWork,
    PositiveIdleRequired,
    V2LeafResourceProofs,
)
from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.adapters.opencode.session_fork import V2ForkedRootObserver, V2ForkPolicy
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    NativeResourceTurn,
    ResourceSemanticAttestation,
    V2TurnResourceReader,
)
from jt_oz_bridge.adapters.opencode.workspace_catalog import (
    V2WorkspaceCatalog,
    WorkspaceCatalogAttestation,
)
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import (
    ZulipAttestation,
    ZulipClient,
    ZulipError,
    ZulipReadUnavailable,
)
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.file_upload import FileUploadAttestation, ZulipFileUploader
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.adapters.zulip.server_release import same_release_line
from jt_oz_bridge.config import Settings, validate_endpoint
from jt_oz_bridge.domain.agent_selection import AgentTransitionEnrollment
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.checks import CheckCatalog
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.domain.enrollment_views import enrollment_union
from jt_oz_bridge.domain.execution import SourceReader
from jt_oz_bridge.domain.existing_sessions import ExistingSessionGraphObservation
from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin
from jt_oz_bridge.domain.git_review import NativeDiffSummary
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.runtime_readiness import ModeReason, RootMode, RootModeFact, scope_key
from jt_oz_bridge.domain.session_adoption import SessionAdoptionPolicy
from jt_oz_bridge.security.downloads import DownloadPolicy
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.policy import ROLES, AccessDenied
from jt_oz_bridge.security.root_files import pinned_root_bytes, root_bytes
from jt_oz_bridge.security.secrets import resolve_secret
from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.catalog_enrollment import catalog_qualification
from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
from jt_oz_bridge.services.check_recovery import OriginalCheckOwner, OwnedCheckRecovery
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_enrollment import (
    component_sha,
    download_origin,
    native_file_qualification,
    upload_qualification,
)
from jt_oz_bridge.services.file_menus import FileMenus
from jt_oz_bridge.services.format_instructions import ZulipFormatInstructions
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_enrollment import generated_qualification
from jt_oz_bridge.services.git_evidence_enrollment import qualify_git_evidence
from jt_oz_bridge.services.live_capture import LiveEventJournal, LiveTextCollector
from jt_oz_bridge.services.live_retention import FeedGenerations
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.runtime import BridgeRuntime, RuntimeFactory, RuntimeResource
from jt_oz_bridge.services.runtime_configuration import RuntimeConfiguration
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.session_creation_activation import SessionCreationActivation
from jt_oz_bridge.services.session_creation_journal import CreationProject, SessionCreationJournal
from jt_oz_bridge.services.session_exports import (
    GeneratedSessionExportJournal,
    SessionExportJournal,
)
from jt_oz_bridge.services.session_fork_registration import SessionForkRegistration
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.upload_associations import SSHUploadAssociations
from jt_oz_bridge.services.workspace_enrollment import (
    WorkspaceNamespacePin,
    source_qualification,
    workspace_qualification,
)
from jt_oz_bridge.services.workspace_journal import WorkspaceJournal
from jt_oz_bridge.services.workspace_runtime import WorkspaceIncoming
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, Grant
from jt_oz_bridge.storage.workspace_files import WorkspaceFiles

LOG = logging.getLogger(__name__)


class RootFile(ControlModel):
    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def absolute(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("absolute_root_managed_evidence_path_required")
        return value

    def read(self) -> bytes:
        return pinned_root_bytes(self.path, self.sha256)


class RealmQualification(ControlModel):
    url: str
    bot_email: str = Field(min_length=3, max_length=255)
    realm_id: str = Field(min_length=1, max_length=255)
    bot_user_id: int = Field(strict=True, gt=0)
    bot_owner_id: int = Field(strict=True, gt=0)
    zulip_version: str = Field(min_length=1, max_length=64)
    feature_level: int = Field(strict=True, ge=334)
    message_limit: int = Field(strict=True, ge=512, le=1000000)
    topic_limit: int = Field(strict=True, gt=0, le=10000)
    evidence: tuple[RootFile, ...] = Field(min_length=1, max_length=20)
    file_upload: RootFile | None = None
    source_uploads: RootFile | None = None
    source_evidence: RootFile | None = None
    upload_realm_id: int | None = Field(default=None, strict=True, gt=0)
    file_private_networks: tuple[str, ...] = Field(default=(), max_length=8)

    @field_validator("url")
    @classmethod
    def fixed_https_realm(cls, value: str) -> str:
        validate_endpoint(value, False)
        if value.endswith("/"):
            raise ValueError("canonical_realm_origin_required")
        return value


class NativeQualification(ControlModel):
    protocol_scope: Literal["session", "backend"] = "session"
    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    owner: RootFile
    owner_socket: Path
    schema_file: RootFile
    policy: RootFile
    model_evidence: RootFile
    outcome_evidence: tuple[RootFile, ...] = Field(min_length=1, max_length=3)
    operation_evidence: tuple[RootFile, ...] = Field(min_length=1, max_length=30)
    verified_operations: frozenset[str] = Field(min_length=1, max_length=60)
    file_read: RootFile | None = None
    generated_outputs: RootFile | None = None
    workspace: RootFile | None = None
    workspace_catalog: RootFile | None = None
    checks: RootFile | None = None
    git_review: RootFile | None = None
    git_patch: RootFile | None = None
    git_evidence: RootFile | None = None
    agent_settings: RootFile | None = None
    agent_transitions: tuple[RootFile, ...] = Field(default=(), max_length=100)

    @model_serializer(mode="wrap")
    def preserve_absent_git_evidence(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        for name in ("git_evidence", "agent_settings", "agent_transitions"):
            if name not in self.model_fields_set:
                value.pop(name, None)
        return value

    @field_validator("owner_socket")
    @classmethod
    def absolute_socket(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("absolute_owner_socket_required")
        return value


class GitReviewRPCRecord(ControlModel):
    operation: str
    method: Literal["GET"]
    status: Literal[200]
    directory: str | None = None
    native_project_id: str | None = None
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    comparison_mode: Literal["working", "branch", "committed"] | None = None
    comparison_base: str | None = Field(default=None, max_length=255)


class GitReviewObservation(ControlModel):
    """Historical operator transcript; never a fresh owner or mutation proof."""

    format: Literal["installed-original-git-review-observation-v1"]
    passed: Literal[True]
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owners: tuple[HostOwnerEvidence, HostOwnerEvidence]
    requests: tuple[GitReviewRPCRecord, ...] = Field(min_length=12, max_length=12)
    original_processes_unchanged: Literal[True]
    live_bridge_counts_unchanged: Literal[True]
    native_database_bytes_read: Literal[False]
    native_http_mutations: int = Field(strict=True, ge=0, le=0)
    zulip_requests: int = Field(strict=True, ge=0, le=0)
    repeated_bundle_equal: Literal[True]
    physical_boundary_unchanged: Literal[True]
    saved_inventory_only: Literal[True]
    mutation_proof_issued: Literal[False]

    @field_validator(
        "passed",
        "original_processes_unchanged",
        "live_bridge_counts_unchanged",
        "native_database_bytes_read",
        "repeated_bundle_equal",
        "physical_boundary_unchanged",
        "saved_inventory_only",
        "mutation_proof_issued",
        mode="before",
    )
    @classmethod
    def literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("runtime_git_review_explicit_boolean_required")
        return value


class GitReviewQualification(ControlModel):
    format: Literal["qualified-original-git-review-v1"]
    operator_review: Literal["installed-evidence-reviewed-for-development-runtime"]
    reference: SessionRef
    native_project_id: str
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    git_component_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_component_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_enrollment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    physical_root: DirectoryScopeRoot
    operations: tuple[str, ...] = Field(min_length=6, max_length=6)
    observation: RootFile


class GitPatchObservation(ControlModel):
    format: Literal["installed-original-git-patch-observation-v1"]
    review: GitReviewObservation
    mode: Literal["working", "branch", "committed"]
    base: str | None = None
    selected_file: NativeDiffSummary
    original_patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_patch_bytes: int = Field(strict=True, gt=0, le=1024**2)
    exact_projection_verified: Literal[True]

    @field_validator("exact_projection_verified", mode="before")
    @classmethod
    def literal_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("runtime_git_patch_explicit_projection_required")
        return value


class GitPatchQualification(ControlModel):
    format: Literal["qualified-original-git-patch-v1"]
    operator_review: Literal["installed-evidence-reviewed-for-development-runtime"]
    reference: SessionRef
    review_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    git_component_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observations: tuple[RootFile, ...] = Field(min_length=1, max_length=3)


class RuntimeGrant(ControlModel):
    project_id: str
    user_id: int = Field(strict=True, gt=0)
    roles: frozenset[str] = Field(min_length=1)

    @field_validator("roles")
    @classmethod
    def roles_known(cls, value: frozenset[str]) -> frozenset[str]:
        if not value <= ROLES.keys():
            raise ValueError("unknown_runtime_grant_role")
        return value


class CreationQualification(ControlModel):
    anchor: SessionRef
    policy_template: RootFile
    rpc_evidence: RootFile


class AdoptionQualification(ControlModel):
    anchor: SessionRef
    policy: RootFile
    lineage: RootFile | None = None


class LineageRPCRecord(ControlModel):
    operation: str = Field(min_length=1, max_length=255)
    method: Literal["GET"]
    status: StrictInt = Field(ge=200, le=200)
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


LINEAGE_CHECKS = frozenset(
    {
        "original_ids_and_parents",
        "complete_resource_reconciliation",
        "queued_and_pending_kinds",
        "same_owner_and_feed",
        "original_five_second_deadline",
        "foreign_and_unseen_children_rejected",
        "policy_and_owner_changes_rejected",
        "no_native_writes",
        "volatile_progress_preserves_identity",
        "settled_message_and_tool_boundaries_remain_exact",
    }
)


class LineageObservation(ControlModel):
    """Root-reviewed offline semantic evidence, never a live execution proof."""

    format: Literal["installed-original-lineage-resource-observation-v1"]
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    upstream_version: Literal["2.0.32"]
    semantics: Literal["original-session-lineage-resources-v2"]
    qualification_scope: Literal["leaf", "tree"]
    graph: ExistingSessionGraphObservation
    checks: dict[str, StrictBool] = Field(min_length=10, max_length=10)
    requests: tuple[LineageRPCRecord, ...] = Field(min_length=1, max_length=10000)
    native_http_mutations: StrictInt = Field(ge=0, le=0)
    native_database_bytes_read: StrictBool

    @model_validator(mode="after")
    def independent_semantics(self) -> "LineageObservation":
        if (
            self.checks.keys() != LINEAGE_CHECKS
            or any(value is not True for value in self.checks.values())
            or self.native_database_bytes_read
            or self.graph.graph_sha256 != graph_identity(self.graph.nodes)
            or self.qualification_scope == "tree"
            and len(self.graph.nodes) < 2
            or self.qualification_scope == "leaf"
            and len(self.graph.nodes) != 1
            or (self.graph.reference.backend_id, self.graph.reference.backend_identity)
            != (self.backend_id, self.backend_identity)
        ):
            raise ValueError("runtime_lineage_independent_original_semantics_required")
        return self


class LineageQualification(ControlModel):
    format: Literal["qualified-original-session-lineage-v1"]
    operator_review: Literal["installed-evidence-reviewed-for-development-runtime"]
    observation: RootFile


class CreationRPCQualification(ControlModel):
    """Operator-reviewed protocol evidence, explicitly not Human acceptance."""

    format: Literal["installed-root-creation-rpc-v1"]
    passed: Literal[True]
    evidence_scope: Literal["operator-rpc-only-not-human-acceptance"]
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    upstream_version: Literal["2.0.32"]
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operations: frozenset[Literal["session.create", "session.get"]] = Field(min_length=2)
    # Keep the actual operator transcript separately pinned and root-managed.
    observation: RootFile
    request_record: RootFile
    response_record: RootFile


def creation_observation(rpc: CreationRPCQualification, template: CreationPolicyTemplate) -> None:
    observation = strict_loads(rpc.observation.read())
    request = strict_loads(rpc.request_record.read())
    response = strict_loads(rpc.response_record.read())
    if not all(isinstance(doc, dict) for doc in (observation, request, response)):
        raise ValueError("runtime_creation_rpc_records_required")
    body, intent, raw = request.get("body"), request.get("intent"), response.get("data")
    if not all(isinstance(doc, dict) for doc in (body, intent, raw)):
        raise ValueError("runtime_creation_rpc_records_required")
    sid = body.get("id")
    scope = template.creation.scope
    if (
        not isinstance(sid, str)
        or len(sid) != 41
        or not sid.startswith("ses_jtoz_")
        or any(c not in "0123456789abcdef" for c in sid[9:])
        or sid == rpc.reference.upstream_session_id
        or observation.get("passed") is not True
        or observation.get("rpc_shape_and_readback_verified") is not True
        or observation.get("stable_double_get") is not True
        or observation.get("owner_unchanged") is not True
        or type(observation.get("native_post_attempts")) is not int
        or observation["native_post_attempts"] != 1
        or type(observation.get("create_http_status")) is not int
        or observation["create_http_status"] != 200
        or observation.get("human_acceptance") is not False
        or observation.get("normal_creation_workflow_qualified") is not False
        or observation.get("request_body_sha256") != digest(body)
        or request.get("body_sha256") != digest(body)
        or request.get("intent_sha256") != digest(intent)
        or intent.get("operator_not_human") is not True
        or intent.get("reference_scope") != scope.model_dump(mode="json")
        or intent.get("native_project_id") != template.creation.native_project_id
        or intent.get("owner_epoch") != rpc.owner_epoch
        or intent.get("source_policy_sha256") != template.source.fingerprint_sha256
        or intent.get("requested_session_id") != sid
        or set(body)
        != {"id", "location", "agent", "permissions", "metadata"}
        | ({"title"} if "title" in body else set())
        or body.get("location") != {"directory": scope.canonical_directory}
        or body.get("agent") != template.creation.agent_id
        or body.get("permissions")
        != [p.model_dump(mode="json") for p in template.creation.permissions]
        or not isinstance(body.get("metadata"), dict)
        or not body["metadata"]
        or raw.get("projectID") != template.creation.native_project_id
        or any(raw.get(key) != body.get(key) for key in body)
        or any(
            observation.get(key) != sid
            for key in ("requested_session_id", "returned_session_id", "created_session_id")
        )
    ):
        raise ValueError("runtime_creation_observed_template_or_rpc_changed")


class RuntimeEnrollment(ControlModel):
    format: Literal[
        "qualified-consumer-runtime-v1",
        "qualified-consumer-runtime-v2",
        "qualified-consumer-runtime-v3",
        "qualified-consumer-runtime-v4",
        "qualified-consumer-runtime-v5",
        "qualified-consumer-runtime-v6",
        "qualified-consumer-runtime-v7",
    ]
    realm: RealmQualification
    backends: tuple[NativeQualification, ...] = Field(min_length=1, max_length=20)
    grants: tuple[RuntimeGrant, ...] = Field(min_length=1, max_length=200)
    operator_review: Literal["installed-evidence-reviewed-for-development-runtime"]
    directory_scope: RootFile | None = None
    directory_socket: Path | None = None
    creation_projects: tuple[CreationQualification, ...] = Field(default=(), max_length=20)
    adoption_projects: tuple[AdoptionQualification, ...] = Field(default=(), max_length=20)
    generated_roots: tuple[SessionRef, ...] | None = Field(default=None, max_length=20)
    workspace_roots: tuple[SessionRef, ...] | None = Field(default=None, max_length=20)

    @model_serializer(mode="wrap")
    def preserve_legacy_scope(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if "workspace_roots" not in self.model_fields_set:
            value.pop("workspace_roots", None)
        if (
            self.format != "qualified-consumer-runtime-v7"
            and "generated_roots" not in self.model_fields_set
        ):
            value.pop("generated_roots", None)
        return value

    def generated_references(self) -> frozenset[SessionRef]:
        """Explicit automatic-return scope; never infer it from a partial packet.

        V6 still requires every original Root. V7 names the exact nonempty set
        whose unchanged per-Root metadata and byte certificates are supplied.
        Calling this again at composition also rejects mutated model copies.
        """
        qualified = frozenset(b.reference for b in self.backends if b.generated_outputs is not None)
        if self.format == "qualified-consumer-runtime-v7":
            selected = self.generated_roots
            if (
                selected is None
                or (not selected and self.workspace_roots is None)
                or any(not isinstance(ref, SessionRef) for ref in selected)
                or len(selected) != len(set(selected))
                or frozenset(selected) != qualified
                or not qualified <= frozenset(b.reference for b in self.backends)
            ):
                raise ValueError("runtime_v7_requires_exact_explicit_generated_roots")
            return qualified
        if "generated_roots" in self.model_fields_set:
            raise ValueError("runtime_explicit_generated_roots_require_v7")
        if self.format == "qualified-consumer-runtime-v6":
            if any(b.generated_outputs is None for b in self.backends):
                raise ValueError("runtime_v6_requires_every_original_generated_qualification")
            return qualified
        if qualified:
            raise ValueError("runtime_generated_evidence_requires_v6")
        return frozenset()

    def workspace_references(self) -> frozenset[SessionRef]:
        """Explicit incoming scope; without the field every enrolled Root is required."""
        qualified = frozenset(b.reference for b in self.backends if b.workspace is not None)
        selected = self.workspace_roots
        if "workspace_roots" not in self.model_fields_set:
            return qualified
        if self.format != "qualified-consumer-runtime-v7":
            raise ValueError("runtime_explicit_workspace_roots_require_v7")
        if (
            not selected
            or any(not isinstance(ref, SessionRef) for ref in selected)
            or len(selected) != len(set(selected))
            or frozenset(selected) != qualified
        ):
            raise ValueError("runtime_v7_requires_exact_explicit_workspace_roots")
        return qualified

    @field_validator("directory_socket")
    @classmethod
    def absolute_directory_socket(cls, value: Path | None) -> Path | None:
        if value is not None and (not value.is_absolute() or ".." in value.parts):
            raise ValueError("absolute_directory_socket_required")
        return value

    @model_validator(mode="after")
    def unique_scope(self) -> "RuntimeEnrollment":
        adoption_ids = [item.anchor.project_id for item in self.adoption_projects]
        if (
            len(set(adoption_ids)) != len(adoption_ids)
            or self.adoption_projects
            and self.format == "qualified-consumer-runtime-v1"
            or any(
                item.anchor not in {b.reference for b in self.backends}
                for item in self.adoption_projects
            )
        ):
            raise ValueError("runtime_adoption_explicit_unique_backend_anchor_required")
        if any(
            b.git_review is not None or b.git_patch is not None or b.git_evidence is not None
            for b in self.backends
        ) and self.format not in {
            "qualified-consumer-runtime-v5",
            "qualified-consumer-runtime-v6",
            "qualified-consumer-runtime-v7",
        }:
            raise ValueError("runtime_git_review_requires_explicit_v5_physical_enrollment")
        self.generated_references()
        self.workspace_references()
        creation_ids = [c.anchor.project_id for c in self.creation_projects]
        if len(set(creation_ids)) != len(creation_ids):
            raise ValueError("runtime_creation_project_must_have_one_explicit_anchor")
        if self.creation_projects and self.format == "qualified-consumer-runtime-v1":
            raise ValueError("runtime_creation_requires_backend_scoped_v2_or_later")
        if any(
            c.anchor not in {b.reference for b in self.backends} for c in self.creation_projects
        ):
            raise ValueError("runtime_creation_anchor_must_already_be_enrolled")
        ids = [b.reference.backend_id for b in self.backends]
        project_ids = [b.reference.project_id for b in self.backends]
        grants = [(g.project_id, g.user_id) for g in self.grants]
        if len(set(grants)) != len(grants):
            raise ValueError("runtime_enrollment_scope_must_be_unique")
        has_workspace = (
            self.realm.source_uploads is not None
            or self.realm.source_evidence is not None
            or any(b.workspace is not None for b in self.backends)
        )
        if self.format == "qualified-consumer-runtime-v4" or (
            self.format
            in {
                "qualified-consumer-runtime-v5",
                "qualified-consumer-runtime-v6",
                "qualified-consumer-runtime-v7",
            }
            and has_workspace
        ):
            if (
                self.realm.source_uploads is None
                or self.realm.source_evidence is None
                or (
                    "workspace_roots" not in self.model_fields_set
                    and any(b.workspace is None for b in self.backends)
                )
            ):
                raise ValueError("runtime_source_and_workspace_qualifications_must_be_complete")
        elif has_workspace:
            raise ValueError("runtime_workspace_evidence_requires_v4_or_v5")
        if self.format in {
            "qualified-consumer-runtime-v5",
            "qualified-consumer-runtime-v6",
            "qualified-consumer-runtime-v7",
        }:
            if (
                self.directory_scope is None
                or self.directory_socket is None
                or any(b.workspace_catalog is None for b in self.backends)
            ):
                raise ValueError("runtime_v5_requires_explicit_catalog_qualifications")
        elif (
            self.directory_scope is not None
            or self.directory_socket is not None
            or any(b.workspace_catalog is not None for b in self.backends)
        ):
            raise ValueError("runtime_catalog_evidence_requires_v5")
        if self.format in {
            "qualified-consumer-runtime-v3",
            "qualified-consumer-runtime-v4",
            "qualified-consumer-runtime-v5",
            "qualified-consumer-runtime-v6",
            "qualified-consumer-runtime-v7",
        }:
            if (
                self.realm.file_upload is None
                or self.realm.upload_realm_id is None
                or any(
                    b.file_read is None or "fs.read" not in b.verified_operations
                    for b in self.backends
                )
            ):
                raise ValueError("runtime_v3_requires_explicit_file_qualifications")
        elif (
            self.realm.file_upload is not None
            or self.realm.upload_realm_id is not None
            or self.realm.file_private_networks
            or any(b.file_read is not None for b in self.backends)
        ):
            raise ValueError("runtime_file_evidence_requires_v3")
        if self.format == "qualified-consumer-runtime-v1":
            if (
                len(set(ids)) != len(ids)
                or len(set(project_ids)) != len(project_ids)
                or any(b.protocol_scope != "session" for b in self.backends)
            ):
                raise ValueError("runtime_v1_requires_unique_backend_project_and_session_protocol")
        native_ids = [
            (b.reference.backend_id, b.reference.upstream_session_id) for b in self.backends
        ]
        if len(set(native_ids)) != len(native_ids):
            raise ValueError("native_root_cannot_have_multiple_enrollment_aliases")
        owner_scopes: dict[str, tuple[object, ...]] = {}
        project_scopes: dict[str, tuple[object, ...]] = {}
        for b in self.backends:
            ref = b.reference
            owner_scope = (
                ref.backend_identity,
                b.owner,
                b.owner_socket,
                b.schema_file,
                b.verified_operations,
            )
            project_scope = (
                ref.backend_id,
                ref.backend_identity,
                ref.canonical_directory,
                b.native_project_id,
            )
            if ref.backend_id in owner_scopes and owner_scopes[ref.backend_id] != owner_scope:
                raise ValueError("runtime_backend_owner_or_contract_conflict")
            if ref.project_id in project_scopes and project_scopes[ref.project_id] != project_scope:
                raise ValueError("runtime_project_directory_or_backend_conflict")
            owner_scopes[ref.backend_id] = owner_scope
            project_scopes[ref.project_id] = project_scope
        if any(g.project_id not in project_ids for g in self.grants):
            raise ValueError("runtime_grant_project_not_qualified")
        return self


def protocol_scope_matches(qualification: NativeQualification, observed: SessionRef) -> bool:
    target = qualification.reference
    if qualification.protocol_scope == "session":
        return observed == target
    return (
        observed.backend_id == target.backend_id
        and observed.backend_identity == target.backend_identity
    )


def adoption_protocol_sha256(anchor: NativeQualification) -> str:
    """Pin the existing reviewed backend codecs; a session-scoped pin cannot widen."""
    return digest(
        {
            "format": "runtime-original-session-backend-codecs-v1",
            "anchor": anchor.reference.model_dump(mode="json"),
            "protocol_scope": anchor.protocol_scope,
            "owner": anchor.owner.sha256,
            "schema": anchor.schema_file.sha256,
            "model": anchor.model_evidence.sha256,
            "outcomes": [item.sha256 for item in anchor.outcome_evidence],
            "operations": [item.sha256 for item in anchor.operation_evidence],
            "verified_operations": sorted(anchor.verified_operations),
        }
    )


def adoption_pins(
    enrollment: RuntimeEnrollment,
) -> dict[str, tuple[SessionAdoptionPolicy, LineageResourceAttestation | None]]:
    result = {}
    for item in enrollment.adoption_projects:
        anchor = next(row for row in enrollment.backends if row.reference == item.anchor)
        policy = SessionAdoptionPolicy.model_validate(strict_loads(item.policy.read()))
        source = NativePolicyEnrollment.model_validate(strict_loads(anchor.policy.read()))
        if (
            anchor.protocol_scope != "backend"
            or policy.anchor != anchor.reference
            or source.reference != anchor.reference
            or source.native_project_id != anchor.native_project_id
            or policy.contract_sha256 != anchor.schema_file.sha256
            or policy.contract_sha256 != source.contract_sha256
            or policy.contract_sha256 != INSTALLED_SCHEMA
            or policy.installed_protocol_evidence_sha256 != adoption_protocol_sha256(anchor)
            or not policy.operations <= source.operations
            or "check.run" in policy.operations
            or not READS <= anchor.verified_operations
        ):
            raise ValueError("runtime_adoption_original_backend_qualification_required")
        lineage = None
        if item.lineage is not None:
            pin = LineageQualification.model_validate(strict_loads(item.lineage.read()))
            observed = LineageObservation.model_validate(strict_loads(pin.observation.read()))
            owner = HostOwnerEnrollment.model_validate(strict_loads(anchor.owner.read()))
            scope = ProjectScope(**anchor.reference.model_dump(exclude={"upstream_session_id"}))
            operations = frozenset(request.operation for request in observed.requests)
            if (
                (observed.backend_id, observed.backend_identity)
                != (anchor.reference.backend_id, anchor.reference.backend_identity)
                or observed.contract_sha256 != policy.contract_sha256
                or observed.executable_sha256 != owner.executable_sha256
                or observed.upstream_version != owner.version
                or not scope.contains(observed.graph.reference)
                or any(
                    node.native_project_id != anchor.native_project_id
                    for node in observed.graph.nodes
                )
                or not READS <= operations <= anchor.verified_operations
            ):
                raise ValueError("runtime_adoption_original_lineage_qualification_required")
            lineage = LineageResourceAttestation(
                observed.backend_id,
                observed.backend_identity,
                observed.contract_sha256,
                LINEAGE_SEMANTICS,
                pin.observation.sha256,
                operations,
                observed.qualification_scope,
            )
        result[anchor.reference.project_id] = policy, lineage
    return result


def creation_pins(
    enrollment: RuntimeEnrollment,
) -> dict[str, tuple[CreationProject, CreationPolicyTemplate]]:
    """Validate all explicit creation pins without credentials or Native I/O."""
    result = {}
    for qualification in enrollment.creation_projects:
        anchor = next(b for b in enrollment.backends if b.reference == qualification.anchor)
        template = CreationPolicyTemplate.model_validate(
            strict_loads(qualification.policy_template.read())
        )
        rpc = CreationRPCQualification.model_validate(
            strict_loads(qualification.rpc_evidence.read())
        )
        creation_observation(rpc, template)
        owner = HostOwnerEnrollment.model_validate(strict_loads(anchor.owner.read()))
        policy = NativePolicyEnrollment.model_validate(strict_loads(anchor.policy.read()))
        if (
            anchor.protocol_scope != "backend"
            or template.source != policy
            or policy.reference != qualification.anchor
            or policy.native_project_id != anchor.native_project_id
            or rpc.reference != qualification.anchor
            or rpc.contract_sha256 != anchor.schema_file.sha256
            or rpc.contract_sha256 != INSTALLED_SCHEMA
            or rpc.executable_sha256 != owner.executable_sha256
            or rpc.upstream_version != owner.version
            or rpc.policy_template_sha256 != template.checksum()
            or not rpc.operations <= anchor.verified_operations
        ):
            raise ValueError("runtime_creation_original_qualification_changed")
        result[qualification.anchor.project_id] = (
            CreationProject(
                template=template.creation,
                owner_epoch=rpc.owner_epoch,
                contract_sha256=rpc.contract_sha256,
                policy_template_sha256=template.checksum(),
            ),
            template,
        )
    return result


def creation_settings(
    settings: Settings, enrollment: RuntimeEnrollment
) -> dict[str, tuple[CreationProject, CreationPolicyTemplate]]:
    if settings.runtime.session_creation_enabled and not enrollment.creation_projects:
        raise ValueError("runtime_creation_requires_explicit_project_and_rpc_qualifications")
    # Even disabled pins must validate; they are never implicitly selected.
    return creation_pins(enrollment)


def catalog_pins(
    enrollment: RuntimeEnrollment,
) -> tuple[DirectoryScopeEnrollment, dict[SessionRef, WorkspaceCatalogAttestation]]:
    """Root document normalization only; no socket, credentials or Native I/O."""
    if (
        enrollment.format
        not in {
            "qualified-consumer-runtime-v5",
            "qualified-consumer-runtime-v6",
            "qualified-consumer-runtime-v7",
        }
        or enrollment.directory_scope is None
        or enrollment.directory_socket is None
    ):
        raise ValueError("runtime_menus_require_v5_enrollment")
    pin = enrollment.directory_scope
    directories = DirectoryScopeEnrollment.model_validate(strict_loads(pin.read()))
    if {r.project_key for r in directories.roots} != {
        directory_project_key(b.reference) for b in enrollment.backends
    }:
        raise ValueError("runtime_catalog_physical_project_scope_changed")
    result = {}
    for b in enrollment.backends:
        if b.workspace_catalog is None:
            raise ValueError("runtime_original_catalog_certificate_required")
        owner = HostOwnerEnrollment.model_validate(strict_loads(b.owner.read()))
        policy = NativePolicyEnrollment.model_validate(strict_loads(b.policy.read()))
        if (
            policy.reference != b.reference
            or policy.contract_sha256 != b.schema_file.sha256
            or policy.native_project_id != b.native_project_id
        ):
            raise ValueError("runtime_catalog_original_policy_changed")
        attestation = catalog_qualification(
            b.workspace_catalog.read(),
            reference=b.reference,
            contract_sha256=b.schema_file.sha256,
            native_policy_sha256=policy.fingerprint_sha256,
            owner=owner,
            directories=directories,
            directory_enrollment_sha256=pin.sha256,
            evidence_sha256=b.workspace_catalog.sha256,
        )
        if (
            not {"fs.list", "fs.find"} <= attestation.operations
            or not attestation.operations <= b.verified_operations
        ):
            raise ValueError("runtime_catalog_list_find_operations_required")
        result[b.reference] = attestation
    return directories, result


def git_review_pin(
    qualification: NativeQualification, directory_pin: RootFile | None
) -> GitReviewAttestation | None:
    """Strict opt-in normalization only: no socket, Native I/O or watch changes."""
    pin = qualification.git_review
    if pin is None:
        return None
    if directory_pin is None:
        raise ValueError("runtime_git_review_physical_enrollment_required")
    q = qualification
    doc = GitReviewQualification.model_validate(strict_loads(pin.read()))
    observed = GitReviewObservation.model_validate(strict_loads(doc.observation.read()))
    owner = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
    policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
    directories = DirectoryScopeEnrollment.model_validate(strict_loads(directory_pin.read()))
    root = next(
        (r for r in directories.roots if r.project_key == directory_project_key(q.reference)),
        None,
    )
    if (
        q.schema_file.sha256 != INSTALLED_SCHEMA
        or OpenAPIProfile(q.schema_file.read()).sha256 != INSTALLED_SCHEMA
        or doc.reference != q.reference
        or doc.native_project_id != q.native_project_id
        or doc.contract_sha256 != q.schema_file.sha256
        or policy.reference != q.reference
        or policy.native_project_id != q.native_project_id
        or policy.contract_sha256 != q.schema_file.sha256
        or doc.native_policy_sha256 != policy.fingerprint_sha256
        or doc.semantics_sha256 != REVIEW_SEMANTICS
        or doc.git_component_sha256 != component_sha(git_review)
        or doc.directory_component_sha256 != component_sha(directory_scope)
        or doc.directory_enrollment_sha256 != directory_pin.sha256
        or doc.directory_config_sha256 != directories.config_sha256
        or doc.directory_implementation_sha256 != directories.implementation_sha256
        or (owner.backend_id, owner.backend_identity, owner.version)
        != (q.reference.backend_id, q.reference.backend_identity, "2.0.32")
        or (directories.server_uid, directories.client_uid) != (owner.native_uid, owner.client_uid)
        or root is None
        or root.directory != q.reference.canonical_directory
        or root.uid != owner.native_uid
        or doc.physical_root != root
        or len(set(doc.operations)) != len(doc.operations)
        or frozenset(doc.operations) != REVIEW_OPERATIONS
        or not REVIEW_OPERATIONS <= q.verified_operations
        or observed.reference != q.reference
        or observed.contract_sha256 != doc.contract_sha256
        or observed.native_policy_sha256 != doc.native_policy_sha256
        or observed.semantics_sha256 != doc.semantics_sha256
        or observed.owners[0].owner_epoch != observed.owners[1].owner_epoch
    ):
        raise ValueError("runtime_git_review_original_qualification_changed")
    for evidence in observed.owners:
        # Historical evidence is checked for coherent identity, not repurposed
        # as a live five-second owner lease. read_scope obtains fresh evidence.
        for key in (
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
        ):
            if getattr(evidence, key) != getattr(owner, key):
                raise ValueError("runtime_git_review_observed_owner_changed")
    # Per-operation duplicate counts cannot distinguish two complete snapshots
    # from adjacent repeated calls. Each recorded six-request boundary must be
    # independently complete; within-bundle order is deliberately unrestricted.
    if any(
        frozenset(row.operation for row in bundle) != REVIEW_OPERATIONS
        for bundle in (observed.requests[:6], observed.requests[6:])
    ):
        raise ValueError("runtime_git_review_two_complete_get_bundles_required")
    for operation in REVIEW_OPERATIONS:
        rows = [row for row in observed.requests if row.operation == operation]
        if len(rows) != 2 or rows[0].response_sha256 != rows[1].response_sha256:
            raise ValueError("runtime_git_review_two_complete_get_bundles_required")
        for row in rows:
            if (
                operation == "worktree.list"
                and (row.native_project_id != q.native_project_id or row.directory is not None)
                or operation != "worktree.list"
                and (
                    row.directory != q.reference.canonical_directory
                    or row.native_project_id is not None
                )
            ):
                raise ValueError("runtime_git_review_observed_get_scope_changed")
    return GitReviewAttestation(
        q.reference,
        q.schema_file.sha256,
        policy.fingerprint_sha256,
        REVIEW_SEMANTICS,
        doc.observation.sha256,
        REVIEW_OPERATIONS,
    )


def git_patch_pin(
    qualification: NativeQualification, directory_pin: RootFile | None
) -> GitPatchAttestation | None:
    """Separate positive patch evidence; never inherit a summary-only pin."""
    pin = qualification.git_patch
    if pin is None:
        return None
    review = git_review_pin(qualification, directory_pin)
    if review is None or qualification.git_review is None:
        raise ValueError("runtime_git_patch_summary_enrollment_required")
    doc = GitPatchQualification.model_validate(strict_loads(pin.read()))
    summary_doc = GitReviewQualification.model_validate(
        strict_loads(qualification.git_review.read())
    )
    summary = GitReviewObservation.model_validate(strict_loads(summary_doc.observation.read()))
    # Apply the same six-operation/owner boundaries to the independently
    # recorded positive patch bundles, rather than accepting arbitrary GETs.
    if (
        doc.reference != qualification.reference
        or doc.review_attestation_sha256 != review_attestation_sha256(review)
        or doc.semantics_sha256 != PATCH_SEMANTICS
        or doc.git_component_sha256 != component_sha(git_review)
    ):
        raise ValueError("runtime_git_patch_original_projection_changed")
    modes: set[str] = set()
    for observed_pin in doc.observations:
        observed = GitPatchObservation.model_validate(strict_loads(observed_pin.read()))
        if observed.mode in modes:
            raise ValueError("runtime_git_patch_duplicate_comparison_evidence")
        modes.add(observed.mode)
        if (
            (observed.mode == "working") != (observed.base is None)
            or observed.original_patch_sha256 != observed.selected_file.patch_sha256
            or observed.original_patch_bytes != observed.selected_file.patch_bytes
        ):
            raise ValueError("runtime_git_patch_original_projection_changed")
        if observed.base is not None:
            git_review.explicit_base(observed.base)
        raw = observed.review
        if (
            raw.reference != summary.reference
            or raw.contract_sha256 != summary.contract_sha256
            or raw.native_policy_sha256 != summary.native_policy_sha256
            or raw.semantics_sha256 != REVIEW_SEMANTICS
            or raw.owners[0].owner_epoch != raw.owners[1].owner_epoch
        ):
            raise ValueError("runtime_git_patch_original_observation_changed")
        for owner in raw.owners:
            for key in (
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
            ):
                if getattr(owner, key) != getattr(summary.owners[0], key):
                    raise ValueError("runtime_git_patch_original_owner_changed")
        if any(
            frozenset(r.operation for r in bundle) != REVIEW_OPERATIONS
            for bundle in (raw.requests[:6], raw.requests[6:])
        ):
            raise ValueError("runtime_git_patch_two_complete_get_bundles_required")
        for operation in REVIEW_OPERATIONS:
            rows = [r for r in raw.requests if r.operation == operation]
            if len(rows) != 2 or rows[0].response_sha256 != rows[1].response_sha256:
                raise ValueError("runtime_git_patch_repeated_bundle_changed")
            for row in rows:
                if (row.comparison_mode, row.comparison_base) != (
                    (observed.mode, observed.base) if operation == "vcs.diff" else (None, None)
                ):
                    raise ValueError("runtime_git_patch_observed_comparison_changed")
                if (
                    operation == "worktree.list"
                    and (
                        row.directory is not None
                        or row.native_project_id != qualification.native_project_id
                    )
                    or operation != "worktree.list"
                    and (
                        row.directory != qualification.reference.canonical_directory
                        or row.native_project_id is not None
                    )
                ):
                    raise ValueError("runtime_git_patch_observed_get_scope_changed")
    return GitPatchAttestation(
        qualification.reference,
        doc.review_attestation_sha256,
        PATCH_SEMANTICS,
        digest({"observations": [p.model_dump(mode="json") for p in doc.observations]}),
        frozenset(modes),
    )


def check_pin(qualification: NativeQualification) -> CheckExecutionAttestation | None:
    if qualification.checks is None:
        return None
    raw = strict_loads(qualification.checks.read())
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {"format", "passed", "catalog", "semantics_sha256", "installed_evidence_sha256"}
        or raw["format"] != "native-approved-checks-v1"
        or raw["passed"] is not True
    ):
        raise ValueError("runtime_check_qualification_document_required")
    catalog = CheckCatalog.model_validate(raw["catalog"])
    result = CheckExecutionAttestation(
        catalog, raw["semantics_sha256"], raw["installed_evidence_sha256"]
    )
    result.require(qualification.reference, qualification.schema_file.sha256)
    policy = NativePolicyEnrollment.model_validate(strict_loads(qualification.policy.read()))
    if (
        "check.run" not in policy.operations
        or not (CHECK_READS | {"session.shell"}) <= qualification.verified_operations
    ):
        raise ValueError("runtime_check_explicit_native_policy_and_operations_required")
    return result


def git_evidence_pin(
    qualification: NativeQualification, directory_pin: RootFile | None
) -> RootReviewedGitEvidencePin | None:
    """Explicit installed history-view opt-in; never executes a Native check."""
    if qualification.git_evidence is None:
        return None
    checks = check_pin(qualification)
    if checks is None or directory_pin is None:
        raise ValueError("runtime_git_evidence_check_and_physical_enrollment_required")
    q = qualification
    directories = DirectoryScopeEnrollment.model_validate(strict_loads(directory_pin.read()))
    physical = next(
        (
            root
            for root in directories.roots
            if root.project_key == directory_project_key(q.reference)
        ),
        None,
    )
    if physical is None:
        raise ValueError("runtime_git_evidence_original_physical_root_required")
    owner = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
    policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
    if (
        policy.reference != q.reference
        or policy.contract_sha256 != q.schema_file.sha256
        or policy.native_project_id != q.native_project_id
        or (directories.server_uid, directories.client_uid) != (owner.native_uid, owner.client_uid)
    ):
        raise ValueError("runtime_git_evidence_original_policy_or_owner_changed")
    return qualify_git_evidence(
        qualification.git_evidence.read(),
        reference=q.reference,
        catalog=checks.catalog,
        contract_sha256=q.schema_file.sha256,
        check_qualification_sha256=checks.enrollment_sha256,
        native_policy_sha256=policy.fingerprint_sha256,
        owner=owner,
        physical_root=physical,
        directory_enrollment_sha256=directory_pin.sha256,
    )


def read_enrollment(settings: Settings) -> tuple[RuntimeEnrollment, str]:
    if not settings.runtime.enabled or settings.runtime.enrollment_file is None:
        raise ValueError("qualified_runtime_not_enabled")
    raw = root_bytes(settings.runtime.enrollment_file)
    value = RuntimeEnrollment.model_validate(strict_loads(raw))
    creation_settings(settings, value)
    adoption_pins(value)
    if settings.runtime.generated_returns_enabled and value.format not in {
        "qualified-consumer-runtime-v6",
        "qualified-consumer-runtime-v7",
    }:
        raise ValueError("runtime_generated_returns_require_v6")

    if settings.runtime.file_returns_enabled and value.format not in {
        "qualified-consumer-runtime-v3",
        "qualified-consumer-runtime-v4",
        "qualified-consumer-runtime-v5",
        "qualified-consumer-runtime-v6",
        "qualified-consumer-runtime-v7",
    }:
        raise ValueError("runtime_file_returns_require_v3_enrollment")
    if settings.runtime.workspace_inputs_enabled and (
        value.format
        not in {
            "qualified-consumer-runtime-v4",
            "qualified-consumer-runtime-v5",
            "qualified-consumer-runtime-v6",
            "qualified-consumer-runtime-v7",
        }
        or value.realm.source_uploads is None
    ):
        raise ValueError("runtime_workspace_inputs_require_v4_or_v5_source_enrollment")
    if settings.runtime.workspace_menus_enabled and value.format not in {
        "qualified-consumer-runtime-v5",
        "qualified-consumer-runtime-v6",
        "qualified-consumer-runtime-v7",
    }:
        raise ValueError("runtime_menus_require_v5_enrollment")
    if value.format in {
        "qualified-consumer-runtime-v5",
        "qualified-consumer-runtime-v6",
        "qualified-consumer-runtime-v7",
    }:
        catalog_pins(value)
    realm = next(
        (x for x in settings.zulip_realms if x.id == value.realm.realm_id and x.enabled), None
    )
    if realm is None or not realm.allowed_channel_ids or not realm.allowed_user_ids:
        raise ValueError("runtime_requires_enabled_explicit_realm_scope")
    if realm.url != value.realm.url or realm.bot_email != value.realm.bot_email:
        raise ValueError("runtime_zulip_origin_or_bot_configuration_changed")
    backends = {x.id: x for x in settings.opencode_backends if x.enabled}
    for backend in backends.values():
        approve_observer_plugins(
            backend.id, tuple((p.id, str(p.path), p.sha256) for p in backend.observer_plugins)
        )
    projects = {x.id: x for x in settings.projects if x.enabled}
    if (
        set(backends) != {b.reference.backend_id for b in value.backends}
        or set(projects) != {b.reference.project_id for b in value.backends}
        or {x.id for x in settings.zulip_realms if x.enabled} != {value.realm.realm_id}
    ):
        raise ValueError("runtime_configuration_and_qualification_scope_differ")
    for pin in value.realm.evidence:
        pin.read()
    if value.realm.file_upload is not None:
        pin = value.realm.file_upload
        assert value.realm.upload_realm_id is not None
        upload_qualification(
            pin.read(),
            realm_id=realm.id,
            realm_url=realm.url,
            numeric_realm_id=value.realm.upload_realm_id,
            bot_user_id=value.realm.bot_user_id,
            zulip_version=value.realm.zulip_version,
            feature_level=value.realm.feature_level,
            evidence_sha256=pin.sha256,
        )
        download_origin(realm.url, value.realm.file_private_networks)
        if (
            settings.runtime.file_returns_enabled
            and realm.url not in settings.attachments.allowed_download_origins
        ):
            raise ValueError("runtime_file_returns_require_explicit_original_download_origin")
    if value.realm.source_uploads is not None:
        assert value.realm.source_evidence is not None
        source_qualification(
            value.realm.source_evidence.read(),
            value.realm.source_uploads.read(),
            config_sha256=value.realm.source_uploads.sha256,
            realm_id=realm.id,
            realm_url=realm.url,
            bot_user_id=value.realm.bot_user_id,
            allowed_channels=frozenset(realm.allowed_channel_ids),
            allowed_users=frozenset(realm.allowed_user_ids),
        )
    namespace_paths: dict[Path, WorkspaceNamespacePin] = {}
    for b in value.backends:
        ref, project = b.reference, projects[b.reference.project_id]
        if (
            project.backend_id != ref.backend_id
            or project.realm_id != realm.id
            or project.workspace_root != ref.canonical_directory
        ):
            raise ValueError("runtime_project_configuration_changed")
        owner = HostOwnerEnrollment.model_validate(strict_loads(b.owner.read()))
        if (owner.backend_id, owner.backend_identity, owner.url) != (
            ref.backend_id,
            ref.backend_identity,
            backends[ref.backend_id].base_url,
        ):
            raise ValueError("runtime_original_owner_configuration_changed")
        OpenAPIProfile(b.schema_file.read())
        if b.generated_outputs is not None:
            generated_qualification(
                b.generated_outputs.read(),
                reference=ref,
                contract_sha256=b.schema_file.sha256,
                executable_sha256=owner.executable_sha256,
                evidence_sha256=b.generated_outputs.sha256,
            )
        policy = NativePolicyEnrollment.model_validate(strict_loads(b.policy.read()))
        if (
            policy.reference != ref
            or policy.native_project_id != b.native_project_id
            or policy.contract_sha256 != b.schema_file.sha256
        ):
            raise ValueError("runtime_policy_scope_changed")
        if b.file_read is not None:
            native_file_qualification(
                b.file_read.read(),
                reference=ref,
                contract_sha256=b.schema_file.sha256,
                native_policy_sha256=policy.fingerprint_sha256,
                executable_sha256=owner.executable_sha256,
                evidence_sha256=b.file_read.sha256,
            )
        if b.workspace is not None:
            namespace = workspace_qualification(
                b.workspace.read(),
                reference=ref,
                contract_sha256=b.schema_file.sha256,
                policy_sha256=policy.fingerprint_sha256,
                owner=owner,
            )
            previous = namespace_paths.setdefault(namespace.path, namespace)
            if previous != namespace:
                raise ValueError("runtime_workspace_namespace_alias_conflict")
        check_pin(b)
        git_review_pin(b, value.directory_scope)
        git_patch_pin(b, value.directory_scope)
        git_evidence_pin(b, value.directory_scope)
        model = strict_loads(b.model_evidence.read())
        if (
            not isinstance(model, dict)
            or model.get("passed") is not True
            or model.get("semantics_sha256") != MODEL_SETTING_SEMANTICS
            or not protocol_scope_matches(b, SessionRef.model_validate(model.get("reference")))
        ):
            raise ValueError("runtime_model_semantics_evidence_invalid")
        outcomes = set()
        for pin in b.outcome_evidence:
            doc = strict_loads(pin.read())
            if not isinstance(doc, dict) or doc.get("passed") is not True:
                raise ValueError("runtime_outcome_observation_not_passed")
            evidence = NativeResourceTurn.model_validate(doc.get("evidence"))
            if (
                not protocol_scope_matches(b, evidence.correlation.reference)
                or evidence.contract_sha256 != b.schema_file.sha256
                or evidence.semantics_sha256 != RESOURCE_SEMANTICS
            ):
                raise ValueError("runtime_outcome_observation_scope_changed")
            outcomes.add(evidence.turn.outcome)
        if not outcomes:
            raise ValueError("runtime_requires_observed_native_outcome")
        for pin in b.operation_evidence:
            pin.read()
    if any(g.user_id not in realm.allowed_user_ids for g in value.grants):
        raise ValueError("runtime_grants_outside_explicit_human_scope")
    return value, hashlib.sha256(raw).hexdigest()


def require_agent_switch_scope(
    agent_roots: Mapping[SessionRef, object], tree_roots: tuple[SessionRef, ...]
) -> None:
    """A tree registration pins each node policy, and its upkeep stops on any drift."""
    if any(root in agent_roots for root in tree_roots):
        raise ValueError("runtime_agent_switching_tree_root_not_qualified")


class OriginalRuntimeObserver:
    def __init__(
        self,
        feed: V2PublicFeed,
        proofs: V2LeafResourceProofs,
        ref: SessionRef,
        recovery: OwnedCheckRecovery | None = None,
    ) -> None:
        self.feed, self.proofs, self.ref, self.recovery = feed, proofs, ref, recovery
        self.mode: Literal[
            "unstarted", "strict", "readonly-owned-check", "readonly-awaiting-idle"
        ] = "unstarted"
        self.owner_epoch: str | None = None
        self.checked_at = 0.0
        self.retry_at = 0.0
        self._mode_transition_at = time.time()
        self._mode_context: tuple[object, ...] | None = None
        self._mode_fact: RootModeFact | None = None

    def _current_mode_context(self) -> tuple[object, ...]:
        index, task = self.feed.index, self.feed.task
        if (
            index is None
            or task is None
            or task.done()
            or task.cancelling()
            or self.owner_epoch is None
            or index.owner_epoch != self.owner_epoch
        ):
            raise ValueError("runtime_mode_feed_unavailable")
        return (index, task, self.feed.transport.attestation, self.proofs.generation(self.ref))

    def _same_mode_context(self, context: tuple[object, ...] | None) -> bool:
        previous = self._mode_context
        return bool(
            previous is not None
            and context is not None
            and all(a is b for a, b in zip(previous[:3], context[:3], strict=True))
            and previous[3:] == context[3:]
        )

    def _set_mode(
        self,
        mode: Literal["strict", "readonly-owned-check", "readonly-awaiting-idle"],
    ) -> None:
        try:
            context = self._current_mode_context()
        except Exception:
            # Optional observation cannot introduce a business-worker failure.
            context = None
        now = time.time()
        if self.mode != mode or not self._same_mode_context(context):
            self._mode_transition_at = now
        self.mode, self.checked_at, self._mode_context = mode, now, context

    def mode_fact(self) -> RootModeFact:
        # This does not call certified_epoch (which can revoke a watch), read
        # Native resources, renew a scope or alter the controller workflow.
        mode: RootMode = self.mode
        reasons: dict[RootMode, ModeReason] = {
            "unstarted": "startup-incomplete",
            "strict": "strict-observation",
            "readonly-owned-check": "owned-check-recovery",
            "readonly-awaiting-idle": "positive-idle-required",
        }
        reason = reasons[self.mode]
        try:
            if self.mode != "unstarted" and not self._same_mode_context(
                self._current_mode_context()
            ):
                raise ValueError("runtime_mode_generation_changed")
        except Exception:
            mode, reason = "unavailable", "feed-unavailable"
        previous = self._mode_fact
        transition = (
            previous.transition_at
            if previous is not None and previous.mode == mode and previous.reason == reason
            else time.time()
            if mode == "unavailable"
            else self._mode_transition_at
        )
        # Same mode in a newly qualified generation is a real transition.
        if mode != "unavailable":
            transition = self._mode_transition_at
        fact = RootModeFact(
            scope_key=scope_key(self.ref), mode=mode, reason=reason, transition_at=float(transition)
        )
        self._mode_fact = fact
        return fact

    async def start(self) -> None:
        await self.feed.start()
        await self.start_root()

    async def start_root(self) -> None:
        scope = await self.proofs.read_scope(self.ref)
        self.owner_epoch = scope.owner_epoch
        try:
            await self.proofs.watch(self.ref)
        except BackgroundRootWork as work:
            await self.degrade(work)
        else:
            self._set_mode("strict")

    async def degrade(self, work: BackgroundRootWork) -> None:
        self.proofs.revoke_watch(self.ref)
        if self.recovery is None:
            raise work
        if work.reference != self.ref or work.owner_epoch != self.owner_epoch:
            raise ContractError("runtime_check_recovery_original_scope_changed")
        owned = await self.recovery.classify(work)
        if (
            owned.reference != self.ref
            or owned.owner_epoch != self.owner_epoch
            or owned.connection_epoch != work.connection_epoch
            or owned.shell_ids != tuple(sorted(work.running_shell_ids))
            or not self.proofs.is_current_background(work)
        ):
            raise ContractError("runtime_check_recovery_ownership_changed")
        self._set_mode("readonly-owned-check")
        self.retry_at = time.monotonic() + 2

    async def retry_recovery(self) -> None:
        if self.mode not in {"readonly-owned-check", "readonly-awaiting-idle"}:
            return
        self.retry_at = time.monotonic() + 2
        scope = await self.proofs.read_scope(self.ref)
        if scope.owner_epoch != self.owner_epoch:
            self.proofs.revoke_watch(self.ref)
            raise ContractError("runtime_check_recovery_owner_changed")
        try:
            witness = await self.proofs.watch(self.ref, require_idle=True)
        except BackgroundRootWork as work:
            await self.degrade(work)
        except PositiveIdleRequired as pending:
            witness = pending.witness
            if (
                witness.reference != self.ref
                or witness.owner_epoch != self.owner_epoch
                or witness.connection_epoch != scope.connection_epoch
                or self.proofs.fence(self.ref, state_only=witness.state_only_fence)
                != witness.resource_fence
                or not witness.issued_at <= time.time() < witness.issued_at + 5
            ):
                raise ContractError("runtime_check_recovery_pending_scope_changed") from None
            self._set_mode("readonly-awaiting-idle")
        else:
            if (
                witness.reference != self.ref
                or witness.owner_epoch != self.owner_epoch
                or witness.state != ExecutionState.IDLE
            ):
                self.proofs.revoke_watch(self.ref)
                raise ContractError("runtime_check_recovery_promotion_scope_changed")
            self._set_mode("strict")

    def lost_watch(self) -> bool:
        """A strict leaf Root without a watch refuses all work and nothing else restores it."""
        return (
            self.mode == "strict"
            and isinstance(self.proofs, V2LeafResourceProofs)
            and not isinstance(self.proofs, V2LineageResourceProofs)
            and not self.proofs.holds_watch(self.ref)
        )

    async def restore_watch(self) -> None:
        """Fresh reads prove the same owner again; a failure stays closed and retries."""
        self.retry_at = time.monotonic() + 5
        LOG.warning("root_watch_lost session=%s", self.ref.upstream_session_id)
        try:
            scope = await self.proofs.read_scope(self.ref)
            if scope.owner_epoch != self.owner_epoch:
                raise ContractError("root_watch_owner_changed")
            await self.proofs.watch(self.ref)
        except BackgroundRootWork as work:
            await self.degrade(work)
        except (ContractError, TransportError) as error:
            LOG.warning(
                "root_watch_restore_deferred session=%s error_type=%s",
                self.ref.upstream_session_id,
                type(error).__name__,
            )
        else:
            LOG.warning("root_watch_restored session=%s", self.ref.upstream_session_id)

    async def close(self) -> None:
        await self.feed.close()
        await self.feed.transport.close()

    async def pulse(self) -> None:
        await self.feed.current_owner()
        index = self.feed.index
        if index is None:
            raise ValueError("runtime_native_feed_unavailable")
        # Observations are wakeups only; fresh resource proofs authorize work.
        while index.pop() is not None:
            pass
        if time.monotonic() >= self.retry_at:
            await self.retry_recovery()

    async def pending(self, ref: SessionRef) -> tuple[str, ...]:
        witness = await self.proofs.capture(ref)
        return tuple(request for request, _kind in witness.pending)


@dataclass(frozen=True, eq=False)
class _DeferredOriginalRoot:
    """An exact configured tree root; deferral itself issues no resource proof."""

    observer: OriginalRuntimeObserver
    factory: V2ExistingSessionFactory
    entry: RegisteredSession = field(init=False)
    execution: V2ExecutionClient = field(init=False)
    lineage: LineageResourceAttestation = field(init=False)
    guard: V2ProjectPolicyGuard = field(init=False)

    def __post_init__(self) -> None:
        root = self.observer.ref
        entry = self.factory.registry.selected(root)
        lineage = self.factory.lineage
        execution = entry.execution
        guard = getattr(execution, "scope_guard", None)
        if (
            lineage is None
            or not isinstance(execution, V2ExecutionClient)
            or not isinstance(guard, V2ProjectPolicyGuard)
        ):
            raise ContractError("runtime_original_tree_startup_qualification_required")
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "execution", execution)
        object.__setattr__(self, "lineage", lineage)
        object.__setattr__(self, "guard", guard)
        self.require()

    def require(self) -> None:
        root = self.observer.ref
        if (
            self.factory.policy.anchor != root
            or self.factory.lineage is not self.lineage
            or self.lineage.qualification_scope != "tree"
            or self.factory.registry.selected(root) is not self.entry
            or self.entry.execution is not self.execution
            or self.execution.proofs is not self.observer.proofs
            or self.execution.scope_guard is not self.guard
            or self.execution.transport is not self.factory._transport
            or self.observer.proofs.feed is not self.observer.feed
            or self.observer.feed is not self.factory._feed
        ):
            raise ContractError("runtime_original_tree_startup_assembly_changed")

    async def activate(self, pipeline: ConsumerPipeline) -> None:
        # Only a real completed restoration can select a detached probe. The
        # tree pin and a journal DTO alone never qualify an original reader.
        self.require()
        root, factory = self.observer.ref, self.factory
        adoption = pipeline.adoption
        if (
            adoption is None
            or adoption.factories.get(root.project_id) is not factory
            or root.project_id not in adoption.updates
            or adoption.updates[root.project_id].factory is not factory
        ):
            raise AccessDenied("runtime_original_tree_startup_not_enrolled")
        authorize, locked = pipeline.graph_authority(root.project_id)
        cell = factory.registry.publication
        generation = cell.generation(root)
        if (
            generation is None
            or generation.root != root
            or generation.entries.get(root) is not self.entry
            or generation.record is None
            or generation.receipt is None
            or not isinstance(generation.context, GraphResourceContext)
            or generation.context.record != generation.record
        ):
            raise ContractError("runtime_original_tree_startup_restoration_required")
        context = generation.context
        context.require()
        async with asyncio.timeout(5):
            if await authorize() is not True:
                raise AccessDenied("runtime_original_tree_startup_authority_changed")
            await self.observer.start_root()
            snapshot, proof = await self.execution.qualified_snapshot(root)
            policy = self.guard.enrollments[root]
            first = await self.guard.bundle(root)
            second = await self.guard.bundle(root)
            if (
                not snapshot.reconciled
                or set(snapshot.descendants) != set(generation.descendants[root])
                or policy is not generation.enrollments[root]
                or first != second
                or first != (policy.fingerprint_sha256, proof.session_info_sha256)
            ):
                raise ContractError("runtime_original_tree_startup_proof_changed")

            def current() -> bool:
                self.require()
                cell.require_current(root, generation)
                context.require()
                self.execution.current(root, proof)
                return True

            # Re-read the authenticated head under the same operator/fence after
            # fresh resource/policy reads. A late prepared/superseding SQL head
            # cannot activate an earlier published generation.
            saved = await adoption.journal.recovery_records(
                pipeline.realm_id, root.project_id, lock_authority=locked, current=current
            )
            matched = next((item for item in saved if item.record.root == root), None)
            if (
                matched is None
                or matched.state != "active"
                or matched.receipt != generation.receipt
                or matched.record != generation.record
            ):
                raise ContractError("runtime_original_tree_startup_head_changed")
            current()


def fork_source(registry: SessionRegistry, ref: SessionRef) -> object:
    """The registered source Root's own policy guard, or None; never a copy."""
    entry = registry.sessions.get(ref)
    return getattr(getattr(entry, "execution", None), "scope_guard", None)


def created_roots(
    creators: tuple[V2CreatedRootFactory, ...],
) -> tuple[tuple[SessionRef, V2LeafResourceProofs], ...]:
    return tuple(item for factory in creators for item in factory.watched_roots())


class BackendRuntimeObserver:
    """One original-owner feed, with separately watched Root proof objects.

    Process liveness stays separate from per-Root mutation readiness. A typed,
    exactly owned running check may keep one Root read-only while peers run.
    """

    def __init__(
        self,
        feed: V2PublicFeed,
        roots: tuple[OriginalRuntimeObserver, ...],
        texts: LiveTextCollector | None = None,
        *,
        deferred: tuple[_DeferredOriginalRoot, ...] = (),
        created: Callable[[], tuple[tuple[SessionRef, V2LeafResourceProofs], ...]] | None = None,
    ) -> None:
        self.feed, self.roots, self.texts = feed, roots, texts
        self.created = created
        self._created_retry: dict[SessionRef, tuple[float, float]] = {}
        if len({id(item.observer) for item in deferred}) != len(deferred) or any(
            not any(item.observer is root for root in roots) or item.observer.feed is not feed
            for item in deferred
        ):
            raise ContractError("runtime_original_tree_startup_roots_changed")
        self.deferred = deferred
        self._recovery_cursor = 0

    def readiness(self) -> tuple[tuple[SessionRef, str], ...]:
        # Diagnostic only. No caller may turn these labels into a proof/cursor.
        return tuple((root.ref, root.mode) for root in self.roots)

    def mode_snapshot(self) -> tuple[RootModeFact, ...]:
        return tuple(root.mode_fact() for root in self.roots)

    async def start(self) -> None:
        await self.feed.start()
        for root in self.roots:
            await root.start_root()

    async def start_before_restoration(self) -> None:
        # The owner feed is needed by GET-only graph recovery. Exact opted-in
        # roots remain unqualified until the later activation resource completes.
        for item in self.deferred:
            item.require()
        await self.feed.start()
        for root in self.roots:
            if not any(item.observer is root for item in self.deferred):
                await root.start_root()

    async def close(self) -> None:
        await self.feed.close()
        await self.feed.transport.close()

    async def pulse(self) -> None:
        await self.feed.current_owner()
        index = self.feed.index
        if index is None:
            raise ValueError("runtime_native_feed_unavailable")
        if self.texts is not None:
            await self.texts.collect()
        while index.pop() is not None:
            pass
        # One due Root per pulse; rotate so a changing Root cannot starve peers.
        count = len(self.roots)
        for offset in range(count):
            position = (self._recovery_cursor + offset) % count
            root = self.roots[position]
            if time.monotonic() < root.retry_at:
                continue
            if root.mode in {"readonly-owned-check", "readonly-awaiting-idle"}:
                self._recovery_cursor = (position + 1) % count
                await root.retry_recovery()
                break
            if root.lost_watch():
                self._recovery_cursor = (position + 1) % count
                await root.restore_watch()
                break
        await self.restore_created()

    async def restore_created(self) -> None:
        """Roots created at runtime get the same lost-watch recovery as configured ones."""
        if self.created is None:
            return
        now = time.monotonic()
        live = self.created()
        current = dict(live)
        self._created_retry = {
            ref: due
            for ref, due in self._created_retry.items()
            if ref in current and not current[ref].holds_watch(ref)
        }
        for ref, proofs in live:
            due, interval = self._created_retry.get(ref, (0.0, 2.5))
            if (
                proofs.feed is not self.feed
                or isinstance(proofs, V2LineageResourceProofs)
                or proofs.holds_watch(ref)
                or now < due
            ):
                continue
            # Back off to one attempt (and two log lines) per minute for a Root
            # that stays unrestorable; a restored Root starts fresh next time.
            interval = min(60.0, interval * 2)
            self._created_retry[ref] = (now + interval, interval)
            LOG.warning("root_watch_lost session=%s", ref.upstream_session_id)
            try:
                scope = await proofs.read_scope(ref)
                index = self.feed.index
                if index is None or scope.owner_epoch != index.owner_epoch:
                    raise ContractError("root_watch_owner_changed")
                await proofs.watch(ref)
            except (BackgroundRootWork, ContractError, TransportError) as error:
                LOG.warning(
                    "root_watch_restore_deferred session=%s error_type=%s",
                    ref.upstream_session_id,
                    type(error).__name__,
                )
            else:
                LOG.warning("root_watch_restored session=%s", ref.upstream_session_id)
            return  # One created Root per pulse, like configured Roots.


@dataclass
class _ZulipScopeIdentity:
    task: object
    attestation: object
    qualification: object
    deadline: float
    requests: int = 0
    closed: bool = False
    bot_user: tuple[int, bool, bool] | None = None


class ZulipRuntimeIdentity:
    """One-second normal guard; bounded task-local coalescing only for scope GETs."""

    def __init__(self, client: ZulipClient, qualification: RealmQualification) -> None:
        self.client, self.qualification = client, qualification
        self._until = 0.0
        self._lock = asyncio.Lock()
        self._scope: ContextVar[_ZulipScopeIdentity | None] = ContextVar(
            "zulip_scope_identity", default=None
        )
        self._refused_release: tuple[object, object] | None = None

    async def _refresh(
        self, *, bot_user: list[tuple[int, bool, bool] | None] | None = None
    ) -> bool:
        self._until = 0.0
        me = await self.client.request("GET", "users/me")
        server = await self.client.server_settings()
        q = self.qualification
        ok = (
            type(me.get("user_id")) is int
            and me["user_id"] == q.bot_user_id
            and me.get("is_bot") is True
            and type(me.get("bot_owner_id")) is int
            and me["bot_owner_id"] == q.bot_owner_id
            and type(me.get("role")) is int
            and me["role"] == 400
            and server.get("realm_url") == q.url
            and self._release_matches(server)
        )
        if ok:
            if bot_user is not None:
                if "is_active" not in me:
                    bot_user.append(None)  # The entire scope retains user.info.
                elif me["is_active"] is not True:
                    raise ZulipError("scope_own_bot_active_record_invalid")
                else:
                    bot_user.append((me["user_id"], True, True))
            self._until = time.monotonic() + 1.0
        return ok

    def _release_matches(self, server: Mapping[str, Any]) -> bool:
        q, live = (
            self.qualification,
            (server.get("zulip_version"), server.get("zulip_feature_level")),
        )
        if same_release_line(q.zulip_version, q.feature_level, *live):
            self._refused_release = None
            return True
        if live != self._refused_release:
            # Once per release seen: a server version is no secret, and without this
            # line a refused upgrade only shows as the bridge restarting.
            self._refused_release = live
            LOG.warning(
                "zulip_release_not_qualified version=%s feature_level=%s qualified=%s/%d",
                str(live[0])[:32],
                live[1] if type(live[1]) is int else "-",
                q.zulip_version,
                q.feature_level,
            )
        return False

    async def __call__(self) -> bool:
        # Writes, file access, cleanup and unscoped callers keep this exact TTL.
        if time.monotonic() < self._until:
            return True
        async with self._lock:
            if time.monotonic() < self._until:
                return True
            return await self._refresh()

    async def _fresh(self, *, bot_user: list[tuple[int, bool, bool] | None] | None = None) -> bool:
        async with self._lock:
            return await self._refresh(bot_user=bot_user)

    def _check_scope(self, state: _ZulipScopeIdentity) -> None:
        if (
            state.closed
            or asyncio.current_task() is not state.task
            or self.client.verify_identity is not self
            or self.client.attestation is not state.attestation
            or self.qualification is not state.qualification
        ):
            raise ZulipError("scope_identity_context_changed")
        if time.monotonic() >= state.deadline:
            raise ZulipReadUnavailable("scope_identity_window_expired")

    def scope_bot_user(self) -> dict[str, int | bool] | None:
        """Current task's own-Bot data only, never a Human ACL or TTL cache."""
        state = self._scope.get()
        if state is None:
            return None
        self._check_scope(state)
        if state.bot_user is None:
            return None
        identity, is_bot, is_active = state.bot_user
        return {"user_id": identity, "is_bot": is_bot, "is_active": is_active}

    async def scope_read(self) -> bool:
        state = self._scope.get()
        if state is None:
            return await self()
        self._check_scope(state)
        if state.requests >= 32:
            raise ZulipError("scope_identity_read_capacity_exceeded")
        state.requests += 1
        return True

    @asynccontextmanager
    async def scope_reads(self) -> AsyncIterator[None]:
        previous = self._scope.get()
        if previous is not None:
            self._check_scope(previous)
            yield  # Nested readers do not refresh or extend the parent window.
            self._check_scope(previous)
            return
        attestation, qualification = self.client.attestation, self.qualification
        if attestation is None or self.client.verify_identity is not self:
            raise ZulipError("scope_identity_context_not_enrolled")
        initial_bot: list[tuple[int, bool, bool] | None] = []
        if not await self._fresh(bot_user=initial_bot) or len(initial_bot) != 1:
            raise ZulipError("scope_identity_not_current")
        state = _ZulipScopeIdentity(
            asyncio.current_task(),
            attestation,
            qualification,
            time.monotonic() + 10,
            bot_user=initial_bot[0],
        )
        token = self._scope.set(state)
        try:
            self._check_scope(state)
            try:
                async with asyncio.timeout(10):
                    yield
                    self._check_scope(state)
                    final_bot: list[tuple[int, bool, bool] | None] = []
                    if (
                        not await self._fresh(bot_user=final_bot)
                        or len(final_bot) != 1
                        or state.bot_user is not None
                        and final_bot[0] != state.bot_user
                    ):
                        raise ZulipError("scope_identity_not_current")
                    self._check_scope(state)
            except TimeoutError:
                raise ZulipReadUnavailable("scope_identity_window_expired") from None
        finally:
            state.closed = True
            self._scope.reset(token)


def build_pipeline(
    settings: Settings,
    enrollment: RuntimeEnrollment,
    enrollment_sha: str,
    db: Database,
    fence: ConsumerFence,
    *,
    check_owner_for: OriginalCheckOwner | None = None,
) -> ConsumerPipeline:
    realm = next(x for x in settings.zulip_realms if x.id == enrollment.realm.realm_id)
    r = enrollment.realm
    generated_scope = enrollment.generated_references()
    if settings.runtime.generated_returns_enabled and not generated_scope:
        raise ValueError("runtime_generated_returns_require_explicit_qualified_scope")
    creation = creation_settings(settings, enrollment)
    if not settings.runtime.session_creation_enabled:
        creation = {}
    creation_factories: dict[str, V2CreatedRootFactory] = {}
    fork_factories: dict[str, V2CreatedRootFactory] = {}
    adoption = adoption_pins(enrollment)
    adoption_factories: dict[str, V2ExistingSessionFactory] = {}
    directories = None
    catalog_attestations: dict[SessionRef, WorkspaceCatalogAttestation] = {}
    if settings.runtime.workspace_menus_enabled or any(
        q.git_review is not None for q in enrollment.backends
    ):
        if settings.runtime.workspace_menus_enabled and not settings.runtime.file_returns_enabled:
            raise ValueError("runtime_menus_require_original_file_runtime")
        directory_enrollment, catalog_attestations = catalog_pins(enrollment)
        assert enrollment.directory_socket is not None
        directories = LinuxDirectoryScopeGuard(directory_enrollment, enrollment.directory_socket)
    file_upload: FileUploadAttestation | None = None
    if settings.runtime.file_returns_enabled:
        if (
            enrollment.format
            not in {
                "qualified-consumer-runtime-v3",
                "qualified-consumer-runtime-v4",
                "qualified-consumer-runtime-v5",
                "qualified-consumer-runtime-v6",
                "qualified-consumer-runtime-v7",
            }
            or r.file_upload is None
        ):
            raise ValueError("runtime_file_composition_requires_explicit_qualified_v3")
        if (
            r.upload_realm_id is None
            or realm.url not in settings.attachments.allowed_download_origins
        ):
            raise ValueError("runtime_file_original_origin_and_numeric_realm_required")
        file_upload = upload_qualification(
            r.file_upload.read(),
            realm_id=realm.id,
            realm_url=realm.url,
            numeric_realm_id=r.upload_realm_id,
            bot_user_id=r.bot_user_id,
            zulip_version=r.zulip_version,
            feature_level=r.feature_level,
            evidence_sha256=r.file_upload.sha256,
        )
    if settings.runtime.workspace_inputs_enabled:
        if (
            enrollment.format
            not in {
                "qualified-consumer-runtime-v4",
                "qualified-consumer-runtime-v5",
                "qualified-consumer-runtime-v6",
                "qualified-consumer-runtime-v7",
            }
            or r.source_uploads is None
            or r.source_evidence is None
        ):
            raise ValueError("runtime_workspace_composition_requires_qualified_source")
        source_qualification(
            r.source_evidence.read(),
            r.source_uploads.read(),
            config_sha256=r.source_uploads.sha256,
            realm_id=realm.id,
            realm_url=realm.url,
            bot_user_id=r.bot_user_id,
            allowed_channels=frozenset(realm.allowed_channel_ids),
            allowed_users=frozenset(realm.allowed_user_ids),
        )
    zulip = ZulipClient(
        realm.url,
        realm.bot_email,
        resolve_secret(realm.api_key_ref).get_secret_value(),
        budget=ZulipRequestBudget.from_config(realm.request_budget),
    )

    zulip.attestation = ZulipAttestation(
        realm.url,
        realm.id,
        r.bot_user_id,
        r.feature_level,
        r.message_limit,
        r.topic_limit,
        verified_scope_operations=SCOPE_OPERATIONS,
        verified_event_operations=EVENT_OPERATIONS | {"cleanup"},
        verified_file_operations=frozenset({"upload", "download"}) if file_upload else frozenset(),
    )
    zulip.verify_identity = ZulipRuntimeIdentity(zulip, r)
    scope = ZulipScopeReader(
        zulip,
        channel_ids=frozenset(realm.allowed_channel_ids),
        bulk_metadata=r.zulip_version == "12.3" and r.feature_level == 500,
    )
    providers = {}
    check_recoveries: list[OwnedCheckRecovery] = []
    anchor_readers: list[V2AnchoredCheckTailReader] = []
    file_readers: dict[SessionRef, V2NativeFileReader] = {}
    generated_readers: dict[SessionRef, V2GeneratedFileReader] = {}
    catalog_readers: dict[SessionRef, V2WorkspaceCatalog] = {}
    # Roots created from chat bring their own readers through their registry.
    registries: list[SessionRegistry] = []
    feeds: list[V2PublicFeed] = []
    instruction_clients: dict[str, V2SessionInstructions] = {}
    groups: dict[str, list[NativeQualification]] = {}
    for qualification in enrollment.backends:
        groups.setdefault(qualification.reference.backend_id, []).append(qualification)
    for backend_id, qualifications in groups.items():
        first = qualifications[0]
        configured = next(x for x in settings.opencode_backends if x.id == backend_id)
        owner_enrollment = HostOwnerEnrollment.model_validate(strict_loads(first.owner.read()))
        owner = LinuxHostOwnerProbe(owner_enrollment, first.owner_socket)
        profile = OpenAPIProfile(first.schema_file.read())
        transport = V2HTTPTransport(
            configured.base_url,
            profile,
            auth=httpx.BasicAuth(
                "opencode", resolve_secret(configured.credential_ref).get_secret_value()
            ),
            attestation=ContractAttestation(
                profile.sha256,
                first.reference.backend_identity,
                owner_enrollment.version,
                first.verified_operations,
            ),
        )
        references = tuple(q.reference for q in qualifications)
        feed = V2PublicFeed(
            transport,
            owner,
            references,
            receipts=LiveEventJournal(db, fence),
            capture_text=settings.runtime.native_drafts_enabled,
        )
        feeds.append(feed)

        async def original_identity(current_feed: V2PublicFeed = feed) -> bool:
            await current_feed.current_owner()
            return True

        transport.verify_identity = original_identity
        instruction_clients[backend_id] = V2SessionInstructions(transport)
        projects = {
            q.reference.project_id: V2CatalogProject(
                ProjectScope(**q.reference.model_dump(exclude={"upstream_session_id"})),
                q.native_project_id,
            )
            for q in qualifications
        }
        observers = []
        sessions = {}
        agent_clients: dict[SessionRef, V2AgentSettings] = {}
        agent_origins: dict[SessionRef, tuple[str, str]] = {}
        agent_policies: dict[SessionRef, str] = {}
        check_readers = {}
        git_review_readers = {}
        git_evidence_pins = {}
        texts = (
            LiveTextCollector(db, fence, feed) if settings.runtime.native_drafts_enabled else None
        )
        for q in qualifications:
            ref = q.reference
            model_doc = strict_loads(q.model_evidence.read())
            observed_ref = SessionRef.model_validate(model_doc["reference"])
            proofs = V2LeafResourceProofs(
                feed,
                projects,
                model_settings=ModelSettingsAttestation(
                    observed_ref,
                    profile.sha256,
                    MODEL_SETTING_SEMANTICS,
                    q.model_evidence.sha256,
                    qualification_scope=q.protocol_scope,
                ),
            )
            policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
            check_qualification = check_pin(q)
            evidence_pin = git_evidence_pin(q, enrollment.directory_scope)
            if evidence_pin is not None:
                git_evidence_pins[ref] = evidence_pin
            execution = V2ExecutionClient(
                transport,
                projects,
                proofs=proofs,
                scope_guard=V2ProjectPolicyGuard(proofs, {ref: policy}),
                check_attestations={ref: check_qualification}
                if check_qualification is not None
                else None,
            )
            git_attestation = git_review_pin(q, enrollment.directory_scope)
            if git_attestation is not None:
                if directories is None:
                    raise ValueError("runtime_git_review_original_physical_guard_required")
                git_review_readers[ref] = V2NativeGitReview(
                    execution,
                    {ref: git_attestation},
                    directories=directories,
                    patch_attestations={ref: patch_attestation}
                    if (patch_attestation := git_patch_pin(q, enrollment.directory_scope))
                    is not None
                    else None,
                )
            if check_qualification is not None:
                from jt_oz_bridge.services.check_results import owned_check_lookup

                known = owned_check_lookup(db, check_qualification)
                proofs.check_tail = V2AnchoredCheckTailReader(
                    transport,
                    check_qualification,
                    known,
                    model_settings=proofs.model_settings,
                    proofs=proofs,
                    reader=execution.checks,
                    original=check_owner_for,
                )
                proofs.check_tail.agent_settings = proofs.agent_settings_for
                anchor_readers.append(proofs.check_tail)
                check_readers[ref] = execution.checks
            if q.agent_settings is not None:
                attestation = AgentSettingsAttestation.model_validate(
                    strict_loads(q.agent_settings.read())
                )
                if attestation.native_project_id != q.native_project_id:
                    raise ValueError("runtime_agent_settings_original_project_required")
                agent_clients[ref] = V2AgentSettings(
                    execution,
                    ref,
                    attestation,
                    tuple(
                        AgentTransitionEnrollment.model_validate(strict_loads(pin.read()))
                        for pin in q.agent_transitions
                    ),
                )
                agent_origins[ref] = (q.policy.sha256, policy.fingerprint_sha256)
                agent_policies[ref] = policy.fingerprint_sha256
            elif q.agent_transitions:
                raise ValueError("runtime_agent_transitions_require_qualification")
            recovery = (
                OwnedCheckRecovery(db, proofs, execution.checks, owner_for=check_owner_for)
                if check_qualification is not None
                else None
            )
            if recovery is not None:
                check_recoveries.append(recovery)
            observer = OriginalRuntimeObserver(feed, proofs, ref, recovery)
            observers.append(observer)
            if directories is not None:
                catalog_readers[ref] = V2WorkspaceCatalog(
                    execution, {ref: catalog_attestations[ref]}, directories=directories
                )
            if file_upload is not None:
                if q.file_read is None:
                    raise ValueError("runtime_original_file_reader_evidence_required")
                file_readers[ref] = V2NativeFileReader(
                    execution,
                    attestation=native_file_qualification(
                        q.file_read.read(),
                        reference=ref,
                        contract_sha256=profile.sha256,
                        native_policy_sha256=policy.fingerprint_sha256,
                        executable_sha256=owner_enrollment.executable_sha256,
                        evidence_sha256=q.file_read.sha256,
                    ),
                )
            outcomes = frozenset(
                NativeResourceTurn.model_validate(strict_loads(pin.read())["evidence"]).turn.outcome
                for pin in q.outcome_evidence
            )
            reader = V2TurnResourceReader(
                execution,
                attestation=ResourceSemanticAttestation(
                    ref.backend_id,
                    ref.backend_identity,
                    profile.sha256,
                    RESOURCE_SEMANTICS,
                    enrollment_sha,
                    RESOURCE_TYPES,
                    outcomes,
                ),
            )
            if settings.runtime.generated_returns_enabled and ref in generated_scope:
                if q.generated_outputs is None or ref not in file_readers:
                    raise ValueError("runtime_original_generated_qualification_required")
                metadata, byte_certificate = generated_qualification(
                    q.generated_outputs.read(),
                    reference=ref,
                    contract_sha256=profile.sha256,
                    executable_sha256=owner_enrollment.executable_sha256,
                    evidence_sha256=q.generated_outputs.sha256,
                )
                generated_readers[ref] = V2GeneratedFileReader(
                    reader,
                    attestation=metadata,
                    file_reader=file_readers[ref],
                    byte_attestation=byte_certificate,
                )
            sessions[ref] = RegisteredSession(
                ref,
                profile.sha256,
                execution,
                execution.models,
                reader,
                observer.pending,
                transcript=V2TranscriptReader(reader),
                metadata=V2NativeMetadataReader(execution, ref),
                live_text=texts,
            )
        registered = SessionRegistry(sessions)
        agent_cell = (
            AgentConfigurationCell(agent_settings_by_reference(agent_clients))
            if agent_clients
            else None
        )
        if agent_cell is not None:
            # Set before any watch starts; every detached probe shares this feed.
            feed.agent_configuration = agent_cell
            registered.attach_configuration(agent_cell)
        registries.append(registered)
        for project_id, (adoption_policy, lineage) in adoption.items():
            if adoption_policy.anchor.backend_id != backend_id:
                continue
            original_execution = registered.selected(adoption_policy.anchor).execution
            assert isinstance(original_execution, V2ExecutionClient)
            assert isinstance(original_execution.scope_guard, V2ProjectPolicyGuard)
            original_metadata = V2ExistingSessionObserver(
                original_execution.scope_guard,
                ExistingSessionProtocol(
                    backend_id,
                    adoption_policy.anchor.backend_identity,
                    profile.sha256,
                    adoption_policy.installed_protocol_evidence_sha256,
                    first.verified_operations,
                ),
                adoption_policy.anchor,
            )
            adoption_factories[project_id] = V2ExistingSessionFactory(
                V2ExistingSessionGraphObserver(original_metadata),
                registered,
                adoption_policy,
                lineage=lineage,
            )
        for project_id, (_project, template) in creation.items():
            ref = template.source.reference
            if ref.backend_id != backend_id:
                continue
            anchor_execution = registered.selected(ref).execution
            assert isinstance(anchor_execution, V2ExecutionClient)
            assert isinstance(anchor_execution.scope_guard, V2ProjectPolicyGuard)
            creator = V2SessionCreation(transport, owner, {project_id: template.creation})
            creation_factories[project_id] = V2CreatedRootFactory(
                creator,
                V2CreationPolicy(anchor_execution.scope_guard, template),
                registered,
                files=file_readers.get(ref),
                catalog=catalog_readers.get(ref),
            )
            if settings.runtime.session_fork_topics_enabled:
                # Same anchor, feed and registry; a fork's policy is its source Root's.
                fork_factories[project_id] = V2CreatedRootFactory(
                    V2ForkedRootObserver(transport, owner, {project_id: template.creation}),
                    V2ForkPolicy(
                        anchor_execution.scope_guard, template, partial(fork_source, registered)
                    ),
                    registered,
                    files=file_readers.get(ref),
                    catalog=catalog_readers.get(ref),
                )
        deferred_roots = []
        for observer in observers:
            factory = adoption_factories.get(observer.ref.project_id)
            if (
                factory is not None
                and factory.policy.anchor == observer.ref
                and factory.lineage is not None
                and factory.lineage.qualification_scope == "tree"
            ):
                deferred_roots.append(_DeferredOriginalRoot(observer, factory))
        deferred = tuple(deferred_roots)
        require_agent_switch_scope(agent_clients, tuple(item.observer.ref for item in deferred))
        backend_creators = tuple(
            factory
            for factory in (*creation_factories.values(), *fork_factories.values())
            if factory.feed is feed
        )
        group = BackendRuntimeObserver(
            feed,
            tuple(observers),
            texts,
            deferred=deferred,
            created=partial(created_roots, backend_creators),
        )
        resources: tuple[RuntimeResource, ...] = (
            RuntimeResource(
                "native:" + backend_id,
                group.start_before_restoration if deferred else group.start,
                group.close,
            ),
        )
        post_restoration_resources: tuple[RuntimeResource, ...] = ()
        if deferred:

            async def activate_original_graphs(
                selected: tuple[_DeferredOriginalRoot, ...] = deferred,
            ) -> None:
                for item in selected:
                    await item.activate(pipeline)

            async def activation_close() -> None:
                return None

            post_restoration_resources = (
                RuntimeResource(
                    "native-graph-activation:" + backend_id,
                    activate_original_graphs,
                    activation_close,
                ),
            )
        if directories is not None:

            async def directory_start(
                refs: tuple[SessionRef, ...] = references,
                guard: LinuxDirectoryScopeGuard | None = directories,
            ) -> None:
                assert guard is not None
                for ref in refs:
                    observed = await guard.observe(ref, ("",))
                    if not guard.current(ref, observed):
                        raise ValueError("runtime_catalog_directory_startup_not_current")

            async def directory_close() -> None:
                # The metadata client owns no persistent socket/descriptor.
                return None

            resources += (
                RuntimeResource(
                    "workspace-catalog:" + backend_id, directory_start, directory_close
                ),
            )
        providers[backend_id] = RuntimeBackend(
            RegisteredBackend(
                first.reference.backend_identity, profile.sha256, registered.projects, registered
            ),
            RegisteredCatalog(
                first.reference.backend_identity,
                profile.sha256,
                registered.projects,
                V2SessionCatalog(
                    transport,
                    projects,
                    root_projects=frozenset(
                        project_id
                        for project_id, (policy, _) in adoption.items()
                        if policy.anchor.backend_id == backend_id
                    ),
                ),
            ),
            registered.models,
            registered.results,
            references,
            registered.pending,
            group.pulse,
            resources,
            registered.transcripts,
            registered.live_text,
            registered.metadata,
            reference_provider=registered.reference_snapshot,
            checks=check_readers,
            mode_snapshot=group.mode_snapshot,
            git_reviews=git_review_readers,
            git_evidence=git_evidence_pins,
            post_restoration_resources=post_restoration_resources,
            agent_settings=agent_clients,
            agent_origins=agent_origins,
            agent_policies=agent_policies,
            agent_configuration=agent_cell,
        )

    expected_generated = (
        generated_scope if settings.runtime.generated_returns_enabled else frozenset()
    )
    if frozenset(generated_readers) != expected_generated:
        raise ValueError("runtime_generated_reader_scope_must_be_exact")

    readable = enrollment_union((file_readers, *(r.files for r in registries)))
    browsable = enrollment_union((catalog_readers, *(r.catalogs for r in registries)))

    def make_files(bindings: BindingService, source: SourceReader, outbox: Outbox) -> FileCommands:
        if file_upload is None or db.cipher is None or not file_readers:
            raise ValueError("runtime_file_cipher_and_qualifications_required")
        files = LocalArtifactFiles(settings.app.state_dir / "file-artifacts")
        try:
            artifacts = ArtifactService(
                bindings,
                files,
                db.cipher,
                maximum_file_bytes=min(
                    settings.attachments.max_file_bytes, file_upload.maximum_file_bytes
                ),
                quota_bytes=settings.retention.artifact_quota_bytes,
                reserve_free_bytes=settings.retention.reserve_free_disk_bytes,
                fence=fence,
            )
            downloader = SafeDownloader(
                DownloadPolicy((download_origin(realm.url, r.file_private_networks),)),
                maximum_file_bytes=min(
                    settings.attachments.max_file_bytes, file_upload.maximum_file_bytes
                ),
            )
            journal_args = (
                artifacts,
                source,
                outbox,
                ZulipFileUploader(zulip, attestation=file_upload),
                downloader,
                readable,
            )
            journal = (
                GeneratedSessionExportJournal(
                    *journal_args,
                    message_limit=r.message_limit,
                    topic_limit=r.topic_limit,
                    generated_readers=generated_readers,
                )
                if settings.runtime.generated_returns_enabled
                else SessionExportJournal(
                    *journal_args,
                    message_limit=r.message_limit,
                    topic_limit=r.topic_limit,
                )
            )
            return FileCommands(
                journal,
                readable,
                artifact_ttl_seconds=settings.retention.temporary_artifact_days * 86400,
            )
        except BaseException:
            files.close()
            raise

    def make_menus(
        bindings: BindingService, source: SourceReader, tokens: TokenService, files: FileCommands
    ) -> FileMenus:
        if set(catalog_readers) != set(file_readers) or any(
            files.readers[ref] is not file_readers[ref]
            or reader.client is not file_readers[ref].client
            for ref, reader in catalog_readers.items()
        ):
            raise ValueError("runtime_menus_require_original_file_readers")
        return FileMenus(bindings, source, tokens, browsable, message_limit=r.message_limit)

    def make_incoming(files: FileCommands) -> WorkspaceIncoming:
        if r.source_uploads is None:
            raise ValueError("runtime_workspace_original_source_pin_required")
        stores: dict[Path, tuple[WorkspaceNamespacePin, WorkspaceFiles, WorkspaceJournal]] = {}
        journals: dict[SessionRef, WorkspaceJournal] = {}
        try:
            scope = enrollment.workspace_references()
            for q in enrollment.backends:
                if q.reference not in scope:
                    continue
                if q.workspace is None:
                    raise ValueError("runtime_workspace_original_namespace_required")
                owner = HostOwnerEnrollment.model_validate(strict_loads(q.owner.read()))
                policy = NativePolicyEnrollment.model_validate(strict_loads(q.policy.read()))
                pin = workspace_qualification(
                    q.workspace.read(),
                    reference=q.reference,
                    contract_sha256=q.schema_file.sha256,
                    policy_sha256=policy.fingerprint_sha256,
                    owner=owner,
                )
                previous = stores.get(pin.path)
                if previous is None:
                    namespace = WorkspaceFiles(
                        pin.storage(), reserve_free_bytes=settings.retention.reserve_free_disk_bytes
                    )
                    try:
                        journal = WorkspaceJournal(
                            files.journal.artifacts,
                            namespace,
                            quota_bytes=settings.retention.workspace_quota_bytes,
                            maximum_objects=settings.retention.workspace_maximum_objects,
                            ttl_seconds=settings.retention.temporary_artifact_days * 86400,
                        )
                    except BaseException:
                        namespace.close()
                        raise
                    stores[pin.path] = (pin, namespace, journal)
                else:
                    if previous[0] != pin:
                        raise ValueError("runtime_workspace_original_namespace_changed")
                    journal = previous[2]
                journals[q.reference] = journal
            return WorkspaceIncoming(files, SSHUploadAssociations(r.source_uploads), journals)
        except BaseException:
            for _, namespace, _ in stores.values():
                namespace.close()
            raise

    def make_creation(
        bindings: BindingService, source: SourceReader, replies: RoutedOutbox
    ) -> SessionCreationActivation:
        journal = SessionCreationJournal(
            bindings,
            source,
            fence,
            {key: value[0] for key, value in creation.items()},
            {
                key: partial(factory.creator.live_epoch, key)
                for key, factory in creation_factories.items()
            },
        )
        return SessionCreationActivation(journal, creation_factories, replies)

    def make_forks(
        activation: SessionCreationActivation, replies: RoutedOutbox
    ) -> SessionForkRegistration:
        return SessionForkRegistration(
            activation.journal, fork_factories, replies, realm_url=realm.url
        )

    def make_adoption(bindings: BindingService, source: SourceReader) -> SessionAdoptionService:
        return SessionAdoptionService(bindings, source, fence, adoption_factories)

    pipeline = ConsumerPipeline(
        db,
        fence,
        scope,
        providers,
        max_global=settings.execution.max_active_sessions_global,
        max_backend=settings.execution.max_active_sessions_per_backend,
        mirror_enabled=settings.runtime.native_mirror_enabled,
        drafts_enabled=settings.runtime.native_drafts_enabled,
        draft_interval=settings.rendering.stream_update_min_interval_ms / 1000,
        draft_interval_resolver=RuntimeConfiguration(db, settings).draft_interval,
        file_factory=make_files if file_upload is not None else None,
        incoming_factory=make_incoming if settings.runtime.workspace_inputs_enabled else None,
        file_menu_factory=make_menus if settings.runtime.workspace_menus_enabled else None,
        creation_factory=make_creation if settings.runtime.session_creation_enabled else None,
        fork_factory=make_forks if fork_factories else None,
        adoption_factory=make_adoption if adoption_factories else None,
        generated_factory=(lambda files: GeneratedCaptureService(files.journal))
        if settings.runtime.generated_returns_enabled
        else None,
        runtime_status_directory=settings.app.state_dir / "runtime-modes",
        platform_locale_file=realm.platform_locale_file,
        default_locale=realm.default_locale,
        zulip_recovery_enabled=settings.runtime.zulip_recovery_enabled,
        zulip_recovery_max_epochs=settings.runtime.zulip_recovery_max_epochs,
        zulip_recovery_max_items=settings.runtime.zulip_recovery_max_items,
        zulip_recovery_max_bytes=settings.runtime.zulip_recovery_max_bytes,
        retention_settings=settings.retention,
        channel_projects={
            item.channel_id: frozenset(item.projects) for item in realm.channel_projects
        },
        git_publish_enabled=settings.runtime.git_publish_enabled,
        prompt_schedules_enabled=settings.runtime.prompt_schedules_enabled,
        timezone=settings.i18n.default_timezone,
        format_instructions=ZulipFormatInstructions(instruction_clients)
        if settings.runtime.zulip_format_instructions_enabled
        else None,
    )
    # The only writers of live receipts; their epochs bound what retention may delete.
    pipeline.retention.live.generations = FeedGenerations(tuple(feeds))
    journal = CheckDispatchRecords(pipeline.bindings, fence)
    for anchor_reader in anchor_readers:
        if anchor_reader.original is None:
            anchor_reader.original = journal.owner_for
    for recovery in check_recoveries:
        if recovery.owner_for is None:
            recovery.owner_for = journal.owner_for
    return pipeline


def runtime_factory(settings: Settings) -> RuntimeFactory:
    enrollment, sha = read_enrollment(settings)

    def create(db: Database, fence: ConsumerFence) -> BridgeRuntime:
        # Re-read all pins at startup; an edited manifest never silently reuses
        # cached qualification or the earlier configuration's credentials.
        current, current_sha = read_enrollment(settings)
        if current != enrollment or current_sha != sha:
            raise ValueError("runtime_enrollment_changed_before_start")
        return build_pipeline(settings, current, sha, db, fence).runtime()

    return create


async def enroll_runtime(settings: Settings, db: Database) -> None:
    enrollment, sha = read_enrollment(settings)
    holder = str(uuid4())
    store = DurableStore(db)
    number = await store.acquire_lease(holder, ttl=120)
    if number is None:
        raise Conflict("stop_bridge_before_explicit_runtime_enrollment")
    pipeline = None
    opened = []
    try:
        pipeline = build_pipeline(settings, enrollment, sha, db, ConsumerFence(holder, number))
        for live_backend in pipeline.backends.values():
            for resource in live_backend.resources:
                opened.append(resource)
                start_owner = getattr(resource.start, "__self__", None)
                if (
                    isinstance(start_owner, BackendRuntimeObserver)
                    and resource.start == start_owner.start_before_restoration
                ):
                    # Explicit enrollment retains its original strict Native
                    # qualification; it does not run graph restoration or issue
                    # a first history/Grant as a side effect of deferral.
                    await start_owner.start()
                else:
                    await resource.start()
        await pipeline.scope.identity()
        configured = next(x for x in settings.zulip_realms if x.id == enrollment.realm.realm_id)
        for channel in configured.allowed_channel_ids:
            info = await pipeline.scope.channel(channel)
            members = await pipeline.scope.members(channel)
            if (
                info["invite_only"] is not True
                or info["is_web_public"] is not False
                or info["history_public_to_subscribers"] is not False
            ):
                raise ValueError("runtime_enrollment_private_channel_required")
            for identity in members:
                user = await pipeline.scope.user(identity)
                if identity != enrollment.realm.bot_user_id and (
                    user["is_bot"] or identity not in configured.allowed_user_ids
                ):
                    raise ValueError("runtime_enrollment_unapproved_channel_member")
        for grant in enrollment.grants:
            user = await pipeline.scope.user(grant.user_id)
            if user["is_bot"] or user["is_active"] is not True:
                raise ValueError("runtime_enrollment_active_human_required")
        async with db.sessions.begin() as session:
            await pipeline.fence.lock(session)
            for backend in enrollment.backends:
                ref = backend.reference
                owner = HostOwnerEnrollment.model_validate(strict_loads(backend.owner.read()))
                existing = await session.get(EnrolledBackend, ref.backend_id)
                if existing is None:
                    session.add(
                        EnrolledBackend(
                            id=ref.backend_id,
                            identity=ref.backend_identity,
                            contract_hash=backend.schema_file.sha256,
                            enabled=True,
                            verified=True,
                            version=owner.version,
                        )
                    )
                elif (
                    existing.identity,
                    existing.contract_hash,
                    existing.enabled,
                    existing.verified,
                    existing.version,
                ) != (ref.backend_identity, backend.schema_file.sha256, True, True, owner.version):
                    raise ValueError("existing_backend_enrollment_differs")
                project = await session.get(EnrolledProject, ref.project_id)
                if project is None:
                    session.add(
                        EnrolledProject(
                            id=ref.project_id,
                            backend_id=ref.backend_id,
                            realm_id=enrollment.realm.realm_id,
                            canonical_directory=ref.canonical_directory,
                            enabled=True,
                        )
                    )
                elif (
                    project.backend_id,
                    project.realm_id,
                    project.canonical_directory,
                    project.enabled,
                ) != (ref.backend_id, enrollment.realm.realm_id, ref.canonical_directory, True):
                    raise ValueError("existing_project_enrollment_differs")
            for grant in enrollment.grants:
                for role in sorted(grant.roles):
                    existing_grant = await session.scalar(
                        select(Grant).where(
                            Grant.realm_id == enrollment.realm.realm_id,
                            Grant.user_id == grant.user_id,
                            Grant.project_id == grant.project_id,
                            Grant.role == role,
                        )
                    )
                    if existing_grant is None:
                        session.add(
                            Grant(
                                realm_id=enrollment.realm.realm_id,
                                user_id=grant.user_id,
                                project_id=grant.project_id,
                                role=role,
                                active=True,
                            )
                        )
                    elif not existing_grant.active:
                        raise ValueError("explicitly_revoked_grant_requires_separate_review")
            session.add(AuditEvent(actor="cli", event="runtime_scope_enrolled", object_id=sha))
    finally:
        for resource in reversed(opened):
            try:
                await resource.close()
            except Exception:
                pass
        try:
            if pipeline is not None and getattr(pipeline, "files", None) is not None:
                await pipeline.close_files()
        finally:
            try:
                if pipeline is not None:
                    await pipeline.scope.client.close()
            finally:
                await store.release_lease(holder, number)
