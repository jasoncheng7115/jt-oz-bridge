"""Explicit qualified service graph and one-attempt consumer loops.

Importing this module performs no I/O. Enrollment and credentials belong to a
trusted operator composition, never a chat command or a catalog response.
"""

import asyncio
import logging
import math
import random
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import cast

from sqlalchemy import case, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.agent_configuration import AgentConfigurationCell
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.git_publish import V2GitPublishState
from jt_oz_bridge.adapters.opencode.transcript import TranscriptReader
from jt_oz_bridge.adapters.opencode.transport import TransportError
from jt_oz_bridge.adapters.opencode.worktree_switch import V2WorktreeSwitchObserver
from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, request_lane
from jt_oz_bridge.adapters.zulip.client import (
    ZulipAuthenticationFailed,
    ZulipError,
    ZulipReadUnavailable,
)
from jt_oz_bridge.adapters.zulip.gateway import ZulipGateway
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.adapters.zulip.typing import ZulipTyping
from jt_oz_bridge.config import Locale, Retention
from jt_oz_bridge.domain.catalog import CatalogPage, ProjectScope, SessionCatalog
from jt_oz_bridge.domain.checks import CheckReader
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.enrollment_views import (
    EnrollmentKeys,
    enrollment_union,
    readonly_enrollment,
)
from jt_oz_bridge.domain.execution import SourceReader
from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin
from jt_oz_bridge.domain.git_publish import GIT_PUBLISH
from jt_oz_bridge.domain.git_review import NativeGitReviewReader
from jt_oz_bridge.domain.model_catalog import ModelCatalog
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.native_metadata import NativeMetadataReader
from jt_oz_bridge.domain.runtime_readiness import MAX_ROOTS, RootModeFact, scope_key
from jt_oz_bridge.domain.worktree_switch import WorkspaceConcurrencyPolicy
from jt_oz_bridge.domain.worktrees import WorktreeProducer
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.security.redaction import visible_controls
from jt_oz_bridge.services.agent_commands import AgentCommands
from jt_oz_bridge.services.agent_configuration import (
    AgentConfigurationRegistry,
    AgentSettingsClient,
)
from jt_oz_bridge.services.agent_setting_publisher import AgentSettingPublisher
from jt_oz_bridge.services.agent_switch_coordinator import AgentSwitchCoordinator
from jt_oz_bridge.services.backend_registry import BackendRegistry, RegisteredBackend
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.check_commands import CheckCommands
from jt_oz_bridge.services.check_results import CheckResultCollector, CheckResultPublisher
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.creation_commands import CreationCommands
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.discovery import DiscoveryService, RegisteredCatalog
from jt_oz_bridge.services.discovery_delivery import DiscoveryDeliveryWorker
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryReplyPublisher
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.file_menus import FileMenus
from jt_oz_bridge.services.format_instructions import FormattedExecution, ZulipFormatInstructions
from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_capture_commands import GeneratedCaptureCommands
from jt_oz_bridge.services.git_evidence import GitEvidenceResults
from jt_oz_bridge.services.git_evidence_commands import GitEvidenceCommands
from jt_oz_bridge.services.git_publish_commands import GitPublishCommands
from jt_oz_bridge.services.git_publish_results import GitPublishResultPublisher, GitPublishResults
from jt_oz_bridge.services.git_review_commands import NativeGitReviewCommands
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.services.live_capture import LiveTextSource
from jt_oz_bridge.services.live_draft_sources import LiveDraftCollector
from jt_oz_bridge.services.model_commands import ModelCommands
from jt_oz_bridge.services.model_setting_publisher import ModelSettingPublisher
from jt_oz_bridge.services.native_metadata_commands import NativeMetadataCommands
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.services.permission_commands import (
    form_notice,
    form_widget,
    permission_notice,
    permission_widget,
    with_requester,
)
from jt_oz_bridge.services.prompt_schedules import PromptSchedules
from jt_oz_bridge.services.reply_publisher import ReplyPublisher
from jt_oz_bridge.services.resource_execution_results import (
    ResourceResultCollector,
    ResourceTurnReader,
)
from jt_oz_bridge.services.resource_history import ResourceHistory
from jt_oz_bridge.services.resource_publisher import ResourcePublisher
from jt_oz_bridge.services.retention import RetentionExecutor
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.runtime import (
    RuntimeResource,
    RuntimeWorker,
    SupervisedRuntime,
    error_label,
)
from jt_oz_bridge.services.runtime_modes import RuntimeModePublisher
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.session_creation_activation import SessionCreationActivation
from jt_oz_bridge.services.session_exports import SessionExportCommands, SessionExportJournal
from jt_oz_bridge.services.session_fork_registration import SessionForkRegistration
from jt_oz_bridge.services.session_lifecycle_commands import SessionLifecycleCommands
from jt_oz_bridge.services.session_lifecycle_controls import SessionLifecycleControls
from jt_oz_bridge.services.session_lifecycle_publisher import SessionRenamePublisher
from jt_oz_bridge.services.session_lifecycle_results import SessionLifecycleResultPublisher
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.services.still_working import StillWorkingNotices
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_commands import NativeTranscriptCommands
from jt_oz_bridge.services.transcript_drafts import TranscriptDraftPublisher
from jt_oz_bridge.services.transcript_publisher import TranscriptPublisher
from jt_oz_bridge.services.typing_status import TypingStatus
from jt_oz_bridge.services.workspace_runtime import WorkspaceIncoming
from jt_oz_bridge.services.zulip_consumer import ZulipCommandConsumer
from jt_oz_bridge.services.zulip_events import ZulipEventJournal
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.session_configuration_heads import SessionConfigurationHeads

LOG = logging.getLogger(__name__)
AGENT_RESTORE_SECONDS = 30
# Uncertain prompts are looked for in OpenCode at most this often.
UNCERTAIN_PROMPT_READ_SECONDS = 30.0
# After a Native restart OpenCode may need a while to settle; then `!reconnect` stays.
AUTO_RECONNECT_TRIES = 10
AUTO_RECONNECT_SPACING = 30.0
# An OpenCode restart's gap notice waits this long for automatic reconnect to answer it.
GAP_NOTICE_HOLD = AUTO_RECONNECT_TRIES * AUTO_RECONNECT_SPACING + 60.0
# Due times are minutes apart; a few seconds late is fine and keeps SQL reads rare.
SCHEDULE_POLL_SECONDS = 5.0
# A Native that keeps failing graph reads is asked again at most once a minute.
GRAPH_RETRY_SECONDS = 60.0
# Due posts are taken back to back; with none due the next look is at most this far off.
DELIVERY_POLL_SECONDS = 0.05
DELIVERY_IDLE_SECONDS = 0.4
# A topic whose directory saw no Native event since its last complete pending scan
# is scanned again only this often; a new permission or question is an arrival there.
# Each scan proves every node of the tree, so this bounds what each subagent costs.
PENDING_QUIET_SECONDS = 30.0
# A tree whose directory saw no Native event since its last complete read is read
# again only this often; any arrival there (a new subagent) reads it at once. The
# read walks every node twice with SQL authority, the costliest per-subagent work.
GRAPH_QUIET_SECONDS = 60.0
# Running turns are looked at for a "still working" line at most this often.
STILL_WORKING_CHECK_SECONDS = 10.0
# Graph maintenance refusals that only mean "the session moved while it was read" or
# "a proof deadline passed". Nothing was published; the next pulse proves it afresh.
GRAPH_RACE_CODES = frozenset(
    {
        "existing_session_original_observation_changed",
        "existing_session_final_observation_expired",
        "existing_session_graph_original_observation_changed",
        "existing_session_graph_final_observation_expired",
        "existing_session_graph_observation_expired",
        "original_graph_generation_changed_during_read",
        "original_graph_update_original_resource_proof_changed",
        "v2_execution_owner_or_snapshot_evidence_changed",
        "original_session_registration_proof_expired",
        "original_graph_update_publication_head_changed",
        "original_graph_update_expired_or_replaced",
        "original_session_graph_maintenance_authority_changed",
    }
)


def fixed_reason(error: Exception) -> str:
    """Only a code-like message may reach the log; free text could carry user data."""
    text = str(error)
    return text if re.fullmatch(r"[a-z0-9_]{1,80}", text) else error_label(error)


PendingReader = Callable[[SessionRef], Awaitable[tuple[str, ...]]]


class EnrolledSessionCatalog:
    """Keep Native paging/search but expose only explicitly watched references.

    An empty filtered page keeps its Native continuation; it does not pretend
    that another session was qualified merely because the server listed it.
    """

    def __init__(
        self,
        native: SessionCatalog,
        references: tuple[SessionRef, ...],
        *,
        reference_provider: Callable[[], tuple[SessionRef, ...]] | None = None,
        adoption: SessionAdoptionService | None = None,
    ) -> None:
        self.native, self._references = native, frozenset(references)
        self.reference_provider = reference_provider
        self.adoption = adoption

    @property
    def references(self) -> frozenset[SessionRef]:
        if self.reference_provider is None:
            return self._references
        values = self.reference_provider()
        if (
            type(values) is not tuple
            or len(values) > 1000
            or len(set(values)) != len(values)
            or not self._references <= set(values)
        ):
            raise ValueError("catalog_reference_provider_is_not_append_only")
        return frozenset(values)

    def contract_for_project(self, scope: ProjectScope) -> str:
        return self.native.contract_for_project(scope)

    async def list_sessions(
        self, scope: ProjectScope, *, search: str, cursor: str | None, limit: int
    ) -> CatalogPage:
        page = await self.native.list_sessions(scope, search=search, cursor=cursor, limit=limit)
        if self.adoption is not None and scope.project_id in self.adoption.factories:
            factory = self.adoption.factories[scope.project_id]
            anchor = factory.policy.anchor
            self.adoption.factory(anchor)
            if (
                not scope.contains(anchor)
                or self.native.contract_for_project(scope) != factory.policy.contract_sha256
            ):
                raise ValueError("catalog_adoption_original_scope_changed")
            return page  # Metadata only; Discovery attaches original selection identities.
        return page.model_copy(
            update={"items": tuple(x for x in page.items if x.reference in self.references)}
        )


@dataclass(frozen=True)
class RuntimeBackend:
    registered: RegisteredBackend
    catalog: RegisteredCatalog
    models: ModelCatalog
    results: ResourceTurnReader
    references: tuple[SessionRef, ...]
    pending: PendingReader
    pulse: Callable[[], Awaitable[None]]
    resources: tuple[RuntimeResource, ...]
    transcripts: Mapping[SessionRef, TranscriptReader] = field(default_factory=dict)
    live_text: Mapping[SessionRef, LiveTextSource] = field(default_factory=dict)
    metadata: Mapping[SessionRef, NativeMetadataReader] = field(default_factory=dict)
    reference_provider: Callable[[], tuple[SessionRef, ...]] | None = None
    checks: Mapping[SessionRef, CheckReader] = field(default_factory=dict)
    mode_snapshot: Callable[[], tuple[RootModeFact, ...]] | None = None
    git_reviews: Mapping[SessionRef, NativeGitReviewReader] = field(default_factory=dict)
    git_evidence: Mapping[SessionRef, RootReviewedGitEvidencePin] = field(default_factory=dict)
    post_restoration_resources: tuple[RuntimeResource, ...] = ()
    # Exact optional Agent qualification. Empty means switching is simply absent.
    agent_settings: Mapping[SessionRef, AgentSettingsClient] = field(default_factory=dict)
    agent_origins: Mapping[SessionRef, tuple[str, str]] = field(default_factory=dict)
    agent_policies: Mapping[SessionRef, str] = field(default_factory=dict)
    agent_configuration: AgentConfigurationCell | None = None

    @property
    def current_references(self) -> tuple[SessionRef, ...]:
        values = (
            self.reference_provider() if self.reference_provider is not None else self.references
        )
        if (
            type(values) is not tuple
            or len(values) > 1000
            or len(set(values)) != len(values)
            or not set(self.references) <= set(values)
            or any(
                ref.backend_id != self.references[0].backend_id
                or ref.backend_identity != self.registered.identity
                or self.registered.projects.get(ref.project_id) != ref.canonical_directory
                or self.registered.client.contract_for(ref) != self.registered.contract_sha256
                for ref in values
            )
        ):
            raise ValueError("runtime_reference_provider_scope_changed")
        return values

    def reference_snapshot(self) -> tuple[SessionRef, ...]:
        return self.current_references

    def __post_init__(self) -> None:
        object.__setattr__(self, "transcripts", readonly_enrollment(self.transcripts))
        object.__setattr__(self, "live_text", readonly_enrollment(self.live_text))
        object.__setattr__(self, "metadata", readonly_enrollment(self.metadata))
        object.__setattr__(self, "checks", readonly_enrollment(self.checks))
        object.__setattr__(self, "git_reviews", readonly_enrollment(self.git_reviews))
        evidence = {
            ref: RootReviewedGitEvidencePin.model_validate(pin.model_dump(mode="python"))
            for ref, pin in self.git_evidence.items()
        }
        if not set(evidence) <= set(self.references) & set(self.checks) or any(
            pin.reference != ref
            or pin.contract_sha256 != self.registered.contract_sha256
            or self.checks[ref].contract_for(ref) != pin.contract_sha256
            or self.checks[ref].qualification_for(ref) != pin.qualification_sha256
            or digest(self.checks[ref].catalog(ref).model_dump(mode="json")) != pin.catalog_sha256
            or pin.check not in self.checks[ref].catalog(ref).checks
            for ref, pin in evidence.items()
        ):
            raise ValueError("runtime_git_evidence_original_check_scope_changed")
        object.__setattr__(self, "git_evidence", readonly_enrollment(evidence))
        if not set(self.git_reviews) <= set(self.references) or any(
            not reader.qualified(ref) or reader.contract_for(ref) != self.registered.contract_sha256
            for ref, reader in self.git_reviews.items()
        ):
            raise ValueError("runtime_git_review_scope_or_contract_changed")
        if not set(self.checks) <= set(self.references) or any(
            reader.contract_for(ref) != self.registered.contract_sha256
            for ref, reader in self.checks.items()
        ):
            raise ValueError("runtime_check_reader_scope_or_contract_changed")
        if not set(self.metadata) <= set(self.references) or any(
            reader.contract_for(ref) != self.registered.contract_sha256
            for ref, reader in self.metadata.items()
        ):
            raise ValueError("runtime_native_metadata_scope_or_contract_changed")
        if not set(self.live_text) <= set(self.transcripts):
            raise ValueError("runtime_live_text_requires_matching_original_readers")
        if not set(self.transcripts) <= set(self.references) or any(
            reader.contract_for(ref) != self.registered.contract_sha256
            for ref, reader in self.transcripts.items()
        ):
            raise ValueError("runtime_transcript_scope_or_contract_changed")
        if (
            not self.references
            or len(set(self.references)) != len(self.references)
            or self.catalog.backend_identity != self.registered.identity
            or self.catalog.contract_sha256 != self.registered.contract_sha256
            or dict(self.catalog.projects) != dict(self.registered.projects)
        ):
            raise ValueError("runtime_backend_requires_one_explicit_qualified_scope")
        for ref in self.references:
            if (
                ref.backend_identity != self.registered.identity
                or self.registered.projects.get(ref.project_id) != ref.canonical_directory
                or self.registered.client.contract_for(ref) != self.registered.contract_sha256
                or self.models.contract_for(ref) != self.registered.contract_sha256
            ):
                raise ValueError("runtime_backend_reference_not_qualified")


class ConsumerPipeline:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        scope: ZulipScopeReader,
        backends: Mapping[str, RuntimeBackend],
        *,
        max_global: int = 4,
        max_backend: int = 2,
        interval: float = 1.0,
        delivery_interval: float = 1.0,
        mirror_enabled: bool = False,
        drafts_enabled: bool = False,
        draft_interval: float = 1.0,
        draft_interval_resolver: Callable[[AsyncSession], Awaitable[float]] | None = None,
        file_factory: Callable[[BindingService, SourceReader, Outbox], FileCommands] | None = None,
        incoming_factory: Callable[[FileCommands], WorkspaceIncoming] | None = None,
        generated_factory: Callable[[FileCommands], GeneratedCaptureService] | None = None,
        file_menu_factory: Callable[
            [BindingService, SourceReader, TokenService, FileCommands], FileMenus
        ]
        | None = None,
        runtime_status_directory: Path | None = None,
        platform_locale_file: Path | None = None,
        default_locale: Locale = "en",
        zulip_recovery_enabled: bool = False,
        zulip_recovery_max_epochs: int = 128,
        zulip_recovery_max_items: int = 10000,
        zulip_recovery_max_bytes: int = 128 * 1024**2,
        retention_settings: Retention | None = None,
        creation_factory: Callable[
            [BindingService, SourceReader, RoutedOutbox], SessionCreationActivation
        ]
        | None = None,
        adoption_factory: Callable[[BindingService, SourceReader], SessionAdoptionService]
        | None = None,
        fork_factory: Callable[[SessionCreationActivation, RoutedOutbox], SessionForkRegistration]
        | None = None,
        channel_projects: Mapping[int, frozenset[str]] | None = None,
        git_publish_enabled: bool = False,
        format_instructions: ZulipFormatInstructions | None = None,
        prompt_schedules_enabled: bool = False,
        timezone: str = "UTC",
    ) -> None:
        if not 0.01 <= interval <= 60 or not backends:
            raise ValueError("runtime_requires_qualified_backends_and_bounded_interval")
        if drafts_enabled and not mirror_enabled:
            raise ValueError("native_drafts_require_native_mirror")
        self.db, self.fence, self.scope = db, fence, scope
        self.retention = RetentionExecutor(db, fence, retention_settings or Retention())
        self.backends = MappingProxyType(dict(backends))
        self.runtime_status_directory = runtime_status_directory
        self._mode_scope_attestation = scope.client.attestation
        self._mode_scope_guard = scope.client.verify_identity
        self._missing_modes: dict[str, float] = {}
        self.interval = interval
        self.drafts_enabled = drafts_enabled
        self.realm_id, bot = scope.enrolled.realm_id, scope.enrolled.bot_user_id
        self.registry = BackendRegistry({key: b.registered for key, b in backends.items()})
        for key, backend in backends.items():
            if any(ref.backend_id != key for ref in backend.references):
                raise ValueError("runtime_backend_id_mismatch")
        self.bindings = BindingService(db, self.registry, scope)
        self.journal = ZulipEventJournal(
            db,
            fence,
            realm_id=self.realm_id,
            bot_user_id=bot,
            url=scope.client.url,
            channel_ids=scope.channel_ids,
        )
        self.source = ZulipSourceReader(
            scope,
            self.journal.expected_channel,
            language_file=platform_locale_file,
            default_locale=default_locale,
        )
        self.inbox = CommandInbox(db, fence.holder, fence.fencing)
        self.tokens = TokenService(db, fence=fence)
        self.adoption = adoption_factory(self.bindings, self.source) if adoption_factory else None
        if self.adoption is not None:
            if (
                self.adoption.bindings is not self.bindings
                or self.adoption.reader is not self.source
                or self.adoption.journal.fence != fence
            ):
                raise ValueError("runtime_adoption_original_composition_required")
            for adopter_factory in self.adoption.factories.values():
                anchor = adopter_factory.policy.anchor
                adoption_backend = self.backends.get(anchor.backend_id)
                if (
                    adoption_backend is None
                    or adoption_backend.registered.client is not adopter_factory.registry
                    or adoption_backend.models is not adopter_factory.registry.models
                    or adoption_backend.results is not adopter_factory.registry.results
                    or adoption_backend.transcripts is not adopter_factory.registry.transcripts
                    or adoption_backend.metadata is not adopter_factory.registry.metadata
                    or adoption_backend.live_text is not adopter_factory.registry.live_text
                    or getattr(adoption_backend.reference_provider, "__self__", None)
                    is not adopter_factory.registry
                    or getattr(adoption_backend.reference_provider, "__func__", None)
                    is not SessionRegistry.reference_snapshot
                    or getattr(adoption_backend.pending, "__self__", None)
                    is not adopter_factory.registry
                    or getattr(adoption_backend.pending, "__func__", None)
                    is not SessionRegistry.pending
                ):
                    raise ValueError("runtime_adoption_original_dynamic_backend_required")
        catalogs = {
            key: RegisteredCatalog(
                b.catalog.backend_identity,
                b.catalog.contract_sha256,
                b.catalog.projects,
                EnrolledSessionCatalog(
                    b.catalog.client,
                    b.references,
                    reference_provider=b.reference_snapshot,
                    adoption=self.adoption,
                ),
            )
            for key, b in backends.items()
        }
        self.discovery = DiscoveryService(
            self.bindings, catalogs, adoption=self.adoption, channel_projects=channel_projects
        )
        models = ModelCommands(
            self.bindings,
            {key: b.models for key, b in backends.items()},
            self.tokens,
            self.source,
            capabilities=self.registry.capabilities,
        )
        transcripts = enrollment_union(b.transcripts for b in backends.values())
        history: HistoryCommands = (
            NativeTranscriptCommands(
                self.bindings,
                self.tokens,
                self.source,
                transcripts,
                message_limit=scope.enrolled.max_message_length,
            )
            if transcripts
            else HistoryCommands(
                ResourceHistory(self.bindings),
                self.tokens,
                self.source,
                message_limit=scope.enrolled.max_message_length,
            )
        )
        if mirror_enabled and not transcripts:
            raise ValueError("native_mirror_requires_qualified_transcript_readers")
        self.mirrors = (
            TranscriptCollector(self.bindings, transcripts, fence, drafts_enabled=drafts_enabled)
            if mirror_enabled
            else None
        )
        self.live_drafts = (
            LiveDraftCollector(
                self.mirrors,
                enrollment_union(backend.live_text for backend in backends.values()),
            )
            if self.mirrors and drafts_enabled
            else None
        )
        self.bound_outbox = Outbox(self.bindings, bot, fence=fence)
        from jt_oz_bridge.services.dispatch_feedback import DispatchFeedback

        self.dispatch_feedback = DispatchFeedback(
            self.bound_outbox,
            self.source,
            realm_id=self.realm_id,
            message_limit=scope.enrolled.max_message_length,
            topic_limit=scope.enrolled.max_topic_length,
        )
        self.files = (
            file_factory(self.bindings, self.source, self.bound_outbox)
            if file_factory is not None
            else None
        )
        if file_factory is not None and self.files is None:
            raise ValueError("runtime_file_factory_returned_no_composition")
        if self.files is not None:
            file_journal = self.files.journal
            if (
                self.files.bindings is not self.bindings
                or self.files.reader is not self.source
                or self.files.fence != fence
                or file_journal.outbox is not self.bound_outbox
                or file_journal.uploader.client is not scope.client
                or file_journal.realm_id != self.realm_id
                or file_journal.message_limit > scope.enrolled.max_message_length
                or file_journal.topic_limit > scope.enrolled.max_topic_length
                or not self.files.readers
                or not set(self.files.readers)
                <= {ref for backend in backends.values() for ref in backend.current_references}
            ):
                raise ValueError("runtime_file_composition_scope_mismatch")
        self.exports: SessionExportCommands | None = None
        if self.files is not None and isinstance(self.files.journal, SessionExportJournal):
            self.files.journal.configure_exports(transcripts)
            self.exports = SessionExportCommands(self.files.journal, self.tokens)
        self.generated: GeneratedCaptureService | None = None
        if generated_factory is not None:
            if self.files is None:
                raise ValueError("generated_runtime_requires_original_file_runtime")
            try:
                self.generated = generated_factory(self.files)
                if (
                    not isinstance(self.generated, GeneratedCaptureService)
                    or self.generated.journal is not self.files.journal
                    or self.generated.bindings is not self.bindings
                    or self.generated.journal.source is not self.source
                    or self.generated.fence != fence
                    or not set(self.generated.journal.generated_readers) <= set(self.files.readers)
                ):
                    raise ValueError("generated_runtime_original_composition_required")
                for ref, generated_reader in self.generated.journal.generated_readers.items():
                    backend = self.backends[ref.backend_id]
                    client = backend.registered.client
                    original = (
                        client.selected(ref).results
                        if isinstance(client, SessionRegistry)
                        else backend.results
                    )
                    if (
                        getattr(generated_reader, "turns", None) is not original
                        or getattr(generated_reader, "file_reader", None)
                        is not self.files.readers[ref]
                    ):
                        raise ValueError("generated_runtime_original_native_graph_required")
            except BaseException:
                self.files.journal.artifacts.files.close()
                raise
        self.generated_commands = GeneratedCaptureCommands(
            self.bindings, self.source, self.tokens, self.generated
        )
        self.file_menus: FileMenus | None = None
        if file_menu_factory is not None:
            if self.files is None:
                raise ValueError("file_menu_runtime_requires_original_file_commands")
            try:
                self.file_menus = file_menu_factory(
                    self.bindings, self.source, self.tokens, self.files
                )
                if (
                    not isinstance(self.file_menus, FileMenus)
                    or self.file_menus.bindings is not self.bindings
                    or self.file_menus.source is not self.source
                    or self.file_menus.tokens is not self.tokens
                    or self.file_menus.fence != fence
                    or self.file_menus.message_limit > scope.enrolled.max_message_length
                    or not set(self.file_menus.catalogs) <= set(self.files.readers)
                ):
                    raise ValueError("file_menu_runtime_scope_mismatch")
                self.files.choices = self.file_menus.choices
            except BaseException:
                self.files.journal.artifacts.files.close()
                raise
        self.incoming: WorkspaceIncoming | None = None
        if incoming_factory is not None:
            if self.files is None:
                raise ValueError("incoming_runtime_requires_shared_file_composition")
            try:
                self.incoming = incoming_factory(self.files)
                if self.incoming is None or self.incoming.files is not self.files:
                    raise ValueError("incoming_runtime_requires_original_file_composition")
            except BaseException:
                self.files.journal.artifacts.files.close()
                raise
        self._file_recovery_cutoff = time.time()
        self._file_prune_at = 0.0
        destinations = OutputDestinations(self.discovery, self.source, fence)
        self.discovery_outbox = DiscoveryOutbox(destinations, bot)
        self.bound_replies = RoutedOutbox(
            self.bound_outbox,
            realm_id=self.realm_id,
            message_limit=scope.enrolled.max_message_length,
            topic_limit=scope.enrolled.max_topic_length,
        )
        self.creation: SessionCreationActivation | None = None
        self.forks: SessionForkRegistration | None = None
        if fork_factory is not None and creation_factory is None:
            raise ValueError("runtime_fork_topics_require_session_creation")
        if creation_factory is not None:
            try:
                self.creation = creation_factory(self.bindings, self.source, self.bound_replies)
                if (
                    not isinstance(self.creation, SessionCreationActivation)
                    or self.creation.journal.bindings is not self.bindings
                    or self.creation.journal.reader is not self.source
                    or self.creation.journal.fence != fence
                    or self.creation.replies is not self.bound_replies
                ):
                    raise ValueError("runtime_creation_requires_original_composition")
                for project in self.creation.journal.projects.values():
                    selected = project.template.scope
                    creation_backend = self.backends.get(selected.backend_id)
                    factory = self.creation.factories[selected.project_id]
                    if (
                        creation_backend is None
                        or creation_backend.registered.identity != selected.backend_identity
                        or creation_backend.registered.contract_sha256 != project.contract_sha256
                        or creation_backend.registered.projects.get(selected.project_id)
                        != selected.canonical_directory
                        or creation_backend.registered.client is not factory.registry
                        or factory.anchor.transcript is None
                        or factory.anchor.metadata is None
                        or getattr(creation_backend.reference_provider, "__self__", None)
                        is not factory.registry
                        or getattr(creation_backend.reference_provider, "__func__", None)
                        is not SessionRegistry.reference_snapshot
                        or creation_backend.models is not factory.registry.models
                        or creation_backend.results is not factory.registry.results
                        or getattr(creation_backend.pending, "__self__", None)
                        is not factory.registry
                        or getattr(creation_backend.pending, "__func__", None)
                        is not SessionRegistry.pending
                        or creation_backend.transcripts is not factory.registry.transcripts
                        or creation_backend.metadata is not factory.registry.metadata
                        or creation_backend.live_text is not factory.registry.live_text
                    ):
                        raise ValueError("runtime_creation_requires_original_dynamic_backend")
                if self.adoption is not None:
                    self.creation.configure_graph_recovery(self.adoption, self.graph_authority)
                if fork_factory is not None:
                    self.forks = fork_factory(self.creation, self.bound_replies)
                    if (
                        not isinstance(self.forks, SessionForkRegistration)
                        or self.forks.journal is not self.creation.journal
                        or self.forks.replies is not self.bound_replies
                        or any(
                            factory.registry is not self.creation.factories[key].registry
                            or factory.feed is not self.creation.factories[key].feed
                            for key, factory in self.forks.factories.items()
                        )
                    ):
                        raise ValueError("runtime_fork_topics_require_original_composition")
            except BaseException:
                if self.files is not None:
                    self.files.journal.artifacts.files.close()
                raise
        # Opt-in only: the same qualified review readers, read through GETs.
        publish_readers = {
            ref: V2GitPublishState(review)
            for ref, review in enrollment_union(b.git_reviews for b in backends.values()).items()
        }
        try:
            self.creation_commands = (
                CreationCommands(self.creation, self.inbox, self.discovery)
                if self.creation
                else None
            )
            if self.creation_commands is not None:
                self.creation_commands.forks = self.forks
            self.router = CommandRouter(
                self.bindings,
                self.source,
                self.inbox,
                capabilities=self.registry.capabilities,
                discovery=self.discovery,
                models=models,
                checks=CheckCommands(
                    self.bindings,
                    enrollment_union(b.checks for b in backends.values()),
                    self.tokens,
                    self.source,
                    self.registry.capabilities,
                    message_limit=scope.enrolled.max_message_length,
                ),
                lifecycle=SessionLifecycleCommands(
                    self.bindings, self.source, fence, self.registry.capabilities
                ),
                lifecycle_controls=SessionLifecycleControls(
                    self.bindings,
                    self.tokens,
                    self.source,
                    self.registry.capabilities,
                    fork_topics=frozenset(self.forks.factories) if self.forks else frozenset(),
                ),
                metadata=NativeMetadataCommands(
                    self.bindings,
                    enrollment_union(b.metadata for b in backends.values()),
                    self.tokens,
                    self.source,
                    message_limit=scope.enrolled.max_message_length,
                ),
                git_review=NativeGitReviewCommands(
                    self.bindings,
                    enrollment_union(b.git_reviews for b in backends.values()),
                    self.tokens,
                    self.source,
                    message_limit=scope.enrolled.max_message_length,
                ),
                git_evidence=GitEvidenceCommands(
                    GitEvidenceResults(
                        self.bindings,
                        self.source,
                        enrollment_union(b.checks for b in backends.values()),
                        fence=fence,
                        pins=enrollment_union(b.git_evidence for b in backends.values()),
                    ),
                    self.tokens,
                    message_limit=scope.enrolled.max_message_length,
                ),
                history=history,
                files=self.files,
                exports=self.exports,
                file_menus=self.file_menus,
                resume_guard=self.mirrors.require_continuity if self.mirrors else None,
                creation=self.creation_commands,
                generated=self.generated_commands,
                git_publish=GitPublishCommands(
                    self.bindings,
                    publish_readers,
                    self.tokens,
                    self.source,
                    self.registry.capabilities,
                    message_limit=scope.enrolled.max_message_length,
                )
                if git_publish_enabled
                else None,
            )
        except BaseException:
            if self.files is not None:
                self.files.journal.artifacts.files.close()
            raise
        replies = ReplyPublisher(
            self.bound_replies,
            DiscoveryReplyPublisher(
                self.discovery_outbox,
                realm_id=self.realm_id,
                message_limit=scope.enrolled.max_message_length,
                topic_limit=scope.enrolled.max_topic_length,
            ),
        )
        if self.router.unbound is not None:
            self.router.unbound.configure_closed_menus(
                self.discovery_outbox,
                realm_id=self.realm_id,
                message_limit=scope.enrolled.max_message_length,
                topic_limit=scope.enrolled.max_topic_length,
            )
        from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue

        self.closed_bound = ClosedBoundQueue(
            self.bindings,
            self.source,
            self.router.inbox,
            self.router.queue,
            self.bound_outbox,
            message_limit=scope.enrolled.max_message_length,
            topic_limit=scope.enrolled.max_topic_length,
            continuity=self.mirrors,
            journal=self.journal,
        )
        self.router.closed_bound = self.closed_bound
        if self.mirrors is not None:
            from jt_oz_bridge.services.transcript_reconnect import TranscriptReconnectService

            self.router.reconnect = TranscriptReconnectService(
                self.mirrors,
                self.source,
                self.inbox,
                self.tokens,
                source_guard=self.closed_bound,
                queue=self.router.queue,
            )
        replies.closed_bound = self.closed_bound
        self.typing = TypingStatus(self.bindings, fence, ZulipTyping(scope.client), self.realm_id)
        self.typing.quiet_fence = self._feed_directory_fence
        self.router.configure_typing(self.typing)
        self.reply_publisher = replies
        self.consumer = ZulipCommandConsumer(
            scope,
            self.source,
            self.journal,
            self.router,
            publish=replies.publish,
            typing_status=True,
            recover_gaps=zulip_recovery_enabled,
            recovery_max_epochs=zulip_recovery_max_epochs,
            recovery_max_items=zulip_recovery_max_items,
            recovery_max_bytes=zulip_recovery_max_bytes,
        )
        self.gateway = ZulipGateway(scope.client)
        self.dispatcher = Dispatcher(
            self.bindings,
            # Only the dispatcher's prompts first ensure the Zulip formatting entry.
            FormattedExecution(self.registry, format_instructions)
            if format_instructions is not None
            else self.registry,
            self.source,
            fence.holder,
            fence.fencing,
            max_global=max_global,
            max_backend=max_backend,
            require_control_source=True,
            attachment_realm_url=scope.client.url,
            attachment_imports=self.incoming.imports if self.incoming else None,
            workspace_ready=self.incoming.qualified if self.incoming else None,
            workspace_scope=self.incoming.journals.__contains__ if self.incoming else None,
            processing=self.typing.processing,
        )
        # Opt-in only: a confirmed repeat becomes timed ordinary prompts; see docs/SCHEDULES.md.
        self.schedules: PromptSchedules | None = None
        if prompt_schedules_enabled:
            self.schedules = PromptSchedules(
                self.bindings, self.tokens, self.source, self.router.queue, timezone=timezone
            )
            self.schedules.replies = self.bound_replies
            self.router.schedules = self.dispatcher.schedules = self.schedules
        self.collectors = {
            key: ResourceResultCollector(self.bindings, b.results, fence, capture=self.generated)
            for key, b in backends.items()
        }
        self.interactions = InteractionService(self.bindings, fence=fence)
        mirrored = EnrollmentKeys(transcripts) if mirror_enabled else frozenset()
        self.results = ResourcePublisher(self.bound_replies, excluded_references=mirrored)
        self.model_results = ModelSettingPublisher(self.bound_replies, excluded_references=mirrored)
        self.agent_registry: AgentConfigurationRegistry | None = None
        self.agent_coordinator: AgentSwitchCoordinator | None = None
        self.agent_results: AgentSettingPublisher | None = None
        enrolled = [b for b in backends.values() if b.agent_settings]
        if len(enrolled) > 1:
            raise ValueError("runtime_agent_switching_requires_one_backend")
        if enrolled:
            backend = enrolled[0]
            if backend.agent_configuration is None:
                raise ValueError("runtime_agent_switching_readiness_pointer_required")
            self.agent_registry = AgentConfigurationRegistry(
                SessionConfigurationHeads(db, fence, enabled=True),
                backend.agent_configuration,
                backend.agent_settings,
                backend.agent_origins,
                backend.agent_policies,
            )
            self.router.agents = AgentCommands(
                self.bindings, self.agent_registry, self.tokens, self.source
            )
            self.agent_coordinator = AgentSwitchCoordinator(
                self.bindings, self.agent_registry, self.source, fence, realm_id=self.realm_id
            )
            self.agent_results = AgentSettingPublisher(
                self.bound_replies, ready=self.agent_registry.published
            )
        self.lifecycle_results = SessionRenamePublisher(self.bound_replies)
        self.lifecycle_control_results = SessionLifecycleResultPublisher(self.bound_replies)
        self.check_results = CheckResultPublisher(self.bound_replies)
        self.git_results = (
            GitPublishResults(
                self.bindings,
                publish_readers,
                {key: b.results for key, b in backends.items()},
                fence,
            )
            if git_publish_enabled
            else None
        )
        self.git_notices = GitPublishResultPublisher(self.bound_replies)
        self.check_collector = CheckResultCollector(
            self.bindings, enrollment_union(b.checks for b in backends.values()), fence
        )
        self.transcript_output = (
            TranscriptPublisher(
                self.mirrors, self.bound_replies, history.body, drafts_enabled=drafts_enabled
            )
            if self.mirrors and isinstance(history, NativeTranscriptCommands)
            else None
        )
        if self.transcript_output is not None:
            self.transcript_output.gap_notice_due = self.gap_notice_due
            self.transcript_output.creates_here = self.creates_here
            self.transcript_output.diff_here = self.diff_here
        self.draft_output = (
            TranscriptDraftPublisher(
                self.mirrors,
                self.bound_replies,
                history.body,
                minimum_interval=draft_interval,
                interval_resolver=draft_interval_resolver,
            )
            if self.mirrors and drafts_enabled and isinstance(history, NativeTranscriptCommands)
            else None
        )
        self.bound_delivery = DeliveryWorker(
            self.bound_outbox,
            self.gateway,
            fence.holder,
            fence.fencing,
            minimum_interval=delivery_interval,
            draft_readers=transcripts,
            file_returns=self.files.journal if self.files else None,
            dispatch_feedback=self.dispatch_feedback,
        )
        self.discovery_delivery = DiscoveryDeliveryWorker(
            self.discovery_outbox,
            self.gateway,
            fence.holder,
            fence.fencing,
            minimum_interval=delivery_interval,
        )
        self.tr = Translator()
        # Safe coarse counters only; no private text or upstream exception body.
        self.deferred: dict[str, int] = {}
        self._uncertain_read_at = -UNCERTAIN_PROMPT_READ_SECONDS
        self._deferred_logged: dict[str, float] = {}
        self._announced: set[tuple[str, int, SessionRef, str]] = set()
        self._mirror_seen: dict[tuple[str, int], tuple[str | None, float, str]] = {}
        # Automatic reconnect tries per paused stream: (stream hash, tries, next try).
        self._auto_reconnect: dict[tuple[str, int], tuple[str, int, float]] = {}
        # Per paused stream: whether its gap notice still goes (False once the person
        # was asked in one line), and when the held notice was first due.
        self._gap_settled: dict[tuple[str, int], bool] = {}
        self._gap_seen: dict[tuple[str, int], float] = {}
        self._mirror_retry_at = 0.0
        self._background_retry_at = 0.0
        self._pending_retry_at = 0.0
        self._results_retry_at = 0.0
        self._publication_wake = asyncio.Event()
        self._graph_cursor = 0
        self._graph_quiet: dict[SessionRef, tuple[str, float]] = {}
        self.graph_quiet_seconds = GRAPH_QUIET_SECONDS
        self._pending_quiet: dict[tuple[str, int], tuple[str, float]] = {}
        self.pending_quiet_seconds = PENDING_QUIET_SECONDS
        # A turn that runs on with nothing new in its topic gets one quiet line.
        # Typing's own notion of running work; a topic waiting on a person gets none.
        self.still_working = StillWorkingNotices(
            self.bound_replies,
            self.typing.running,
            waiting=lambda binding: any(
                notice[:2] == (binding.id, binding.revision) for notice in self._announced
            ),
        )
        self._still_working_at = 0.0

    def configure_worktrees(self, producers: Mapping[SessionRef, "WorktreeProducer"]) -> None:
        """Trusted composition only; no implicit qualification or live pin changes."""
        from jt_oz_bridge.services.worktree_commands import WorktreeCommands

        if self.router.worktrees is not None:
            raise ValueError("worktree_pipeline_already_configured")
        self.router.worktrees = WorktreeCommands(self.bindings, self.source, self.tokens, producers)

    async def start_consumer(self) -> None:
        self.gateway.queue_id = await self.consumer.start()

    def mode_scope_current(self) -> bool:
        return (
            self.scope.client.attestation is self._mode_scope_attestation
            and self.scope.enrolled is self._mode_scope_attestation
            and self.scope.client.verify_identity is self._mode_scope_guard
            and self._mode_scope_guard is not None
        )

    def mode_facts(self) -> tuple[RootModeFact, ...]:
        if not self.mode_scope_current():
            raise ValueError("runtime_mode_scope_unavailable")
        result: dict[str, RootModeFact] = {}
        for backend in self.backends.values():
            allowed = {scope_key(ref) for ref in backend.current_references}
            facts = backend.mode_snapshot() if backend.mode_snapshot is not None else ()
            if self.adoption is not None:
                facts += tuple(
                    fact
                    for factory in self.adoption.factories.values()
                    if factory.policy.anchor.backend_id == backend.references[0].backend_id
                    for fact in factory.mode_facts()
                )
            if (
                type(facts) is not tuple
                or len(facts) > MAX_ROOTS
                or any(
                    type(fact) is not RootModeFact or fact.scope_key not in allowed
                    for fact in facts
                )
                or len({fact.scope_key for fact in facts}) != len(facts)
            ):
                raise ValueError("runtime_mode_provider_scope_invalid")
            known = {fact.scope_key: fact for fact in facts}
            for key in allowed:
                if key in result:
                    raise ValueError("runtime_mode_duplicate_scope")
                if key not in known:
                    transition = self._missing_modes.setdefault(key, time.time())
                    known[key] = RootModeFact(
                        scope_key=key,
                        mode="not-observed",
                        reason="not-observed",
                        transition_at=transition,
                    )
                else:
                    self._missing_modes.pop(key, None)
                result[key] = known[key]
            if len(result) > MAX_ROOTS:
                raise ValueError("runtime_mode_root_capacity")
        self._missing_modes = {
            key: stamp for key, stamp in self._missing_modes.items() if key in result
        }
        return tuple(result[key] for key in sorted(result))

    def runtime(self) -> SupervisedRuntime:
        # Own file descriptors before starting upstream resources, so an early
        # Native startup failure still releases already constructed local stores.
        resources: tuple[RuntimeResource, ...] = ()
        if self.files is not None:
            resources += (RuntimeResource("file-returns", self.start_files, self.close_files),)
        if self.incoming is not None:
            resources += (
                RuntimeResource("workspace-inputs", self.incoming.start, self.incoming.close),
            )
        resources += tuple(r for b in self.backends.values() for r in b.resources)
        resources += (RuntimeResource("zulip-client", self.noop, self.scope.client.close),)
        if self.creation is not None:
            # Restore original creation provenance/base readers before a saved
            # graph can attach descendants to those exact existing objects.
            resources += (RuntimeResource("session-restoration", self.restore_created, self.noop),)
        if self.adoption is not None:
            resources += (
                RuntimeResource("original-session-restoration", self.restore_adopted, self.noop),
            )
        resources += tuple(
            resource
            for backend in self.backends.values()
            for resource in backend.post_restoration_resources
        )
        if self.forks is not None:
            # Last: a fork's source Root may be a created or restored original Root.
            resources += (RuntimeResource("fork-restoration", self.restore_forks, self.noop),)
        if self.agent_registry is not None:
            # GET-only, before input can arrive. A head never resumes an old attempt.
            resources += (
                RuntimeResource(
                    "agent-configuration-restoration", self.agent_registry.restore_all, self.noop
                ),
            )
        resources += (RuntimeResource("zulip-consumer", self.start_consumer, self.consumer.close),)
        resources += (RuntimeResource("zulip-typing-cleanup", self.noop, self.typing.close),)
        workers: tuple[RuntimeWorker, ...] = (
            RuntimeWorker("zulip-input", self.poll),
            RuntimeWorker("zulip-typing", self.typing.run),
            RuntimeWorker("native-owner-feed", self.pulse),
            RuntimeWorker("native-dispatch", self.dispatch),
            RuntimeWorker("native-results", self.collect),
            RuntimeWorker("native-interactions", self.pending),
            RuntimeWorker("result-publications", self.publish),
            RuntimeWorker("zulip-delivery", self.deliver),
            RuntimeWorker("bridge-retention", self.retention.run),
        )
        if self.adoption is not None and self.adoption.updates:
            workers += (RuntimeWorker("native-session-graphs", self.maintain_original_graphs),)
        if self.agent_coordinator is not None:
            workers += (RuntimeWorker("native-agent-settings", self.maintain_agent_settings),)
        if self.files is not None:
            workers += (RuntimeWorker("file-transfers", self.transfer_files),)
        if self.generated is not None:
            workers += (RuntimeWorker("generated-capture", self.capture_outputs),)
        if self.creation_commands is not None:
            workers += (RuntimeWorker("native-session-creation", self.create_sessions),)
        if self.schedules is not None:
            workers += (RuntimeWorker("prompt-schedules", self.fire_schedules),)
        publisher = (
            RuntimeModePublisher(
                self.db,
                self.fence,
                self.runtime_status_directory,
                self.mode_facts,
                self.mode_scope_current,
            )
            if self.runtime_status_directory is not None
            else None
        )
        return SupervisedRuntime(
            self.db,
            self.fence,
            resources,
            workers,
            mode_publisher=publisher,
            metrics=self.process_metrics,
        )

    def process_metrics(self) -> dict[str, int]:
        # Process-lifetime counts with fixed names; no realm, topic or Root labels.
        budget = self.scope.client.budget
        live = self.retention.live
        return {
            "zulip_rate_limited_total": budget.rate_limits if budget is not None else 0,
            "zulip_requests_deferred_total": budget.deferred if budget is not None else 0,
            "native_feeds_connected": live.generations.connected()
            if live.generations is not None
            else 0,
            "live_receipts_deleted_total": live.deleted["native_feed_receipts"],
            "live_captures_deleted_total": live.deleted["native_live_captures"],
        }

    async def maintain_agent_settings(self) -> None:
        assert self.agent_registry is not None and self.agent_coordinator is not None
        restore_at = time.monotonic() + AGENT_RESTORE_SECONDS
        while True:
            await self.agent_coordinator.run_once()
            if time.monotonic() >= restore_at:
                # Detects a Native change made elsewhere. GET only, and it never compensates.
                await self.agent_registry.restore_all()
                restore_at = time.monotonic() + AGENT_RESTORE_SECONDS
            await asyncio.sleep(self.interval)

    async def restore_created(self) -> None:
        if self.router.worktrees is not None:
            await self.router.worktrees.recover()
        if self.creation is not None:
            await self.creation.restore_active()
            assert self.creation_commands is not None
            await self.creation_commands.recover()

    async def restore_forks(self) -> None:
        if self.forks is not None:
            await self.forks.restore_active()

    def graph_authority(
        self, project_id: str
    ) -> tuple[Callable[[], Awaitable[bool]], Callable[[AsyncSession], Awaitable[None]]]:
        """Current configured operator/lease, never a recovered Human command."""
        adoption = self.adoption
        if adoption is None or project_id not in adoption.factories:
            raise AccessDenied("original_session_graph_runtime_not_enrolled")
        factory = adoption.factories[project_id]
        anchor = factory.policy.anchor
        journal = adoption.journal

        async def locked(session: AsyncSession) -> None:
            if (
                self.adoption is not adoption
                or adoption.factories.get(project_id) is not factory
                or adoption.journal is not journal
                or journal.db is not self.db
                or journal.fence != self.fence
                or not self.mode_scope_current()
                or adoption.factory(anchor) is not factory
            ):
                raise AccessDenied("original_session_graph_runtime_assembly_changed")
            await self.fence.lock(session)
            await journal.enrollment_scope(
                session, self.realm_id, anchor, factory.policy.contract_sha256
            )
            operator = await session.scalar(
                select(Grant.id)
                .where(
                    Grant.realm_id == self.realm_id,
                    Grant.project_id == project_id,
                    Grant.user_id > 0,
                    Grant.active.is_(True),
                    Grant.role.in_(
                        [
                            role
                            for role, permissions in ROLES.items()
                            if Permission.OPERATE in permissions
                        ]
                    ),
                )
                .limit(1)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if operator is None:
                raise AccessDenied("original_session_startup_current_operator_required")

        async def authorize() -> bool:
            async with self.db.sessions.begin() as session:
                await locked(session)
            return True

        return authorize, locked

    def original_graph_roots(self) -> tuple[SessionRef, ...]:
        adoption = self.adoption
        if adoption is None:
            return ()
        roots: list[SessionRef] = []
        for project_id, updates in adoption.updates.items():
            factory = adoption.factories[project_id]
            if (
                updates.factory is not factory
                or adoption.factory(factory.policy.anchor) is not factory
            ):
                raise AccessDenied("original_session_graph_runtime_assembly_changed")
            roots.extend(
                root
                for root in factory.registry.publication.snapshot().roots
                if root.project_id == project_id
            )
        if len(roots) > MAX_ROOTS or len(set(roots)) != len(roots):
            raise Conflict("original_session_graph_runtime_root_capacity")
        return tuple(sorted(roots, key=scope_key))

    async def restore_adopted(self) -> None:
        """Restore true history/baselines before starting the consumer."""
        if self.adoption is None:
            return
        # A chat-created Root whose own restore failed stays unregistered alone.
        deferred = self.creation.unrestored_roots() if self.creation is not None else frozenset()
        for project_id in self.adoption.factories:
            authorize, locked = self.graph_authority(project_id)
            await self.adoption.recover_project(
                self.realm_id,
                project_id,
                authorize=authorize,
                lock_authority=locked,
                deferred=deferred,
            )
        # Created roots are restored by the preceding resource. Only explicitly
        # tree-qualified projects may establish a first original live baseline.
        for root in self.original_graph_roots():
            authorize, locked = self.graph_authority(root.project_id)
            await self.adoption.maintain_root(
                self.realm_id,
                root.project_id,
                root,
                authorize=authorize,
                lock_authority=locked,
            )

    async def maintain_original_graphs_once(self) -> bool:
        roots = self.original_graph_roots()
        if not roots:
            return False
        # One root per pulse with stable round-robin fairness. Dynamic routing
        # supplies registered roots only; children are not independent sessions.
        root = roots[self._graph_cursor % len(roots)]
        self._graph_cursor = (self._graph_cursor + 1) % len(roots)
        quiet = self._graph_quiet_fence(root)
        last = self._graph_quiet.get(root)
        if (
            quiet is not None
            and last is not None
            and last[0] == quiet
            and 0 <= time.monotonic() - last[1] < self.graph_quiet_seconds
        ):
            return False
        authorize, locked = self.graph_authority(root.project_id)
        assert self.adoption is not None
        self._graph_quiet.pop(root, None)
        changed = await self.adoption.maintain_root(
            self.realm_id,
            root.project_id,
            root,
            authorize=authorize,
            lock_authority=locked,
        )
        if quiet is not None:
            # Taken before the read: anything arriving during it reads again.
            self._graph_quiet[root] = (quiet, time.monotonic())
        return changed

    def _feed_directory_fence(self, ref: SessionRef) -> str | None:
        """Arrivals in this enrolled Root's directory on its live feed, else None."""
        generations = self.retention.live.generations
        if generations is None:
            return None
        for feed in generations.feeds:
            index = feed.index
            if index is not None and index.references.get(ref.upstream_session_id) == ref:
                try:
                    return index.directory_fence(ref.canonical_directory, state_only=True)
                except ContractError:
                    return None
        return None

    def _graph_quiet_fence(self, root: SessionRef) -> str | None:
        """This tree's directory arrivals on the live feed; None reads every pulse.

        Only skips a read-only pulse. Publication still needs the complete read.
        """
        try:
            assert self.adoption is not None
            feed = self.adoption.factory(root).observer.observer.anchor.proofs.feed
            index = feed.index if feed is not None else None
            if index is None:
                return None
            return index.directory_fence(root.canonical_directory, state_only=True)
        except Exception:
            return None

    async def maintain_original_graphs(self) -> None:
        delay = self.interval
        while True:
            try:
                await self.maintain_original_graphs_once()
                delay = self.interval
            except SnapshotBoundaryChanged:
                # Retryable: this mutable-read boundary, a failed GET and the race
                # codes below. Owner, origin, schema, SQL authority/fence and
                # authentication failures keep their typed failure and stop the
                # supervised worker.
                self.defer("original_graph_snapshot_not_current")
            except TransportError as error:
                # This worker only reads, so a timeout or refused GET changed
                # nothing in Native and nothing here; read again later instead
                # of stopping the whole bridge.
                self.defer("original_graph_native_unavailable", error)
                delay = min(GRAPH_RETRY_SECONDS, max(self.interval, delay * 2))
            except (ContractError, Conflict, AccessDenied) as error:
                # A session that changed mid-read, or a proof that took too long,
                # is read again. Every other typed refusal still stops the worker.
                if str(error) not in GRAPH_RACE_CODES:
                    raise
                self.defer("original_graph_changed_while_reading", error)
                delay = min(GRAPH_RETRY_SECONDS, max(self.interval, delay * 2))
            await asyncio.sleep(delay)

    async def create_sessions(self) -> None:
        delay = 1.0
        while True:
            assert self.creation_commands is not None
            try:
                with request_lane("control"):
                    await self.creation_commands.once()
                    if self.creation is not None:
                        await self.creation.retry_restores()
                    if self.forks is not None:
                        await self.forks.once()
            except ZulipReadUnavailable:
                self.defer("creation_read_unavailable")
                await asyncio.sleep(random.uniform(max(1, delay / 2), delay))
                delay = min(60, delay * 2)
                continue
            except DeliveryRateLimited as error:
                self.defer("creation_rate_limited")
                await asyncio.sleep(max(1, min(3600, error.retry_after)))
                continue
            delay = 1.0
            await asyncio.sleep(self.interval)

    async def fire_schedules(self) -> None:
        assert self.schedules is not None
        delay = 1.0
        while True:
            try:
                with request_lane("control"):
                    await self.schedules.fire_once()
            except ZulipReadUnavailable:
                self.defer("schedule_read_unavailable")
                await asyncio.sleep(random.uniform(max(1, delay / 2), delay))
                delay = min(60, delay * 2)
                continue
            except DeliveryRateLimited as error:
                self.defer("schedule_rate_limited")
                await asyncio.sleep(max(1, min(3600, error.retry_after)))
                continue
            delay = 1.0
            await asyncio.sleep(SCHEDULE_POLL_SECONDS)

    async def start_files(self) -> None:
        if self.files is not None:
            await self.files.journal.recover_uploading(before=self._file_recovery_cutoff)
            await self.files.journal.artifacts.recover_incomplete(
                self.fence.holder, self.fence.fencing, before=self._file_recovery_cutoff
            )
            if self.generated is not None:
                await self.generated.recover(before=self._file_recovery_cutoff)

    async def close_files(self) -> None:
        if self.files is not None:
            try:
                if self.incoming is not None:
                    await self.incoming.close()
            finally:
                try:
                    await self.files.journal.downloader.close()
                finally:
                    self.files.journal.artifacts.files.close()

    async def transfer_files_once(self) -> None:
        if self.files is not None:
            if time.monotonic() >= self._file_prune_at:
                await self.files.journal.artifacts.prune_expired(
                    self.fence.holder, self.fence.fencing, limit=10
                )
                self._file_prune_at = time.monotonic() + 60
            if self.incoming is not None:
                await self.incoming.prune_once()
            identity = await self.files.journal.next_pending()
            if identity is not None:
                with request_lane("final"):
                    await self.files.journal.advance(identity)

    async def transfer_files(self) -> None:
        while True:
            await self.transfer_files_once()
            await asyncio.sleep(self.interval)

    async def capture_outputs_once(self) -> None:
        if self.generated is not None:
            identity = await self.generated.next_pending()
            if identity is not None:
                with request_lane("final"):
                    await self.generated.advance(identity)

    async def capture_outputs(self) -> None:
        while True:
            await self.capture_outputs_once()
            await asyncio.sleep(self.interval)

    @staticmethod
    async def noop() -> None:
        pass

    def defer(self, category: str, error: Exception | None = None) -> None:
        self.deferred[category] = self.deferred.get(category, 0) + 1
        if error is None:
            return
        # A retried refusal can hide a dead session, so say so, at most every five minutes.
        now = time.monotonic()
        if now - self._deferred_logged.get(category, -300.0) >= 300:
            self._deferred_logged[category] = now
            LOG.warning(
                "work_deferred category=%s count=%d reason=%s",
                category,
                self.deferred[category],
                fixed_reason(error),
            )

    async def poll(self) -> None:
        read_failures = 0
        while True:
            try:
                with request_lane("control"):
                    await self.consumer.poll()
                read_failures = 0
            except ZulipReadUnavailable:
                # Retry only GETs on the existing cursor. Register, writes,
                # authentication, invalid schemas and expired queues are not
                # made retryable by this path. A fresh poll rechecks authority.
                self.defer("zulip_input_read_unavailable")
                ceiling = min(60, 2**read_failures)
                read_failures = min(6, read_failures + 1)
                await asyncio.sleep(random.uniform(max(1, ceiling / 2), ceiling))
            except DeliveryRateLimited as error:
                self.defer("zulip_input_rate_limited")
                # Pre-poll/receipt-check reads restart as a complete attempt,
                # just like a safely deferred route. Let the rolling quota
                # refill instead of spending each partially freed slot again.
                budget = self.scope.client.budget
                delay = (
                    max(error.retry_after, budget.window)
                    if budget is not None
                    else error.retry_after
                )
                await asyncio.sleep(max(1, min(3600, delay)))
            # Also bound CPU use for an empty/fast synthetic or unusual server.
            await asyncio.sleep(0.01)

    async def pulse(self) -> None:
        while True:
            for backend in self.backends.values():
                await backend.pulse()
            await asyncio.sleep(self.interval)

    def configure_worktree_switch(
        self,
        observers: Mapping[tuple[SessionRef, SessionRef], V2WorktreeSwitchObserver],
        *,
        workspace_policies: tuple[WorkspaceConcurrencyPolicy, ...] = (),
    ) -> None:
        """Explicit trusted composition only; absent enrollment makes no extra GET."""
        from jt_oz_bridge.adapters.opencode.worktree_switch import V2WorktreeSwitchObserver
        from jt_oz_bridge.services.worktree_switch import WorktreeSwitchCommands

        if self.router.worktree_switch is not None or any(
            type(value) is not V2WorktreeSwitchObserver
            or self.registry.selected(value.original).client is not value.registry
            or self.registry.selected(value.target).client is not value.registry
            for value in observers.values()
        ):
            raise ValueError("worktree_switch_original_registry_composition_required")
        for policy in workspace_policies:
            found = False
            for observer in observers.values():
                for ref, review in zip(
                    (observer.original, observer.target), observer.reviews, strict=True
                ):
                    if (ref.backend_id, ref.backend_identity, ref.canonical_directory) != (
                        policy.backend_id,
                        policy.backend_identity,
                        policy.canonical_directory,
                    ):
                        continue
                    enrollment = getattr(review.directories, "enrolled", None)
                    if enrollment is not None and any(
                        root.directory == policy.canonical_directory
                        and (root.device, root.inode) == (policy.device, policy.inode)
                        for root in enrollment.roots
                    ):
                        found = True
            if not found:
                raise ValueError("workspace_policy_root_managed_physical_scope_required")
        commands = WorktreeSwitchCommands(
            self.router.inbox,
            self.tokens,
            self.discovery_outbox,
            self.bound_outbox,
            observers,
            message_limit=self.scope.enrolled.max_message_length,
            topic_limit=self.scope.enrolled.max_topic_length,
        )
        self.router.worktree_switch = commands
        self.reply_publisher.worktree_switch = commands
        self.dispatcher.configure_workspace_policies(workspace_policies)

    async def dispatch_once(self) -> None:
        async with self.db.sessions() as session:
            identities = list(
                (
                    await session.scalars(
                        select(Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .where(
                            Binding.realm_id == self.realm_id,
                            Action.state == "queued",
                            Binding.state == "active",
                            Action.operation.not_in(
                                ["session.create", "worktree.create", "agent.switch"]
                            ),
                        )
                        .order_by(
                            case(
                                (Action.operation == "interrupt", 0),
                                (Action.operation == "prompt", 2),
                                else_=1,
                            ),
                            Action.created_at,
                            Action.id,
                        )
                        .limit(100)
                    )
                ).all()
            )
        for identity in identities:
            async with self.db.sessions() as session:
                action = await session.get(Action, identity)
                binding = (
                    await session.get(Binding, action.binding_id) if action is not None else None
                )
            if action is None or binding is None or binding.state != "active":
                continue
            if await self.dispatcher.blocked_by_workspace(identity):
                self.defer("dispatch_workspace_policy_blocked")
                continue
            if await self.dispatcher.blocked_by_fifo(identity):
                self.defer("dispatch_fifo_blocked")
                continue
            if (
                action.operation == "prompt"
                and self.mirrors
                and reference(binding) in self.mirrors.readers
            ):
                try:
                    await self.mirrors.require_continuity(binding, ready=True)
                except Conflict:
                    self.defer("transcript_context_not_ready")
                    continue
            if action.operation in {"prompt", "check.run", GIT_PUBLISH} and not await self.idle(
                reference(binding),
                # A prompt may join a busy session; the dispatcher decides exactly.
                join=await self.dispatcher.join_hint(action, binding),
            ):
                continue
            if await self.dispatcher.advance(identity) == "rejected":
                self._publication_wake.set()

    async def idle(self, ref: SessionRef, *, join: frozenset[str] = frozenset()) -> bool:
        try:
            snapshot = await self.registry.snapshot(ref)
            return snapshot.reconciled and (
                snapshot.state == ExecutionState.IDLE or snapshot.state in join
            )
        except (ContractError, Conflict, AccessDenied, TransportError) as error:
            self.defer("native_state_not_current", error)
            return False

    async def dispatch(self) -> None:
        read_failures = 0
        while True:
            try:
                await self.dispatch_once()
            except ZulipReadUnavailable:
                # Only unclaimed preflight reads escape Dispatcher. Restart
                # their full authority checks; no prepared proof survives sleep.
                self.defer("zulip_dispatch_read_unavailable")
                ceiling = min(60, 2**read_failures)
                read_failures = min(6, read_failures + 1)
                await asyncio.sleep(random.uniform(max(1, ceiling / 2), ceiling))
                continue
            except DeliveryRateLimited as error:
                self.defer("zulip_dispatch_rate_limited")
                budget = self.scope.client.budget
                delay = (
                    max(error.retry_after, budget.window)
                    if budget is not None
                    else error.retry_after
                )
                await asyncio.sleep(max(1, min(3600, delay)))
                continue
            read_failures = 0
            await asyncio.sleep(self.interval)

    async def settle_uncertain_once(self) -> None:
        """An uncertain prompt OpenCode holds becomes admitted and is collected next;
        one it provably never received is refused. Its own read, at most every 30 s."""
        now = time.monotonic()
        if now - self._uncertain_read_at >= UNCERTAIN_PROMPT_READ_SECONDS:
            self._uncertain_read_at = now
            await self.dispatcher.reconcile_uncertain_prompts()

    async def collect_once(self) -> None:
        # Bound each operation independently before the single snapshot read.
        # A check backlog must not consume the prompt allowance (or vice versa).
        # Empty check enrollment still permits recovery of durable check results.
        checks = (
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.realm_id == self.realm_id,
                Binding.state == "active",
                Binding.revision == Action.binding_revision,
                Action.operation == "check.run",
                Action.state.in_(["admitted", "running", "ambiguous"]),
            )
            .order_by(Action.created_at, Action.id)
            .limit(100)
            .subquery()
        )
        prompts = (
            select(Action.id)
            .join(Binding, Binding.id == Action.binding_id)
            .where(
                Binding.realm_id == self.realm_id,
                Binding.state == "active",
                Action.operation == "prompt",
                Action.state.in_(["admitted", "running"]),
            )
            .order_by(Action.created_at, Action.id)
            .limit(100)
            .subquery()
        )
        candidates = union_all(select(checks.c.id), select(prompts.c.id)).subquery()
        async with self.db.sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(Action.id, Action.operation, Binding)
                        .join(candidates, candidates.c.id == Action.id)
                        .join(Binding, Binding.id == Action.binding_id)
                        .order_by(Action.created_at, Action.id)
                    )
                ).all()
            )
        for identity, operation, binding in rows:
            if operation == "check.run":
                try:
                    if await self.check_collector.collect(identity, self.realm_id):
                        self._publication_wake.set()
                except DeliveryRateLimited as error:
                    LOG.warning(
                        "native_result_collection_deferred phase=check error_type=%s",
                        error_label(error),
                    )
                    raise
                except (ContractError, Conflict, AccessDenied, TransportError):
                    self.defer("check_result_not_current_or_authorized")
                continue
            backend = binding.backend_id
            if backend not in self.collectors:
                self.defer("unregistered_result_backend")
                continue
            try:
                if not await self.idle(reference(binding)):
                    continue
                await self.collectors[backend].collect(identity, self.realm_id)
                self._publication_wake.set()
            except DeliveryRateLimited as error:
                LOG.warning(
                    "native_result_collection_deferred phase=prompt error_type=%s",
                    error_label(error),
                )
                raise
            except (ContractError, Conflict, AccessDenied) as error:
                # A not-yet-final or changing read is not permission to resend.
                self.defer("result_not_current_or_authorized", error)

    async def collect_git_once(self) -> None:
        """Read Git again after each confirmed Git prompt's turn; never sends anything."""
        if self.git_results is None:
            return
        for identity in await self.git_results.pending(self.realm_id):
            try:
                if await self.git_results.collect(identity, self.realm_id):
                    self._publication_wake.set()
            except DeliveryRateLimited:
                raise
            except (ContractError, Conflict, AccessDenied, TransportError) as error:
                # Not finished yet, or not current: read again later, never resend.
                self.defer("git_publish_result_not_current", error)

    async def collect(self) -> None:
        while True:
            phase = "mirror"
            delay = self.interval
            try:
                await self.mirror_once()
                phase = "uncertain"
                await self.settle_uncertain_once()
                phase = "collection"
                await self.collect_once()
                phase = "git"
                await self.collect_git_once()
            except DeliveryRateLimited as error:
                # These collectors issue reads and commit correlated ownDB evidence,
                # never Native mutations. Retry the entire fresh read boundary;
                # completed records disappear from the next candidate query.
                self.defer("native_result_scope_rate_limited")
                window = (
                    error.refill_window
                    if isinstance(error, RequestBudgetDeferred) and error.refill_window is not None
                    else 0
                )
                retry = (
                    max(1, min(3600, error.retry_after)) if math.isfinite(error.retry_after) else 60
                )
                delay = max(self.interval, retry, window)
            except Exception as error:
                # Fixed labels only: preserve fatal/auth/unknown errors and let
                # the supervisor stop peers. Never print error text or traceback.
                LOG.warning(
                    "native_result_collection_failed phase=%s error_type=%s",
                    phase,
                    error_label(error),
                )
                raise
            await asyncio.sleep(delay)

    async def mirror_once(self) -> None:
        # Actual original-state/terminal intake must retain final headroom even
        # when speculative preview publication exhausted its background lane.
        with request_lane("final"):
            await self.mirror_bindings_once()

    async def mirror_bindings_once(self) -> None:
        if self.mirrors is None or time.monotonic() < self._mirror_retry_at:
            return
        async with self.db.sessions() as session:
            bindings = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(Binding.realm_id == self.realm_id, Binding.state == "active")
                        .order_by(Binding.created_at, Binding.id)
                        .limit(100)
                    )
                ).all()
            )
        live = set()
        for binding in bindings:
            ref = reference(binding)
            reader = self.mirrors.readers.get(ref)
            if reader is None:
                continue
            key = (binding.id, binding.revision)
            live.add(key)
            try:
                change = getattr(
                    reader,
                    "draft_change_token"
                    if self.drafts_enabled
                    and (self.live_drafts is None or ref not in self.live_drafts.sources)
                    else "change_token",
                    None,
                )
                token = change(ref) if callable(change) else None
                if token is not None and not isinstance(token, str):
                    raise ContractError("transcript_scheduling_token_invalid")
                before = self._mirror_seen.get(key)
                now = time.monotonic()
                if (
                    token is not None
                    and before
                    and before[0] == token
                    and before[2] != "scanning"
                    and now - before[1] < 30
                ):
                    if self.live_drafts and await self.live_drafts.collect(binding):
                        self._publication_wake.set()
                    continue  # Work scheduling only; every capture/output reauthorizes.
                state = await self.mirrors.collect(binding)
                if self.live_drafts and await self.live_drafts.collect(binding):
                    self._publication_wake.set()
                # A scan started at an earlier head; changes during continuation
                # must trigger another fresh-head scan immediately after it closes.
                scan_token = before[0] if before and before[2] == "scanning" else token
                self._mirror_seen[key] = (scan_token, now, state.status)
                self._publication_wake.set()
                if state.status == "gap":
                    await self.reconnect_owner_gap(binding)
            except DeliveryRateLimited as error:
                self._mirror_retry_at = time.monotonic() + max(1, error.retry_after)
                self.defer("transcript_scope_rate_limited")
                break
            except (ContractError, Conflict, AccessDenied, TransportError, ZulipError) as error:
                self.defer("transcript_not_current_or_authorized", error)
                if str(error) == "transcript_original_owner_or_semantics_changed":
                    # Just detected: try at once, so usually only the reconnected line shows.
                    await self.reconnect_owner_gap(binding)
        self._mirror_seen = {key: value for key, value in self._mirror_seen.items() if key in live}
        self._auto_reconnect = {
            key: value for key, value in self._auto_reconnect.items() if key in live
        }
        self._gap_settled = {k: v for k, v in self._gap_settled.items() if k in live}
        self._gap_seen = {k: v for k, v in self._gap_seen.items() if k in live}

    def creates_here(self, binding: Binding) -> bool:
        """Whether `!new` in another topic offers a new conversation in this binding's project."""
        project = self.creation.journal.projects.get(binding.project_id) if self.creation else None
        return project is not None and (
            project.template.scope.backend_id,
            project.template.scope.backend_identity,
        ) == (binding.backend_id, binding.backend_identity)

    def diff_here(self, binding: Binding) -> bool:
        """Whether `!diff` in this binding's topic shows its conversation's changes."""
        return self.file_menus is not None and self.file_menus.available(binding, "diff")

    def gap_notice_due(self, binding: Binding, reason: str | None) -> bool:
        """Hold an OpenCode restart's notice while automatic reconnect may still answer.

        A reconnect says so in one line, and a changed installation asks for `!reconnect`
        in one line; only a refusal, or no answer within the hold, posts the notice.
        """
        from jt_oz_bridge.services.transcript_reconnect import OWNER_GAP

        if reason != OWNER_GAP or self.mirrors is None or self.router.reconnect is None:
            return True
        key = (binding.id, binding.revision)
        if key in self._gap_settled:
            return self._gap_settled[key]
        first = self._gap_seen.setdefault(key, time.monotonic())
        return time.monotonic() - first >= GAP_NOTICE_HOLD

    async def reconnect_owner_gap(self, binding: Binding) -> bool:
        """Reconnect a conversation OpenCode restarted under, without asking anyone.

        Bounded tries per paused stream; a refusal leaves the gap and `!reconnect`
        as the person's fallback. Never raises into the mirror loop.
        """
        from jt_oz_bridge.services.transcript_reconnect import OWNER_GAP

        reconnect = self.router.reconnect
        if self.mirrors is None or reconnect is None:
            return False
        key = (binding.id, binding.revision)
        try:
            state, expected = await self.mirrors.load(binding)
        except (Conflict, ValueError) as error:
            self.defer("transcript_auto_reconnect_refused", error)
            self._gap_settled.setdefault(key, True)
            return False
        if (
            state is None
            or expected is None
            or state.status != "gap"
            or state.gap_reason != OWNER_GAP
        ):
            self._auto_reconnect.pop(key, None)
            self._gap_settled.pop(key, None)
            self._gap_seen.pop(key, None)
            return False
        seen, tries, next_at = self._auto_reconnect.get(key, (expected, 0, 0.0))
        if seen != expected:
            tries, next_at = 0, 0.0
        now = time.monotonic()
        if tries >= AUTO_RECONNECT_TRIES:
            self._gap_settled.setdefault(key, True)
            return False
        if now < next_at:
            return False
        self._auto_reconnect[key] = (expected, tries + 1, now + AUTO_RECONNECT_SPACING)
        try:
            await reconnect.automatic(
                binding,
                queue=self.router.queue,
                outbox=self.bound_outbox,
                message_limit=self.scope.enrolled.max_message_length,
                topic_limit=self.scope.enrolled.max_topic_length,
            )
        except DeliveryRateLimited as error:
            # Not a refusal: give this try back and wait like the mirror loop does.
            self._auto_reconnect[key] = (expected, tries, now + max(1, error.retry_after))
            self._mirror_retry_at = time.monotonic() + max(1, error.retry_after)
            self.defer("transcript_scope_rate_limited")
            return False
        except (
            ContractError,
            Conflict,
            AccessDenied,
            TransportError,
            ZulipError,
            ValueError,
        ) as error:
            self.defer("transcript_auto_reconnect_refused", error)
            if str(error) == "reconnect_automatic_installed_evidence_changed":
                self._gap_settled[key] = False  # The person was asked in one line.
            elif tries + 1 >= AUTO_RECONNECT_TRIES:
                self._gap_settled.setdefault(key, True)
            return False
        self._auto_reconnect.pop(key, None)
        self._gap_settled.pop(key, None)
        self._gap_seen.pop(key, None)
        LOG.info("transcript_auto_reconnected binding=%s", binding.id)
        self._publication_wake.set()
        return True

    async def pending_once(self) -> None:
        if time.monotonic() < self._pending_retry_at:
            return
        with request_lane("control"):
            await self.pending_notices_once()

    async def pending_lineage(
        self, binding: Binding, backend: RuntimeBackend
    ) -> tuple[SessionRef, ...]:
        root = reference(binding)
        await self.bindings.enrolled(root, binding.realm_id)
        current = await self.registry.snapshot(root)
        selected_nodes = (root, *current.descendants)
        if (
            current.reference != root
            or not current.reconciled
            or current.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
            or len(selected_nodes) > 1000
            or len(set(selected_nodes)) != len(selected_nodes)
            or not set(selected_nodes) <= set(backend.current_references)
        ):
            raise Conflict("pending_original_lineage_not_current")
        return selected_nodes

    async def pending_notices_once(self) -> None:
        async with self.db.sessions() as session:
            bindings = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(Binding.realm_id == self.realm_id, Binding.state == "active")
                        .order_by(Binding.created_at, Binding.id)
                        .limit(100)
                    )
                ).all()
            )
        live_notices: set[tuple[str, int, SessionRef, str]] = set()
        scan_complete = True
        for binding in bindings:
            backend = self.backends.get(binding.backend_id)
            if backend is None or reference(binding) not in backend.current_references:
                continue
            topic = (binding.id, binding.revision)
            quiet = self._feed_directory_fence(reference(binding))
            last = self._pending_quiet.pop(topic, None)
            if (
                quiet is not None
                and last is not None
                and last[0] == quiet
                and 0 <= time.monotonic() - last[1] < self.pending_quiet_seconds
            ):
                # Nothing arrived in its directory: what was pending still is.
                self._pending_quiet[topic] = last
                live_notices.update(n for n in self._announced if n[:2] == topic)
                continue
            try:
                root = reference(binding)
                selected_nodes = await self.pending_lineage(binding, backend)
                for selected in selected_nodes:
                    request_ids = await backend.pending(selected)
                    for request_id in request_ids:
                        notice = (binding.id, binding.revision, selected, request_id)
                        live_notices.add(notice)
                        if notice in self._announced:
                            continue
                        # One notice is one decision: Zulip is read in full here
                        # and again by queue_batch before the outbox commit. In
                        # between only owned SQL is re-checked against this read.
                        audience = await self.bindings.audience_for_output(binding)
                        locale = (
                            cast(Locale, binding.locale)
                            if binding.locale in {"en", "zh-TW"}
                            else "en"
                        )
                        quick: str | None = None
                        widget: str | None = None
                        try:
                            snapshot = await self.registry.interaction(selected, request_id)
                            if not snapshot.pending:
                                continue
                            identity = await self.interactions.observe(
                                binding, snapshot, audience=audience
                            )
                            key = "runtime-pending:" + identity
                            message_key = "runtime.pending"
                            quick = permission_notice(self.tr, snapshot, identity, locale)
                            if quick is not None:
                                # A new key: notices already sent in the old form stay as sent.
                                key = "runtime-permission:" + identity
                                widget = permission_widget(self.tr, snapshot, identity, locale)
                            elif quick := form_notice(self.tr, snapshot, identity, locale):
                                key = "runtime-question:" + identity
                                widget = form_widget(self.tr, snapshot, identity, locale)
                        except (ZulipAuthenticationFailed, AccessDenied, Conflict):
                            raise  # Scope/authority loss is never an unsupported preview.
                        except (ContractError, ValueError):
                            # A request resolved by the TUI or removed from the
                            # original tree is not an unsupported-preview notice.
                            if selected not in await self.pending_lineage(binding, backend):
                                raise Conflict("pending_request_lineage_changed") from None
                            if request_id not in await backend.pending(selected):
                                continue
                            # Still pending, but no actor decision token or
                            # substitute root request may be fabricated.
                            key = "runtime-unpreviewable:" + digest(
                                {
                                    "binding": binding.id,
                                    "revision": binding.revision,
                                    "reference": selected.model_dump(),
                                    "request": request_id,
                                }
                            )
                            message_key = "runtime.pending_unpreviewable"
                        text = quick if quick is not None else self.tr.render(message_key, locale)
                        if selected != root:
                            text += "\n\n" + self.tr.render(
                                "runtime.pending_requester",
                                locale,
                                parent=literal(visible_controls(root.upstream_session_id)[0]),
                                session=literal(visible_controls(selected.upstream_session_id)[0]),
                            )
                            widget = with_requester(
                                widget,
                                self.tr,
                                locale,
                                root.upstream_session_id,
                                selected.upstream_session_id,
                            )
                        if (
                            await self.bound_outbox.cached_batch(
                                key, binding.id, binding.revision, audience=audience
                            )
                            is not None
                        ):
                            # Sent before in an earlier wording: keep it, never re-render.
                            self._announced.add(notice)
                            continue
                        await self.bound_outbox.queue_batch(
                            key,
                            binding.id,
                            binding.revision,
                            (text,),
                            renderer_version=(
                                "runtime-question-notice-v1"
                                if key.startswith("runtime-question:")
                                else "runtime-permission-notice-v1"
                            )
                            if quick is not None
                            else "runtime-pending-notice-v3"
                            if selected != root
                            else "runtime-pending-notice-v2",
                            message_limit=self.scope.enrolled.max_message_length,
                            topic_limit=self.scope.enrolled.max_topic_length,
                            priority=5,
                            widget=widget,
                        )
                        self._announced.add(notice)
                if quiet is not None:
                    # Taken before the scan: anything arriving during it scans again.
                    self._pending_quiet[topic] = (quiet, time.monotonic())
            except DeliveryRateLimited as error:
                self._pending_retry_at = time.monotonic() + max(1, error.retry_after)
                scan_complete = False
                self.defer("pending_scope_rate_limited")
                break
            except ZulipAuthenticationFailed:
                raise  # Stop the supervised runtime; credentials need operator review.
            except (ContractError, Conflict, AccessDenied, TransportError, ZulipError) as error:
                scan_complete = False
                self.defer("pending_not_current_or_authorized", error)
        if scan_complete:
            self._announced.intersection_update(live_notices)

    async def pending(self) -> None:
        while True:
            await self.pending_once()
            await self.still_working_once()
            await asyncio.sleep(self.interval)

    async def still_working_once(self) -> None:
        """Optional and cosmetic: a failure here never stops pending notices."""
        if time.monotonic() < self._still_working_at:
            return
        self._still_working_at = time.monotonic() + STILL_WORKING_CHECK_SECONDS
        try:
            await self.still_working.once()
        except ZulipAuthenticationFailed:
            raise
        except Exception as error:
            self.defer("still_working_notice_not_current", error)

    async def publish_once(self) -> None:
        feedback_identity = await self.dispatch_feedback.next_pending()
        if feedback_identity is not None:
            try:
                with request_lane("control"):
                    await self.dispatch_feedback.publish(feedback_identity)
            except ZulipAuthenticationFailed:
                raise
            except DeliveryRateLimited as error:
                self.dispatch_feedback.defer(feedback_identity, error.retry_after)
                self.defer("unsent_feedback_rate_limited")
            except (ContractError, Conflict, AccessDenied, TransportError, ZulipError):
                self.dispatch_feedback.defer(feedback_identity)
                self.defer("unsent_feedback_not_current_or_authorized")
        if self.transcript_output is not None and time.monotonic() >= self._mirror_retry_at:
            try:
                pending = await self.transcript_output.next_pending()
                if pending is not None:
                    kind, identity = pending
                    if kind == "version":
                        with request_lane("final"):
                            await self.transcript_output.publish(identity)
                    else:
                        await self.transcript_output.scope_notice(identity, kind)
            except DeliveryRateLimited as error:
                self._mirror_retry_at = time.monotonic() + max(1, error.retry_after)
                self.defer("transcript_publication_rate_limited")
            except (ContractError, Conflict, AccessDenied, TransportError, ZulipError):
                self.defer("transcript_publication_not_authorized")
        for publisher in (
            self.results,
            self.model_results,
            self.lifecycle_results,
            self.lifecycle_control_results,
            self.check_results,
            self.git_notices,
            *((self.agent_results,) if self.agent_results is not None else ()),
        ):
            if time.monotonic() < self._results_retry_at:
                break
            next_identity = await publisher.next_pending()
            if next_identity is not None:
                try:
                    with request_lane("final"):
                        await publisher.publish(next_identity)
                except DeliveryRateLimited as error:
                    self._results_retry_at = time.monotonic() + max(1, error.retry_after)
                    self.defer("result_publication_rate_limited")
                    break
        if self.draft_output is not None and time.monotonic() >= max(
            self._mirror_retry_at, self._background_retry_at
        ):
            for _ in range(32):
                draft_identity = await self.draft_output.next_pending()
                if draft_identity is None:
                    break
                try:
                    with request_lane("draft"):
                        batch = await self.draft_output.publish(draft_identity)
                    if batch is not None:
                        break  # Bound actual publication work; empty/coalesced plans may drain.
                except DeliveryRateLimited as error:
                    if isinstance(error, RequestBudgetDeferred):
                        self._background_retry_at = time.monotonic() + max(1, error.retry_after)
                    else:
                        self._mirror_retry_at = time.monotonic() + max(1, error.retry_after)
                    await self.draft_output.defer(draft_identity, error.retry_after)
                    self.defer("draft_publication_rate_limited")
                    break
                except (ContractError, Conflict, AccessDenied, TransportError, ZulipError):
                    await self.draft_output.defer(draft_identity, 5)
                    self.defer("draft_publication_not_authorized")

    async def publish(self) -> None:
        while True:
            self._publication_wake.clear()
            await self.publish_once()
            try:
                await asyncio.wait_for(self._publication_wake.wait(), timeout=self.interval)
            except TimeoutError:
                pass

    async def deliver_once(self) -> bool:
        async with self.db.sessions() as session:
            identity = await session.scalar(DeliveryWorker.next_pending(self.realm_id, time.time()))
            saved = await session.get(Delivery, identity) if identity else None
        if saved is not None:
            worker = (
                self.discovery_delivery if saved.destination_id is not None else self.bound_delivery
            )
            await worker.advance(saved.id)
        return saved is not None

    async def deliver(self) -> None:
        delay = DELIVERY_POLL_SECONDS
        while True:
            sent = await self.deliver_once()
            # Back to back while posts wait; an idle Bridge looks a few times a second.
            delay = DELIVERY_POLL_SECONDS if sent else min(DELIVERY_IDLE_SECONDS, delay * 2)
            await asyncio.sleep(delay)
