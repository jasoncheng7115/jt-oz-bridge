"""Confirmed, bounded conversation exports through the existing file return journal.

Only the existing safe transcript projection is exported. No raw Native endpoint,
reasoning/tool bodies, workspace path or HTML execution is introduced here.
"""

import asyncio
import hashlib
import json
import math
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any, Literal, cast
from uuid import uuid4
from weakref import WeakKeyDictionary, WeakValueDictionary
from weakref import ref as weakref

from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.transcript import (
    ERROR_TYPE,
    FILE_PATH_LIMIT,
    FILES_LIMIT,
    TOKEN_LIMIT,
    NativeTranscriptPage,
    TranscriptEntry,
    TranscriptReader,
)
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import NativeAttachmentProjection
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.security.workspace_paths import canonical_relative
from jt_oz_bridge.services.artifacts import FileDescriptor
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandClaim
from jt_oz_bridge.services.file_returns import (
    AnyFileReturnPlan,
    FileReturnDeferred,
    FileReturnJournal,
    check_content,
)
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.services.session_export_plans import (
    EXPORT_SCHEMA,
    OMITTED,
    ExportContext,
    TranscriptExportPlan,
)
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer

MAX_EXPORT_BYTES = 4 * 1024 * 1024
MAX_EXPORT_PAGES = 10


def safe_export_entry(entry: TranscriptEntry) -> dict[str, object]:
    """Fail closed if an injected/custom reader widens the history projection."""
    checked = TranscriptEntry.model_validate_json(entry.model_dump_json())
    value = checked.projection()
    fields = {
        "user": {"text", "attachments_present"},
        "assistant": {
            "content",
            "agent",
            "model",
            "tokens",
            "error",
            "retry",
            "files",
            "files_total",
        },
        "idle": {"outcome", "error_sha256", "error"},
        "model-switched": {"model", "previous"},
        "agent-switched": {"agent"},
        "shell": {"status", "exit"},
        "compaction": {"status", "exit", "reason", "error"},
    }.get(entry.kind, set())
    if set(value) - {"id", "type", "time"} - fields:
        raise Conflict("session_export_projection_widened")

    def error(raw: object) -> None:
        """Only the safe type and HTTP status the adapter keeps of an OpenCode error."""
        if (
            not isinstance(raw, dict)
            or set(raw) - {"type", "status"}
            or "type" in raw
            and not (isinstance(raw["type"], str) and ERROR_TYPE.fullmatch(raw["type"]))
            or "status" in raw
            and not (type(raw["status"]) is int and 100 <= raw["status"] <= 599)
        ):
            raise Conflict("session_export_error_projection_changed")

    def timestamp(raw: object) -> None:
        if (
            not isinstance(raw, dict)
            or set(raw) - {"created", "started", "streamed", "ran", "completed"}
            or any(
                type(v) not in {int, float} or not math.isfinite(v) or v < 0 for v in raw.values()
            )
        ):
            raise Conflict("session_export_time_projection_changed")

    def model(raw: object) -> None:
        if (
            not isinstance(raw, dict)
            or set(raw) - {"providerID", "id", "variant"}
            or any(not isinstance(v, str) for v in raw.values())
        ):
            raise Conflict("session_export_model_projection_changed")

    def calls(raw: object) -> None:
        """Only the MCP tool names and states a code-mode step ran."""
        if (
            not isinstance(raw, list)
            or len(raw) > 20
            or any(
                not isinstance(call, dict)
                or set(call) != {"tool", "status"}
                or not isinstance(call["tool"], str)
                or len(call["tool"]) > 200
                or not isinstance(call["status"], str)
                or len(call["status"]) > 32
                for call in raw
            )
        ):
            raise Conflict("session_export_tool_calls_projection_changed")

    def tokens(raw: object) -> None:
        """A finished step's whole-number token counts, nothing else."""
        if (
            not isinstance(raw, dict)
            or set(raw) != {"input", "output", "reasoning", "cache_read", "cache_write"}
            or any(type(v) is not int or not 0 <= v <= TOKEN_LIMIT for v in raw.values())
        ):
            raise Conflict("session_export_tokens_projection_changed")

    timestamp(value["time"])
    if entry.kind == "user" and not isinstance(value.get("text"), str):
        raise Conflict("session_export_text_projection_changed")
    if entry.kind == "assistant":
        model(value.get("model"))
        if not isinstance(value.get("agent"), str) or not isinstance(value.get("content"), list):
            raise Conflict("session_export_assistant_projection_changed")
        for part in value["content"]:
            if not isinstance(part, dict):
                raise Conflict("session_export_part_projection_changed")
            allowed = (
                {"type", "index", "text"}
                if part.get("type") == "text"
                else {
                    "type",
                    "index",
                    "id",
                    "name",
                    "status",
                    "time",
                    "exit_code",
                    "error_sha256",
                    "calls",
                }
            )
            if part.get("type") not in {"text", "tool"} or set(part) - allowed:
                raise Conflict("session_export_part_projection_widened")
            if part["type"] == "text" and not isinstance(part.get("text"), str):
                raise Conflict("session_export_part_text_changed")
            if part["type"] == "tool":
                timestamp(part.get("time"))
                if any(not isinstance(part.get(k), str) for k in ("id", "name", "status")):
                    raise Conflict("session_export_tool_projection_changed")
                if "calls" in part:
                    calls(part["calls"])
    if entry.kind == "model-switched":
        model(value.get("model"))
        if value.get("previous") is not None:
            model(value["previous"])
    if "tokens" in value:
        tokens(value["tokens"])
    if "error" in value:
        error(value["error"])
    if "retry" in value:
        retry = value["retry"]
        if (
            not isinstance(retry, dict)
            or set(retry) != {"attempt", "error"}
            or type(retry["attempt"]) is not int
            or retry["attempt"] < 1
        ):
            raise Conflict("session_export_retry_projection_changed")
        error(retry["error"])
    if "files" in value or "files_total" in value:
        # Only the bounded canonical relative paths the adapter keeps of a snapshot.
        files, total = value.get("files"), value.get("files_total", None)
        try:
            if (
                not isinstance(files, list)
                or not 1 <= len(files) <= FILES_LIMIT
                or any(
                    not isinstance(path, str)
                    or len(path) > FILE_PATH_LIMIT
                    or canonical_relative(path) != path
                    for path in files
                )
                or len(set(files)) != len(files)
                or "files_total" in value
                and (type(total) is not int or total <= len(files))
            ):
                raise ValueError("session_export_files_shape")
        except ValueError:
            raise Conflict("session_export_files_projection_changed") from None
    # No nested arbitrary objects may ride in an otherwise allowed scalar.
    for key in fields - {"content", "model", "previous", "tokens", "error", "retry", "files"}:
        if key in value and not isinstance(value[key], (str, int, float, bool, type(None))):
            raise Conflict("session_export_scalar_projection_changed")
    return value


def encode_conversation(pages: tuple[NativeTranscriptPage, ...], encoding: str) -> bytes:
    if not pages or encoding not in {"json", "markdown"}:
        raise ValueError("session_export_capture_required")
    first = pages[0]
    value = {
        "format": EXPORT_SCHEMA,
        "reference": first.reference.model_dump(mode="json"),
        "captured_at": first.observed_at,
        "capture_window_end": pages[-1].observed_at,
        "coverage": {
            "order": "newest-first",
            "older_omitted": pages[-1].next_cursor is not None,
            "omitted_fields": list(OMITTED),
            "complete_raw_native_export": False,
        },
        "entries": [safe_export_entry(entry) for page in pages for entry in page.entries],
    }
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if encoding == "markdown":
        # JSON in one balanced fence preserves every safe projected field and
        # hostile HTML/mentions as file data, never a chat execution surface.
        fence = "`" * max(3, max((len(m[0]) + 1 for m in re.finditer(r"`+", text)), default=3))
        text = (
            "# Safe conversation export\n\nPartial projection; see coverage and omitted fields.\n\n"
            + fence
            + "json\n"
            + text
            + fence
            + "\n"
        )
    content = text.encode("utf-8")
    if len(content) > MAX_EXPORT_BYTES:
        raise Conflict("session_export_capacity_exceeded")
    check_content(content)
    return content


async def capture_conversation(
    selected: TranscriptReader, ref: SessionRef
) -> tuple[NativeTranscriptPage, ...]:
    pages: list[NativeTranscriptPage] = []
    cursor = None
    seen: set[str] = set()
    cursors: set[str] = set()
    captured_bytes = 0
    for _ in range(MAX_EXPORT_PAGES):
        page = await selected.capture(ref, cursor=cursor, limit=20)
        # Revalidate copied nested DTOs, but retain original issuer object for current().
        NativeTranscriptPage.model_validate_json(page.model_dump_json())
        if (
            page.reference != ref
            or page.cursor != cursor
            or page.limit != 20
            or page.contract_sha256 != selected.contract_for(ref)
            or len(page.entries) > 20
            or any(entry.native_id in seen for entry in page.entries)
            or len({entry.native_id for entry in page.entries}) != len(page.entries)
            or page.next_cursor is not None
            and (not page.entries or page.next_cursor in cursors)
            or not page.observed_at <= time.time() < page.expires_at <= page.observed_at + 5
            or page.next_cursor is not None
            and not 1 <= len(page.next_cursor) <= 8192
            or not selected.current(page)
            or pages
            and any(
                getattr(page, field) != getattr(pages[0], field)
                for field in (
                    "contract_sha256",
                    "semantics_sha256",
                    "installed_evidence_sha256",
                    "owner_epoch",
                    "connection_epoch",
                    "resource_fence",
                    "session_info_sha256",
                    "state",
                )
            )
        ):
            raise Conflict("session_export_page_boundary_changed")
        captured_bytes += len(page.model_dump_json().encode())
        if captured_bytes > MAX_EXPORT_BYTES:
            raise Conflict("session_export_capture_capacity_exceeded")
        pages.append(page)
        seen.update(entry.native_id for entry in page.entries)
        if page.next_cursor is None:
            break
        cursors.add(page.next_cursor)
        cursor = page.next_cursor
    if not all(selected.current(page) for page in pages):
        raise Conflict("session_export_capture_expired_or_replaced")
    return tuple(pages)


class SessionExportJournal(FileReturnJournal):
    """Adds an honest transcript artifact origin to the shared upload state machine."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._export_scopes: WeakKeyDictionary[
            asyncio.Task[Any], tuple[str, Callable[[], bool]]
        ] = WeakKeyDictionary()

    async def observe_export(self, context: ExportContext) -> Callable[[], bool]:
        """Fresh GET-only original scope proof; never replace the sealed artifact bytes."""
        selected = self.export_readers.get(context.reference)
        if selected is None or selected.contract_for(context.reference) != context.contract_sha256:
            raise Conflict("session_export_scope_reader_unavailable")
        page = await selected.capture(context.reference, limit=1)
        if (
            (
                page.reference,
                page.contract_sha256,
                page.owner_epoch,
                page.connection_epoch,
                page.semantics_sha256,
                page.installed_evidence_sha256,
            )
            != (
                context.reference,
                context.contract_sha256,
                context.owner_epoch,
                context.connection_epoch,
                context.semantics_sha256,
                context.installed_evidence_sha256,
            )
            or page.cursor is not None
            or page.limit != 1
        ):
            raise Conflict("session_export_original_upstream_scope_changed")
        task = asyncio.current_task()
        if task is None:
            raise Conflict("session_export_scope_task_required")
        task_ref = weakref(task)

        def current() -> bool:
            try:
                return (
                    asyncio.current_task() is task_ref()
                    and self.export_readers.get(context.reference) is selected
                    and selected.contract_for(context.reference) == context.contract_sha256
                    and page.observed_at <= time.time() < page.expires_at <= page.observed_at + 5
                    and selected.current(page)
                )
            except (TypeError, ValueError):
                return False

        if not current():
            raise Conflict("session_export_upstream_scope_not_current")
        return current

    async def current(self, plan: AnyFileReturnPlan) -> Binding:
        binding = await super().current(plan)
        if not isinstance(plan, TranscriptExportPlan):
            return binding
        current = await self.observe_export(plan.preview)
        # Source/audience work may await after Native; keep the original issued
        # proof current through those awaits and the later SQL/send boundary.
        for source in (plan.preview.preview_source, plan.source):
            if await self.source.read(source.realm_id, source.message_id) != source:
                raise Conflict("session_export_original_human_source_changed")
        binding = await self.bindings.get(
            plan.binding_id, plan.source.realm_id, plan.source.author_id, Permission.OPERATE
        )
        if (
            binding.revision != plan.binding_revision
            or reference(binding) != plan.reference
            or not current()
        ):
            raise Conflict("session_export_final_scope_changed")
        task = asyncio.current_task()
        if task is None:
            raise Conflict("session_export_scope_task_required")
        self._export_scopes[task] = (plan.id, current)
        return binding

    def export_scope_witness(self, plan: TranscriptExportPlan) -> Callable[[], bool]:
        task = asyncio.current_task()
        issued = self._export_scopes.get(task) if task is not None else None
        if issued is None or issued[0] != plan.id:
            raise Conflict("session_export_current_scope_not_issued_for_task")
        return issued[1]

    def require_export_scope(self, plan: TranscriptExportPlan) -> None:
        if not self.export_scope_witness(plan)():
            raise Conflict("session_export_original_scope_expired_before_commit")

    def configure_exports(self, readers: Mapping[SessionRef, TranscriptReader]) -> None:
        if hasattr(self, "export_readers"):
            raise ValueError("session_export_readers_already_configured")
        self.export_readers = readonly_enrollment(readers)

    async def authorize_source(self, plan: AnyFileReturnPlan) -> None:
        if not isinstance(plan, TranscriptExportPlan):
            await super().authorize_source(plan)
            return
        selected = self.export_readers.get(plan.reference)
        if (
            selected is None
            or selected.contract_for(plan.reference) != plan.preview.contract_sha256
        ):
            raise Conflict("session_export_reader_contract_changed")
        if (
            await self.source.read(plan.source.realm_id, plan.preview.preview_source.message_id)
            != plan.preview.preview_source
        ):
            raise Conflict("session_export_preview_source_changed")
        async with self.db.sessions() as session:
            await self.export_scope(session, plan)

    async def export_scope(self, session: AsyncSession, plan: TranscriptExportPlan) -> None:
        token = await session.get(ControlToken, plan.token_hash)
        if (
            token is None
            or (
                token.kind,
                token.used,
                token.realm_id,
                token.user_id,
                token.binding_id,
                token.binding_revision,
                token.context_hash,
                token.context,
            )
            != (
                "session-export",
                True,
                plan.source.realm_id,
                plan.source.author_id,
                plan.binding_id,
                plan.binding_revision,
                plan.token_context_hash,
                plan.preview.model_dump(mode="json"),
            )
            or digest(token.context) != token.context_hash
        ):
            raise Conflict("session_export_confirmation_changed")
        saved = await session.get(CommandReceipt, plan.confirmation_id)
        if saved is None or (
            saved.command,
            saved.realm_id,
            saved.message_id,
            saved.actor_id,
            saved.channel_id,
            saved.topic,
            saved.source_revision,
            saved.source_hash,
            saved.binding_id,
            saved.binding_revision,
        ) != (
            "export",
            plan.source.realm_id,
            plan.source.message_id,
            plan.source.author_id,
            plan.source.channel_id,
            plan.source.topic,
            plan.source.revision,
            digest(plan.source.model_dump(mode="json")),
            plan.binding_id,
            plan.binding_revision,
        ):
            raise Conflict("session_export_original_confirmation_receipt_changed")
        if saved.state == "processing":
            raise FileReturnDeferred("session_export_command_still_processing")
        if saved.state != "completed" or saved.response != {
            "text": self.tr.render(
                "file.record",
                plan.locale,
                state=self.tr.render("file.state.prepared", plan.locale),
            ),
            "locale": plan.locale,
        }:
            raise Conflict("session_export_confirmation_not_completed")

    async def lock_plan(self, session: AsyncSession, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, TranscriptExportPlan):
            await self.export_scope(session, plan)
            self.require_export_scope(plan)
        else:
            await super().lock_plan(session, plan)

    async def publishable(self, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, TranscriptExportPlan):
            async with self.db.sessions() as session:
                await self.export_scope(session, plan)
        else:
            await super().publishable(plan)


class GeneratedSessionExportJournal(SessionExportJournal, GeneratedFileReturnJournal):
    """Both enrolled origins, retaining each origin's cooperative guard chain."""


class SessionExportCommands:
    def __init__(self, journal: SessionExportJournal, tokens: TokenService) -> None:
        if (
            not hasattr(journal, "export_readers")
            or tokens.db is not journal.db
            or tokens.fence != journal.fence
        ):
            raise ValueError("session_export_original_scope_required")
        self.journal, self.tokens = journal, tokens
        self.bindings, self.reader, self.db, self.fence = (
            journal.bindings,
            journal.source,
            journal.db,
            journal.fence,
        )
        self.tr = journal.tr
        self._locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        self._slots = asyncio.Semaphore(2)

    def available(self, binding: Binding) -> bool:
        ref = reference(binding)
        return ref in self.journal.export_readers

    async def current(self, binding: Binding, source: HumanMessage, claim: CommandClaim) -> None:
        parsed = parse_input(source.text, bound=True)
        if (
            parsed.kind != "command"
            or parsed.command != "export"
            or source.is_bot
            or source.deleted
            or source.revision != 0
            or (source.realm_id, source.channel_id, source.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or claim.status != "claimed"
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("session_export_original_human_changed")
        current = await self.bindings.get(
            binding.id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            current.revision != binding.revision
            or reference(current) != reference(binding)
            or not self.available(current)
        ):
            raise Conflict("session_export_original_binding_changed")
        if self.journal.export_readers[reference(binding)].contract_for(
            reference(binding)
        ) != self.bindings.control.contract_for(reference(binding)):
            raise Conflict("session_export_original_contract_changed")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.journal.operator_lock(session, binding, source.author_id)
            await self.claim_in_session(session, binding, source, claim)

    async def claim_in_session(
        self, session: AsyncSession, binding: Binding, source: HumanMessage, claim: CommandClaim
    ) -> None:
        saved = await session.get(CommandReceipt, claim.id, with_for_update=True)
        if saved is None or (
            saved.version,
            saved.state,
            saved.holder,
            saved.fencing,
            saved.command,
            saved.realm_id,
            saved.message_id,
            saved.actor_id,
            saved.channel_id,
            saved.topic,
            saved.source_revision,
            saved.source_hash,
            saved.binding_id,
            saved.binding_revision,
        ) != (
            claim.version,
            "processing",
            self.fence.holder,
            self.fence.fencing,
            "export",
            source.realm_id,
            source.message_id,
            source.author_id,
            source.channel_id,
            source.topic,
            source.revision,
            digest(source.model_dump(mode="json")),
            binding.id,
            binding.revision,
        ):
            raise Conflict("session_export_owned_command_required")

    async def preview(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        claim: CommandClaim,
        encoding: Literal["json", "markdown"],
    ) -> str:
        await self.current(binding, source, claim)
        ref = reference(binding)
        selected = self.journal.export_readers[ref]
        pages = await capture_conversation(selected, ref)
        content = encode_conversation(tuple(pages), encoding)
        await self.current(binding, source, claim)
        self.require_capture(binding, selected, pages)
        projection = NativeAttachmentProjection(
            filename="conversation.json" if encoding == "json" else "conversation.md",
            mime_type="application/json" if encoding == "json" else "text/markdown",
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
        )

        async def chunks() -> AsyncIterator[bytes]:
            yield content

        artifact = await self.journal.artifacts.create(
            binding.id,
            source.realm_id,
            source.author_id,
            FileDescriptor(filename=projection.filename, mime_type=projection.mime_type),
            chunks(),
            kind="export",
            expected_size=len(content),
            expected_sha256=projection.sha256,
            source_message_id=source.message_id,
            ttl_seconds=3600,
        )
        await self.current(binding, source, claim)
        self.require_capture(binding, selected, pages)
        context = ExportContext(
            artifact_id=artifact,
            preview_source=source,
            reference=ref,
            contract_sha256=selected.contract_for(ref),
            projection=projection,
            owner_epoch=pages[0].owner_epoch,
            connection_epoch=pages[0].connection_epoch,
            semantics_sha256=pages[0].semantics_sha256,
            installed_evidence_sha256=pages[0].installed_evidence_sha256,
            captured_at=pages[0].observed_at,
            entry_count=sum(len(page.entries) for page in pages),
            older_omitted=pages[-1].next_cursor is not None,
            encoding=encoding,
        )
        # Token and final SQL scope are one transaction; no network publication here.
        if self.tokens.active_plan is not None:
            raise Conflict("session_export_nested_token_plan_forbidden")
        with self.tokens.planning() as plan:
            token = await self.tokens.issue(
                "session-export",
                source.realm_id,
                source.author_id,
                context.model_dump(mode="json"),
                ttl=300,
                binding_id=binding.id,
                binding_revision=binding.revision,
            )
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await self.journal.operator_lock(session, binding, source.author_id)
                await self.claim_in_session(session, binding, source, claim)
                self.require_capture(binding, selected, pages)
                await plan.commit(session)
                self.require_capture(binding, selected, pages)
        return self.tr.render(
            "export.preview",
            locale,
            count=sum(len(page.entries) for page in pages),
            size=len(content),
            sha256=projection.sha256,
            coverage=self.tr.render(
                "export.truncated" if context.older_omitted else "export.all_available", locale
            ),
            token=token,
        )

    def require_capture(
        self, binding: Binding, selected: TranscriptReader, pages: tuple[NativeTranscriptPage, ...]
    ) -> None:
        if self.journal.export_readers.get(reference(binding)) is not selected or not all(
            selected.current(p) for p in pages
        ):
            raise Conflict("session_export_capture_expired_or_replaced")

    async def confirm(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        claim: CommandClaim,
        token: str,
    ) -> str:
        await self.current(binding, source, claim)
        saved = await self.tokens.inspect(
            token, "session-export", source.realm_id, source.author_id
        )
        context = ExportContext.model_validate(saved.context)
        if (
            saved.binding_id,
            saved.binding_revision,
            context.reference,
            context.contract_sha256,
        ) != (
            binding.id,
            binding.revision,
            reference(binding),
            self.bindings.control.contract_for(reference(binding)),
        ):
            raise Conflict("session_export_preview_scope_changed")
        if (
            context.preview_source.realm_id,
            context.preview_source.author_id,
            context.preview_source.channel_id,
            context.preview_source.topic,
        ) != (source.realm_id, source.author_id, source.channel_id, source.topic):
            raise Conflict("session_export_preview_actor_or_topic_changed")
        if (
            await self.reader.read(source.realm_id, context.preview_source.message_id)
            != context.preview_source
        ):
            raise Conflict("session_export_preview_source_changed")
        artifact = await self.journal.artifacts.read(
            context.artifact_id, source.realm_id, source.author_id
        )
        if (
            artifact.sha256,
            len(artifact.content),
            artifact.descriptor.filename,
            artifact.descriptor.mime_type,
        ) != (
            context.projection.sha256,
            context.projection.size,
            context.projection.filename,
            context.projection.mime_type,
        ):
            raise Conflict("session_export_preview_bytes_changed")
        check_content(artifact.content)
        await self.current(binding, source, claim)
        current_scope = await self.journal.observe_export(context)
        if (
            await self.reader.read(source.realm_id, context.preview_source.message_id)
            != context.preview_source
        ):
            raise Conflict("session_export_preview_source_changed")
        await self.current(binding, source, claim)
        if not current_scope():
            raise Conflict("session_export_scope_expired_before_confirmation")
        plan = TranscriptExportPlan(
            id=str(uuid4()),
            artifact_id=context.artifact_id,
            binding_id=binding.id,
            binding_revision=binding.revision,
            source=source,
            reference=reference(binding),
            preview=context,
            confirmation_id=claim.id,
            token_hash=saved.token_hash,
            token_context_hash=saved.context_hash,
            projection=context.projection,
            locale=locale,
            realm_url=self.journal.uploader.client.url,
            bot_user_id=self.journal.outbox.bot_user_id,
            message_limit=self.journal.message_limit,
            topic_limit=self.journal.topic_limit,
        )
        if self.tokens.active_plan is not None:
            raise Conflict("session_export_nested_token_plan_forbidden")
        payload = plan.model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.journal.operator_lock(session, binding, source.author_id)
            await self.claim_in_session(session, binding, source, claim)
            row = await session.get(Artifact, context.artifact_id, with_for_update=True)
            if (
                row is None
                or (
                    row.kind,
                    row.state,
                    row.binding_id,
                    row.binding_revision,
                    row.realm_id,
                    row.project_id,
                    row.actor_id,
                    row.source_message_id,
                    row.size_bytes,
                    row.checksum,
                )
                != (
                    "export",
                    "ready",
                    binding.id,
                    binding.revision,
                    source.realm_id,
                    binding.project_id,
                    source.author_id,
                    context.preview_source.message_id,
                    context.projection.size,
                    context.projection.sha256,
                )
                or row.expires_at <= time.time()
            ):
                raise Conflict("session_export_artifact_scope_changed")
            await self.tokens.consume_in_session(session, saved, database_deadline=True)
            session.add(
                FileTransfer(
                    id=plan.id,
                    dedupe_key="session-export:" + saved.token_hash,
                    artifact_id=context.artifact_id,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    realm_id=source.realm_id,
                    source_message_id=source.message_id,
                    actor_id=source.author_id,
                    state="prepared",
                    version=1,
                    attempts=0,
                    retry_at=0,
                    payload=payload,
                    payload_hash=digest(payload),
                )
            )
            await session.flush()
            if not current_scope():
                raise Conflict("session_export_scope_expired_before_confirmation_commit")
        return self.tr.render(
            "file.record",
            locale,
            state=self.tr.render("file.state.prepared", locale),
        )

    async def route(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        arguments: str,
        claim: CommandClaim,
    ) -> str:
        lock = self._locks.setdefault(claim.id, asyncio.Lock())
        async with lock, self._slots:
            return await self._route(binding, source, locale, arguments, claim)

    async def _route(
        self,
        binding: Binding,
        source: HumanMessage,
        locale: Locale,
        arguments: str,
        claim: CommandClaim,
    ) -> str:
        if parse_input(source.text, bound=True).arguments != arguments:
            raise Conflict("session_export_route_source_changed")
        if not self.available(binding):
            return self.tr.render("export.unavailable", locale)
        if arguments.strip() in {"", "json", "markdown"}:
            return await self.preview(
                binding,
                source,
                locale,
                claim,
                cast(Literal["json", "markdown"], arguments.strip() or "json"),
            )
        match = re.fullmatch(r"confirm ([A-Za-z0-9_-]{32})", arguments.strip())
        if match is None:
            raise ValueError("session_export_usage")
        return await self.confirm(binding, source, locale, claim, match[1])
