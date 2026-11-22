"""Bounded original check suffix reconciliation against a sealed positive Idle.

No Native history is skipped by message-type filtering. An anchor shortens a
previously proved prefix; it never converts absence of active work into Idle.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from jt_oz_bridge.adapters.opencode.checks import (
    CheckExecutionAttestation,
    KnownCheck,
    V2CheckRunner,
    V2CheckTailReader,
    project_check,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport
from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.check_idle_anchor import CheckIdleAnchor
from jt_oz_bridge.domain.checks import check_message_id
from jt_oz_bridge.domain.model_catalog import NativeModelRef
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs

OriginalPreflight = Callable[[str, str, SessionRef, str], Awaitable[CheckDispatchPreflight]]
# The existing 51-record reconciliation bound is unchanged. Small pages prevent
# aggregating many 1 MiB shell previews into an over-budget response.
TAIL_RECORD_LIMIT = 51
TAIL_PAGE_SIZE = 2


class V2AnchoredCheckTailReader(V2CheckTailReader):
    def __init__(
        self,
        transport: V2HTTPTransport,
        qualification: CheckExecutionAttestation,
        known: Callable[[SessionRef, str], Awaitable[KnownCheck]],
        *,
        model_settings: ModelSettingsAttestation | None,
        proofs: V2LeafResourceProofs,
        reader: V2CheckRunner,
        original: OriginalPreflight | None,
    ) -> None:
        super().__init__(transport, qualification, known, model_settings=model_settings)
        self.proofs, self.reader, self.original = proofs, reader, original

    @staticmethod
    def same_model(a: NativeModelRef | None, b: NativeModelRef | None) -> bool:
        return a is None and b is None or a is not None and a.same_native_selection(b)

    @staticmethod
    def notice_pair(notice: dict[str, Any], row: dict[str, Any]) -> None:
        metadata = notice.get("metadata", {})
        if (
            row.get("type") != "shell"
            or row.get("status") not in {"exited", "timeout", "killed"}
            or metadata.get("source") != "shell"
            or metadata.get("shellID") != row.get("shellID")
            or metadata.get("state") != ("cancelled" if row["status"] == "killed" else "completed")
            or metadata.get("exit") != row.get("exit")
            or row.get("exit") is not None
            and type(row["exit"]) is not int
            or type(row.get("time", {}).get("completed")) is not int
            or row["time"]["completed"] > notice["time"]["created"]
        ):
            raise ContractError("native_check_anchor_notice_pair_changed")

    async def read(
        self, ref: SessionRef, info: dict[str, Any], latest: dict[str, Any]
    ) -> dict[str, Any]:
        qualification = self.qualification
        qualification.require(ref, self.transport.profile.sha256)
        attestation = self.transport.attestation
        model_settings = self.model_settings
        original_for = self.original
        if original_for is None:
            raise ContractError("native_check_anchor_original_journal_required")
        if (
            attestation is None
            or not {"session.message.list", "session.message.get", "shell.get"}
            <= attestation.verified_operations
            or self.reader.attestations.get(ref) is not qualification
        ):
            raise ContractError("native_check_anchor_reads_unqualified")
        started = time.time()
        fence = self.proofs.fence(ref)
        before = await self.proofs.read_scope(ref)
        if before.session_info_sha256 != digest(self.proofs.project_info(ref, info)):
            raise SnapshotBoundaryChanged("native_check_anchor_root_metadata_changed")
        expected_model = native_ref(info["model"]) if "model" in info else None
        expected_agent = info.get("agent")
        controls: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []
        ids: set[str] = set()
        cursors: set[str] = set()
        rows: list[dict[str, Any]] = []
        position, count = 0, 0
        next_cursor: str | None = None
        first_page = True
        exhausted = False
        newest = info["time"]["updated"]
        anchor: CheckIdleAnchor | None = None
        original: CheckDispatchPreflight | None = None
        notice: dict[str, Any] | None = None
        legacy = False

        async def next_row() -> dict[str, Any] | None:
            nonlocal rows, position, count, next_cursor, first_page, exhausted
            if position >= len(rows) and exhausted:
                return None
            if count >= TAIL_RECORD_LIMIT:
                raise ContractError("native_check_anchor_record_capacity")
            if position >= len(rows):
                page_limit = min(TAIL_PAGE_SIZE, TAIL_RECORD_LIMIT - count)
                query = {"limit": str(page_limit)}
                if first_page:
                    query["order"] = "desc"
                else:
                    if next_cursor is None or next_cursor in cursors:
                        raise ContractError("native_check_anchor_cursor_changed")
                    cursors.add(next_cursor)
                    query["cursor"] = next_cursor
                page = await self.transport.request(
                    "session.message.list",
                    path={"sessionID": ref.upstream_session_id},
                    query=query,
                )
                rows, position = page["data"], 0
                if not rows or len(rows) > page_limit:
                    raise ContractError("native_check_anchor_page_boundary_changed")
                if first_page and rows[0] != latest:
                    raise SnapshotBoundaryChanged("native_check_anchor_latest_changed")
                first_page = False
                next_cursor = page["cursor"].get("next")
                exhausted = next_cursor is None
            row = rows[position]
            position += 1
            count += 1
            if row["id"] in ids:
                raise ContractError("native_check_anchor_duplicate_message")
            ids.add(row["id"])
            return row

        async def finish(idle: dict[str, Any] | None, *, pristine: bool) -> dict[str, Any]:
            if notice is not None:
                raise ContractError("native_check_anchor_unpaired_notice")
            after = await self.proofs.read_scope(ref)
            if (
                (before.owner_epoch, before.connection_epoch, before.session_info_sha256)
                != (after.owner_epoch, after.connection_epoch, after.session_info_sha256)
                or self.proofs.fence(ref) != fence
                or self.transport.attestation is not attestation
                or self.qualification is not qualification
                or self.reader.attestations.get(ref) is not qualification
                or self.model_settings is not model_settings
                or self.original is not original_for
                or not started <= time.time() < started + 5
            ):
                raise SnapshotBoundaryChanged("native_check_anchor_owner_or_boundary_changed")
            return {
                "checks": checks,
                "model_controls": controls,
                "idle": idle,
                "pristine": pristine,
                "preflight_anchor_sha256": digest(original.model_dump(mode="json"))
                if original is not None
                else None,
            }

        async def anchored_boundary() -> dict[str, Any]:
            assert anchor is not None
            if anchor.model_settings_sha256 != (
                model_settings.enrollment_sha256 if model_settings is not None else None
            ) or not self.same_model(expected_model, anchor.selected_model):
                raise ContractError("native_check_anchor_model_boundary_changed")
            if anchor.idle is None:
                if not anchor.pristine or "outcome" in info or "idle" in info["time"]:
                    raise ContractError("native_check_anchor_pristine_changed")
                return await finish(None, pristine=True)
            idle = anchor.idle
            observed = (
                await self.transport.request(
                    "session.message.get",
                    path={"sessionID": ref.upstream_session_id, "messageID": idle.id},
                )
            )["data"]
            if (
                observed.get("type") != "idle"
                or observed.get("id") != idle.id
                or observed.get("outcome") != idle.outcome
                or observed.get("time", {}).get("created") != idle.created_at
                or type(observed.get("time", {}).get("created")) is not int
                or info.get("outcome") != idle.outcome
                or info["time"].get("idle") != idle.created_at
            ):
                raise ContractError("native_check_anchor_positive_idle_changed")
            return await finish(idle.wire(), pristine=False)

        while True:
            row = await next_row()
            if row is None:
                if anchor is not None and anchor.head is None:
                    return await anchored_boundary()
                if anchor is None and notice is None:
                    if (
                        "outcome" not in info
                        and "idle" not in info["time"]
                        and (not controls or expected_model is None)
                    ):
                        return await finish(None, pristine=True)
                    raise ContractError("native_check_tail_positive_idle_not_found_within_limit")
                raise ContractError("native_check_anchor_saved_head_missing")
            created = row["time"]["created"]
            if type(created) is not int or created > newest:
                raise ContractError("native_check_anchor_time_order_changed")
            newest = created
            if anchor is not None and anchor.head is not None and row["id"] == anchor.head.id:
                if (
                    row["type"] != anchor.head.type
                    or created != anchor.head.created_at
                    or digest({"latest": row}) != anchor.head.sha256
                ):
                    raise ContractError("native_check_anchor_saved_head_changed")
                if notice is not None:
                    # A late notice can follow the already terminal pre-send
                    # head. Validate that exact pair without replaying the old
                    # anchored check as a new action or requiring evicted output.
                    self.notice_pair(notice, row)
                    controls.append({"id": notice["id"], "sha256": digest(notice)})
                    notice = None
                return await anchored_boundary()
            if row["type"] == "idle":
                if anchor is not None or notice is not None:
                    raise ContractError("native_check_anchor_saved_head_not_reached")
                # Legacy journals still require an actual positive Native
                # boundary. Continue this same small-page scan and budget;
                # restarting another reader would silently read more than 51.
                if row["outcome"] != info.get("outcome") or created != info["time"].get("idle"):
                    raise ContractError("native_check_tail_idle_boundary_changed")
                return await finish(
                    {key: row[key] for key in ("id", "type", "time", "outcome")},
                    pristine=False,
                )
            if row["type"] == "agent-switched":
                if (
                    notice is not None
                    or self.agent_settings is None
                    or self.agent_settings(ref) is None
                ):
                    raise ContractError("native_check_anchor_agent_qualification_required")
                if row["agent"] != expected_agent:
                    raise ContractError("native_check_anchor_agent_chain_changed")
                expected_agent = row.get("previous")
                controls.append({"id": row["id"], "sha256": digest(row)})
                continue
            if row["type"] == "model-switched":
                if notice is not None or model_settings is None:
                    raise ContractError("native_check_anchor_model_qualification_required")
                model_settings.require(ref, self.transport.profile.sha256)
                if not native_ref(row["model"]).same_native_selection(expected_model):
                    raise ContractError("native_check_anchor_model_chain_changed")
                expected_model = native_ref(row["previous"]) if "previous" in row else None
                controls.append({"id": row["id"], "sha256": digest(row)})
                continue
            if row["type"] == "synthetic":
                metadata = row.get("metadata", {})
                if (
                    notice is not None
                    or metadata.get("source") != "shell"
                    or not isinstance(metadata.get("shellID"), str)
                    or metadata.get("state") not in {"completed", "cancelled"}
                ):
                    raise ContractError("native_check_anchor_unowned_synthetic")
                notice = row
                continue
            if row["type"] != "shell" or row["status"] not in {"exited", "timeout", "killed"}:
                raise ContractError("native_check_anchor_unknown_or_running_input")
            known = await self.known(ref, row["id"])
            if (
                known.qualification_sha256 != self.enrollment_sha256
                or row["id"] != check_message_id(known.action_id)
                or known.check not in qualification.catalog.checks
            ):
                raise ContractError("native_check_anchor_original_action_changed")
            recorded = await original_for(
                known.action_id, known.operation_digest, ref, qualification.enrollment_sha256
            )
            if (
                recorded.action_id != known.action_id
                or recorded.operation_digest != known.operation_digest
                or recorded.reference != ref
                or recorded.owner_epoch != before.owner_epoch
                or recorded.contract_sha256 != self.transport.profile.sha256
                or recorded.qualification_sha256 != qualification.enrollment_sha256
                or recorded.message_id != row["id"]
                or recorded.state != "idle"
            ):
                raise ContractError("native_check_anchor_original_owner_changed")
            observed = await self.reader.observe(ref, known.action_id, known.check)
            shell = await self.transport.request(
                "shell.get",
                path={"id": observed.shell_id},
                query={"location": {"directory": ref.canonical_directory}},
            )
            if shell["location"] != {
                "directory": ref.canonical_directory
            } or observed != project_check(
                ref,
                known.action_id,
                known.check,
                row,
                shell["data"],
                qualification_sha256=qualification.enrollment_sha256,
            ):
                raise SnapshotBoundaryChanged("native_check_anchor_terminal_pair_changed")
            if observed.outcome == "running":
                raise ContractError("native_check_anchor_terminal_required")
            if notice is not None:
                self.notice_pair(notice, row)
            checks.append(
                {
                    "message_id": row["id"],
                    "action_id": known.action_id,
                    "operation_digest": known.operation_digest,
                    "shell_sha256": digest(row),
                    "notice_sha256": digest(notice) if notice is not None else None,
                    "observation_sha256": observed.evidence_sha256,
                }
            )
            notice = None
            if recorded.idle_anchor is None:
                # A legacy record never borrows a later persisted anchor. Its
                # complete suffix must reach the real Idle/pristine boundary
                # within this single scan's original 51-record limit.
                legacy = True
            if anchor is None and not legacy and recorded.idle_anchor is not None:
                anchor, original = recorded.idle_anchor, recorded
                if anchor.reference != ref:
                    raise ContractError("native_check_anchor_original_root_changed")
