"""Native read-only backend catalog/state observations, never execution proofs."""

import asyncio
import time
from typing import Any, Protocol

from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head, reconcile_aborted_turn_tail
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence
from jt_oz_bridge.adapters.opencode.model_settings import reconcile_model_tail
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, last_outcome, root_state
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import InspectionSession

INSPECTION_READS = frozenset(
    {
        "session.list",
        "session.get",
        "session.active",
        "session.inbox.list",
        "session.permission.list",
        "session.form.list",
        "session.message.list",
        "shell.list",
    }
)


class InspectionOwner(Protocol):
    async def read(self) -> HostOwnerEvidence: ...


class V2SessionInspection:
    def __init__(
        self,
        transport: V2HTTPTransport,
        owner: InspectionOwner,
        backend_id: str,
        backend_identity: str,
    ) -> None:
        self.transport, self.owner = transport, owner
        self.backend_id, self.backend_identity = backend_id, backend_identity
        self._gate = asyncio.Semaphore(2)

    @property
    def contract_sha256(self) -> str:
        """Current qualified read contract, never a database registration hint."""
        return self.selected().schema_sha256

    def selected(self) -> ContractAttestation:
        a = self.transport.attestation
        if (
            a is None
            or a.schema_sha256 != INSTALLED_SCHEMA
            or self.transport.profile.sha256 != INSTALLED_SCHEMA
            or a.backend_identity != self.backend_identity
            or a.upstream_version != "2.0.32"
            or not INSPECTION_READS <= a.verified_operations
            or self.transport.verify_identity is None
        ):
            raise ContractError("installed_backend_inspection_contract_required")
        return a

    async def original_owner(self) -> HostOwnerEvidence:
        self.selected()
        value = await self.owner.read()
        if (
            value.backend_id != self.backend_id
            or value.backend_identity != self.backend_identity
            or value.version != "2.0.32"
            or not 0 <= time.time() - value.observed_at < 5
        ):
            raise ContractError("local_inspection_original_owner_unverified")
        return value

    def project(self, raw: dict[str, Any]) -> InspectionSession:
        self.transport.profile.prepare("session.get", path={"sessionID": raw["id"]})
        directory = raw["location"]["directory"]
        if not directory.startswith("/") or "\x00" in directory:
            raise ContractError("native_catalog_location_invalid")
        return InspectionSession(
            backend_id=self.backend_id,
            backend_identity=self.backend_identity,
            session_id=raw["id"],
            native_project_id=raw["projectID"],
            directory=directory,
            title=raw.get("title", raw["id"])[:10000],
            title_truncated=len(raw.get("title", raw["id"])) > 10000,
            agent_id=raw.get("agent"),
            provider_id=raw.get("model", {}).get("providerID"),
            model_id=raw.get("model", {}).get("id"),
            variant=raw.get("model", {}).get("variant"),
            parent_id=raw.get("parentID"),
            fork_source_id=raw.get("fork", {}).get("sessionID"),
            last_outcome=raw.get("outcome"),
            observed_at=time.time(),
        )

    async def page(
        self, limit: int, cursor: str | None, *, project: tuple[str, str] | None = None
    ) -> tuple[tuple[InspectionSession, ...], str | None]:
        if (
            type(limit) is not int
            or not 1 <= limit <= 50
            or cursor is not None
            and (not cursor or len(cursor) > 8192)
        ):
            raise ValueError("bounded_inspection_page_required")
        before = await self.original_owner()
        attestation = self.selected()
        query = {"limit": str(limit), "order": "desc"}
        if cursor:
            query["cursor"] = cursor
        if project:
            query.update(project=project[0], directory=project[1])
        response = await self.transport.request("session.list", query=query)
        raw = response["data"]
        if len(raw) > limit or len({r["id"] for r in raw}) != len(raw):
            raise ContractError("native_inspection_duplicate_or_oversized_page")
        if project and any((r["projectID"], r["location"]["directory"]) != project for r in raw):
            raise ContractError("native_inspection_project_filter_changed")
        rows = tuple(self.project(r) for r in raw)
        after = await self.original_owner()
        next_cursor = response["cursor"].get("next")
        if (
            self.selected() is not attestation
            or before.owner_epoch != after.owner_epoch
            or next_cursor is not None
            and next_cursor == cursor
        ):
            raise ContractError("native_inspection_identity_or_cursor_changed")
        return tuple(
            row.model_copy(update={"owner_epoch": after.owner_epoch}) for row in rows
        ), next_cursor

    async def _bundle(self, row: InspectionSession) -> dict[str, Any]:
        sid = {"sessionID": row.session_id}
        t = self.transport
        info, active, inbox, permissions, forms, messages, shells = await asyncio.gather(
            t.request("session.get", path=sid),
            t.request("session.active"),
            t.request("session.inbox.list", path=sid),
            t.request("session.permission.list", path=sid),
            t.request("session.form.list", path=sid),
            t.request("session.message.list", path=sid, query={"limit": "1", "order": "desc"}),
            t.request("shell.list", query={"location": {"directory": row.directory}}),
        )
        raw = info["data"]
        if (raw["id"], raw["projectID"], raw["location"]["directory"]) != (
            row.session_id,
            row.native_project_id,
            row.directory,
        ):
            raise ContractError("native_inspection_session_scope_changed")
        if shells["location"]["directory"] != row.directory:
            raise ContractError("native_inspection_shell_location_changed")
        catalogs = [inbox["data"], permissions["data"], forms["data"], shells["data"]]
        if any(len(c) > 1000 or len({v["id"] for v in c}) != len(c) for c in catalogs):
            raise ContractError("native_inspection_catalog_capacity_or_identity")
        if any(v["sessionID"] != row.session_id for c in catalogs[:3] for v in c):
            raise ContractError("native_inspection_pending_foreign_session")
        if any(f.get("state", {"status": "pending"})["status"] != "pending" for f in forms["data"]):
            raise ContractError("native_inspection_settled_form_in_pending_list")
        if any(s["status"] != "running" for s in shells["data"]):
            raise ContractError("native_inspection_running_shell_contract_changed")
        if (
            len(messages["data"]) > 1
            or not messages["data"]
            and messages["cursor"].get("next") is not None
        ):
            raise ContractError("native_inspection_latest_message_boundary")
        latest = messages["data"][0] if messages["data"] else None
        if latest is not None and latest.get("sessionID", row.session_id) != row.session_id:
            raise ContractError("native_inspection_latest_message_scope")
        fields = (
            {k: latest[k] for k in ("id", "type", "time", "outcome") if k in latest}
            if latest is not None
            else None
        )
        bundle: dict[str, Any] = {
            "info": {
                k: v
                for k, v in raw.items()
                if k not in ("tokens", "cost", "metadata", "permissions")
            },
            "active": row.session_id in active["data"],
            "inbox_ids": sorted(v["id"] for v in inbox["data"]),
            "permissions": sorted(v["id"] for v in permissions["data"]),
            "forms": sorted(v["id"] for v in forms["data"]),
            "running_shell_ids": sorted(v["id"] for v in shells["data"]),
            "latest": fields,
            "model_settings": None,
        }
        # Updated/viewed timestamps need not be constant while another client
        # reads. Keep exact idle/created evidence and all classification facts.
        bundle["info"]["time"] = {
            k: v for k, v in raw["time"].items() if k not in ("updated", "viewed")
        }
        if (
            latest is not None
            and latest["type"] == "model-switched"
            and not bundle["active"]
            and not any(
                bundle[k] for k in ("inbox_ids", "permissions", "forms", "running_shell_ids")
            )
        ):
            tail = await t.request(
                "session.message.list", path=sid, query={"limit": "51", "order": "desc"}
            )
            if not tail["data"] or tail["data"][0] != latest:
                raise ContractError("native_inspection_model_tail_changed")
            bundle["model_settings"] = reconcile_model_tail(raw, tail)
        if (
            latest is not None
            and aborted_head(latest)
            and not bundle["active"]
            and not any(
                bundle[k] for k in ("inbox_ids", "permissions", "forms", "running_shell_ids")
            )
        ):
            tail = await t.request(
                "session.message.list", path=sid, query={"limit": "51", "order": "desc"}
            )
            if not tail["data"] or tail["data"][0] != latest:
                raise ContractError("native_inspection_aborted_turn_tail_changed")
            bundle["aborted_turn"] = reconcile_aborted_turn_tail(raw, tail)
        return bundle

    async def state(self, row: InspectionSession) -> InspectionSession:
        if (row.backend_id, row.backend_identity) != (self.backend_id, self.backend_identity):
            raise ValueError("inspection_row_backend_mismatch")
        async with self._gate:
            try:
                async with asyncio.timeout(8):
                    before = await self.original_owner()
                    a = self.selected()
                    first = await self._bundle(row)
                    second = await self._bundle(row)
                    after = await self.original_owner()
                    if (
                        first != second
                        or before.owner_epoch != after.owner_epoch
                        or self.selected() is not a
                    ):
                        return row.model_copy(
                            update={
                                "state": ExecutionState.UNKNOWN,
                                "coordinator_active": None,
                                "state_reason": "resource_changed",
                                "owner_epoch": None,
                                "observed_at": time.time(),
                            }
                        )
                    if ("parentID" in second["info"] or "fork" in second["info"]) and not second[
                        "active"
                    ]:
                        return row.model_copy(
                            update={
                                "state": ExecutionState.UNKNOWN,
                                "state_reason": "lineage_unqualified",
                                "owner_epoch": after.owner_epoch,
                                "coordinator_active": False,
                                "observed_at": time.time(),
                            }
                        )
                    state = root_state(second)
                    return row.model_copy(
                        update={
                            "title": second["info"].get("title", row.session_id)[:10000],
                            "title_truncated": len(second["info"].get("title", row.session_id))
                            > 10000,
                            "agent_id": second["info"].get("agent"),
                            "provider_id": second["info"].get("model", {}).get("providerID"),
                            "model_id": second["info"].get("model", {}).get("id"),
                            "variant": second["info"].get("model", {}).get("variant"),
                            "parent_id": second["info"].get("parentID"),
                            "fork_source_id": second["info"].get("fork", {}).get("sessionID"),
                            "state": state,
                            "state_reason": "repeated_resources",
                            "owner_epoch": after.owner_epoch,
                            "coordinator_active": second["active"],
                            "last_outcome": last_outcome(second),
                            "observed_at": time.time(),
                        }
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                return row.model_copy(
                    update={
                        "state": ExecutionState.UNKNOWN,
                        "state_reason": "resource_unavailable",
                        "owner_epoch": None,
                        "observed_at": time.time(),
                    }
                )

    async def detail(self, session_id: str) -> InspectionSession:
        before = await self.original_owner()
        a = self.selected()
        raw = (await self.transport.request("session.get", path={"sessionID": session_id}))["data"]
        if raw["id"] != session_id:
            raise ContractError("native_inspection_detail_target_changed")
        row = self.project(raw)
        after = await self.original_owner()
        if self.selected() is not a or before.owner_epoch != after.owner_epoch:
            raise ContractError("native_inspection_detail_owner_changed")
        return await self.state(row)
