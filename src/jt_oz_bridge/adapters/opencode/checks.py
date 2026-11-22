"""Exact installed shell association; API success and Agent prose are not check PASS."""

from __future__ import annotations

import fnmatch
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.domain.checks import (
    ApprovedCheck,
    CheckCatalog,
    CheckObservation,
    check_message_id,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport

CHECK_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"
CHECK_SOURCES = {
    "session.ts": "53d67aef56a1a6b518fad623d51a15b26f071db25c7e5f1c71a21c36ac3a9d11",
    "message-updater.ts": "40d7a2ae2852db7b4c985ed0c2c8cfbebb92a91a3d60e3007b37b4f282703ee2",
    "session-shell.ts": "30429785fb0481a24c82ad5f79af2caa268e1b8830f20490365d44a14bf8b311",
    "shell.ts": "a715f3ebee5669722cbf3e70b6223760e2a2f0291fc4fa3d4bd8512556cb334d",
    "wildcard.ts": "8c38258732c7e569febf52a36468181e2c851f2dceea7112b618c0cf43ed3170",
}
CHECK_SEMANTICS = digest({"version": "2.0.32", "sources": CHECK_SOURCES})
CHECK_READS = frozenset({"session.message.get", "shell.get", "location.get"})


@dataclass(frozen=True)
class CheckExecutionAttestation:
    """Root-managed installed qualification, never a user-supplied chat assertion."""

    catalog: CheckCatalog
    semantics_sha256: str
    installed_evidence_sha256: str

    @property
    def enrollment_sha256(self) -> str:
        return digest(
            {
                "catalog": self.catalog.model_dump(mode="json"),
                "semantics_sha256": self.semantics_sha256,
                "installed_evidence_sha256": self.installed_evidence_sha256,
            }
        )

    def require(self, reference: SessionRef, schema: str) -> CheckCatalog:
        if (
            reference != self.catalog.reference
            or self.catalog.contract_sha256 != schema
            or schema != CHECK_SCHEMA
            or self.semantics_sha256 != CHECK_SEMANTICS
            or len(self.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.installed_evidence_sha256)
        ):
            raise ContractError("native_check_execution_not_qualified")
        return CheckCatalog.model_validate(self.catalog.model_dump(mode="python"))


def native_pattern(value: str, pattern: str) -> bool:
    """Linux Native * / ? semantics with literal brackets and optional trailing ' *'.

    Python's translated glob uses atomic star groups, avoiding untrusted regex
    backtracking. No Windows case-folding qualification is claimed.
    """
    value, pattern = value.replace("\\", "/"), pattern.replace("\\", "/")

    # The installed JS RegExp has no Unicode flag: '?' consumes one UTF-16
    # code unit, not a Python Unicode scalar. In particular, it must not widen
    # an exact permission over an astral character such as an emoji.
    def units(text: str) -> str:
        encoded = text.encode("utf-16-le", "surrogatepass")
        return "".join(
            chr(int.from_bytes(encoded[i : i + 2], "little")) for i in range(0, len(encoded), 2)
        )

    value, pattern = units(value), units(pattern)

    def matches(candidate: str) -> bool:
        escaped = "".join("[[]" if c == "[" else "[]]" if c == "]" else c for c in candidate)
        return re.match(fnmatch.translate(escaped), value) is not None

    return matches(pattern) or (pattern.endswith(" *") and matches(pattern[:-2]))


def require_shell_allow(facts: dict[str, Any], command: str) -> None:
    """Require configured Agent+session ALLOW; saved grants/hooks cannot bypass it."""
    rules = [*facts["agent"]["permissions"], *facts["session_permissions"]]
    if len(rules) > 256:
        raise ContractError("native_check_permission_inventory_capacity")
    effect = "ask"
    for rule in rules:
        if any(len(rule[k]) > 1024 for k in ("action", "resource")):
            raise ContractError("native_check_permission_pattern_capacity")
        if native_pattern("shell", rule["action"]) and native_pattern(command, rule["resource"]):
            effect = rule["effect"]
    if effect != "allow":
        raise ContractError("native_check_original_shell_not_allowed")


def project_check(
    reference: SessionRef,
    action_id: str,
    check: ApprovedCheck,
    message: dict[str, Any],
    shell: dict[str, Any],
    *,
    qualification_sha256: str,
) -> CheckObservation:
    """Inputs must first pass the exact installed API schemas and original owner checks."""
    if (
        message.get("id") != check_message_id(action_id)
        or message.get("type") != "shell"
        or message.get("command") != check.command
        or message.get("shellID") != shell.get("id")
        or shell.get("command") != check.command
        or shell.get("cwd") != reference.canonical_directory
        or shell.get("metadata", {}).get("sessionID") != reference.upstream_session_id
        or shell.get("metadata", {}).get("background") is not True
        or message.get("status") != shell.get("status")
        or shell.get("status") == "exited"
        and shell.get("signal") is not None
    ):
        raise ContractError("native_check_original_shell_identity_changed")
    raw_exit, shell_exit = message.get("exit"), shell.get("exit")
    if raw_exit != shell_exit or any(
        value is not None and type(value) is not int for value in (raw_exit, shell_exit)
    ):
        raise ContractError("native_check_exit_not_exact_integer")
    started = shell["time"]["started"]
    completed = shell["time"].get("completed")
    message_time = message["time"]
    # Shell.create precedes publishing the Started message. Ended uses a later
    # server event timestamp; it must never precede actual shell completion.
    if (
        type(started) is not int
        or completed is not None
        and type(completed) is not int
        or type(message_time["created"]) is not int
        or message_time["created"] < started
        or (completed is None) != (message_time.get("completed") is None)
        or completed is not None
        and (
            type(message_time["completed"]) is not int
            or message_time["completed"] < max(completed, message_time["created"])
        )
    ):
        raise ContractError("native_check_original_shell_time_changed")
    output = message.get("output", {})
    return CheckObservation(
        reference=reference,
        action_id=action_id,
        check=check,
        message_id=message["id"],
        shell_id=shell["id"],
        status=shell["status"],
        exit_code=raw_exit,
        started_at=started,
        completed_at=completed,
        evidence_sha256=digest({"message": message, "shell": shell}),
        qualification_sha256=qualification_sha256,
        output=output.get("output", ""),
        output_truncated=output.get("truncated", False),
    )


class V2CheckRunner:
    def __init__(
        self,
        client: V2ExecutionClient,
        attestations: Mapping[SessionRef, CheckExecutionAttestation],
    ) -> None:
        self.client, self.attestations = client, MappingProxyType(dict(attestations))

    def catalog(self, reference: SessionRef) -> CheckCatalog:
        qualification = self.attestations.get(reference)
        attestation = self.client.transport.attestation
        if (
            qualification is None
            or attestation is None
            or not (CHECK_READS | {"session.shell"}) <= attestation.verified_operations
        ):
            raise ContractError("native_check_operations_unqualified")
        self.client.selected(reference)
        return qualification.require(reference, self.client.transport.profile.sha256)

    def qualification_for(self, reference: SessionRef) -> str:
        self.catalog(reference)
        return self.attestations[reference].enrollment_sha256

    def contract_for(self, reference: SessionRef) -> str:
        return self.catalog(reference).contract_sha256

    def selected(self, reference: SessionRef, check: ApprovedCheck) -> CheckExecutionAttestation:
        catalog = self.catalog(reference)
        if check not in catalog.checks:
            raise ContractError("native_check_definition_changed")
        return self.attestations[reference]

    async def location(self, reference: SessionRef) -> dict[str, Any]:
        location = await self.client.transport.request(
            "location.get", query={"location": {"directory": reference.canonical_directory}}
        )
        if (
            not isinstance(location, dict)
            or location["directory"] != reference.canonical_directory
            or location["project"]["directory"] != reference.canonical_directory
            or location["project"]["id"] != self.client.selected(reference).upstream_project_id
        ):
            raise ContractError("native_check_project_root_changed")
        return location

    async def observe(
        self, reference: SessionRef, action_id: str, check: ApprovedCheck
    ) -> CheckObservation:
        qualification = self.selected(reference, check)
        transport_attestation = self.client.transport.attestation
        scope_provider = self.client.proofs
        read_scope = getattr(scope_provider, "read_scope", None)
        read_epoch = getattr(scope_provider, "read_epoch", None)
        readonly = read_scope is not None or read_epoch is not None
        observation_started = time.time()

        # Reading an already-running user's shell must not depend on the
        # coordinator having an Idle after it. Owner/Root reads remain strict;
        # this read-only scope witness cannot authorize a Native mutation.
        async def scope() -> tuple[str, str, str | None]:
            if readonly:
                # The optional trusted provider has a distinct read interface.
                # If it rejects, never fall back to an old mutation watch.
                from jt_oz_bridge.adapters.opencode.resources import ReadOnlyRootScope

                if not callable(read_scope) or not callable(read_epoch):
                    raise ContractError("native_check_read_only_provider_incomplete")
                observed = await read_scope(reference)
                if (
                    not isinstance(observed, ReadOnlyRootScope)
                    or observed.reference != reference
                    or observed.contract_sha256 != self.contract_for(reference)
                    or observed.native_project_id
                    != self.client.selected(reference).upstream_project_id
                    or read_epoch(reference, observed.contract_sha256) != observed.connection_epoch
                ):
                    raise ContractError("native_check_read_only_scope_unqualified")
                return (
                    observed.connection_epoch,
                    observed.session_info_sha256,
                    observed.owner_epoch,
                )
            # Existing trusted providers without a separate read interface keep
            # their original strict execution certification requirement.
            epoch = self.client.epoch(reference)
            await self.client.peer(reference)
            info = (
                await self.client.transport.request(
                    "session.get", path={"sessionID": reference.upstream_session_id}
                )
            )["data"]
            if (
                info["id"] != reference.upstream_session_id
                or info["projectID"] != self.client.selected(reference).upstream_project_id
                or info["location"] != {"directory": reference.canonical_directory}
                or "parentID" in info
                or info.get("time", {}).get("archived") is not None
                or self.client.epoch(reference) != epoch
            ):
                raise ContractError("native_check_read_only_root_scope_changed")
            return epoch, digest(info), None

        before = await scope()
        location = await self.location(reference)

        async def read() -> CheckObservation:
            message = (
                await self.client.transport.request(
                    "session.message.get",
                    path={
                        "sessionID": reference.upstream_session_id,
                        "messageID": check_message_id(action_id),
                    },
                )
            )["data"]
            if message.get("type") != "shell" or not isinstance(message.get("shellID"), str):
                raise ContractError("native_check_original_shell_message_required")
            shell = await self.client.transport.request(
                "shell.get",
                path={"id": message["shellID"]},
                query={"location": {"directory": reference.canonical_directory}},
            )
            if shell["location"] != {"directory": reference.canonical_directory}:
                raise ContractError("native_check_shell_location_changed")
            return project_check(
                reference,
                action_id,
                check,
                message,
                shell["data"],
                qualification_sha256=qualification.enrollment_sha256,
            )

        first, second = await read(), await read()
        if first != second or await self.location(reference) != location:
            raise ContractError("native_check_observation_changed")
        after = await scope()
        await self.client.peer(reference)
        if before != after:
            raise ContractError("native_check_read_only_owner_or_root_changed")
        if readonly:
            if not callable(read_epoch):
                raise ContractError("native_check_read_only_provider_incomplete")
            current_epoch = read_epoch(reference, self.contract_for(reference))
        else:
            current_epoch = self.client.epoch(reference)
        if (
            current_epoch != before[0]
            or self.client.proofs is not scope_provider
            or readonly
            and not observation_started <= time.time() < observation_started + 5
        ):
            raise ContractError("native_check_read_only_owner_or_root_changed")
        if (
            self.selected(reference, check) is not qualification
            or self.client.transport.attestation is not transport_attestation
        ):
            raise ContractError("native_check_qualification_changed")
        return second


@dataclass(frozen=True)
class KnownCheck:
    action_id: str
    operation_digest: str
    check: ApprovedCheck
    qualification_sha256: str


class V2CheckTailReader:
    """Reconcile terminal user-shell tails against owned durable Actions.

    This only restores an Idle behind completed non-coordinator inputs. It
    never grants a background shell stop or treats arbitrary Synthetic prose
    as completion. Running/unowned background work stays fail-closed.
    """

    def __init__(
        self,
        transport: V2HTTPTransport,
        qualification: CheckExecutionAttestation,
        known: Callable[[SessionRef, str], Awaitable[KnownCheck]],
        *,
        model_settings: ModelSettingsAttestation | None,
        agent_settings: Callable[[SessionRef], object | None] | None = None,
    ) -> None:
        self.transport, self.qualification, self.known = transport, qualification, known
        self.model_settings = model_settings
        # Optional exact-Root attestation lookup; absent keeps original refusal.
        self.agent_settings = agent_settings

    @property
    def enrollment_sha256(self) -> str:
        return self.qualification.enrollment_sha256

    async def read(
        self, ref: SessionRef, info: dict[str, Any], latest: dict[str, Any]
    ) -> dict[str, Any]:
        catalog = self.qualification.require(ref, self.transport.profile.sha256)
        if (
            self.transport.attestation is None
            or "session.message.list" not in self.transport.attestation.verified_operations
        ):
            raise ContractError("native_check_tail_read_unqualified")
        page = await self.transport.request(
            "session.message.list",
            path={"sessionID": ref.upstream_session_id},
            query={"limit": "51", "order": "desc"},
        )
        rows = page["data"]
        if (
            not 1 <= len(rows) <= 51
            or rows[0] != latest
            or len({row["id"] for row in rows}) != len(rows)
        ):
            raise ContractError("native_check_tail_boundary_changed")
        expected_model = native_ref(info["model"]) if "model" in info else None
        expected_agent = info.get("agent")
        controls: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []
        newest = info["time"]["updated"]
        index = 0
        while index < len(rows):
            row = rows[index]
            created = row["time"]["created"]
            if type(created) is not int or created > newest:
                raise ContractError("native_check_tail_time_order_changed")
            newest = created
            if row["type"] == "idle":
                if row["outcome"] != info.get("outcome") or created != info["time"].get("idle"):
                    raise ContractError("native_check_tail_idle_boundary_changed")
                return {
                    "checks": checks,
                    "model_controls": controls,
                    "idle": {k: row[k] for k in ("id", "type", "time", "outcome")},
                    "pristine": False,
                }
            if row["type"] == "model-switched":
                if self.model_settings is None:
                    raise ContractError("native_check_tail_model_qualification_required")
                self.model_settings.require(ref, self.transport.profile.sha256)
                target = native_ref(row["model"])
                if not target.same_native_selection(expected_model):
                    raise ContractError("native_check_tail_model_chain_changed")
                expected_model = native_ref(row["previous"]) if "previous" in row else None
                controls.append({"id": row["id"], "sha256": digest(row)})
                index += 1
                continue
            if row["type"] == "agent-switched":
                if self.agent_settings is None or self.agent_settings(ref) is None:
                    raise ContractError("native_check_tail_agent_qualification_required")
                if row["agent"] != expected_agent:
                    raise ContractError("native_check_tail_agent_chain_changed")
                expected_agent = row.get("previous")
                controls.append({"id": row["id"], "sha256": digest(row)})
                index += 1
                continue
            notice = None
            if row["type"] == "synthetic":
                notice = row
                metadata = row.get("metadata", {})
                if (
                    metadata.get("source") != "shell"
                    or not isinstance(metadata.get("shellID"), str)
                    or metadata.get("state") not in {"completed", "cancelled"}
                ):
                    raise ContractError("native_check_tail_unowned_synthetic")
                index += 1
                if index >= len(rows):
                    raise ContractError("native_check_tail_shell_pair_missing")
                row = rows[index]
                if row["time"]["created"] > newest:
                    raise ContractError("native_check_tail_shell_time_changed")
                newest = row["time"]["created"]
            if row["type"] != "shell" or row["status"] not in {"exited", "timeout", "killed"}:
                raise ContractError("native_check_tail_unsupported_or_running_input")
            known = await self.known(ref, row["id"])
            if (
                row["id"] != check_message_id(known.action_id)
                or known.check not in catalog.checks
                or known.qualification_sha256 != self.enrollment_sha256
                or row["command"] != known.check.command
                or type(row["time"].get("completed")) is not int
                or row["time"]["completed"] < row["time"]["created"]
                or row.get("exit") is not None
                and type(row["exit"]) is not int
            ):
                raise ContractError("native_check_tail_original_action_or_terminal_changed")
            if notice is not None:
                metadata = notice["metadata"]
                expected_state = "cancelled" if row["status"] == "killed" else "completed"
                if (
                    metadata["shellID"] != row["shellID"]
                    or metadata["state"] != expected_state
                    or metadata.get("exit") != row.get("exit")
                    or row["time"]["completed"] > notice["time"]["created"]
                ):
                    raise ContractError("native_check_tail_notice_identity_changed")
            checks.append(
                {
                    "message_id": row["id"],
                    "action_id": known.action_id,
                    "operation_digest": known.operation_digest,
                    "shell_sha256": digest(row),
                    "notice_sha256": digest(notice) if notice is not None else None,
                }
            )
            index += 1
        if (
            page["cursor"].get("next") is None
            and "outcome" not in info
            and "idle" not in info["time"]
            and (not controls or expected_model is None)
        ):
            return {"checks": checks, "model_controls": controls, "idle": None, "pristine": True}
        raise ContractError("native_check_tail_positive_idle_not_found_within_limit")
