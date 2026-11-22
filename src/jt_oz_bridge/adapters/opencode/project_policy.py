"""Root-enrolled native policy drift checks, not an OS sandbox or tool grant.

No config/credential endpoint is read and no upstream policy is changed. Native
permission semantics and each permitted tool still require installed qualification.
"""

import asyncio
import hashlib
import os
import stat
import time
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from pydantic import Field

from jt_oz_bridge.adapters.opencode.checks import require_shell_allow
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.graph_generation import generation_bound
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, V2LeafResourceProofs
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

POLICY_READS = frozenset(
    {"session.get", "agent.get", "plugin.list", "permission.saved.list", "mcp.list"}
)
PERMISSION_SOURCE = "d69278896f9a541dac7cf46056c859834d840ecc16ac57a639cbabc1afdda9a5"
GUARDED_OPERATIONS = frozenset(
    {
        "prompt",
        "permission.reply",
        "form.reply",
        "form.cancel",
        "model.switch",
        "session.rename",
        "check.run",
        "session.fork",
        "session.compact",
        "session.revert.stage",
        "session.revert.clear",
        "session.revert.commit",
    }
)

# Only answering the request a Root is positively waiting on may use the
# state-only fence of that active witness. Interrupt never reaches this guard.
WAITING_REPLY_OPERATIONS = frozenset({"permission.reply", "form.reply", "form.cancel"})
WAITING_STATES = frozenset({ExecutionState.WAITING_PERMISSION, ExecutionState.WAITING_INPUT})


class NativePolicyEnrollment(ControlModel):
    """Administrator input. Reading current API data does not certify its safety."""

    format: Literal["native-project-policy-v1"]
    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    permission_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operations: frozenset[
        Literal[
            "prompt",
            "permission.reply",
            "form.reply",
            "form.cancel",
            "model.switch",
            "session.rename",
            "check.run",
            "worktree.create",
            "session.fork",
            "session.compact",
            "session.revert.stage",
            "session.revert.clear",
            "session.revert.commit",
        ]
    ]


def root_policy_enrollment(path: Path) -> NativePolicyEnrollment:
    if not path.is_absolute():
        raise ContractError("absolute_root_policy_enrollment_required")
    parents = []
    for directory in reversed(path.parents):
        s = directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ContractError("root_managed_policy_parent_required")
        parents.append((directory, s.st_dev, s.st_ino, s.st_mode))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ContractError("root_managed_policy_enrollment_required")
        content = os.read(fd, 65537)
        if len(content) > 65536:
            raise ContractError("policy_enrollment_too_large")
        for directory, device, inode, mode in parents:
            now = directory.lstat()
            if (now.st_dev, now.st_ino, now.st_mode) != (device, inode, mode):
                raise ContractError("policy_parent_changed")
        named = path.lstat()
        if (named.st_dev, named.st_ino, named.st_uid, named.st_mode) != (
            s.st_dev,
            s.st_ino,
            s.st_uid,
            s.st_mode,
        ):
            raise ContractError("policy_enrollment_changed")
        return NativePolicyEnrollment.model_validate(strict_loads(content))
    finally:
        os.close(fd)


# Local plugins an operator approved as observe-only, per backend: (id, path, sha256).
_OBSERVERS: dict[str, tuple[tuple[str, str, str], ...]] = {}
OBSERVER_PLUGIN_LIMIT = 1024 * 1024


def approve_observer_plugins(backend_id: str, pins: tuple[tuple[str, str, str], ...]) -> None:
    """Set one backend's approved observe-only plugins, replacing any earlier set."""
    _OBSERVERS[backend_id] = pins


def _observer(backend_id: str, record: dict[str, Any]) -> bool:
    """An approved local plugin whose file still has exactly the approved bytes.

    Only such a plugin leaves the fingerprint, so adding a passive audit plugin
    does not invalidate every Root. Any other plugin, a changed file, a symlink,
    or a record that differs in source, features or state stays in the facts
    and is refused as policy drift, as before.
    """
    for plugin_id, path, sha256 in _OBSERVERS.get(backend_id, ()):
        expected = {
            "id": plugin_id,
            "source": {"type": "local", "path": path},
            "features": {"server": True},
            "state": {"status": "active"},
        }
        if record != expected:
            continue
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return False
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            content = os.read(fd, OBSERVER_PLUGIN_LIMIT + 1)
        except OSError:
            return False
        finally:
            os.close(fd)
        return (
            len(content) <= OBSERVER_PLUGIN_LIMIT and hashlib.sha256(content).hexdigest() == sha256
        )
    return False


def rules(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 10000:
        raise ContractError("bounded_native_permission_rules_required")
    for r in value:
        if (
            not isinstance(r, dict)
            or set(r) != {"action", "resource", "effect"}
            or any(not isinstance(r[k], str) or not 1 <= len(r[k]) <= 8192 for k in r)
            or r["effect"] not in {"allow", "ask", "deny"}
        ):
            raise ContractError("native_permission_rule_invalid")
    # Preserve order: native evaluation uses the last matching rule.
    return value


def _mcp_policy_inventory(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Separate known transport health from authority without changing API metadata."""
    projected = []
    for record in records:
        item = dict(record)
        if "status" in item:
            status = item["status"]
            transport_health = isinstance(status, dict) and (
                (status == {"status": "connected"})
                or (
                    set(status) == {"status", "error"}
                    and status["status"] == "failed"
                    and isinstance(status["error"], str)
                )
            )
            # Tag both branches: an unknown API value resembling our sentinel must
            # never collide with a recognized connection-health projection.
            item["status"] = (
                {"projection": "transport-v1"}
                if transport_health
                else {"projection": "exact-v1", "value": status}
            )
        projected.append(item)
    return sorted(projected, key=lambda item: item["name"])


def _policy_facts(
    ref: SessionRef,
    native_project_id: str,
    info: dict[str, Any],
    agent: dict[str, Any],
    plugins: dict[str, Any],
    saved: dict[str, Any],
    mcp: dict[str, Any],
    *,
    expected_parent_id: str | None = None,
) -> dict[str, Any]:
    if (
        info.get("id") != ref.upstream_session_id
        or info.get("projectID") != native_project_id
        or (
            "parentID" in info
            if expected_parent_id is None
            else info.get("parentID") != expected_parent_id
        )
        or info.get("location") != {"directory": ref.canonical_directory}
        or not isinstance(info.get("agent"), str)
        or not info["agent"]
        or info.get("time", {}).get("archived") is not None
    ):
        raise ContractError("native_policy_original_root_scope_changed")
    for response in (agent, plugins, mcp):
        if response.get("location") != {"directory": ref.canonical_directory}:
            raise ContractError("native_policy_location_changed")
    a = agent.get("data")
    if (
        not isinstance(a, dict)
        or a.get("id") != info["agent"]
        or a.get("mode")
        not in ({"primary", "all"} if expected_parent_id is None else {"subagent", "all"})
    ):
        raise ContractError("native_policy_explicit_primary_agent_required")
    p, s, m = plugins.get("data"), saved.get("data"), mcp.get("data")
    if any(not isinstance(v, list) or len(v) > 1000 for v in (p, s, m)):
        raise ContractError("bounded_native_policy_inventory_required")
    assert isinstance(p, list) and isinstance(s, list) and isinstance(m, list)
    if any(
        not isinstance(v, dict) or v.get("projectID") != native_project_id or not v.get("id")
        for v in s
    ):
        raise ContractError("native_saved_permission_project_changed")
    if any(not isinstance(v, dict) or not v.get("name") for v in m):
        raise ContractError("native_mcp_inventory_invalid")
    if any(
        not isinstance(v, dict) or not v.get("id") or v.get("state") != {"status": "active"}
        for v in p
    ):
        raise ContractError("native_plugin_inventory_unqualified")
    if any(
        len({v[key] for v in rows}) != len(rows)
        for rows, key in ((p, "id"), (s, "id"), (m, "name"))
    ):
        raise ContractError("native_policy_duplicate_inventory_identity")
    p = [v for v in p if not _observer(ref.backend_id, v)]
    facts = {
        "format": "native-project-policy-fingerprint-v2",
        "reference": ref.model_dump(mode="json"),
        "native_project_id": native_project_id,
        "session_permissions": rules(info.get("permissions", [])),
        "agent": {"id": a["id"], "mode": a["mode"], "permissions": rules(a.get("permissions"))},
        "plugins": sorted(p, key=lambda v: v["id"]),
        "saved_permissions": sorted(s, key=lambda v: v["id"]),
        "mcp": _mcp_policy_inventory(m),
    }
    if expected_parent_id is not None:
        facts["parent_session_id"] = expected_parent_id
    if len(checked_json(facts)) > 2 * 1024 * 1024:
        raise ContractError("native_policy_inventory_too_large")
    # Agent request/system and config/credentials are deliberately excluded.
    return facts


def policy_fingerprint(
    ref: SessionRef,
    native_project_id: str,
    info: dict[str, Any],
    agent: dict[str, Any],
    plugins: dict[str, Any],
    saved: dict[str, Any],
    mcp: dict[str, Any],
) -> str:
    return digest(_policy_facts(ref, native_project_id, info, agent, plugins, saved, mcp))


class NativePolicyWitness(ControlModel):
    reference: SessionRef
    operation: str
    session_info_sha256: str
    resource_fence: str
    connection_epoch: str
    owner_epoch: str
    checked_at: float
    expires_at: float
    fingerprint_sha256: str


class V2ProjectPolicyGuard:
    _graph_publication: object | None = None

    def __init__(
        self,
        proofs: V2LeafResourceProofs,
        enrollments: Mapping[SessionRef, NativePolicyEnrollment],
    ) -> None:
        if not enrollments or any(
            ref != e.reference
            or e.contract_sha256 != INSTALLED_SCHEMA
            or e.permission_source_sha256 != PERMISSION_SOURCE
            or not e.operations
            for ref, e in enrollments.items()
        ):
            raise ValueError("explicit_qualified_project_policy_required")
        self.proofs = proofs
        self.enrollments: Mapping[SessionRef, NativePolicyEnrollment] = MappingProxyType(
            dict(enrollments)
        )
        self.witnesses: dict[SessionRef, NativePolicyWitness] = {}
        self._gate = asyncio.Lock()

    def expected_fingerprint(self, ref: SessionRef, operation: str) -> str:
        """Approved current policy: original enrollment unless a head is published."""
        original = self.enrollments[ref].fingerprint_sha256
        configuration = self.proofs.feed.agent_configuration
        if configuration is None:
            return original
        expected: str = configuration.policy_sha256(ref, original, operation)
        return expected

    def _operation_enrolled(
        self, ref: SessionRef, enrolled: NativePolicyEnrollment, op: str
    ) -> bool:
        if op != "agent.switch":
            return op in enrolled.operations
        # Exact per-Root qualification; old policy files stay valid and unchanged.
        configuration = self.proofs.feed.agent_configuration
        return configuration is not None and configuration.attestation(ref) is not None

    @generation_bound(policy=True)
    def enrolled(self, ref: SessionRef, operation: str) -> bool:
        try:
            e = self.enrollments.get(ref)
            p = self.proofs.select(ref)
            a = self.proofs.feed.transport.attestation
            return bool(
                e
                and self._operation_enrolled(ref, e, operation)
                and e.native_project_id == p.upstream_project_id
                and a
                and POLICY_READS <= a.verified_operations
            )
        except (ValueError, TypeError):
            return False

    async def _bundle_facts(self, ref: SessionRef) -> tuple[dict[str, Any], str]:
        e = self.enrollments[ref]
        t = self.proofs.feed.transport
        info = (await t.request("session.get", path={"sessionID": ref.upstream_session_id}))["data"]
        aid = info.get("agent")
        if not isinstance(aid, str) or not aid:
            raise ContractError("explicit_native_agent_required_for_policy_guard")
        query = {"location": {"directory": ref.canonical_directory}}
        agent, plugins, saved, mcp = await asyncio.gather(
            t.request("agent.get", path={"agentID": aid}, query=query),
            t.request("plugin.list", query=query),
            t.request("permission.saved.list", query={"projectID": e.native_project_id}),
            t.request("mcp.list", query=query),
        )
        facts = _policy_facts(ref, e.native_project_id, info, agent, plugins, saved, mcp)
        return facts, digest(info)

    @generation_bound(policy=True)
    async def bundle(self, ref: SessionRef) -> tuple[str, str]:
        facts, info = await self._bundle_facts(ref)
        return digest(facts), info

    def fence_current(self, ref: SessionRef, operation: str, proof: OriginalExecutionProof) -> bool:
        """The strict resource fence, or a positively waiting witness's state fence.

        The latter only answers the waited-on request: a waiting Root's proof
        carries the state-only fence, so a strict-only check refused every reply.
        Prompts and every other mutation keep requiring the strict fence.
        """
        fence = proof.resource_fence
        if not isinstance(fence, str):
            return False
        if fence == self.proofs.fence(ref):
            return True
        return bool(
            operation in WAITING_REPLY_OPERATIONS
            and proof.state in WAITING_STATES
            and self.proofs.valid_fence(ref, fence)
        )

    @generation_bound(policy=True)
    async def authorize(
        self, ref: SessionRef, operation: str, proof: OriginalExecutionProof
    ) -> NativePolicyWitness:
        async with self._gate:
            self.witnesses.pop(ref, None)
            if (
                not self.enrolled(ref, operation)
                or proof.reference != ref
                or proof.contract_sha256 != INSTALLED_SCHEMA
                or not proof.issued_at <= time.time() < proof.expires_at
            ):
                raise ContractError("native_project_policy_not_enrolled")
            if not self.fence_current(ref, operation, proof):
                raise ContractError("native_project_policy_changed_or_unqualified")
            fence = proof.resource_fence
            assert fence is not None  # fence_current requires a current string fence.
            before = await self.proofs.feed.current_owner()
            first = await self.bundle(ref)
            second = await self.bundle(ref)
            after = await self.proofs.feed.current_owner()
            expected = self.expected_fingerprint(ref, operation)
            if (
                not self.enrolled(ref, operation)
                or before.owner_epoch != after.owner_epoch
                or not self.fence_current(ref, operation, proof)
                or first != second
                or first != (expected, proof.session_info_sha256)
                or self.proofs.generation(ref) != proof.connection_epoch
            ):
                raise ContractError("native_project_policy_changed_or_unqualified")
            now = time.time()
            result = NativePolicyWitness(
                reference=ref,
                operation=operation,
                session_info_sha256=first[1],
                resource_fence=fence,
                connection_epoch=proof.connection_epoch,
                owner_epoch=after.owner_epoch,
                checked_at=now,
                expires_at=now + 5,
                fingerprint_sha256=first[0],
            )
            self.witnesses[ref] = result
            return result

    @generation_bound(policy=True)
    async def authorize_check(
        self, ref: SessionRef, proof: OriginalExecutionProof, command: str
    ) -> NativePolicyWitness:
        witness = await self.authorize(ref, "check.run", proof)
        facts, info = await self._bundle_facts(ref)
        if digest(facts) != witness.fingerprint_sha256 or info != proof.session_info_sha256:
            raise ContractError("native_check_policy_changed")
        require_shell_allow(facts, command)
        if not self.current(ref, "check.run", proof, witness):
            raise ContractError("native_check_policy_expired")
        return witness

    @generation_bound(policy=True)
    async def authorize_worktree(
        self, ref: SessionRef, proof: OriginalExecutionProof, setup_command: str
    ) -> NativePolicyWitness:
        # Separate opt-in, preserving the original qualified per-node active/idle fence.
        async with self._gate:
            self.witnesses.pop(ref, None)
            if (
                not self.enrolled(ref, "worktree.create")
                or proof.reference != ref
                or proof.contract_sha256 != INSTALLED_SCHEMA
                or not proof.issued_at <= time.time() < proof.expires_at
                or not isinstance(proof.resource_fence, str)
                or not self.proofs.valid_fence(ref, proof.resource_fence)
            ):
                raise ContractError("native_worktree_original_scope_not_current")
            before = await self.proofs.feed.current_owner()
            facts, info = await self._bundle_facts(ref)
            second = await self.bundle(ref)
            after = await self.proofs.feed.current_owner()
            expected = self.expected_fingerprint(ref, "worktree.create")
            if (
                before.owner_epoch != after.owner_epoch
                or (digest(facts), info) != second
                or second != (expected, proof.session_info_sha256)
                or self.proofs.generation(ref) != proof.connection_epoch
                or not self.proofs.valid_fence(ref, proof.resource_fence)
            ):
                raise ContractError("native_worktree_policy_changed")
            if setup_command:
                require_shell_allow(facts, setup_command)
            now = time.time()
            witness = NativePolicyWitness(
                reference=ref,
                operation="worktree.create",
                session_info_sha256=info,
                resource_fence=proof.resource_fence,
                connection_epoch=proof.connection_epoch,
                owner_epoch=after.owner_epoch,
                checked_at=now,
                expires_at=min(now + 5, proof.expires_at),
                fingerprint_sha256=expected,
            )
            self.witnesses[ref] = witness
            if not self.worktree_current(ref, proof, witness):
                raise ContractError("native_worktree_policy_expired")
            return witness

    @generation_bound(policy=True)
    def worktree_current(
        self, ref: SessionRef, proof: OriginalExecutionProof, witness: object
    ) -> bool:
        now = time.time()
        return bool(
            isinstance(witness, NativePolicyWitness)
            and self.witnesses.get(ref) is witness
            and self.enrolled(ref, "worktree.create")
            and witness.reference == proof.reference == ref
            and witness.operation == "worktree.create"
            and witness.resource_fence == proof.resource_fence
            and isinstance(proof.resource_fence, str)
            and self.proofs.valid_fence(ref, proof.resource_fence)
            and witness.session_info_sha256 == proof.session_info_sha256
            and witness.connection_epoch == proof.connection_epoch == self.proofs.generation(ref)
            and witness.fingerprint_sha256 == self.expected_fingerprint(ref, "worktree.create")
            and proof.contract_sha256 == INSTALLED_SCHEMA
            and proof.issued_at <= now < proof.expires_at
            and witness.checked_at <= now < witness.expires_at
        )

    @generation_bound(policy=True)
    def current(
        self, ref: SessionRef, operation: str, proof: OriginalExecutionProof, witness: Any
    ) -> bool:
        try:
            now = time.time()
            return bool(
                isinstance(witness, NativePolicyWitness)
                and self.witnesses.get(ref) is witness
                and self.enrolled(ref, operation)
                and witness.reference == ref
                and witness.operation == operation
                and witness.session_info_sha256 == proof.session_info_sha256
                and witness.resource_fence == proof.resource_fence
                and self.fence_current(ref, operation, proof)
                and witness.connection_epoch
                == proof.connection_epoch
                == self.proofs.generation(ref)
                and witness.fingerprint_sha256 == self.expected_fingerprint(ref, operation)
                and witness.checked_at <= now <= witness.expires_at
                and proof.contract_sha256 == INSTALLED_SCHEMA
                and proof.issued_at <= now < proof.expires_at
            )
        except (ValueError, TypeError):
            return False
