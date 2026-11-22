"""Original Native catalogs/diffs with independent installed qualification.

No file content, tools or mutations are requested. Schema presence alone never
qualifies these operations. Protected names are hidden, malformed paths reject
rather than being silently normalized into a different workspace.
"""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.files import FILE_SOURCES
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    ReadOnlyRootScope,
    V2LeafResourceProofs,
)
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from jt_oz_bridge.domain.directory_scope import DirectoryScopeGuard, DirectoryScopeSnapshot
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_catalog import (
    WorkspaceChanges,
    WorkspaceDiff,
    WorkspaceEntry,
    WorkspaceListing,
    WorkspaceTurn,
    WorkspaceTurns,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import canonical_relative, disclosed_path
from jt_oz_bridge.storage.durable import digest

OPERATIONS = {
    "list": "fs.list",
    "find": "fs.find",
    "diff": "session.diff",
    "turns": "session.message.list",
    "turn-diff": "session.diff",
}
CATALOG_SEMANTICS = digest(
    {
        "version": "2.0.32",
        "sources": FILE_SOURCES,
        "projection": "bounded-relative-files-v5",
        "search_order": "retain-native-rank-before-thousand-entry-cutoff",
        "unprovable_search_parents": "omit-only-after-bounded-per-parent-checks-and-fresh-batch-proof",
        "physical_directories": "metadata-only-pinned-root-and-no-symlink-before-after-v1",
        "find": "repeat-exact-native-query-between-physical-parent-witnesses",
        "directory_wire_marker": "remove-exactly-one-terminal-slash-for-directories",
        "search_entry_type": "file-only",
        "search_limit_probe": 1001,
        "diff": "original-session-default-or-selected-user-turn-v2",
        "turns": "bounded-type-user-cursor-list-no-text-v1",
        "selected_turn": "same-session-message-get-before-after-digest-and-explicit-from-v1",
        "read_authority": "original-owner-read-scope-without-mutation-watch-v1",
        "deadline": "first-read-scope-issued-at-plus-five-seconds",
        "max_entries": 1000,
        "max_patch_bytes": 1024**2,
    }
)


def entry_path(path: str, kind: str) -> str:
    """Decode the installed directory marker, never normalize arbitrary paths.

    Real Native fs.list marks directories with a terminal slash. The logical
    catalog and subsequent query paths are canonical project-relative names.
    Removing one marker leaves repeated separators/traversal/absolute paths
    invalid, and a file path is never allowed to borrow this rule.
    """
    if kind not in {"file", "directory"}:
        raise ContractError("workspace_catalog_entry_kind_invalid")
    if kind == "directory" and isinstance(path, str):
        path = path.removesuffix("/")
    return canonical_relative(path)


@dataclass(frozen=True)
class WorkspaceCatalogAttestation:
    reference: SessionRef
    schema_sha256: str
    native_policy_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    operations: frozenset[str]


@dataclass(frozen=True)
class _Context:
    original: ReferenceType[WorkspaceListing | WorkspaceChanges | WorkspaceTurns]
    scope: ReadOnlyRootScope
    attestation: WorkspaceCatalogAttestation
    transport_attestation: ContractAttestation | None
    feed_context: tuple[object, object, object]
    resource_fence: str
    scope_deadline: float
    deadline: float
    directory_scope: DirectoryScopeSnapshot


class V2WorkspaceCatalog:
    def __init__(
        self,
        client: V2ExecutionClient,
        attestations: Mapping[SessionRef, WorkspaceCatalogAttestation],
        *,
        directories: DirectoryScopeGuard | None = None,
    ) -> None:
        if (
            not isinstance(client.proofs, V2LeafResourceProofs)
            or not isinstance(client.scope_guard, V2ProjectPolicyGuard)
            or client.scope_guard.proofs is not client.proofs
            or client.transport is not client.proofs.feed.transport
            or any(ref != a.reference for ref, a in attestations.items())
        ):
            raise ValueError("workspace_catalog_original_owner_policy_required")
        self.client, self.proofs, self.guard = client, client.proofs, client.scope_guard
        self.directories = directories
        self.attestations = MappingProxyType(dict(attestations))
        self._observed: dict[int, _Context] = {}

    def require(self, ref: SessionRef, kind: str) -> WorkspaceCatalogAttestation:
        self.proofs.select(ref)
        current = self.attestations.get(ref)
        transport = self.client.transport
        policy = self.guard.enrollments.get(ref)
        if (
            self.client.proofs is not self.proofs
            or self.client.scope_guard is not self.guard
            or self.guard.proofs is not self.proofs
            or transport is not self.proofs.feed.transport
            or current is None
            or kind not in OPERATIONS
            or self.directories is None
            or not self.directories.qualified(ref)
            or policy is None
            or current.schema_sha256 != INSTALLED_SCHEMA
            or transport.profile.sha256 != INSTALLED_SCHEMA
            or current.native_policy_sha256 != policy.fingerprint_sha256
            or current.semantics_sha256 != CATALOG_SEMANTICS
            or len(current.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in current.installed_evidence_sha256)
            or (kind == "turn-diff" and "session.message.get" not in current.operations)
            or OPERATIONS[kind] not in current.operations
            or transport.attestation is None
            or transport.attestation.backend_identity != ref.backend_identity
            or transport.attestation.schema_sha256 != INSTALLED_SCHEMA
            or transport.attestation.upstream_version != "2.0.32"
            or (
                kind == "turn-diff"
                and "session.message.get" not in transport.attestation.verified_operations
            )
            or OPERATIONS[kind] not in transport.attestation.verified_operations
        ):
            raise ContractError("workspace_catalog_operation_not_qualified")
        return current

    def qualified(
        self, reference: SessionRef, kind: Literal["list", "find", "diff", "turns", "turn-diff"]
    ) -> bool:
        try:
            self.require(reference, kind)
            return True
        except (ValueError, KeyError):
            return False

    def _current_scope(
        self,
        ref: SessionRef,
        scope: ReadOnlyRootScope,
        attestation: ContractAttestation | None,
        feed_context: tuple[object, object, object],
        resource_fence: str,
        deadline: float,
    ) -> None:
        if (
            scope.reference != ref
            or self.client.transport.attestation is not attestation
            or self.proofs.feed is not feed_context[0]
            or self.proofs.feed.index is not feed_context[1]
            or self.proofs.feed.task is not feed_context[2]
            or self.proofs.read_epoch(ref, INSTALLED_SCHEMA) != scope.connection_epoch
            or self.proofs.fence(ref) != resource_fence
            or not scope.issued_at <= time.time() < deadline
        ):
            raise ContractError("workspace_catalog_original_read_scope_changed")

    async def _read(
        self,
        ref: SessionRef,
        kind: str,
        *,
        directory: str = "",
        query: str = "",
        cursor: str | None = None,
        from_message: str | None = None,
        turn_sha256: str | None = None,
    ) -> WorkspaceListing | WorkspaceChanges | WorkspaceTurns:
        selected = self.require(ref, kind)
        is_diff = kind in {"diff", "turn-diff"}
        if from_message is not None:
            WorkspaceTurn(native_id=from_message, created=0, message_sha256=turn_sha256 or "")
        if (from_message is not None) != (kind == "turn-diff") or (
            from_message is None and turn_sha256 is not None
        ):
            raise ContractError("workspace_diff_selected_turn_required")
        if cursor is not None and (
            kind != "turns" or not isinstance(cursor, str) or not 1 <= len(cursor) <= 2048
        ):
            raise ContractError("workspace_turn_cursor_invalid")
        if directory:
            disclosed_path(directory)
        if (
            not isinstance(query, str)
            or len(query) > 255
            or any(ord(c) < 32 or ord(c) == 127 for c in query)
        ):
            raise ContractError("workspace_catalog_bounded_query_required")
        if kind == "list" and query or kind != "list" and directory:
            raise ContractError("workspace_catalog_query_mode_changed")
        transport_attestation = self.client.transport.attestation
        feed_context = (self.proofs.feed, self.proofs.feed.index, self.proofs.feed.task)
        monotonic_deadline = time.monotonic() + 5
        before = await self.proofs.read_scope(ref)
        deadline = before.expires_at
        resource_fence = self.proofs.fence(ref)
        policy_before = await self.guard.bundle(ref)
        self._current_scope(
            ref, before, transport_attestation, feed_context, resource_fence, deadline
        )
        if policy_before != (selected.native_policy_sha256, before.session_info_sha256):
            raise ContractError("workspace_catalog_original_policy_changed")
        path = {"sessionID": ref.upstream_session_id} if is_diff or kind == "turns" else {}
        params: dict[str, Any] = (
            {}
            if is_diff or kind == "turns"
            else {"location": {"directory": ref.canonical_directory}}
        )
        if kind == "turns":
            params.update(type="user", limit="10")
            if cursor is not None:
                params["cursor"] = cursor
            else:
                params["order"] = "desc"
        if from_message is not None:
            params["from"] = from_message
        if kind == "list" and directory:
            params["path"] = directory
        if kind == "find":
            params.update(query=query, type="file", limit="1001")
        assert self.directories is not None
        physical_before = await self.directories.observe(
            ref, (directory if kind == "list" else "",)
        )
        if not self.directories.current(ref, physical_before):
            raise ContractError("workspace_catalog_physical_root_not_current")

        async def selected_turn() -> None:
            if from_message is None:
                return
            self._current_scope(
                ref, before, transport_attestation, feed_context, resource_fence, deadline
            )
            row = (
                await self.client.transport.request(
                    "session.message.get", path={**path, "messageID": from_message}
                )
            )["data"]
            if row["id"] != from_message or row["type"] != "user" or digest(row) != turn_sha256:
                raise ContractError("workspace_diff_original_user_turn_changed")
            self._current_scope(
                ref, before, transport_attestation, feed_context, resource_fence, deadline
            )

        await selected_turn()
        self._current_scope(
            ref, before, transport_attestation, feed_context, resource_fence, deadline
        )
        value = await self.client.transport.request(OPERATIONS[kind], path=path, query=params)
        await selected_turn()
        if (
            not is_diff
            and kind != "turns"
            and value["location"] != {"directory": ref.canonical_directory}
        ):
            raise ContractError("workspace_catalog_original_location_changed")
        rows = value["data"]
        if not isinstance(rows, list) or len(rows) > (
            10 if kind == "turns" else 1001 if kind == "find" else 1000
        ):
            raise ContractError("workspace_catalog_response_capacity")
        seen = set()
        hidden = 0
        entries = []
        diffs = []
        patch_bytes = 0
        turns = []
        for row in rows:
            if kind == "turns":
                if row["type"] != "user":
                    raise ContractError("workspace_turn_user_required")
                turns.append(
                    WorkspaceTurn(
                        native_id=row["id"],
                        created=row["time"]["created"],
                        message_sha256=digest(row),
                    )
                )
                continue
            if kind == "find" and row["type"] != "file":
                raise ContractError("workspace_catalog_search_file_type_changed")
            relative = (
                canonical_relative(row["file"]) if is_diff else entry_path(row["path"], row["type"])
            )
            if relative in seen:
                raise ContractError("workspace_catalog_duplicate_path")
            seen.add(relative)
            try:
                disclosed_path(relative)
            except AccessDenied:
                hidden += 1
                continue
            if kind == "list" and relative.rpartition("/")[0] != directory:
                raise ContractError("workspace_catalog_entry_outside_listed_directory")
            if is_diff:
                patch_bytes += len(row["patch"].encode("utf-8"))
                if patch_bytes > 1024**2:
                    raise ContractError("workspace_diff_byte_capacity")
                diffs.append(
                    WorkspaceDiff(
                        path=relative,
                        patch=row["patch"],
                        additions=row["additions"],
                        deletions=row["deletions"],
                        status=row["status"],
                    )
                )
            else:
                entries.append(WorkspaceEntry(path=relative, kind=row["type"]))
        if kind == "find":
            # fs.find has no physical identities. Confirm every disclosed file's
            # parent, repeat the exact Native query while those witnesses are
            # current, then re-observe the same directory chain. Nothing from a
            # first, potentially out-of-scope response becomes a public DTO.
            parents = tuple(sorted({e.path.rpartition("/")[0] for e in entries} or {""}))
            try:
                physical_parents = await self.directories.observe(ref, parents)
            except ValueError:
                # Native search can include symlink descendants or stale paths.
                # Retain only parents for which physical authority succeeds,
                # then obtain one coherent fresh batch witness for that subset.
                # A service/root failure cannot become an unguarded result.
                self._current_scope(
                    ref, before, transport_attestation, feed_context, resource_fence, deadline
                )
                if len(parents) > 32:
                    raise ContractError(
                        "workspace_catalog_refine_unprovable_parent_scope"
                    ) from None
                accepted = set()
                for parent in parents:
                    self._current_scope(
                        ref, before, transport_attestation, feed_context, resource_fence, deadline
                    )
                    try:
                        observed_parent = await self.directories.observe(ref, (parent,))
                    except ValueError:
                        continue
                    if (
                        not self.directories.current(ref, observed_parent)
                        or observed_parent.records[0] != physical_before.records[0]
                    ):
                        raise ContractError("workspace_catalog_physical_root_changed") from None
                    accepted.add(parent)
                kept = [e for e in entries if e.path.rpartition("/")[0] in accepted]
                hidden += len(entries) - len(kept)
                entries = kept
                parents = tuple(sorted(accepted or {""}))
                self._current_scope(
                    ref, before, transport_attestation, feed_context, resource_fence, deadline
                )
                physical_parents = await self.directories.observe(ref, parents)
            if physical_parents.records[0] != physical_before.records[0]:
                raise ContractError("workspace_catalog_physical_root_changed")
            repeated = await self.client.transport.request(
                OPERATIONS[kind], path=path, query=params
            )
            if repeated != value:
                raise ContractError("workspace_catalog_search_changed_during_parent_check")
            physical_after = await self.directories.observe(ref, parents)
        else:
            physical_parents = physical_before
            physical_after = await self.directories.observe(ref, physical_before.directories)
        if (
            physical_parents.fingerprint != physical_after.fingerprint
            or not self.directories.current(ref, physical_before)
            or not self.directories.current(ref, physical_parents)
            or not self.directories.current(ref, physical_after)
        ):
            raise ContractError("workspace_catalog_physical_directory_boundary_changed")
        result: WorkspaceListing | WorkspaceChanges | WorkspaceTurns
        if kind == "turns":
            result = WorkspaceTurns(
                reference=ref,
                cursor=cursor,
                next_cursor=value["cursor"].get("next"),
                entries=tuple(turns),
            )
            if result.next_cursor is not None and result.next_cursor == cursor:
                raise ContractError("workspace_turn_cursor_repeated")
        elif is_diff:
            result = WorkspaceChanges(
                reference=ref,
                from_message=from_message,
                turn_sha256=turn_sha256,
                files=tuple(diffs),
                hidden_count=hidden,
            )
        else:
            complete = kind != "find" or len(rows) < 1001
            result = WorkspaceListing(
                reference=ref,
                directory=directory,
                query=query,
                entries=tuple(
                    (
                        entries
                        if kind == "find"
                        else sorted(entries, key=lambda e: (e.kind != "directory", e.path))
                    )[:1000]
                ),
                complete=complete,
                hidden_count=hidden,
            )
        after = await self.proofs.read_scope(ref)
        policy_after = await self.guard.bundle(ref)
        self._current_scope(
            ref, before, transport_attestation, feed_context, resource_fence, deadline
        )
        if (
            self.require(ref, kind) is not selected
            or policy_after != (selected.native_policy_sha256, after.session_info_sha256)
            or policy_after != policy_before
            or before.owner_epoch != after.owner_epoch
            or before.session_info_sha256 != after.session_info_sha256
            or before.connection_epoch != after.connection_epoch
        ):
            raise ContractError("workspace_catalog_original_boundary_changed")
        now = time.monotonic()
        self._observed = {
            key: v
            for key, v in self._observed.items()
            if v.original() is not None and v.deadline > now
        }
        if len(self._observed) >= 32:
            raise ContractError("workspace_catalog_observation_capacity")
        self._observed[id(result)] = _Context(
            weakref(result),
            after,
            selected,
            transport_attestation,
            feed_context,
            resource_fence,
            deadline,
            min(monotonic_deadline, now + max(0, deadline - time.time())),
            physical_after,
        )
        if not self.current(result):
            raise ContractError("workspace_catalog_current_original_object_required")
        return result

    async def listing(
        self, reference: SessionRef, *, directory: str = "", query: str = ""
    ) -> WorkspaceListing:
        result = await self._read(
            reference, "find" if query else "list", directory=directory, query=query
        )
        assert isinstance(result, WorkspaceListing)
        return result

    async def turns(self, reference: SessionRef, *, cursor: str | None = None) -> WorkspaceTurns:
        result = await self._read(reference, "turns", cursor=cursor)
        assert isinstance(result, WorkspaceTurns)
        return result

    async def diff(
        self,
        reference: SessionRef,
        *,
        from_message: str | None = None,
        turn_sha256: str | None = None,
    ) -> WorkspaceChanges:
        result = await self._read(
            reference,
            "turn-diff" if from_message is not None else "diff",
            from_message=from_message,
            turn_sha256=turn_sha256,
        )
        assert isinstance(result, WorkspaceChanges)
        return result

    def current(self, value: WorkspaceListing | WorkspaceChanges | WorkspaceTurns) -> bool:
        item = self._observed.get(id(value))
        try:
            if (
                item is None
                or item.original() is not value
                or item.deadline <= time.monotonic()
                or self.attestations.get(value.reference) is not item.attestation
                or self.directories is None
                or not self.directories.current(value.reference, item.directory_scope)
            ):
                return False
            self.require(
                value.reference,
                "turns"
                if isinstance(value, WorkspaceTurns)
                else "turn-diff"
                if isinstance(value, WorkspaceChanges) and value.from_message is not None
                else "diff"
                if isinstance(value, WorkspaceChanges)
                else "find"
                if value.query
                else "list",
            )
            self._current_scope(
                value.reference,
                item.scope,
                item.transport_attestation,
                item.feed_context,
                item.resource_fence,
                item.scope_deadline,
            )
            return time.monotonic() < item.deadline
        except (ValueError, KeyError):
            return False
