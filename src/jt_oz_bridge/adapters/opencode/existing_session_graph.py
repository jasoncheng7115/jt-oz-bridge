"""Bounded GET-only observation of a complete original session descendant tree.

Metadata closure and policy stability do not prove coordinator/resource state.
This adapter does not enroll feed references, authorize execution or register
sessions. A separate resource graph provider and durable controller are required.
"""

import asyncio
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.existing_sessions import (
    Authority,
    V2ExistingSessionObserver,
)
from jt_oz_bridge.domain.existing_sessions import (
    ExistingSessionGraphObservation,
    ExistingSessionObservation,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

# Subagents nest a few levels at most. A deeper chain is refused, never truncated:
# every node's proof re-reads all of its ancestors within one short deadline.
MAX_GRAPH_DEPTH = 16


@dataclass(frozen=True)
class _ObservedGraph:
    original: ReferenceType[ExistingSessionGraphObservation]
    observer: V2ExistingSessionObserver
    nodes: tuple[ReferenceType[ExistingSessionObservation], ...]


def graph_identity(nodes: tuple[ExistingSessionObservation, ...]) -> str:
    """Stable identity and policy only; live title/usage are not an idle fence."""
    return digest(
        {
            "nodes": [
                {
                    "reference": node.reference.model_dump(mode="json"),
                    "origin_sha256": node.origin_sha256,
                    "policy_sha256": node.policy_sha256,
                }
                for node in sorted(nodes, key=lambda node: node.reference.upstream_session_id)
            ]
        }
    )


class V2ExistingSessionGraphObserver:
    def __init__(self, observer: V2ExistingSessionObserver) -> None:
        self.observer = observer
        self._observer = observer
        self._graphs: OrderedDict[int, _ObservedGraph] = OrderedDict()
        self.require(observer.reference)

    def require(self, target: SessionRef) -> None:
        self.observer.require(target)
        if (
            self.observer is not self._observer
            or "session.list" not in self.observer.protocol.operations
        ):
            raise ContractError("existing_session_graph_explicit_backend_list_contract_required")

    async def children(
        self, parent: SessionRef, *, authorize: Authority, remaining: int
    ) -> tuple[tuple[SessionRef, int], ...]:
        self.require(parent)
        cursor: str | None = None
        cursors: set[str] = set()
        found: dict[SessionRef, int] = {}
        # Empty pages with cursors cannot evade the total node/page bound.
        for _ in range(1000):
            if await authorize() is not True:
                raise ContractError("existing_session_graph_current_authority_required")
            self.require(parent)
            query = {"parentID": parent.upstream_session_id, "limit": "100", "order": "asc"}
            if cursor is not None:
                query["cursor"] = cursor
            # Deliberately no project/directory/search filter: a foreign child
            # must fail the scope check rather than silently disappear.
            page = await self.observer._feed.transport.request("session.list", query=query)
            self.require(parent)
            if await authorize() is not True:
                raise ContractError("existing_session_graph_current_authority_required")
            if len(page["data"]) > 100:
                raise ContractError("existing_session_graph_page_capacity_exceeded")
            for row in page["data"]:
                reference = parent.model_copy(update={"upstream_session_id": row["id"]})
                self.require(reference)
                origin = self.observer.origin(reference, row, parent)
                if reference == parent or reference in found:
                    raise ContractError("existing_session_graph_duplicate_or_cyclic_edge")
                found[reference] = origin["created_at"]
                if len(found) > remaining:
                    raise ContractError("existing_session_graph_capacity_exceeded")
            cursor = page["cursor"].get("next")
            if cursor is None:
                return tuple(sorted(found.items(), key=lambda item: item[0].upstream_session_id))
            if not cursor or len(cursor) > 8192 or cursor in cursors:
                raise ContractError("existing_session_graph_cursor_not_progressing")
            cursors.add(cursor)
        raise ContractError("existing_session_graph_page_capacity_exceeded")

    async def walk(
        self, target: SessionRef, *, authorize: Authority
    ) -> tuple[ExistingSessionObservation, ...]:
        self.require(target)
        todo: deque[tuple[SessionRef, SessionRef | None, int | None, int]] = deque(
            [(target, None, None, 0)]
        )
        seen = {target}
        nodes = []
        while todo:
            reference, parent, created, depth = todo.popleft()
            value = await self.observer.observe(reference, parent=parent, authorize=authorize)
            if created is not None and value.native_created_at != created:
                raise ContractError("existing_session_graph_list_get_origin_changed")
            nodes.append(value)
            children = await self.children(
                reference, authorize=authorize, remaining=1000 - len(seen)
            )
            if children and depth >= MAX_GRAPH_DEPTH:
                raise ContractError("existing_session_graph_depth_exceeded")
            for child, child_created in children:
                if child in seen:
                    raise ContractError("existing_session_graph_duplicate_or_cyclic_edge")
                seen.add(child)
                todo.append((child, reference, child_created, depth + 1))
        return tuple(nodes)

    async def observe(
        self, target: SessionRef, *, authorize: Authority
    ) -> ExistingSessionGraphObservation:
        self.require(target)
        try:
            async with asyncio.timeout(5):
                started = time.time()
                before = await self.observer.owner()
                first = await self.walk(target, authorize=authorize)
                second = await self.walk(target, authorize=authorize)
                after = await self.observer.owner()
                await self.observer.peer()
                now = time.time()
                self.require(target)
                if (
                    before != after
                    or graph_identity(first) != graph_identity(second)
                    or not started <= now < started + 5
                    or any(not self.observer.current(node) for node in second)
                    or await authorize() is not True
                ):
                    raise ContractError("existing_session_graph_original_observation_changed")
                if (
                    await self.observer.owner() != before
                    or not started <= time.time() < started + 5
                ):
                    raise ContractError("existing_session_graph_original_observation_changed")
                value = ExistingSessionGraphObservation(
                    reference=target,
                    nodes=second,
                    graph_sha256=graph_identity(second),
                    owner_epoch=after[0],
                    observed_at=started,
                    expires_at=min(started + 5, *(node.expires_at for node in second)),
                )
                self._graphs = OrderedDict(
                    (key, saved)
                    for key, saved in self._graphs.items()
                    if (original := saved.original()) is not None and original.expires_at > now
                )
                while len(self._graphs) >= 32:
                    self._graphs.popitem(last=False)
                self._graphs[id(value)] = _ObservedGraph(
                    weakref(value), self.observer, tuple(weakref(node) for node in second)
                )
                if not self.current(value):
                    raise ContractError("existing_session_graph_final_observation_expired")
                return value
        except TimeoutError:
            raise ContractError("existing_session_graph_observation_expired") from None

    def current(self, value: ExistingSessionGraphObservation) -> bool:
        try:
            self.require(value.reference)
            saved = self._graphs.get(id(value))
            return bool(
                saved
                and saved.original() is value
                and saved.observer is self.observer
                and len(saved.nodes) == len(value.nodes)
                and all(
                    original() is node
                    for original, node in zip(saved.nodes, value.nodes, strict=True)
                )
                and all(self.observer.current(node) for node in value.nodes)
                and value.graph_sha256 == graph_identity(value.nodes)
                and value.observed_at <= time.time() < value.expires_at
            )
        except ValueError:
            return False
