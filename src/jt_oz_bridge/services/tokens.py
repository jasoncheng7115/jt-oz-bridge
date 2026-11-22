import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence


@dataclass
class TokenPlan:
    """Unpublished catalog tokens committed with their command response."""

    owner: "TokenService"
    issued: list[ControlToken] = field(default_factory=list)
    consumed: list[tuple[ControlToken, bool]] = field(default_factory=list)
    committed: bool = False
    required_output_source: HumanMessage | None = None

    def require_output_source(self, source: HumanMessage) -> None:
        if self.committed or self.required_output_source not in (None, source):
            raise Conflict("catalog_output_source_changed")
        self.required_output_source = source

    async def commit(self, session: AsyncSession, *, target: DiscoveryTarget | None = None) -> None:
        if self.committed or self.owner.fence is None:
            raise Conflict("catalog_token_plan_not_owned")
        if self.required_output_source is not None and (
            target is None or target.source != self.required_output_source
        ):
            raise Conflict("catalog_fresh_output_source_required")
        if target is not None:
            if target.expires_at <= time.time():
                raise Conflict("catalog_output_authorization_expired")
            projects = {p.scope.project_id: p.model_dump(mode="json") for p in target.projects}
            for saved in self.issued:
                if (saved.realm_id, saved.user_id) != (
                    target.source.realm_id,
                    target.source.author_id,
                ):
                    raise Conflict("catalog_token_output_actor_changed")
                context = saved.context
                if any(
                    context.get(k) != value
                    for k, value in {
                        "channel_id": target.source.channel_id,
                        "topic": target.source.topic,
                        "audience_hash": digest(target.audience.model_dump(mode="json")),
                    }.items()
                ):
                    raise Conflict("catalog_token_output_audience_changed")
                if saved.kind.startswith("discover-"):
                    scopes = context.get("projects")
                    if not isinstance(scopes, list) or any(
                        not isinstance(p, dict)
                        or not isinstance(p.get("scope"), dict)
                        or p != projects.get(p["scope"].get("project_id"))
                        for p in scopes
                    ):
                        raise Conflict("catalog_token_output_projects_changed")
                elif saved.kind == "binding-confirm":
                    ref = context.get("reference", {})
                    if ref.get("project_id") not in projects:
                        raise Conflict("catalog_binding_output_project_changed")
        await self.owner.fence.lock(session)
        for saved, deadline in self.consumed:
            await self.owner._consume_in_session(session, saved, database_deadline=deadline)
        for saved in self.issued:
            if saved.expires_at <= time.time() or saved.context_hash != digest(saved.context):
                raise Conflict("catalog_token_plan_expired")
            session.add(saved)
        await session.flush()
        self.committed = True


# Tokens issued while one command runs; menu buttons may only carry these.
MINTED: ContextVar[list[str] | None] = ContextVar("minted_control_tokens", default=None)


class TokenService:
    def __init__(self, db: Database, *, fence: ConsumerFence | None = None) -> None:
        self.db, self.fence = db, fence
        self._plan: ContextVar[TokenPlan | None] = ContextVar("catalog_token_plan", default=None)

    @property
    def active_plan(self) -> TokenPlan | None:
        return self._plan.get()

    @contextmanager
    def planning(self) -> Iterator[TokenPlan]:
        if self.active_plan is not None or self.fence is None:
            raise Conflict("nested_or_unfenced_catalog_token_plan")
        plan = TokenPlan(self)
        token = self._plan.set(plan)
        try:
            yield plan
        finally:
            self._plan.reset(token)

    async def issue(
        self,
        kind: str,
        realm: str,
        user_id: int,
        context: dict[str, Any],
        *,
        ttl: int = 900,
        binding_id: str | None = None,
        binding_revision: int | None = None,
    ) -> str:
        if user_id <= 0 or ttl <= 0 or ttl > 3600:
            raise ValueError("invalid token scope or lifetime")
        if (binding_id is None) != (binding_revision is None):
            raise ValueError("binding revision required")
        token = secrets.token_urlsafe(24)
        minted = MINTED.get()
        if minted is not None:
            minted.append(token)
        saved = ControlToken(
            token_hash=token_hash(token),
            kind=kind,
            realm_id=realm,
            user_id=user_id,
            binding_id=binding_id,
            binding_revision=binding_revision,
            context=context,
            context_hash=digest(context),
            expires_at=time.time() + ttl,
        )
        plan = self.active_plan
        if plan is not None:
            if plan.committed or len(plan.issued) >= 32:
                raise Conflict("catalog_token_plan_bound")
            plan.issued.append(saved)
            return token
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            session.add(saved)
        return token

    async def inspect(self, token: str, kind: str, realm: str, user_id: int) -> ControlToken:
        return await self.inspect_allowed(token, frozenset({kind}), realm, user_id)

    async def inspect_allowed(
        self, token: str, kinds: frozenset[str], realm: str, user_id: int
    ) -> ControlToken:
        if not kinds or len(kinds) > 8:
            raise ValueError("invalid_control_token_kinds")
        async with self.db.sessions() as session:
            saved = await session.get(ControlToken, token_hash(token))
            if (
                not saved
                or saved.kind not in kinds
                or saved.realm_id != realm
                or saved.user_id != user_id
                or saved.used
                or saved.expires_at <= time.time()
                or saved.context_hash != digest(saved.context)
            ):
                raise Conflict("control token unavailable")
            if saved.binding_id is not None:
                binding = await session.get(Binding, saved.binding_id)
                if (
                    not binding
                    or binding.state != "active"
                    or binding.realm_id != realm
                    or binding.revision != saved.binding_revision
                ):
                    raise Conflict("control token binding changed")
            return saved

    async def consume(self, token: str, kind: str, realm: str, user_id: int) -> dict[str, Any]:
        saved = await self.inspect(token, kind, realm, user_id)
        async with self.db.sessions.begin() as session:
            await self.consume_in_session(session, saved)
        return saved.context

    async def consume_in_session(
        self, session: AsyncSession, saved: ControlToken, *, database_deadline: bool = False
    ) -> None:
        """Consume an already-authorized inspect result inside the caller's transaction."""
        plan = self.active_plan
        if plan is not None:
            if (
                plan.committed
                or len(plan.consumed) >= 4
                or any(row.token_hash == saved.token_hash for row, _ in plan.consumed)
            ):
                raise Conflict("catalog_token_plan_consumption_bound")
            plan.consumed.append((saved, database_deadline))
            return
        await self._consume_in_session(session, saved, database_deadline=database_deadline)

    async def _consume_in_session(
        self, session: AsyncSession, saved: ControlToken, *, database_deadline: bool = False
    ) -> None:
        if self.fence is not None:
            await self.fence.lock(session)
        statement = update(ControlToken).where(
            ControlToken.token_hash == saved.token_hash,
            ControlToken.kind == saved.kind,
            ControlToken.realm_id == saved.realm_id,
            ControlToken.user_id == saved.user_id,
            ControlToken.context_hash == saved.context_hash,
            ControlToken.used.is_(False),
            ControlToken.expires_at > time.time(),
        )
        if database_deadline:
            clock = (
                (func.julianday("now") - 2440587.5) * 86400.0
                if self.db.engine.dialect.name == "sqlite"
                else func.extract("epoch", func.clock_timestamp())
            )
            statement = statement.where(ControlToken.expires_at > clock)
        if saved.binding_id is not None:
            statement = statement.where(
                ControlToken.binding_id == saved.binding_id,
                ControlToken.binding_revision == saved.binding_revision,
                select(Binding.id)
                .where(
                    Binding.id == saved.binding_id,
                    Binding.state == "active",
                    Binding.realm_id == saved.realm_id,
                    Binding.revision == saved.binding_revision,
                )
                .exists(),
            )
        result = await session.execute(statement.values(used=True))
        if result.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("control_token_consumed_expired_or_context_changed")


class MenuService:
    def __init__(self, tokens: TokenService) -> None:
        self.tokens = tokens

    async def page(
        self,
        realm: str,
        user_id: int,
        entries: list[dict[str, Any]],
        *,
        offset: int = 0,
        size: int = 10,
    ) -> tuple[str, list[dict[str, Any]], int | None]:
        if offset < 0 or size < 1 or size > 10:
            raise ValueError("invalid menu page")
        selected = entries[offset : offset + size]
        token = await self.tokens.issue("menu", realm, user_id, {"items": selected})
        more = offset + size if offset + size < len(entries) else None
        return token, selected, more

    async def choose(self, token: str, realm: str, user_id: int, index: int) -> dict[str, Any]:
        saved = await self.tokens.inspect(token, "menu", realm, user_id)
        items = saved.context["items"]
        if index < 1 or index > len(items):
            raise Conflict("menu index unavailable")
        context = await self.tokens.consume(token, "menu", realm, user_id)
        return dict(context["items"][index - 1])
