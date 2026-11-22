"""Shared web-administrator session/fence/deadline checks; no Agent grants."""

import time
from typing import Any

from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Settings
from jt_oz_bridge.security.admin import AdminAuth, LoginRejected
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AdminAccount, AdminSession, WorkerLease


class AdministrativeAuthority:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db, self.settings, self.auth = db, settings, AdminAuth(db)

    async def _principal(self, session: AsyncSession, token: str, admin_id: str) -> str:
        if not self.settings.admin.enabled:
            raise LoginRejected("admin_disabled")
        return await self.auth.lock_active_session(session, token, admin_id)

    def _clock(self) -> Any:
        # Evaluate inside the SQL statement, after encoding and any row-lock wait.
        # Database/server clocks must be synchronized for timestamp-based leases.
        if self.db.engine.dialect.name == "sqlite":
            return (func.julianday("now") - 2440587.5) * 86400.0
        return func.extract("epoch", func.clock_timestamp())

    def _authority(self, admin_id: str, session_hash: str, fence: ConsumerFence) -> tuple[Any, ...]:
        now = self._clock()
        return (
            select(AdminAccount.id)
            .where(AdminAccount.id == admin_id, AdminAccount.must_reset.is_(False))
            .exists(),
            select(AdminSession.token_hash)
            .where(
                AdminSession.token_hash == session_hash,
                AdminSession.admin_id == admin_id,
                AdminSession.expires_at > now,
            )
            .exists(),
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == fence.holder,
                WorkerLease.fencing == fence.fencing,
                WorkerLease.expires_at > now,
            )
            .exists(),
        )

    async def _require_live(
        self, session: AsyncSession, admin_id: str, session_hash: str, fence: ConsumerFence
    ) -> None:
        if (
            await session.scalar(
                select(literal(1)).where(*self._authority(admin_id, session_hash, fence))
            )
            != 1
        ):
            raise Conflict("admin_authority_expired_during_validation")

    async def _pending_previews(self, session: AsyncSession, admin_id: str) -> int:
        from jt_oz_bridge.storage.admin_models import AdminDecision
        from jt_oz_bridge.storage.runtime_config_models import RuntimeSettingDecision

        count = 0
        for model in (AdminDecision, RuntimeSettingDecision):
            count += int(
                await session.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(
                        model.admin_id == admin_id,
                        model.state == "pending",
                        model.expires_at > time.time(),
                    )
                )
                or 0
            )
        return count
