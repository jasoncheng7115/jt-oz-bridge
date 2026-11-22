from enum import StrEnum

from sqlalchemy import select

from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Grant


class Permission(StrEnum):
    VIEW = "view"
    OPERATE = "operate"
    APPROVE = "approve"
    MANAGE = "manage"


ROLES = {
    "viewer": {Permission.VIEW},
    "operator": {Permission.VIEW, Permission.OPERATE},
    "approver": {Permission.VIEW, Permission.APPROVE},
    "administrator": set(Permission),
}


class AccessDenied(ValueError):
    pass


class Policy:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def require(
        self,
        realm: str,
        user_id: int,
        project: str,
        permission: Permission,
        *,
        is_bot: bool = False,
    ) -> None:
        if is_bot or user_id <= 0:
            raise AccessDenied("human authorization required")
        async with self.db.sessions() as session:
            roles = (
                await session.scalars(
                    select(Grant.role).where(
                        Grant.realm_id == realm,
                        Grant.user_id == user_id,
                        Grant.project_id == project,
                        Grant.active.is_(True),
                    )
                )
            ).all()
        if not any(permission in ROLES.get(role, set()) for role in roles):
            raise AccessDenied("permission denied")

    async def require_audience(
        self, realm: str, user_ids: set[int], project: str, *, private: bool
    ) -> None:
        if not private or not user_ids:
            raise AccessDenied("private verified audience required")
        for user_id in user_ids:
            await self.require(realm, user_id, project, Permission.VIEW)
