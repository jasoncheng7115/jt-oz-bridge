import asyncio
import hashlib
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import case, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import AdminAccount, AdminSession, AuditEvent, AuthThrottle
from jt_oz_bridge.storage.statements import insert

HASHER = PasswordHasher()
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class LoginRejected(ValueError):
    pass


class AdminAuth:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(self, username: str) -> str:
        password = secrets.token_urlsafe(32)
        hashed = await asyncio.to_thread(HASHER.hash, password)
        async with self.db.sessions.begin() as session:
            if await session.scalar(select(AdminAccount.id).limit(1)):
                raise LoginRejected("administrator_already_bootstrapped")
            session.add(AdminAccount(username=username, password_hash=hashed, must_reset=True))
            session.add(AuditEvent(actor="cli", event="admin_bootstrapped", object_id=username))
        return password

    async def login(self, username: str, password: str, peer: str) -> tuple[str, str, bool]:
        key, now = token_hash(peer), time.time()
        async with self.db.sessions.begin() as session:
            expired = AuthThrottle.window_start <= now - 300
            attempts = (
                await session.execute(
                    insert(self.db, AuthThrottle)
                    .values(key=key, attempts=1, window_start=now)
                    .on_conflict_do_update(
                        index_elements=["key"],
                        set_={
                            "attempts": case((expired, 1), else_=AuthThrottle.attempts + 1),
                            "window_start": case((expired, now), else_=AuthThrottle.window_start),
                        },
                    )
                    .returning(AuthThrottle.attempts)
                )
            ).scalar_one()
            account = await session.scalar(
                select(AdminAccount).where(AdminAccount.username == username)
            )
        if attempts > 5:
            raise LoginRejected("login_throttled")
        valid: bool
        try:
            valid = await asyncio.to_thread(
                HASHER.verify, account.password_hash if account else DUMMY_HASH, password
            )
        except VerificationError:
            valid = False
        if not valid or account is None:
            raise LoginRejected("invalid_credentials")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        async with self.db.sessions.begin() as session:
            # Serialize with password changes; a credential verified just before a reset
            # cannot create a fresh session after that reset has invalidated old sessions.
            still_current = (
                await session.execute(
                    update(AdminAccount)
                    .where(
                        AdminAccount.id == account.id,
                        AdminAccount.password_hash == account.password_hash,
                    )
                    .values(password_hash=account.password_hash)
                    .returning(AdminAccount.must_reset)
                )
            ).scalar_one_or_none()
            if still_current is None:
                raise LoginRejected("invalid_credentials")
            session.add(
                AdminSession(
                    token_hash=token_hash(token),
                    admin_id=account.id,
                    csrf_hash=token_hash(csrf),
                    expires_at=now + 3600,
                )
            )
            session.add(AuditEvent(actor=account.id, event="admin_login", object_id=account.id))
        return token, csrf, still_current

    async def authenticate(self, token: str) -> AdminAccount:
        async with self.db.sessions() as session:
            saved = await session.get(AdminSession, token_hash(token))
            if saved is None or saved.expires_at <= time.time():
                raise LoginRejected("authentication_required")
            account = await session.get(AdminAccount, saved.admin_id)
            if account is None:
                raise LoginRejected("authentication_required")
            return account

    async def lock_active_session(self, session: AsyncSession, token: str, admin_id: str) -> str:
        # Keep the same account -> session lock order as password reset. SQLite
        # uses the enclosing BEGIN IMMEDIATE; PostgreSQL locks these exact rows.
        account = (
            await session.execute(
                select(AdminAccount.id, AdminAccount.must_reset)
                .where(AdminAccount.id == admin_id)
                .with_for_update()
            )
        ).one_or_none()
        saved = (
            await session.execute(
                select(AdminSession.admin_id, AdminSession.expires_at)
                .where(AdminSession.token_hash == token_hash(token))
                .with_for_update()
            )
        ).one_or_none()
        if (
            account is None
            or account.must_reset
            or saved is None
            or (saved.admin_id != admin_id or saved.expires_at <= time.time())
        ):
            raise LoginRejected("active_administrator_session_required")
        return token_hash(token)

    async def check_csrf(self, token: str, csrf: str) -> None:
        async with self.db.sessions() as session:
            saved = await session.get(AdminSession, token_hash(token))
            if (
                saved is None
                or saved.expires_at <= time.time()
                or not secrets.compare_digest(saved.csrf_hash, token_hash(csrf))
            ):
                raise LoginRejected("csrf_failed")

    async def reset_password(self, account: AdminAccount, password: str) -> None:
        if len(password) < 12 or len(password) > 1024:
            raise LoginRejected("password_length")
        hashed = await asyncio.to_thread(HASHER.hash, password)
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(AdminAccount)
                .where(
                    AdminAccount.id == account.id,
                    AdminAccount.password_hash == account.password_hash,
                )
                .values(password_hash=hashed, must_reset=False)
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                raise LoginRejected("credential_changed")
            await session.execute(delete(AdminSession).where(AdminSession.admin_id == account.id))
            session.add(
                AuditEvent(actor=account.id, event="password_changed", object_id=account.id)
            )

    async def logout(self, token: str) -> None:
        async with self.db.sessions.begin() as session:
            await session.execute(
                delete(AdminSession).where(AdminSession.token_hash == token_hash(token))
            )
