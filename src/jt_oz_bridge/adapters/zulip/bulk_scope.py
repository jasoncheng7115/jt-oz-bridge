"""One-response metadata batching within an original qualified scope read.

Each before/after side issues new subscription and explicitly filtered profile
GETs. Nothing is reused across sides, operations, tasks or identity changes;
this carries no Source, local-write or Native mutation authority.
"""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from jt_oz_bridge.adapters.zulip.client import ZulipError

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader


def _positive(value: Any) -> int:
    if type(value) is not int or not 0 < value < 10**18:
        raise ZulipError("bulk_scope_numeric_identity_required")
    return value


@dataclass
class _Side:
    channel_id: int
    value: dict[str, Any]
    ids: tuple[int, ...]
    channel_read: bool = False
    members_read: bool = False
    profiles: dict[int, dict[str, Any]] | None = None
    seen_users: set[int] = field(default_factory=set)


@dataclass
class _Operation:
    current: Callable[[], None]
    side: _Side | None = None
    closed: bool = False


class BulkScopeReads:
    def __init__(self, reader: "ZulipScopeReader", *, enabled: bool) -> None:
        self.reader, self.enabled = reader, enabled
        self._operation: ContextVar[_Operation | None] = ContextVar(
            "zulip_bulk_scope", default=None
        )

    @asynccontextmanager
    async def operation(self) -> AsyncIterator[None]:
        # Keep unknown versions and custom guards on their original API path.
        # Imported here because runtime enrollment itself constructs the reader.
        from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity

        reader = self.reader
        client, guard = reader.client, reader.client.verify_identity
        if (
            not self.enabled
            or type(guard) is not ZulipRuntimeIdentity
            or guard.client is not client
            or guard.qualification.zulip_version != "12.3"
            or guard.qualification.feature_level != 500
            or reader.enrolled.feature_level != 500
        ):
            yield
            return
        http, transport = client.client, client.client._transport
        enrolled, channels, qualification = reader.enrolled, reader.channel_ids, guard.qualification
        qualification_fields = (
            "bot_user_id",
            "bot_owner_id",
            "url",
            "zulip_version",
            "feature_level",
        )
        qualification_values = tuple(getattr(qualification, key) for key in qualification_fields)
        task = asyncio.current_task()

        def current() -> None:
            if (
                operation.closed
                or asyncio.current_task() is not task
                or reader.client is not client
                or client.client is not http
                or http._transport is not transport
                or client.verify_identity is not guard
                or client.attestation is not enrolled
                or reader.enrolled is not enrolled
                or reader.channel_ids is not channels
                or guard.qualification is not qualification
                or tuple(getattr(qualification, key) for key in qualification_fields)
                != qualification_values
            ):
                raise ZulipError("bulk_scope_identity_changed")
            # Original task/window check, never a refreshed or extended TTL.
            guard.scope_bot_user()

        operation = _Operation(current)
        token = self._operation.set(operation)
        try:
            current()
            yield
            current()
        finally:
            operation.closed = True
            operation.side = None
            self._operation.reset(token)

    async def _side(self, channel: int, *, members: bool) -> _Side | None:
        operation = self._operation.get()
        if operation is None:
            return None
        operation.current()
        reader = self.reader
        reader.scope(reader.enrolled.realm_id, channel)
        side = operation.side
        consumed = side is not None and (side.members_read if members else side.channel_read)
        if side is None or side.channel_id != channel or consumed:
            response = await reader.client.request(
                "GET", "users/me/subscriptions", params={"include_subscribers": "true"}
            )
            operation.current()
            rows = response.get("subscriptions")
            if type(rows) is not list or not 1 <= len(rows) <= 10000:
                raise ZulipError("complete_subscription_scope_required")
            ids: set[int] = set()
            selected: dict[str, Any] | None = None
            for row in rows:
                if type(row) is not dict:
                    raise ZulipError("subscription_metadata_contract_mismatch")
                identity = _positive(row.get("stream_id"))
                if identity in ids:
                    raise ZulipError("subscription_identity_not_unique")
                ids.add(identity)
                if identity == channel:
                    selected = row
            if selected is None:
                raise ZulipError("enrolled_subscription_required")
            values = (
                "invite_only",
                "is_web_public",
                "history_public_to_subscribers",
                "is_archived",
            )
            if (
                any(type(selected.get(key)) is not bool for key in values)
                or selected["is_archived"]
            ):
                raise ZulipError("subscription_metadata_contract_mismatch")
            raw = selected.get("subscribers")
            if (
                "partial_subscribers" in selected
                or type(raw) is not list
                or not 1 <= len(raw) <= 10000
            ):
                raise ZulipError("complete_subscription_membership_required")
            subscribers = tuple(sorted(_positive(value) for value in raw))
            if (
                len(set(subscribers)) != len(subscribers)
                or reader.enrolled.bot_user_id not in subscribers
            ):
                raise ZulipError("unique_membership_including_dedicated_bot_required")
            side = _Side(
                channel,
                {key: selected[key] for key in ("stream_id", *values[:-1])},
                subscribers,
            )
            operation.side = side
        if members:
            side.members_read = True
        else:
            side.channel_read = True
        return side

    async def channel(self, channel: int) -> dict[str, Any] | None:
        side = await self._side(channel, members=False)
        return dict(side.value) if side is not None else None

    async def members(self, channel: int) -> tuple[int, ...] | None:
        side = await self._side(channel, members=True)
        return side.ids if side is not None else None

    async def user(self, user_id: int) -> dict[str, Any] | None:
        operation = self._operation.get()
        if operation is None:
            return None
        operation.current()
        side = operation.side
        reader = self.reader
        if side is None or user_id not in side.ids or user_id == reader.enrolled.bot_user_id:
            return None
        if side.profiles is None or user_id in side.seen_users:
            requested = tuple(
                identity for identity in side.ids if identity != reader.enrolled.bot_user_id
            )
            response = await reader.client.request(
                "GET",
                "users",
                params={
                    "user_ids": json.dumps(requested),
                    "client_gravatar": "false",
                    "include_custom_profile_fields": "false",
                },
            )
            operation.current()
            rows = response.get("members")
            if type(rows) is not list or len(rows) != len(requested):
                raise ZulipError("complete_filtered_profiles_required")
            profiles: dict[int, dict[str, Any]] = {}
            for row in rows:
                if type(row) is not dict:
                    raise ZulipError("filtered_profile_contract_mismatch")
                identity = _positive(row.get("user_id"))
                if (
                    identity not in requested
                    or identity in profiles
                    or row.get("is_active") is not True
                    or type(row.get("is_bot")) is not bool
                ):
                    raise ZulipError("filtered_profile_contract_mismatch")
                profiles[identity] = {key: row[key] for key in ("user_id", "is_active", "is_bot")}
            if set(profiles) != set(requested):
                raise ZulipError("complete_filtered_profiles_required")
            side.profiles, side.seen_users = profiles, set()
        side.seen_users.add(user_id)
        return dict(side.profiles[user_id])
