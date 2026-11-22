"""Narrow, raw-Markdown messaging for a separately enrolled dedicated Bot."""

import json
from typing import Any

from jt_oz_bridge.adapters.zulip.client import ZulipClient, ZulipError
from jt_oz_bridge.domain.delivery import PostedMessage


class ZulipGateway:
    def __init__(self, client: ZulipClient, *, queue_id: str | None = None) -> None:
        enrolled = client.attestation
        if not enrolled or enrolled.feature_level < 334:
            raise ZulipError("enrolled_message_contract_required")
        if enrolled.max_message_length <= 0 or enrolled.max_topic_length <= 0:
            raise ZulipError("registered_message_limits_required")
        self.client, self.queue_id = client, queue_id
        self.realm_id, self.bot_user_id = enrolled.realm_id, enrolled.bot_user_id
        self.max_message_length, self.max_topic_length = (
            enrolled.max_message_length,
            enrolled.max_topic_length,
        )

    @property
    def writes_enabled(self) -> bool:
        return self.client.attestation is not None and self.client.verify_identity is not None

    def content(self, content: str) -> None:
        if not content or len(content) > self.max_message_length:
            raise ZulipError("registered_message_limit_exceeded")

    async def send(
        self, channel: int, topic: str, content: str, marker: str, *, widget: str | None = None
    ) -> int:
        self.content(content)
        if (
            isinstance(channel, bool)
            or not isinstance(channel, int)
            or channel <= 0
            or len(topic) > self.max_topic_length
        ):
            raise ZulipError("invalid_channel_or_topic")
        if not marker.startswith("jtoz:") or len(marker) > 80:
            raise ZulipError("invalid_correlation_marker")
        values = {
            "type": "stream",
            "to": json.dumps(channel),
            "topic": topic,
            "content": content,
            "read_by_sender": "true",
        }
        if widget is not None:
            values["widget_content"] = widget
        if self.queue_id:
            values.update(queue_id=self.queue_id, local_id=marker)
        data = await self.client.request("POST", "messages", data=values)
        message_id = data.get("id")
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            raise ZulipError("invalid_message_admission_receipt")
        return message_id

    async def edit(self, message_id: int, content: str) -> None:
        self.content(content)
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            raise ZulipError("invalid_message_id")
        await self.client.request("PATCH", f"messages/{message_id}", data={"content": content})

    def message(self, raw: Any) -> PostedMessage:
        try:
            if (
                not isinstance(raw, dict)
                or raw.get("type") != "stream"
                or raw.get("content_type") != "text/x-markdown"
            ):
                raise ValueError("raw channel message required")
            return PostedMessage(
                realm_id=self.realm_id,
                id=raw["id"],
                channel_id=raw["stream_id"],
                topic=raw["subject"],
                sender_id=raw["sender_id"],
                content=raw["content"],
            )
        except (KeyError, TypeError, ValueError):
            raise ZulipError("raw_message_contract_mismatch") from None

    async def get(self, message_id: int) -> PostedMessage:
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            raise ZulipError("invalid_message_id")
        data = await self.client.request(
            "GET",
            f"messages/{message_id}",
            params={"apply_markdown": "false", "allow_empty_topic_name": "true"},
        )
        message = self.message(data.get("message"))
        if message.id != message_id:
            raise ZulipError("message_identity_mismatch")
        return message

    async def find(self, channel: int, topic: str, marker: str) -> tuple[PostedMessage, ...]:
        data = await self.client.request(
            "GET",
            "messages",
            params={
                "narrow": json.dumps(
                    [
                        {"operator": "channel", "operand": channel},
                        {"operator": "topic", "operand": topic},
                    ]
                ),
                "anchor": "newest",
                "num_before": 100,
                "num_after": 0,
                "apply_markdown": "false",
                "allow_empty_topic_name": "true",
            },
        )
        raw = data.get("messages")
        if not isinstance(raw, list) or len(raw) > 101:
            raise ZulipError("history_contract_mismatch")
        messages = tuple(self.message(item) for item in raw)
        return tuple(
            item
            for item in messages
            if item.channel_id == channel
            and item.topic == topic
            and item.sender_id == self.bot_user_id
            and marker in item.content
        )
