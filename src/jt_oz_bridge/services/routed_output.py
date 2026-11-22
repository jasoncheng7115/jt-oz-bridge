"""Render authorized router replies into immutable, atomic outbox page batches."""

from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.services.outbox import Outbox, QueuedBatch
from jt_oz_bridge.storage.durable import Conflict

RENDERER_VERSION = "router-mobile-markdown-v2"
FOOTER_SIZE = MARKER_FOOTER_SIZE


class RoutedOutbox:
    def __init__(
        self, outbox: Outbox, *, realm_id: str, message_limit: int, topic_limit: int
    ) -> None:
        if (
            outbox.fence is None
            or not realm_id
            or not isinstance(message_limit, int)
            or isinstance(message_limit, bool)
            or not isinstance(topic_limit, int)
            or isinstance(topic_limit, bool)
            or message_limit < 173
            or topic_limit < 1
        ):
            raise ValueError("verified_reply_contract_and_fence_required")
        self.outbox, self.realm_id = outbox, realm_id
        self.message_limit, self.topic_limit = message_limit, topic_limit
        self.tr = Translator()

    async def publish(self, routed: RoutedInput) -> QueuedBatch | None:
        if routed.state == "ignore":
            return None
        if (
            not routed.binding_id
            or routed.binding_revision is None
            or not routed.delivery_key
            or not routed.text
        ):
            raise ValueError("incomplete_routed_reply")
        binding = await self.outbox.target(routed.binding_id, routed.binding_revision)
        if binding.realm_id != self.realm_id:
            raise Conflict("reply_realm_mismatch")
        existing = await self.outbox.cached_batch(
            routed.delivery_key, routed.binding_id, routed.binding_revision
        )
        if existing is not None:
            return existing
        # Reserve the longest allowed page number before rendering; all output
        # pages and correlation footers must fit the actual verified server cap.
        maximum_header = self.tr.page_prefix(routed.locale, 100, 100)
        rendered = MobileMarkdown(locale=routed.locale).render(
            routed.text, self.message_limit, reserved_characters=FOOTER_SIZE + len(maximum_header)
        )
        if not rendered.pages or len(rendered.pages) > 100:
            raise ValueError("reply_requires_authorized_full_output")
        pages = (
            tuple(rendered.pages)
            if len(rendered.pages) == 1
            else tuple(
                self.tr.page_prefix(routed.locale, index, len(rendered.pages)) + page
                for index, page in enumerate(rendered.pages, 1)
            )
        )
        return await self.outbox.queue_batch(
            routed.delivery_key,
            routed.binding_id,
            routed.binding_revision,
            pages,
            renderer_version=RENDERER_VERSION,
            message_limit=self.message_limit,
            topic_limit=self.topic_limit,
            priority=10,
            widget=routed.widget,
        )
