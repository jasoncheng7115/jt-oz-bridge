from dataclasses import dataclass
from typing import Literal

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.output_target import DiscoveryTarget, WorktreeSwitchPreviewTarget


class SavedReply(ControlModel):
    text: str
    locale: Locale
    # Desktop buttons for a menu reply; saved so a replay shows the same buttons.
    widget: str | None = None
    # The numbered rows' commands, in order, for a phone's `!N`.
    shortcuts: list[str] | None = None


@dataclass(frozen=True)
class RoutedInput:
    state: Literal["ignore", "reply", "busy", "held", "ambiguous"]
    binding_id: str | None = None
    binding_revision: int | None = None
    text: str = ""
    delivery_key: str | None = None
    action_id: str | None = None
    locale: Locale = "en"
    discovery_target: WorktreeSwitchPreviewTarget | DiscoveryTarget | None = None
    # A record of work already committed with the command, never an ACL proof.
    queued_batch_id: str | None = None
    # Zulip button payload for the last page; the text alone stays complete.
    widget: str | None = None


class RoutingRateDeferred(DeliveryRateLimited):
    """Throttled while the router had performed only source/scope reads."""
