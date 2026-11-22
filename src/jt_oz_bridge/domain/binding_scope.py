"""Immutable routing scope, separate from mutable titles, cursors and queue pause."""

from typing import Annotated

from pydantic import Field, StrictInt

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


class BindingScope(ControlModel):
    binding_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    revision: StrictInt = Field(gt=0)
    realm_id: str = Field(min_length=1)
    channel_id: StrictInt = Field(gt=0)
    topic: str = Field(min_length=1)
    reference: SessionRef
    owner_id: StrictInt = Field(gt=0)
    anchor_message_id: StrictInt | None = Field(default=None, gt=0)
    audience_revision: str = Field(min_length=1)
    audience_user_ids: frozenset[Annotated[StrictInt, Field(gt=0)]] = Field(min_length=1)
