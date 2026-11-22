"""Safe Native model metadata; configured availability is not inference proof."""

from typing import Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


class NativeModelRef(ControlModel):
    provider_id: str = Field(min_length=1, max_length=255)
    model_id: str = Field(min_length=1, max_length=4096)
    # Omission means the Native default variant. The literal "none" is a
    # distinct, selectable Native ID and must survive a round trip unchanged.
    variant: str | None = Field(default=None, min_length=1, max_length=1024)

    @field_validator("provider_id", "model_id", "variant")
    @classmethod
    def inert_identifier(cls, value: str | None) -> str | None:
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("model_identifier_contains_control_character")
        return value

    def wire(self) -> dict[str, str]:
        result = {"providerID": self.provider_id, "id": self.model_id}
        if self.variant is not None:
            result["variant"] = self.variant
        return result

    def same_native_selection(self, other: Self | None) -> bool:
        """Native session/info.ts maps an omitted variant to literal default.

        Preserve both wire representations in evidence; compare them as Native
        switchModel does. The variant named none remains a different selection.
        """
        return (
            other is not None
            and self.provider_id == other.provider_id
            and self.model_id == other.model_id
            and (self.variant or "default") == (other.variant or "default")
        )


class NativeModelOption(ControlModel):
    reference: NativeModelRef
    # This is the provider's modelID, which can differ from the selection alias.
    upstream_model_id: str = Field(min_length=1, max_length=4096)
    name: str = Field(max_length=8192)
    status: Literal["alpha", "beta", "deprecated", "active"]
    variant_ids: tuple[str, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def valid_choices(self) -> Self:
        if self.reference.variant is not None or len(set(self.variant_ids)) != len(
            self.variant_ids
        ):
            raise ValueError("model_option_variant_identity_invalid")
        for variant in self.variant_ids:
            NativeModelRef(
                provider_id=self.reference.provider_id,
                model_id=self.reference.model_id,
                variant=variant,
            )
        return self

    def supports(self, selected: NativeModelRef) -> bool:
        return (
            selected.provider_id == self.reference.provider_id
            and selected.model_id == self.reference.model_id
            and (selected.variant in {None, "default"} or selected.variant in self.variant_ids)
        )


class NativeModelCatalog(ControlModel):
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: tuple[NativeModelOption, ...] = Field(max_length=4096)
    selected: NativeModelRef | None = None
    default: NativeModelRef | None = None

    @model_validator(mode="after")
    def distinct_models(self) -> Self:
        keys = [(x.reference.provider_id, x.reference.model_id) for x in self.items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate_model_selection_identity")
        return self

    def option(self, selected: NativeModelRef) -> NativeModelOption | None:
        return next((item for item in self.items if item.supports(selected)), None)

    @property
    def providers(self) -> tuple[str, ...]:
        return tuple(sorted({item.reference.provider_id for item in self.items}))


class ModelCatalog(Protocol):
    def contract_for(self, reference: SessionRef) -> str: ...

    async def read(self, reference: SessionRef) -> NativeModelCatalog: ...


class ModelSelection(ControlModel):
    """Pinned safe menu choice, not a free-form provider or credential request."""

    origin: Literal["model", "variant"]
    target: NativeModelRef
    previous: NativeModelRef | None
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def only_selected_setting(self) -> Self:
        if self.origin == "model" and self.target.variant is not None:
            raise ValueError("model_choice_requires_native_default_variant")
        if self.origin == "variant" and (
            self.previous is None
            or self.target.provider_id != self.previous.provider_id
            or self.target.model_id != self.previous.model_id
        ):
            raise ValueError("variant_choice_cannot_change_provider_or_model")
        return self


class ModelSettingOutcome(ControlModel):
    operation: Literal["model.switch"]
    target: NativeModelRef
    observed: NativeModelRef
    effect: Literal["subsequent_provider_turns"]
    catalog_before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_settings_semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_settings_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    starts_execution: Literal[False]
    turn_completed: Literal[False]

    @model_validator(mode="after")
    def matching_readback(self) -> Self:
        if not self.target.same_native_selection(self.observed):
            raise ValueError("model_setting_outcome_readback_does_not_match")
        return self
