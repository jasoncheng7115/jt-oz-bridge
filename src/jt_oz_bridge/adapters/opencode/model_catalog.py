"""Location-scoped Native model catalog with an explicit safe-field projection.

Model.Info and its variants may contain request headers, bodies and settings.
Those fields are necessarily received by the Native RPC, but are never copied
into our DTO, hashes, tokens, logs or persistence by this adapter.
"""

import asyncio
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport
from jt_oz_bridge.domain.model_catalog import (
    NativeModelCatalog,
    NativeModelOption,
    NativeModelRef,
)
from jt_oz_bridge.domain.models import SessionRef

READS = frozenset({"session.get", "model.list", "model.default"})


def native_ref(raw: dict[str, Any]) -> NativeModelRef:
    return NativeModelRef(
        provider_id=raw["providerID"], model_id=raw["id"], variant=raw.get("variant")
    )


def safe_option(raw: dict[str, Any]) -> NativeModelOption:
    return NativeModelOption(
        reference=NativeModelRef(provider_id=raw["providerID"], model_id=raw["id"]),
        upstream_model_id=raw["modelID"],
        name=raw["name"],
        status=raw["status"],
        variant_ids=tuple(v["id"] for v in raw["variants"]),
    )


class V2ModelCatalog:
    def __init__(
        self, transport: V2HTTPTransport, projects: Mapping[str, V2CatalogProject]
    ) -> None:
        if not projects or any(key != entry.scope.project_id for key, entry in projects.items()):
            raise ValueError("invalid_model_catalog_project_enrollment")
        if len({(p.scope.backend_id, p.scope.backend_identity) for p in projects.values()}) != 1:
            raise ValueError("model_catalog_cannot_mix_backend_instances")
        self.transport, self.projects = transport, MappingProxyType(dict(projects))

    def select(self, ref: SessionRef) -> V2CatalogProject:
        entry, attestation = self.projects.get(ref.project_id), self.transport.attestation
        if (
            entry is None
            or not entry.scope.contains(ref)
            or attestation is None
            or attestation.backend_identity != ref.backend_identity
            or attestation.schema_sha256 != self.transport.profile.sha256
            or not READS <= attestation.verified_operations
        ):
            raise ContractError("model_catalog_scope_or_installed_contract_unqualified")
        self.transport.profile.prepare("session.get", path={"sessionID": ref.upstream_session_id})
        return entry

    def contract_for(self, reference: SessionRef) -> str:
        self.select(reference)
        return self.transport.profile.sha256

    async def identity(self) -> None:
        verify = self.transport.verify_identity
        if verify is None or not await verify():
            raise ContractError("model_catalog_original_backend_unverified")

    def session(self, ref: SessionRef, raw: dict[str, Any]) -> NativeModelRef | None:
        entry = self.select(ref)
        if (
            raw["id"] != ref.upstream_session_id
            or raw["projectID"] != entry.upstream_project_id
            or raw["location"]["directory"] != ref.canonical_directory
        ):
            raise ContractError("model_catalog_original_session_scope_changed")
        return native_ref(raw["model"]) if "model" in raw else None

    async def read(self, reference: SessionRef) -> NativeModelCatalog:
        self.select(reference)
        attestation = self.transport.attestation
        await self.identity()
        self.select(reference)
        if self.transport.attestation is not attestation:
            raise ContractError("model_catalog_attestation_changed")
        query = {"location": {"directory": reference.canonical_directory}}
        path = {"sessionID": reference.upstream_session_id}
        info, models, default = await asyncio.gather(
            self.transport.request("session.get", path=path),
            self.transport.request("model.list", query=query),
            self.transport.request("model.default", query=query),
        )
        selected = self.session(reference, info["data"])
        if any(
            row["location"]["directory"] != reference.canonical_directory
            for row in (models, default)
        ):
            raise ContractError("model_catalog_native_location_changed")
        rows = models["data"]
        if len(rows) > 4096:
            raise ContractError("model_catalog_capacity_exceeded")
        keys = [(row["providerID"], row["id"]) for row in rows]
        if len(keys) != len(set(keys)):
            raise ContractError("model_catalog_duplicate_native_identity")
        # Validate disabled entries' identifiers too, but disclose only enabled
        # choices. Never choose a provider modelID in place of its Native alias.
        options = [safe_option(row) for row in rows]
        items = tuple(
            sorted(
                (option for option, raw in zip(options, rows, strict=True) if raw["enabled"]),
                key=lambda x: (x.reference.provider_id, x.reference.model_id),
            )
        )
        default_ref = native_ref(default["data"]) if default["data"] is not None else None
        after = await self.transport.request("session.get", path=path)
        if self.session(reference, after["data"]) != selected:
            raise ContractError("model_catalog_session_selection_changed")
        await self.identity()
        self.select(reference)
        if self.transport.attestation is not attestation:
            raise ContractError("model_catalog_attestation_changed")
        return NativeModelCatalog(
            reference=reference,
            contract_sha256=self.transport.profile.sha256,
            items=items,
            selected=selected,
            default=default_ref,
        )
