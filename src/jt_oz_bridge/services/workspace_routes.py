"""Trusted per-realm workspace providers on a shared original backend.

Only runtime composition installs/removes registrations. Chat payloads cannot
select providers; the unchanged original source realm chooses its own entry.
"""

from dataclasses import dataclass
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.domain.attachments import WorkspaceAttachmentManifest
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_attachments import (
    PreparedWorkspaceAttachments,
    WorkspaceAttachmentProvider,
)
from jt_oz_bridge.storage.durable import Conflict


@dataclass(frozen=True, slots=True)
class WorkspaceRegistration:
    realm_id: str
    provider: WorkspaceAttachmentProvider


class WorkspaceProviderRoutes:
    def __init__(self) -> None:
        self._realms: dict[str, WorkspaceRegistration] = {}
        self._prepared: dict[
            tuple[str, str],
            tuple[ReferenceType[PreparedWorkspaceAttachments], WorkspaceRegistration],
        ] = {}

    def register(
        self, realm_id: str, provider: WorkspaceAttachmentProvider
    ) -> WorkspaceRegistration:
        if not realm_id or realm_id in self._realms or len(self._realms) >= 64:
            raise ValueError("workspace_explicit_unique_realm_registration_required")
        registration = WorkspaceRegistration(realm_id, provider)
        self._realms[realm_id] = registration
        return registration

    def unregister(self, registration: WorkspaceRegistration) -> None:
        if self._realms.get(registration.realm_id) is not registration:
            raise ValueError("workspace_original_registration_required")
        self._realms.pop(registration.realm_id)
        self._prepared = {
            key: value for key, value in self._prepared.items() if value[1] is not registration
        }

    def qualified(self, reference: SessionRef, schema_sha256: str) -> bool:
        return any(
            item.provider.qualified(reference, schema_sha256) for item in self._realms.values()
        )

    async def prepare(
        self,
        ref: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: WorkspaceAttachmentManifest,
        original_text: str,
    ) -> PreparedWorkspaceAttachments:
        registration = self._realms.get(source.realm_id)
        if registration is None:
            raise Conflict("workspace_original_realm_provider_unavailable")
        prepared = await registration.provider.prepare(
            ref, action_id, source, manifest, original_text
        )
        if (
            self._realms.get(source.realm_id) is not registration
            or prepared.realm_id != source.realm_id
        ):
            raise Conflict("workspace_original_realm_registration_changed")
        self._prepared = {
            key: value for key, value in self._prepared.items() if value[0]() is not None
        }
        if len(self._prepared) >= 256:
            raise Conflict("workspace_realm_preparation_capacity")
        self._prepared[(source.realm_id, action_id)] = (weakref(prepared), registration)
        return prepared

    def current(
        self, ref: SessionRef, action_id: str, prepared: PreparedWorkspaceAttachments
    ) -> bool:
        registration = self._realms.get(prepared.realm_id)
        issued = self._prepared.get((prepared.realm_id, action_id))
        return bool(
            registration is not None
            and issued is not None
            and issued[0]() is prepared
            and issued[1] is registration
            and registration.provider.current(ref, action_id, prepared)
        )
