"""Root-reviewed original source/shared-path certificates, never chat authority.

Certificates are historical qualification. Every runtime transfer still needs
fresh original-source, per-upload, Native, filesystem and consumer-fence checks.
No credential or filesystem is opened while normalizing these documents.
"""

import hashlib
import re
from pathlib import Path

from pydantic import Field, StrictInt, field_validator

from jt_oz_bridge.adapters.opencode import native_workspace
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_attachments import WORKSPACE_SEMANTICS
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.services import upload_associations
from jt_oz_bridge.services.file_enrollment import component_sha, object_data, zero
from jt_oz_bridge.services.upload_associations import SSHAssociationConfig
from jt_oz_bridge.storage import workspace_files
from jt_oz_bridge.storage.workspace_files import WorkspaceNamespace

REVIEW = "installed-evidence-reviewed-for-development-runtime"
SOURCE_NEGATIVES = frozenset({"bot-source", "foreign-source", "unlinked-upload", "wrong-author"})


class WorkspaceNamespacePin(ControlModel):
    path: Path
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(gt=0)
    owner_uid: StrictInt = Field(gt=0)
    reader_gid: StrictInt = Field(gt=0)

    @field_validator("path")
    @classmethod
    def original_controlled_path(cls, value: Path) -> Path:
        if (
            not value.is_absolute()
            or ".." in value.parts
            or re.fullmatch(r"\.jt-oz-incoming-[A-Za-z0-9][A-Za-z0-9_-]{0,110}", value.name) is None
        ):
            raise ValueError("workspace_enrolled_controlled_namespace_required")
        return value

    def storage(self) -> WorkspaceNamespace:
        return WorkspaceNamespace(
            self.path, self.device, self.inode, self.owner_uid, self.reader_gid
        )


def workspace_qualification(
    raw: bytes,
    *,
    reference: SessionRef,
    contract_sha256: str,
    policy_sha256: str,
    owner: HostOwnerEnrollment,
) -> WorkspaceNamespacePin:
    doc = object_data(strict_loads(raw))
    namespace = WorkspaceNamespacePin.model_validate(doc.get("namespace"))
    observation = object_data(doc.get("observation"))
    if (
        doc.get("format") != "qualified-original-workspace-v1"
        or doc.get("operator_review") != REVIEW
        or doc.get("reference") != reference.model_dump(mode="json")
        or doc.get("contract_sha256") != contract_sha256
        or doc.get("native_policy_sha256") != policy_sha256
        or doc.get("executable_sha256") != owner.executable_sha256
        or type(doc.get("native_uid")) is not int
        or doc["native_uid"] != owner.native_uid
        or namespace.owner_uid != owner.client_uid
        or namespace.path.parent != Path(reference.canonical_directory)
        or doc.get("workspace_component_sha256") != component_sha(native_workspace)
        or doc.get("storage_component_sha256") != component_sha(workspace_files)
        or doc.get("workspace_semantics_sha256") != WORKSPACE_SEMANTICS
        or type(observation.get("files")) is not int
        or observation["files"] != MAX_ATTACHMENTS
        or type(observation.get("bytes_each")) is not int
        or observation["bytes_each"] != MAX_ATTACHMENT_BYTES
        or observation.get("aggregate_original_object_current") is not True
        or observation.get("namespace_identity_preserved") is not True
        or observation.get("controlled_files_removed") is not True
        or observation.get("namespace_retained") is not True
        or observation.get("native_database_bytes_read") is not False
        or not zero(observation.get("native_mutations"))
        or not zero(observation.get("zulip_requests"))
        or not isinstance(observation.get("evidence_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", observation["evidence_sha256"]) is None
    ):
        raise ValueError("workspace_original_namespace_qualification_changed")
    return namespace


def source_qualification(
    raw: bytes,
    config_raw: bytes,
    *,
    config_sha256: str,
    realm_id: str,
    realm_url: str,
    bot_user_id: int,
    allowed_channels: frozenset[int],
    allowed_users: frozenset[int],
) -> SSHAssociationConfig:
    config = SSHAssociationConfig.model_validate(strict_loads(config_raw))
    doc = object_data(strict_loads(raw))
    positive = object_data(doc.get("positive"))
    negatives = doc.get("negatives")
    if (
        doc.get("format") != "qualified-original-source-uploads-v1"
        or doc.get("operator_review") != REVIEW
        or (doc.get("realm_id"), doc.get("realm_url"), doc.get("bot_user_id"))
        != (realm_id, realm_url, bot_user_id)
        or (config.realm_id, config.realm_url) != (realm_id, realm_url)
        or not config.channel_ids <= allowed_channels
        or doc.get("config_sha256") != config_sha256
        or hashlib.sha256(config_raw).hexdigest() != config_sha256
        or doc.get("transport_component_sha256") != component_sha(upload_associations)
        or doc.get("helper_sha256") != config.helper_sha256
        or doc.get("remote_policy_sha256") != config.remote_policy_sha256
        or doc.get("installed_evidence_sha256") != config.installed_evidence_sha256
        or type(positive.get("author_id")) is not int
        or positive["author_id"] not in allowed_users
        or positive["author_id"] == bot_user_id
        or type(positive.get("channel_id")) is not int
        or positive["channel_id"] not in config.channel_ids
        or type(positive.get("message_id")) is not int
        or positive["message_id"] <= 0
        or type(positive.get("upload_count")) is not int
        or not 1 <= positive["upload_count"] <= MAX_ATTACHMENTS
        or positive.get("mode") != "human-source"
        or positive.get("is_bot") is not False
        or positive.get("transaction_read_only") is not True
        or positive.get("original_association_current") is not True
        or not isinstance(positive.get("source_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", positive["source_sha256"]) is None
        or not isinstance(negatives, dict)
        or set(negatives) != SOURCE_NEGATIVES
        or any(negatives[key] is not True for key in SOURCE_NEGATIVES)
    ):
        raise ValueError("workspace_original_source_qualification_changed")
    return config
