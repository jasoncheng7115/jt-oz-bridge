"""Operator-reviewed installed Git evidence; no execution or self-enrollment.

Root packets are deployment trust inputs. Original Human check journals and
current VIEW authorization remain mandatory at query time. Nothing here reads
workspace content, runs a binary, upgrades Git or grants mutation authority.
"""

import hashlib
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, StrictBool, model_validator

from jt_oz_bridge.adapters.opencode.directory_scope import DirectoryScopeRoot
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEnrollment, HostOwnerEvidence
from jt_oz_bridge.domain.checks import CheckCatalog, CheckObservation
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.directory_scope import directory_project_key
from jt_oz_bridge.domain.git_evidence import RootReviewedGitEvidencePin, parse_git_evidence
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.security.root_files import pinned_root_bytes
from jt_oz_bridge.storage.durable import digest

SCRIPT = Path("/opt/jt-oz-bridge/git-inspect225.py")
REGISTRY = Path("/etc/jt-oz-bridge/git-inspect225.json")
CASES = frozenset(
    {
        "sha1-v2",
        "sha1-v3",
        "sha256-v2",
        "sha256-v3",
        "complete-head",
        "complete-index",
        "count-overflow-denied",
        "byte-overflow-denied",
        "config-drift-denied",
        "physical-alias-denied",
        "aggregate-deadline",
        "transport-disabled",
        "no-lazy-fetch-flag",
        "native-policy-denied",
        "original-check-identity",
        "repository-unchanged",
    }
)


class GitEvidenceAsset(ControlModel):
    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def read(self) -> bytes:
        return pinned_root_bytes(self.path, self.sha256)


class GitEvidenceInstalledObservation(ControlModel):
    format: Literal["installed-original-git-evidence-observation-v1"]
    passed: StrictBool
    reference: SessionRef
    installation_semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owners: tuple[HostOwnerEvidence, HostOwnerEvidence]
    checks: tuple[CheckObservation, CheckObservation]
    cases: dict[str, StrictBool] = Field(min_length=len(CASES), max_length=len(CASES))
    repository_unchanged: StrictBool
    native_database_bytes_read: StrictBool
    formal_acceptance: StrictBool

    @model_validator(mode="after")
    def complete(self) -> "GitEvidenceInstalledObservation":
        if (
            not self.passed
            or set(self.cases) != CASES
            or not all(self.cases.values())
            or not self.repository_unchanged
            or self.native_database_bytes_read
            or self.formal_acceptance
        ):
            raise ValueError("git_evidence_complete_installed_observation_required")
        return self


class GitEvidenceInstallPacket(ControlModel):
    format: Literal["installed-original-git-evidence-qualification-v1"]
    passed: StrictBool
    pin: RootReviewedGitEvidencePin
    script: GitEvidenceAsset
    registry: GitEvidenceAsset
    python_binary: GitEvidenceAsset
    git_binary: GitEvidenceAsset
    plugin_policy: GitEvidenceAsset
    observation: GitEvidenceAsset
    directory_enrollment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    physical_root: DirectoryScopeRoot


def _config_asset(asset: GitEvidenceAsset) -> bytes:
    if not asset.path.is_absolute() or not asset.path.is_relative_to("/etc/jt-oz-bridge"):
        raise ValueError("git_evidence_config_asset_scope_required")
    return asset.read()


def _binary(asset: GitEvidenceAsset) -> bytes:
    if not asset.path.is_absolute() or not any(
        asset.path.is_relative_to(base)
        for base in ("/usr/bin", "/usr/local/bin", "/opt/jt-oz-tools")
    ):
        raise ValueError("git_evidence_root_binary_scope_required")
    raw = asset.read()
    if not raw.startswith(b"\x7fELF"):
        raise ValueError("git_evidence_original_elf_required")
    return raw


def python_command_target() -> Path:
    """The helper independently rechecks its actual Native interpreter at run time."""
    return Path("/usr/bin/python3").resolve(strict=True)


def qualify_git_evidence(
    raw: bytes,
    *,
    reference: SessionRef,
    catalog: CheckCatalog,
    contract_sha256: str,
    check_qualification_sha256: str,
    native_policy_sha256: str,
    owner: HostOwnerEnrollment,
    physical_root: DirectoryScopeRoot,
    directory_enrollment_sha256: str,
) -> RootReviewedGitEvidencePin:
    """Normalize a full installed packet, including assets even when disabled.

    Hashes and observations do not authenticate themselves: only the existing
    root-managed manifest may select this reviewed packet. No successful packet
    is manufactured by the runtime, live responses or these normalization rules.
    """
    packet = GitEvidenceInstallPacket.model_validate(strict_loads(raw))
    pin = packet.pin
    if (
        not packet.passed
        or pin.reference != reference
        or pin.contract_sha256 != contract_sha256
        or pin.native_policy_sha256 != native_policy_sha256
        or pin.qualification_sha256 != check_qualification_sha256
        or catalog.reference != reference
        or catalog.contract_sha256 != contract_sha256
        or pin.check not in catalog.checks
        or digest(catalog.model_dump(mode="json")) != pin.catalog_sha256
        or packet.physical_root != physical_root
        or physical_root.directory != reference.canonical_directory
        or physical_root.project_key != directory_project_key(reference)
        or physical_root.uid != owner.native_uid
        or (owner.backend_id, owner.backend_identity)
        != (reference.backend_id, reference.backend_identity)
        or packet.directory_enrollment_sha256 != directory_enrollment_sha256
        or pin.physical_scope_sha256 != digest(physical_root.model_dump(mode="json"))
        or packet.script.path != SCRIPT
        or packet.script.sha256 != pin.script_sha256
        or packet.registry.path != REGISTRY
        or packet.python_binary.sha256 != pin.python_binary_sha256
        or packet.git_binary.sha256 != pin.git_binary_sha256
        or packet.plugin_policy.sha256 != pin.plugin_policy_sha256
        or packet.observation.sha256 != pin.installed_qualification_sha256
    ):
        raise ValueError("git_evidence_original_installation_scope_changed")
    script = packet.script.read()
    if hashlib.sha256(script).hexdigest() != pin.script_sha256:
        raise ValueError("git_evidence_installed_script_changed")
    _binary(packet.python_binary)
    _binary(packet.git_binary)
    if python_command_target() != packet.python_binary.path:
        raise ValueError("git_evidence_original_python_command_changed")
    registry = strict_loads(_config_asset(packet.registry))
    if (
        not isinstance(registry, dict)
        or set(registry) != {"format", "script_sha256", "python", "git", "scopes"}
        or registry["format"] != "git-inspect225-root-v1"
        or registry["script_sha256"] != pin.script_sha256
        or registry["python"]
        != {
            "path": str(packet.python_binary.path),
            "sha256": pin.python_binary_sha256,
            "version": pin.python_version,
        }
        or registry["git"]
        != {
            "path": str(packet.git_binary.path),
            "sha256": pin.git_binary_sha256,
            "version": pin.git_version,
        }
        or not isinstance(registry["scopes"], dict)
        or not 1 <= len(registry["scopes"]) <= 64
    ):
        raise ValueError("git_evidence_original_registry_changed")
    entry = registry["scopes"].get(pin.scope_sha256)
    if (
        not isinstance(entry, dict)
        or set(entry)
        != {
            "reference",
            "cwd",
            "git_dir",
            "common_dir",
            "object_dir",
            "home",
            "index_uid",
            "configs",
            "qualification",
        }
        or entry["reference"] != reference.model_dump(mode="json")
        or type(entry["index_uid"]) is not int
        or entry["index_uid"] != owner.native_uid
        or entry["cwd"]
        != {
            "path": physical_root.directory,
            "dev": physical_root.device,
            "ino": physical_root.inode,
            "uid": physical_root.uid,
            "gid": physical_root.gid,
            "mode": physical_root.mode,
        }
        or entry["qualification"]
        != {
            key: getattr(pin, key)
            for key in (
                "physical_scope_sha256",
                "native_policy_sha256",
                "plugin_policy_sha256",
                "installed_qualification_sha256",
            )
        }
    ):
        raise ValueError("git_evidence_original_registry_scope_changed")
    _directory_identity(entry["cwd"])
    # The Native helper checks every directory/config FD and its drift. Here we
    # validate the complete declared schema without reading Native's workspace.
    for key in ("git_dir", "common_dir", "object_dir", "home"):
        _directory_identity(entry[key])
    if (
        entry["object_dir"]["path"] != entry["common_dir"]["path"] + "/objects"
        or not isinstance(entry["configs"], dict)
        or set(entry["configs"]) != {"system", "xdg", "global", "local"}
        or not isinstance(entry["configs"]["local"], dict)
        or entry["configs"]["local"].get("path") != entry["common_dir"]["path"] + "/config"
    ):
        raise ValueError("git_evidence_original_config_scope_changed")
    for key, value in entry["configs"].items():
        if value is None and key != "local":
            continue
        if not isinstance(value, dict) or set(value) != {
            "path",
            "dev",
            "ino",
            "uid",
            "gid",
            "mode",
            "sha256",
        }:
            raise ValueError("git_evidence_original_config_scope_changed")
        _directory_identity({k: v for k, v in value.items() if k != "sha256"})
        if (
            not isinstance(value["sha256"], str)
            or len(value["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in value["sha256"])
        ):
            raise ValueError("git_evidence_original_config_scope_changed")
    plugin = strict_loads(_config_asset(packet.plugin_policy))
    if (
        plugin
        != {
            "format": "git-evidence-reviewed-plugin-policy-v1",
            "reviewed": True,
            "reference": reference.model_dump(mode="json"),
            "native_policy_sha256": native_policy_sha256,
            "script_sha256": pin.script_sha256,
            "check_command_sha256": hashlib.sha256(pin.check.command.encode()).hexdigest(),
        }
        or type(plugin.get("reviewed")) is not bool
    ):
        raise ValueError("git_evidence_original_plugin_policy_changed")
    observed = GitEvidenceInstalledObservation.model_validate(
        strict_loads(_config_asset(packet.observation))
    )
    if observed.installation_semantic_sha256 != installation_semantics(packet, registry):
        raise ValueError("git_evidence_installed_registry_or_pins_changed")
    if (
        observed.reference != reference
        or observed.owners[0].owner_epoch != observed.owners[1].owner_epoch
    ):
        raise ValueError("git_evidence_installed_original_owner_changed")
    for identity in observed.owners:
        for key in (
            "backend_id",
            "backend_identity",
            "unit",
            "unit_sha256",
            "native_uid",
            "version",
            "url",
            "executable_sha256",
            "dataset_device",
            "dataset_inode",
        ):
            if getattr(identity, key) != getattr(owner, key):
                raise ValueError("git_evidence_installed_original_owner_changed")
    samples = []
    for check in observed.checks:
        if (
            check.reference != reference
            or check.check != pin.check
            or check.qualification_sha256 != pin.qualification_sha256
            or check.outcome != "passed"
            or check.output_truncated
        ):
            raise ValueError("git_evidence_original_check_observation_required")
        sample = parse_git_evidence(check.output, pin=pin)
        if (
            check.completed_at is None
            or not observed.owners[0].observed_at
            <= check.started_at / 1000
            <= sample.capture_started_at
            <= sample.capture_finished_at
            <= check.completed_at / 1000
            <= observed.owners[1].observed_at
        ):
            raise ValueError("git_evidence_original_capture_outside_owner_or_shell")
        samples.append(sample)
    # Two separate original checks must show the same complete semantic state.
    if (
        observed.checks[0].action_id == observed.checks[1].action_id
        or observed.checks[0].shell_id == observed.checks[1].shell_id
        or observed.checks[0].completed_at is None
        or observed.checks[0].completed_at > observed.checks[1].started_at
        or any(
            getattr(samples[0], k) != getattr(samples[1], k)
            for k in (
                "object_format",
                "branch_safe_label",
                "head_oid",
                "head_tree_oid",
                "index_sha256",
                "index_semantic_sha256",
                "index_tree_oid",
                "index_entries",
                "staged_paths",
                "remote_aliases",
            )
        )
    ):
        raise ValueError("git_evidence_two_complete_installed_samples_required")
    return pin


def installation_semantics(packet: GitEvidenceInstallPacket, registry: dict[str, Any]) -> str:
    """Bind all installation facts without a self-referential evidence hash.

    The installed-observation hash is only an attribution backlink. Exclude that
    one field from each declared scope and the pin; retain every other registry
    field, all paths, policies, binary versions and physical enrollment facts.
    """
    normalized = dict(registry)
    normalized["scopes"] = {}
    for key, entry in registry["scopes"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("qualification"), dict):
            raise ValueError("git_evidence_complete_registry_required")
        normalized["scopes"][key] = entry | {
            "qualification": {
                k: v
                for k, v in entry["qualification"].items()
                if k != "installed_qualification_sha256"
            }
        }
    return digest(
        {
            "pin": packet.pin.model_dump(mode="json", exclude={"installed_qualification_sha256"}),
            "registry": normalized,
            "directory_enrollment_sha256": packet.directory_enrollment_sha256,
            "physical_root": packet.physical_root.model_dump(mode="json"),
            "python_path": str(packet.python_binary.path),
            "git_path": str(packet.git_binary.path),
        }
    )


def _directory_identity(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"path", "dev", "ino", "uid", "gid", "mode"}
        or not isinstance(value["path"], str)
        or not Path(value["path"]).is_absolute()
        or str(Path(value["path"])) != value["path"]
        or ".." in Path(value["path"]).parts
        or value["path"].startswith("//")
        or value["path"] == "/"
        or len(value["path"].encode("utf-8")) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in value["path"])
        or any(
            type(value[k]) is not int or value[k] < 0 for k in ("dev", "ino", "uid", "gid", "mode")
        )
        or value["ino"] == 0
        or value["mode"] > 0o7777
        or value["mode"] & 0o022
    ):
        raise ValueError("git_evidence_complete_physical_identity_required")
