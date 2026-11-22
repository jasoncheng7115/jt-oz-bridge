"""Bounded historical ApprovedCheck projection, never Git mutation authority."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from jt_oz_bridge.domain.checks import ApprovedCheck
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.workspace_paths import disclosed_path

Sha = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
Label = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"
    ),
]
Timestamp = Annotated[StrictFloat | StrictInt, Field(ge=0, le=2**53, allow_inf_nan=False)]


class RootReviewedGitEvidencePin(ControlModel):
    """Root-only enrollment input, not self-authenticating Human/Native proof.

    The runtime loader must establish all these pins from reviewed installed
    script, binary, physical scope, plugin and original-check qualification.
    A matching check ID alone cannot enable this projection.
    """

    reference: SessionRef
    check: ApprovedCheck
    catalog_sha256: Sha
    contract_sha256: Sha
    qualification_sha256: Sha
    scope_sha256: Sha
    script_sha256: Sha
    script_version: Literal["git-inspect225-v1"]
    python_binary_sha256: Sha
    python_version: Label
    git_binary_sha256: Sha
    # Vanilla Git may read includes before `config --no-includes` takes effect.
    # A version label is not qualification; exact reviewed binary/source and
    # original-check receipts remain mandatory for this dedicated build.
    git_version: Literal["2.56.0.jtoz-metadata1"]
    physical_scope_sha256: Sha
    native_policy_sha256: Sha
    plugin_policy_sha256: Sha
    installed_qualification_sha256: Sha

    @model_validator(mode="after")
    def exact_command(self) -> "RootReviewedGitEvidencePin":
        expected_scope = hashlib.sha256(
            json.dumps(
                self.reference.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        if self.scope_sha256 != expected_scope:
            raise ValueError("git_evidence_full_reference_scope_digest_required")
        if self.check.command != (
            "/usr/bin/python3 -I -B /opt/jt-oz-bridge/git-inspect225.py --scope "
            + self.scope_sha256
        ):
            raise ValueError("git_evidence_exact_reviewed_command_required")
        return self


class StagedPath(ControlModel):
    safe_relative_path: str = Field(strict=True, min_length=1, max_length=4096)
    change: Literal["added", "modified", "deleted", "type_changed"]
    mode: Literal["100644", "100755", "120000", "160000"]

    @field_validator("safe_relative_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        if any(c in value for c in "<>@&[]`"):
            raise ValueError("git_evidence_path_not_safe_for_projection")
        return disclosed_path(value)


class RemoteAlias(ControlModel):
    safe_alias: Label
    push_config_sha256: Sha


class GitIndexEvidence(ControlModel):
    format: Literal["native-git-index-evidence-v1"]
    scope_sha256: Sha
    capture_started_at: Timestamp
    capture_finished_at: Timestamp
    git_binary_sha256: Sha
    script_sha256: Sha
    object_format: Literal["sha1", "sha256"]
    branch_safe_label: Label | None
    head_oid: str = Field(strict=True)
    head_tree_oid: str = Field(strict=True)
    index_sha256: Sha
    index_semantic_sha256: Sha
    index_tree_oid: str = Field(strict=True)
    index_entries: StrictInt = Field(ge=0, le=4096)
    staged_paths: tuple[StagedPath, ...] = Field(max_length=4096)
    remote_aliases: tuple[RemoteAlias, ...] = Field(max_length=8)
    complete_index: StrictBool
    remote_live_verified: Literal[False]
    working_tree_content_verified: Literal[False]

    @field_validator("remote_live_verified", "working_tree_content_verified", mode="before")
    @classmethod
    def strict_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("git_evidence_literal_false_required")
        return False

    @model_validator(mode="after")
    def bounded_complete(self) -> "GitIndexEvidence":
        import re

        size = 40 if self.object_format == "sha1" else 64
        if any(
            re.fullmatch(r"[0-9a-f]{" + str(size) + "}", x) is None
            for x in (self.head_oid, self.head_tree_oid, self.index_tree_oid)
        ):
            raise ValueError("git_evidence_object_format_changed")
        if (
            not self.complete_index
            or not 0 <= self.capture_finished_at - self.capture_started_at <= 5
        ):
            raise ValueError("git_evidence_incomplete_or_capture_window_invalid")
        paths = [p.safe_relative_path for p in self.staged_paths]
        aliases = [r.safe_alias for r in self.remote_aliases]
        if len(set(paths)) != len(paths) or len(set(aliases)) != len(aliases):
            raise ValueError("git_evidence_duplicate_path_or_alias")
        if sum(len(p.encode("utf-8")) for p in paths) > 32768:
            raise ValueError("git_evidence_staged_names_capacity")
        # Deleted paths are absent from the resulting index; no incorrect
        # len(staged_paths) <= index_entries assumption is made.
        return self


class GitEvidenceView(ControlModel):
    format: Literal["historical-git-check-view-v1"] = "historical-git-check-view-v1"
    action_id: str = Field(strict=True, min_length=1, max_length=36)
    result_sha256: Sha
    preflight_sha256: Sha
    evidence: GitIndexEvidence
    historical: Literal[True] = True
    current_index_verified: Literal[False] = False
    mutation_confirmation_usable: Literal[False] = False


def parse_git_evidence(output: str, *, pin: RootReviewedGitEvidencePin) -> GitIndexEvidence:
    """Accept one entire bounded JSON document; never return raw stdout/errors."""
    pin = RootReviewedGitEvidencePin.model_validate(pin.model_dump(mode="python"))
    if type(output) is not str or not 1 <= len(output.encode("utf-8")) <= 65536:
        raise ValueError("git_evidence_output_capacity")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("git_evidence_duplicate_json_key")
            result[key] = value
        return result

    def constant(value: str) -> object:
        raise ValueError("git_evidence_nonfinite_json")

    try:
        data = json.loads(output, object_pairs_hook=pairs, parse_constant=constant)
        evidence = GitIndexEvidence.model_validate(data)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("git_evidence_invalid_document") from None
    if (evidence.scope_sha256, evidence.script_sha256, evidence.git_binary_sha256) != (
        pin.scope_sha256,
        pin.script_sha256,
        pin.git_binary_sha256,
    ):
        raise ValueError("git_evidence_installed_scope_or_script_changed")
    return evidence
