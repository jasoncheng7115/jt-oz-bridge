"""Git commit/push from chat: a previewed state, one confirmed prompt, GET-only checks.

The bridge never runs Git. A confirmation becomes one ordinary prompt asking the
original session's agent to run one fixed command, under that agent's own rules.
Results are what the bridge reads back with `vcs.*` GETs, never the agent's text.

OpenCode 2.0.32 exposes no HEAD id, commit log, staged/unstaged split, conflict
state or remote server ref. What can and cannot be checked is listed in
docs/GIT_PUBLISH.md; the notice says the same.
"""

import re
import shlex
from typing import Literal, Protocol, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.workspace_paths import disclosed_path

GIT_PUBLISH = "git.publish"
CONFIRM_TOKEN = "git-publish-confirm"
MAX_PATHS = 50
MAX_MESSAGE = 500
REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
SHA = r"^[0-9a-f]{64}$"


def safe_branch(value: str) -> str:
    """A plain branch name: never a refspec (`+`, `:`), option, range or expression."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is None
        or value.endswith(("/", ".", ".lock"))
        or any(not part or part.startswith(".") for part in value.split("/"))
        or ".." in value
    ):
        raise ValueError("git_publish_plain_branch_required")
    return value


def safe_remote(value: str) -> str:
    if not isinstance(value, str) or REMOTE.fullmatch(value) is None or ".." in value:
        raise ValueError("git_publish_plain_remote_required")
    return value


def commit_message(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > MAX_MESSAGE
        or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value)
        or any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in value)
    ):
        raise ValueError("git_publish_single_line_message_required")
    return value


class GitFile(ControlModel):
    path: str = Field(min_length=1, max_length=4096)
    status: Literal["added", "deleted", "modified"]
    additions: StrictInt = Field(ge=0)
    deletions: StrictInt = Field(ge=0)
    patch_sha256: str = Field(pattern=SHA)

    @field_validator("path")
    @classmethod
    def disclosed(cls, value: str) -> str:
        return disclosed_path(value)


class GitPublishState(ControlModel):
    """One GET-only reading of the Root's repository, protected paths left out.

    `files` is HEAD → working copy. `ahead` is merge-base(comparison) → HEAD and is
    None without a comparison. Neither says which commit HEAD is.
    """

    reference: SessionRef
    branch: str | None = Field(default=None, max_length=255)
    files: tuple[GitFile, ...] = Field(max_length=1000)
    hidden_files: StrictInt = Field(ge=0, le=1000)
    conflict_files: StrictInt = Field(ge=0, le=1000)
    remote: str
    tracking_present: bool
    comparison: str | None = Field(default=None, max_length=255)
    ahead: tuple[GitFile, ...] | None = Field(default=None, max_length=1000)
    ahead_hidden: StrictInt = Field(default=0, ge=0, le=1000)
    projection: Literal["git-publish-state-v1"] = "git-publish-state-v1"

    @field_validator("remote")
    @classmethod
    def plain_remote(cls, value: str) -> str:
        return safe_remote(value)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.branch is not None:
            safe_branch(self.branch)
        if self.comparison is not None:
            safe_branch(self.comparison)
        if len({f.path for f in self.files}) != len(self.files) or (
            self.ahead is not None and len({f.path for f in self.ahead}) != len(self.ahead)
        ):
            raise ValueError("git_publish_duplicate_path")
        if (self.ahead is None) != (self.comparison is None) or (
            self.ahead is None and self.ahead_hidden
        ):
            raise ValueError("git_publish_comparison_shape_invalid")
        if self.tracking_present and self.branch is None:
            raise ValueError("git_publish_tracking_requires_branch")
        return self

    @property
    def tracking(self) -> str | None:
        return f"{self.remote}/{self.branch}" if self.branch is not None else None

    def changed(self) -> dict[str, GitFile]:
        return {f.path: f for f in self.files}

    def committed(self) -> dict[str, GitFile]:
        return {f.path: f for f in self.ahead or ()}


Compare = Literal["auto", "tracking", "fixed"]


class GitPublishReader(Protocol):
    """GET-only `vcs.*` readings of one enrolled Root; never a mutation or proof of HEAD.

    `compare` picks what `ahead` is measured against: "tracking" is
    `<remote>/<branch>` when the branch list shows it; "auto" is that, or else the
    inferred review base when it is not the current branch; "fixed" is `base`
    exactly (None when `base` is the missing tracking ref).
    """

    def qualified(self, ref: SessionRef) -> bool: ...

    async def read(
        self, ref: SessionRef, *, remote: str, compare: Compare, base: str | None = None
    ) -> GitPublishState: ...


def quote_all(values: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(value) for value in values)


class GitPublishPlan(ControlModel):
    """Exactly what a person previews; the agent command comes only from these fields."""

    kind: Literal["commit", "push"]
    directory: str = Field(min_length=1, max_length=4096)
    branch: str
    remote: str
    message: str | None = None
    paths: tuple[str, ...] = Field(default=(), max_length=MAX_PATHS)
    state_sha256: str = Field(pattern=SHA)

    @model_validator(mode="after")
    def exact_shape(self) -> Self:
        safe_branch(self.branch)
        safe_remote(self.remote)
        if not self.directory.startswith("/") or any(ord(c) < 32 for c in self.directory):
            raise ValueError("git_publish_absolute_directory_required")
        if self.kind == "commit":
            if self.message is None or not self.paths:
                raise ValueError("git_publish_commit_message_and_paths_required")
            commit_message(self.message)
            for path in self.paths:
                disclosed_path(path)
            if len(set(self.paths)) != len(self.paths) or list(self.paths) != sorted(self.paths):
                raise ValueError("git_publish_paths_must_be_unique_and_sorted")
        elif self.message is not None or self.paths:
            raise ValueError("git_publish_push_has_no_message_or_paths")
        return self

    @property
    def tracking(self) -> str:
        return f"{self.remote}/{self.branch}"

    def command(self) -> str:
        """Fixed shell text. Never --force, --no-verify, a refspec or a pathspec glob."""
        git = "git --literal-pathspecs -C " + shlex.quote(self.directory)
        if self.kind == "commit":
            assert self.message is not None
            files = quote_all(self.paths)
            return f"{git} add -- {files} && {git} commit -m {shlex.quote(self.message)} -- {files}"
        return f"{git} push {shlex.quote(self.remote)} {shlex.quote(self.branch)}"

    def prompt(self) -> str:
        """The one prompt text; it names the command and forbids anything else."""
        return (
            "[jt-oz-bridge] The person in this Zulip topic previewed and confirmed this Git "
            f"{self.kind}. Run exactly this one shell command once, unchanged:\n\n"
            f"{self.command()}\n\n"
            "Do not run any other command, edit files, retry, or add options such as "
            "--force or --no-verify. If you are not allowed to run shell commands, or the "
            "command fails, say so and stop. Reply with the command's output."
        )


class GitPublishRequest(ControlModel):
    """One durable confirmed Action; `source` is the `!confirm`, `preview` the command."""

    operation: Literal["git.publish"] = "git.publish"
    reference: SessionRef
    source: HumanMessage
    preview: HumanMessage
    plan: GitPublishPlan
    before: GitPublishState
    text: str = Field(min_length=1, max_length=65536)
    reply_locale: Literal["en", "zh-TW"]
    confirm_expires_at: float = Field(gt=0, allow_inf_nan=False)
    confirmation_token_sha256: str = Field(pattern=SHA)

    @model_validator(mode="after")
    def one_person_one_topic(self) -> Self:
        from jt_oz_bridge.security.admin import token_hash
        from jt_oz_bridge.storage.durable import digest

        opening = parse_input(self.preview.text, bound=True)
        confirmed = parse_input(self.source.text, bound=True)
        words = confirmed.arguments.split()
        messages = (self.preview, self.source)
        if (
            (opening.kind, opening.command) != ("command", "git")
            or opening.arguments.split()[:1] != [self.plan.kind]
            or (confirmed.kind, confirmed.command) != ("command", "confirm")
            or len(words) > 1
            or words
            and token_hash(words[0]) != self.confirmation_token_sha256
            or self.preview.message_id == self.source.message_id
            or any(m.is_bot or m.deleted or m.revision != 0 for m in messages)
            or len({(m.realm_id, m.channel_id, m.topic, m.author_id) for m in messages}) != 1
            or self.before.reference != self.reference
            or self.plan.directory != self.reference.canonical_directory
            or self.plan.state_sha256 != digest(self.before.model_dump(mode="json"))
            or self.text != self.plan.prompt()
        ):
            raise ValueError("git_publish_original_human_sources_and_plan_required")
        return self


Outcome = Literal["verified", "not_done", "not_verified"]


class GitPublishCheck(ControlModel):
    """One verified (or failed) fact, rendered from a fixed key and safe values."""

    key: str = Field(pattern=r"^[a-z_]{1,64}$")
    passed: bool
    values: dict[str, str] = Field(default_factory=dict, max_length=8)


class GitPublishVerification(ControlModel):
    outcome: Outcome
    checks: tuple[GitPublishCheck, ...] = Field(max_length=32)
    # Always listed, because 2.0.32 GET data cannot show them.
    unverifiable: tuple[str, ...] = Field(max_length=8)


class GitPublishResult(ControlModel):
    format: Literal["git-publish-result-v1"] = "git-publish-result-v1"
    action_id: str = Field(min_length=1, max_length=255)
    operation_digest: str = Field(pattern=SHA)
    turn_outcome: Literal["succeeded", "failed", "interrupted"]
    turn_user_id: str = Field(min_length=1, max_length=255)
    after: GitPublishState
    verification: GitPublishVerification
    verified_at: float = Field(ge=0, allow_inf_nan=False)


def _check(key: str, passed: bool, **values: str) -> GitPublishCheck:
    return GitPublishCheck(key=key, passed=passed, values=values)


def verify(
    plan: GitPublishPlan, before: GitPublishState, after: GitPublishState
) -> GitPublishVerification:
    """Compare two GET readings. Only facts both readings show are claimed."""
    if plan.kind == "commit":
        return _verify_commit(plan, before, after)
    return _verify_push(plan, before, after)


def _verify_commit(
    plan: GitPublishPlan, before: GitPublishState, after: GitPublishState
) -> GitPublishVerification:
    unverifiable = ("commit_id", "commit_message", "commit_count")
    old, new = before.changed(), after.changed()
    selected = set(plan.paths)
    others_kept = (
        before.hidden_files == after.hidden_files
        and all(new.get(p) == old[p] for p in old if p not in selected)
        and not set(new) - set(old)
    )
    checks = [
        _check("same_branch", after.branch == plan.branch, branch=plan.branch),
        _check("other_changes_kept", others_kept),
    ]
    left = [p for p in sorted(selected) if p in new]
    if (
        after.branch == plan.branch
        and all(new.get(p) == old[p] for p in selected)
        and after.comparison == before.comparison
        and after.ahead == before.ahead
        and after.ahead_hidden == before.ahead_hidden
    ):
        # The previewed files are exactly as they were and HEAD shows no change.
        return GitPublishVerification(
            outcome="not_done",
            checks=(*checks, _check("files_committed", False, count=str(len(selected)))),
            unverifiable=unverifiable,
        )
    checks.append(_check("files_no_longer_changed", not left, count=str(len(selected) - len(left))))
    if before.comparison is None or after.comparison != before.comparison:
        # Gone from the working diff could also mean discarded. Say HEAD is unseen.
        checks.append(_check("head_unseen", False))
        return GitPublishVerification(
            outcome="not_verified", checks=tuple(checks), unverifiable=unverifiable
        )
    was, now = before.committed(), after.committed()
    exact = all(
        p in now
        and now[p] != was.get(p)
        and (p in was or now[p].patch_sha256 == old[p].patch_sha256)
        for p in selected
    )
    others = (
        before.ahead_hidden == after.ahead_hidden
        and all(now.get(p) == was[p] for p in was if p not in selected)
        and not set(now) - set(was) - selected
    )
    checks.append(_check("head_contains_preview", exact, comparison=before.comparison))
    checks.append(_check("head_other_files_unchanged", others))
    outcome: Outcome = "verified" if all(c.passed for c in checks) else "not_verified"
    return GitPublishVerification(outcome=outcome, checks=tuple(checks), unverifiable=unverifiable)


def _verify_push(
    plan: GitPublishPlan, before: GitPublishState, after: GitPublishState
) -> GitPublishVerification:
    unverifiable = ("remote_server_ref", "commit_id", "fast_forward")
    checks = [
        _check("same_branch", after.branch == plan.branch, branch=plan.branch),
        _check(
            "working_copy_unchanged",
            after.files == before.files and after.hidden_files == before.hidden_files,
        ),
    ]
    caught_up = (
        after.tracking_present
        and after.comparison == plan.tracking
        and after.ahead == ()
        and after.ahead_hidden == 0
    )
    checks.append(_check("tracking_has_head", caught_up, ref=plan.tracking))
    if not caught_up and (
        before.tracking_present,
        before.comparison,
        before.ahead,
        before.ahead_hidden,
    ) == (after.tracking_present, after.comparison, after.ahead, after.ahead_hidden):
        return GitPublishVerification(
            outcome="not_done", checks=tuple(checks), unverifiable=unverifiable
        )
    outcome: Outcome = "verified" if all(c.passed for c in checks) else "not_verified"
    return GitPublishVerification(outcome=outcome, checks=tuple(checks), unverifiable=unverifiable)
