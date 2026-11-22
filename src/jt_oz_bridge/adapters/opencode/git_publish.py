"""GET-only Git readings for commit/push previews, on the qualified review reader.

Each part is one complete `V2NativeGitReview.read` (its doubled Native bundle,
owner, policy and physical-directory checks). The parts are not one repository
transaction: a confirmation compares a fresh reading with the previewed one.
"""

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.git_review import explicit_base
from jt_oz_bridge.domain.git_publish import Compare, GitFile, GitPublishState, safe_remote
from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitReviewReader
from jt_oz_bridge.domain.models import SessionRef


def files(rows: tuple[NativeDiffSummary, ...]) -> tuple[GitFile, ...]:
    return tuple(
        GitFile(
            path=row.path,
            status=row.status,
            additions=row.additions,
            deletions=row.deletions,
            patch_sha256=row.patch_sha256,
        )
        for row in rows
    )


class V2GitPublishState:
    def __init__(self, review: NativeGitReviewReader) -> None:
        self.review = review

    def qualified(self, ref: SessionRef) -> bool:
        return self.review.qualified(ref)

    async def read(
        self, ref: SessionRef, *, remote: str, compare: Compare, base: str | None = None
    ) -> GitPublishState:
        safe_remote(remote)
        if compare != "fixed" and base is not None:
            raise ContractError("git_publish_base_only_for_fixed_comparison")
        if base is not None:
            explicit_base(base)
        working = await self.review.read(ref, mode="working")
        branch = working.current_branch
        tracking = f"{remote}/{branch}" if branch is not None else None
        present = False
        if tracking is not None:
            listed = await self.review.read(ref, mode="working", search=tracking, limit=50)
            present = tracking in listed.branches and listed.current_branch == branch
        comparison: str | None
        if compare == "fixed":
            comparison = None if base == tracking and not present else base
        elif present:
            comparison = tracking
        elif (
            compare == "auto"
            and working.inferred_base is not None
            and working.inferred_base.name != branch
        ):
            comparison = explicit_base(working.inferred_base.ref)
        else:
            comparison = None
        ahead = None
        ahead_hidden = 0
        if comparison is not None:
            committed = await self.review.read(ref, mode="committed", base=comparison)
            if committed.current_branch != branch:
                raise ContractError("git_publish_branch_changed_during_reading")
            ahead, ahead_hidden = files(committed.files), committed.hidden_files
        return GitPublishState(
            reference=ref,
            branch=branch,
            files=files(working.files),
            hidden_files=working.hidden_files,
            conflict_files=working.conflict_files,
            remote=remote,
            tracking_present=present,
            comparison=comparison,
            ahead=ahead,
            ahead_hidden=ahead_hidden,
        )
