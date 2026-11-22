"""Bounded allowlisted Native review metadata, never raw patches or authority."""

from typing import Literal

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitReview, SavedWorktree
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text


def visible(value: str, maximum: int = 80) -> str:
    """Redact before truncating, and bound the escaped representation itself."""
    text = sanitize_controls(value)[0].replace("\n", " ").replace("\t", " ")
    text, _ = redact_text(text)
    if len(literal(text)) <= maximum:
        return literal(text)
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if len(literal(text[:mid])) + 1 <= maximum:
            low = mid
        else:
            high = mid - 1
    return literal(text[:low]) + "…"


def count(value: int) -> str:
    return str(value) if value <= 999999 else "999999+"


def render_git_review(
    snapshot: NativeGitReview,
    verb: Literal["context", "branches", "worktrees", "review"],
    locale: Locale,
    *,
    message_limit: int,
    search: str = "",
) -> str:
    if type(message_limit) is not int or not 512 <= message_limit <= 1000000:
        raise ValueError("git_review_message_limit_invalid")
    if not isinstance(snapshot, NativeGitReview) or verb not in {
        "context",
        "branches",
        "worktrees",
        "review",
    }:
        raise ValueError("git_review_projection_required")
    # Defend direct/model_copy callers before traversing their collections. The
    # command service separately validates every field and its live provenance.
    if (
        snapshot.projection != "native-review-metadata-v1"
        or snapshot.saved_inventory_only is not True
        or any(
            type(items) is not tuple or len(items) > bound
            for items, bound in (
                (snapshot.branches, 50),
                (snapshot.saved_worktrees, 128),
                (snapshot.files, 1000),
            )
        )
        or any(
            value is not False
            for value in (
                snapshot.full_diff_display,
                snapshot.index_verified,
                snapshot.head_verified,
                snapshot.remote_verified,
                snapshot.clean_verified,
                snapshot.worktree_switch_usable,
                snapshot.mutation_confirmation_usable,
            )
        )
    ):
        raise ValueError("git_review_metadata_only_required")
    tr = Translator()
    title = tr.render("git_review.title." + verb, locale)
    footer = tr.render("git_review.scope", locale)
    omitted = tr.render("git_review.truncated", locale)
    rows: list[str] = []
    if verb == "context":
        for field, value in (
            ("provider", snapshot.provider),
            ("branch", snapshot.current_branch),
            ("default", snapshot.default_branch),
            ("base", snapshot.inferred_base.name if snapshot.inferred_base else None),
        ):
            rows.append(
                tr.render(
                    "git_review." + field,
                    locale,
                    value=(
                        visible(value)
                        if value is not None
                        else tr.render("git.not_reported", locale)
                    ),
                )
            )
        rows.append(tr.render("git_review.base_hint", locale))
    elif verb == "branches":
        rows.extend("• " + visible(value, 120) for value in snapshot.branches)
        if not snapshot.branches_complete:
            rows.append(tr.render("git_review.partial", locale))
    elif verb == "worktrees":
        rows.append(tr.render("git_review.inventory", locale))
        rows.extend(
            "• "
            + (
                visible(
                    SavedWorktree(relative_directory=item.relative_directory).relative_directory,
                    120,
                )
                if item.relative_directory
                else tr.render("git_review.bound_root", locale)
            )
            for item in snapshot.saved_worktrees
            if not search or search.casefold() in item.relative_directory.casefold()
        )
        if snapshot.hidden_worktrees:
            rows.append(tr.render("git_review.protected", locale))
    else:
        rows.append(tr.render("git_review.comparison." + snapshot.mode, locale))
        if snapshot.requested_base is not None:
            rows.append(
                # Reserve room for the first disclosed path, complete digest
                # and disclaimer even at the minimum cap. Only the display
                # prefix is shortened; the original comparison stays intact.
                tr.render(
                    "git_review.base",
                    locale,
                    value=visible(snapshot.requested_base, min(80, 24 + message_limit - 512)),
                )
            )
        # Revalidate just the displayed nested projection, including callers
        # using model_copy. No full DTO or original SessionRef is serialized.
        files = tuple(
            NativeDiffSummary(
                path=item.path,
                additions=item.additions,
                deletions=item.deletions,
                status=item.status,
                patch_sha256=item.patch_sha256,
                patch_bytes=item.patch_bytes,
            )
            for item in snapshot.files
        )
        rows.extend(
            "• "
            + visible(item.path, 48)
            + " · "
            + tr.render("git.change." + item.status, locale)
            + f" +{count(item.additions)}/−{count(item.deletions)} · {item.patch_sha256}"
            for item in files
        )
        if snapshot.hidden_files:
            rows.append(tr.render("git_review.protected", locale))
    if not rows:
        rows.append(tr.render("git_review.empty", locale))
    # Budget the actual safe wire representation, not text which the outbox
    # will later expand. Separate paragraphs keep a long summary from becoming
    # a code fallback that displays numeric entities as literal text.
    limit = message_limit - 100
    renderer = MobileMarkdown(locale=locale)

    def paragraph(text: str) -> str:
        rendered = renderer.render(text, message_limit, reserved_characters=100)
        if len(rendered.pages) != 1 or rendered.source_fallback_blocks:
            raise ValueError("git_review_safe_paragraph_required")
        return rendered.pages[0]

    title, footer, omitted = map(paragraph, (title, footer, omitted))
    chosen, used = [title], len(title) + len(footer) + 2
    for index, row in enumerate(rows):
        row = paragraph(row)
        # The final row needs no hypothetical "more omitted" paragraph.
        # Earlier rows retain that space so an actual omitted tail is explicit.
        tail_reserve = len(omitted) + 2 if index + 1 < len(rows) else 0
        if used + len(row) + 2 + tail_reserve > limit:
            chosen.append(omitted)
            break
        chosen.append(row)
        used += len(row) + 2
    result = "\n\n".join([*chosen, footer])
    if len(result) > limit:
        raise ValueError("git_review_fixed_text_exceeds_budget")
    again = renderer.render(result, message_limit, reserved_characters=100)
    if again.pages != (result,) or again.source_fallback_blocks:
        raise ValueError("git_review_safe_roundtrip_required")
    return result
