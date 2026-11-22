"""Bounded historical metadata pages; no raw command, URL or authority permit."""

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.git_evidence import GitEvidenceView
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text


def fragments(value: str) -> tuple[str, ...]:
    """Redact the complete value first; split escaped text without losing names."""
    text = redact_text(sanitize_controls(value)[0])[0]
    chunks, current = [], ""
    for char in text:
        escaped = literal(char)
        if current and len(current) + len(escaped) > 64:
            chunks.append(current)
            current = ""
        current += escaped
    if current:
        chunks.append(current)
    return tuple(chunks) or ("—",)


def evidence_rows(view: GitEvidenceView, locale: Locale) -> tuple[str, ...]:
    view = GitEvidenceView.model_validate(view.model_dump(mode="json"))
    value, tr = view.evidence, Translator()
    rows = [
        tr.render("git_evidence.branch", locale),
        tr.render("git_evidence.head", locale, value=value.head_oid),
        tr.render("git_evidence.tree", locale, value=value.index_tree_oid),
        tr.render(
            "git_evidence.counts",
            locale,
            entries=value.index_entries,
            paths=len(value.staged_paths),
        ),
    ]
    rows[1:1] = list(fragments(value.branch_safe_label or "—"))
    for number, entry in enumerate(value.staged_paths, 1):
        rows.append(
            tr.render(
                "git_evidence.entry",
                locale,
                number=number,
                change=tr.render("git_evidence.change." + entry.change, locale),
                mode=entry.mode,
            )
        )
        for part, chunk in enumerate(fragments(entry.safe_relative_path), 1):
            rows.append(f"{number}.{part}: {chunk}")
    if not value.staged_paths:
        rows.append(tr.render("git_evidence.empty", locale))
    for number, remote in enumerate(value.remote_aliases, 1):
        rows.append(tr.render("git_evidence.remote", locale, number=number))
        rows.extend(
            f"{number}.{part}: {chunk}"
            for part, chunk in enumerate(fragments(remote.safe_alias), 1)
        )
        rows.append(
            tr.render("git_evidence.remote_digest", locale, value=remote.push_config_sha256)
        )
    return tuple(rows)


def render_git_evidence_page(
    view: GitEvidenceView, locale: Locale, *, offset: int, message_limit: int
) -> tuple[str, int | None]:
    if type(message_limit) is not int or not 512 <= message_limit <= 1000000:
        raise ValueError("git_evidence_message_limit_required")
    rows = evidence_rows(view, locale)
    if type(offset) is not int or not 0 <= offset < len(rows):
        raise ValueError("git_evidence_page_offset_required")
    tr = Translator()
    title = tr.render("git_evidence.title", locale, action=view.action_id)
    scope = tr.render("git_evidence.scope", locale)
    # Reserve the longest action/token navigation AND Bridge envelope. No row
    # is dropped to fit, and pagination never implies a complete current index.
    reserve = len(tr.render("git_evidence.next", locale, action="_" * 36, token="_" * 32)) + 104
    renderer = MobileMarkdown(locale=locale)

    def paragraph(text: str) -> str:
        rendered = renderer.render(text, message_limit, reserved_characters=reserve)
        if len(rendered.pages) != 1 or rendered.source_fallback_blocks:
            raise ValueError("git_evidence_safe_paragraph_required")
        return rendered.pages[0]

    title, scope = paragraph(title), paragraph(scope)
    chosen: list[str] = []
    cursor = offset
    while cursor < len(rows):
        row = paragraph(rows[cursor])
        candidate = "\n\n".join([title, *chosen, row, scope])
        if len(candidate) + reserve > message_limit:
            break
        chosen.append(row)
        cursor += 1
    if not chosen:
        raise ValueError("git_evidence_one_row_must_fit")
    body = "\n\n".join([title, *chosen, scope])
    checked = renderer.render(body, message_limit, reserved_characters=reserve)
    if checked.pages != (body,) or checked.source_fallback_blocks:
        raise ValueError("git_evidence_balanced_page_required")
    return body, cursor if cursor < len(rows) else None
