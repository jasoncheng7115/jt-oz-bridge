"""Complete bounded history pages, not live Git or mobile qualification."""

from html import unescape

import pytest

from jt_oz_bridge.domain.git_evidence import GitEvidenceView, GitIndexEvidence
from jt_oz_bridge.presentation.git_evidence import (
    evidence_rows,
    fragments,
    render_git_evidence_page,
)
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from tests.unit.test_git_evidence import document


def view(**changes):
    return GitEvidenceView(
        action_id="00000000-0000-4000-8000-000000000001",
        result_sha256="f" * 64,
        preflight_sha256="e" * 64,
        evidence=GitIndexEvidence.model_validate(document(**changes)),
    )


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("limit", [512, 1000, 10000])
def test_all_rows_survive_bounded_pagination_without_duplicate_or_lost_names(locale, limit):
    paths = [
        dict(
            safe_relative_path="src/" + f"{i:03}-" + ("a_b-" * 40) + ".txt",
            change="added",
            mode="100644",
        )
        for i in range(20)
    ]
    value = view(branch_safe_label="feature/" + ("a-" * 50), staged_paths=paths)
    expected = evidence_rows(value, locale)
    offset = 0
    shown = []
    pages = []
    while True:
        body, next_offset = render_git_evidence_page(
            value, locale, offset=offset, message_limit=limit
        )
        assert len(body) <= limit - 100
        assert MobileMarkdown(locale=locale).render(body, limit, reserved_characters=100).pages == (
            body,
        )
        stop = next_offset if next_offset is not None else len(expected)
        assert offset < stop
        for row in expected[offset:stop]:
            # Rows are normalized before publishing, but no text is truncated.
            rendered = MobileMarkdown(locale=locale).render(row, limit).pages[0]
            assert rendered in body
        shown.extend(expected[offset:stop])
        pages.append(body)
        if next_offset is None:
            break
        offset = next_offset
    assert tuple(shown) == expected
    assert len(pages) > 1
    for number, item in enumerate(paths, 1):
        chunks = [row.split(": ", 1)[1] for row in shown if row.startswith(str(number) + ".")]
        # Includes a remote alias only under 1.*; isolate staged rows by order.
        names = list(fragments(item["safe_relative_path"]))
        assert all(chunk in chunks for chunk in names)
    assert not any("…" in page for page in pages)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_empty_index_is_not_claimed_as_clean_working_tree(locale):
    value = view(index_entries=0, staged_paths=[])
    body, _ = render_git_evidence_page(value, locale, offset=0, message_limit=10000)
    assert ("Working files were not checked" if locale == "en" else "沒有檢查工作目錄") in body
    assert ("Past result only" if locale == "en" else "這是當時的結果") in body
    assert not value.current_index_verified and not value.mutation_confirmation_usable


def test_redact_before_chunking_and_inert_literal_entities():
    source = (
        "prefix " * 9
        + "password=secret-value-longer-than-the-boundary "
        + "@**all** [x](https://example.test)"
    )
    chunks = fragments(source)
    text = unescape("".join(chunks))
    assert "secret-value" not in text
    assert "@**all**" in text
    assert all(len(chunk) <= 64 for chunk in chunks)
    assert "@**all**" not in "".join(chunks)
    assert not any(chunk.endswith("&#") for chunk in chunks)


@pytest.mark.parametrize("offset", [-1, True, 100000])
def test_invalid_offset_is_refused(offset):
    with pytest.raises(ValueError):
        render_git_evidence_page(view(), "en", offset=offset, message_limit=512)


@pytest.mark.parametrize("limit", [511, True, 1000001])
def test_invalid_message_budget_is_refused(limit):
    with pytest.raises(ValueError):
        render_git_evidence_page(view(), "en", offset=0, message_limit=limit)


def test_minimum_page_does_not_markdown_parse_the_entire_maximum_inventory(monkeypatch):
    value = view(
        staged_paths=[
            dict(safe_relative_path=f"src/{i:04}.py", change="added", mode="100644")
            for i in range(2000)
        ]
    )
    calls = []
    original = MobileMarkdown.render

    def counted(self, *args, **kwargs):
        calls.append(args[0])
        return original(self, *args, **kwargs)

    monkeypatch.setattr(MobileMarkdown, "render", counted)
    body, next_offset = render_git_evidence_page(value, "en", offset=0, message_limit=512)
    assert next_offset is not None and len(body) <= 412
    assert len(calls) <= next_offset + 4
    assert len(calls) < 20
