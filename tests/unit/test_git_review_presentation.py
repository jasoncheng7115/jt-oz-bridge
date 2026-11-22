"""Safe local metadata rendering; not live Native/Zulip qualification."""

from html import unescape

import pytest

from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitReview, SavedWorktree
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.git_review import render_git_review, visible
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import AccessDenied
from tests.unit.test_markdown import Elements


def report(**changes):
    return NativeGitReview(
        reference=SessionRef(
            backend_id="secret-backend",
            backend_identity="secret-instance",
            upstream_session_id="secret-session",
            project_id="secret-project",
            canonical_directory="/private/hidden-workspace",
        ),
        provider="git",
        current_branch="feature/original",
        default_branch="main",
        saved_worktrees=(SavedWorktree(relative_directory="feature"),),
        hidden_worktrees=1,
        branches=("main", "feature/original"),
        branches_complete=False,
        inferred_base=None,
        mode=changes.pop("mode", "working"),
        files=(
            NativeDiffSummary(
                path="src/a.py",
                additions=1,
                deletions=2,
                status="modified",
                patch_sha256="f" * 64,
                patch_bytes=10,
            ),
        ),
        hidden_files=1,
        **changes,
    )


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("verb", ["context", "branches", "worktrees", "review"])
@pytest.mark.parametrize("maximum", [512, 700, 1200, 10000])
def test_allowlisted_metadata_is_bounded_with_wrapper_and_fixed_disclaimer(locale, verb, maximum):
    text = render_git_review(report(), verb, locale, message_limit=maximum)
    assert len(text) <= maximum - 100
    assert ("都未確認" if locale == "zh-TW" else "are not verified") in text
    assert "HEAD" in text and ("暫存區" if locale == "zh-TW" else "index") in text.lower()
    for private in [
        "secret-backend",
        "secret-instance",
        "secret-session",
        "secret-project",
        "/private/hidden-workspace",
        "patch_bytes",
        "hidden_files",
        "hidden_worktrees",
    ]:
        assert private not in text
    if verb == "review" and maximum >= 700:
        assert "f" * 64 in text and "src/a.py" in unescape(text)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
@pytest.mark.parametrize("verb", ["context", "branches", "worktrees", "review"])
def test_hostile_metadata_never_activates_mentions_links_html_or_controls(locale, verb):
    hostile = "@**all** [click](https://evil.example) <img> :smile: \u202e "
    hostile_path = hostile.replace("https://", "https:")
    current = report().model_copy(
        update={
            "current_branch": hostile,
            "branches": (hostile,),
            "saved_worktrees": (SavedWorktree(relative_directory=hostile_path),),
            "files": (
                NativeDiffSummary(
                    path=hostile_path,
                    additions=1,
                    deletions=1,
                    status="added",
                    patch_sha256="f" * 64,
                    patch_bytes=0,
                ),
            ),
        }
    )
    text = render_git_review(current, verb, locale, message_limit=10000)
    assert "@**all**" not in text and "\u202e" not in text and "<img>" not in text
    parser = Elements()
    parser.feed(MobileMarkdown().preview_html(text))
    assert not parser.links and not {"img", "script", "iframe"} & set(parser.tags)


@pytest.mark.parametrize("maximum", [512, 700, 1200])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_large_collection_and_entity_expansion_keep_whole_message_budget(maximum, locale):
    current = report().model_copy(
        update={
            "branches": tuple(
                "@**all** [x](https://evil.example) " + str(i) + "#" * 3000 for i in range(50)
            ),
        }
    )
    text = render_git_review(current, "branches", locale, message_limit=maximum)
    assert len(text) <= maximum - 100
    assert ("太長" if locale == "zh-TW" else "length") in text
    assert not text.endswith("&#")


def test_secret_is_redacted_before_escaped_value_truncation():
    text = visible("password=THIS-MUST-NOT-LEAK " + "#" * 4000, 50)
    assert "THIS-MUST-NOT-LEAK" not in text and len(text) <= 50


@pytest.mark.parametrize(
    "field",
    ["head_verified", "clean_verified", "full_diff_display", "mutation_confirmation_usable"],
)
def test_model_copy_cannot_turn_summary_into_verified_or_mutation_evidence(field):
    current = report().model_copy(update={field: True})
    with pytest.raises(ValueError, match="metadata_only"):
        render_git_review(current, "review", "en", message_limit=512)


@pytest.mark.parametrize("maximum", [True, 511, 1000001])
def test_invalid_configured_message_budget_fails_closed(maximum):
    current = report()
    with pytest.raises(ValueError):
        render_git_review(current, "context", "en", message_limit=maximum)


def test_worktrees_filter_is_local_saved_inventory_not_a_switch_command():
    current = report().model_copy(
        update={
            "saved_worktrees": (
                SavedWorktree(relative_directory="feature"),
                SavedWorktree(relative_directory="other"),
            )
        }
    )
    text = render_git_review(current, "worktrees", "en", message_limit=10000, search="FEAT")
    assert "feature" in text and "other" not in text and "Saved directories only" in unescape(text)


def test_committed_base_is_explicit_and_hash_is_never_a_complete_patch_claim():
    text = render_git_review(
        report(mode="committed", requested_base="main"), "review", "en", message_limit=10000
    )
    assert "committed" in text and "Base: main" in unescape(text) and "f" * 64 in text
    assert "no full patch" in text and "are not verified" in text


@pytest.mark.parametrize(
    "field,value", [("patch_sha256", "@**all**"), ("path", ".env"), ("additions", True)]
)
def test_nested_model_copy_cannot_bypass_disclosure_or_literal_hash_contract(field, value):
    current = report()
    current = current.model_copy(
        update={"files": (current.files[0].model_copy(update={field: value}),)}
    )
    with pytest.raises((ValueError, AccessDenied)):
        render_git_review(current, "review", "en", message_limit=10000)


def test_huge_native_counts_are_bounded_without_claiming_exact_smaller_values():
    current = report()
    current = current.model_copy(
        update={"files": (current.files[0].model_copy(update={"additions": 10**5000}),)}
    )
    text = render_git_review(current, "review", "en", message_limit=512)
    assert len(text) <= 412 and "999999+" in unescape(text)


@pytest.mark.parametrize(
    "fault",
    ["paragraph-pages", "paragraph-fallback", "final-pages", "final-fallback", "final-drift"],
)
def test_safe_serialization_refuses_extra_pages_fallback_or_noncanonical_final_body(
    monkeypatch, fault
):
    from dataclasses import replace

    current = report()  # A valid original DTO, outside the expected-error scope.
    original = MobileMarkdown.render

    def changed(self, source, *args, **kwargs):
        result = original(self, source, *args, **kwargs)
        final = "\n\n" in source
        if fault.startswith("final-") != final:
            return result
        if fault.endswith("pages"):
            return replace(result, pages=(*result.pages, "unexpected extra page"))
        if fault.endswith("fallback"):
            return replace(result, source_fallback_blocks=1)
        return replace(result, pages=(result.pages[0] + " changed",))

    monkeypatch.setattr(MobileMarkdown, "render", changed)
    with pytest.raises(ValueError, match="git_review_safe_"):
        render_git_review(current, "review", "en", message_limit=512)


def test_large_disclosed_collection_does_not_reserialize_all_prefixes(monkeypatch):
    current = report()
    current = current.model_copy(
        update={
            "files": tuple(
                NativeDiffSummary(
                    path=f"src/file-{i}.py",
                    additions=1,
                    deletions=1,
                    status="modified",
                    patch_sha256="f" * 64,
                    patch_bytes=1,
                )
                for i in range(1000)
            ),
            "hidden_files": 0,
        }
    )
    original, calls = MobileMarkdown.render, []

    def counted(self, source, *args, **kwargs):
        calls.append(len(source))
        return original(self, source, *args, **kwargs)

    monkeypatch.setattr(MobileMarkdown, "render", counted)
    result = render_git_review(current, "review", "en", message_limit=512)
    assert "f" * 64 in result and len(result) <= 412
    assert len(calls) < 20  # Stop after the bounded fitting prefix, then one final roundtrip.
