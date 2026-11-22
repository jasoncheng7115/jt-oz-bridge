"""Bounded immutable projection models, not Native or renderer qualification."""

import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.git_review import absolute_directory, explicit_base
from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeReviewBase, SavedWorktree


@pytest.mark.parametrize("value", ["main", "refs/heads/review-1", "f" * 40, "feature/a_b"])
def test_explicit_base_is_a_bounded_query_reference_not_a_shell_expression(value):
    assert explicit_base(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-main",
        "HEAD~2",
        "main@{1}",
        "a..b",
        "../main",
        "/main",
        "a//b",
        "a/.git",
        "a/..",
        "a\\b",
        "a.lock",
        "a;id",
        "$(id)",
        "x" * 256,
    ],
)
def test_unsupported_reference_expressions_fail_closed(value):
    with pytest.raises(ValueError):
        explicit_base(value)


@pytest.mark.parametrize(
    "value", ["relative", "/a/../b", "/a/./b", "/a//b", "//host/a", "/a/", "/a\\b", "/a\nb"]
)
def test_saved_directories_cannot_silently_normalize(value):
    with pytest.raises(ValueError):
        absolute_directory(value)


@pytest.mark.parametrize(
    "path",
    [
        ".git/index",
        ".ssh/id",
        ".env",
        "secrets/a",
        ".jt-oz-incoming-service/a",
        "x.key",
        "../escape",
    ],
)
def test_public_projection_cannot_retain_protected_relative_paths(path):
    with pytest.raises(ValueError):
        SavedWorktree(relative_directory=path)
    with pytest.raises(ValueError):
        NativeDiffSummary(
            path=path,
            additions=0,
            deletions=0,
            status="added",
            patch_sha256="f" * 64,
            patch_bytes=0,
        )


def test_null_base_is_not_replaced_by_a_default_and_models_are_frozen():
    base = NativeReviewBase(name="main", ref="refs/heads/main", source="default")
    with pytest.raises(ValidationError):
        base.name = "changed"
    with pytest.raises(ValidationError):
        NativeReviewBase(name="bad\nname", ref="main", source="default")
    assert SavedWorktree(relative_directory="").relative_directory == ""
