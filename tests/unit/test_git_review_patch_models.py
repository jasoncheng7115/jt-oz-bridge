"""Git review DTOs reject malformed input; no Native calls or supplied credentials."""

import hashlib

import pytest

from jt_oz_bridge.domain import git_review as models
from tests.contract.test_leaf_resources import REF


def values():
    patch = "@@ -1 +1 @@\n-old\n+繁體中文😀\n"
    data = patch.encode("utf-8")
    return {
        "reference": REF,
        "mode": "working",
        "requested_base": None,
        "file": models.NativeDiffSummary(
            path="src/a.py",
            additions=1,
            deletions=1,
            status="modified",
            patch_sha256=hashlib.sha256(data).hexdigest(),
            patch_bytes=len(data),
        ),
        "patch": patch,
        "hidden_files": 0,
    }


def test_patch_hash_measures_original_utf8_bytes_not_python_character_count():
    view = models.NativeGitPatch(**values())
    assert view.file.patch_bytes > len(view.patch)
    assert not view.index_verified and not view.mutation_confirmation_usable


@pytest.mark.parametrize(
    "fault",
    [
        "bytes",
        "hash",
        "path",
        "negative",
        "index",
        "head",
        "remote",
        "mutation",
        "mode",
        "base",
        "utf8-capacity",
    ],
)
def test_patch_dto_rejects_inconsistent_or_forged_facts(fault):
    item = values()
    if fault in {"bytes", "hash", "path", "negative"}:
        change = {
            "bytes": {"patch_bytes": item["file"].patch_bytes - 1},
            "hash": {"patch_sha256": "0" * 64},
            "path": {"path": ".env"},
            "negative": {"additions": -1},
        }[fault]
        item["file"] = item["file"].model_copy(update=change)
    elif fault in {"index", "head", "remote"}:
        item[fault + "_verified"] = True
    elif fault == "mutation":
        item["mutation_confirmation_usable"] = True
    elif fault == "mode":
        item["mode"] = "staged"
    elif fault == "base":
        item["requested_base"] = "main"
    else:
        item["patch"] = "😀" * (1024**2 // 4 + 1)
        data = item["patch"].encode("utf-8")
        item["file"] = item["file"].model_copy(
            update={
                "patch_bytes": len(data),
                "patch_sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    with pytest.raises(ValueError):
        models.NativeGitPatch(**item)
