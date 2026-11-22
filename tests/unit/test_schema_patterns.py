"""Exact schema-language equivalence and a process-level large-input bound."""

import itertools
import json
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.security.schema_patterns import (
    BASE64_PATTERN,
    BoundedDraft202012Validator,
    base64_pattern_matches,
)


def test_short_language_matches_original_including_padding_and_single_final_lf():
    original = re.compile(BASE64_PATTERN)
    alphabet = "Aa0+/=\n\r-é"
    for length in range(6):
        for symbols in itertools.product(alphabet, repeat=length):
            value = "".join(symbols)
            assert base64_pattern_matches(value) == bool(original.search(value)), repr(value)


def test_longer_group_boundaries_match_original_for_seeded_valid_and_invalid_strings():
    original = re.compile(BASE64_PATTERN)
    rng = random.Random(102)
    for _ in range(5000):
        value = "".join(rng.choices("Aa0+/=\n\r-é", k=rng.randrange(64)))
        assert base64_pattern_matches(value) == bool(original.search(value))
    for groups in range(32):
        for suffix in ("", "AA==", "AAA=", "=", "====", "A", "AA=", "AA==A"):
            for ending in ("", "\n", "\n\n", "\r\n"):
                value = "Ab0/" * groups + suffix + ending
                assert base64_pattern_matches(value) == bool(original.search(value))


@pytest.mark.parametrize(
    "pattern,value",
    [
        ("^msg_", "msg_original"),
        ("^msg_", "other"),
        ("[0-9]+", "x9"),
        ("[0-9]+", "none"),
        ("^$", "\n"),
        ("^$", "x"),
        (BASE64_PATTERN, 123),
    ],
)
def test_other_patterns_and_non_strings_keep_standard_validator_behavior(pattern, value):
    from jsonschema import Draft202012Validator

    schema = {"pattern": pattern}
    assert BoundedDraft202012Validator(schema).is_valid(value) == Draft202012Validator(
        schema
    ).is_valid(value)


@pytest.mark.parametrize(
    "value,valid",
    [
        ("", True),
        ("AAAA", True),
        ("AA==", True),
        ("AAA=", True),
        ("AAAA\n", True),
        ("AA=A", False),
        ("AA==\n\n", False),
        ("éAAA", False),
    ],
)
def test_actual_installed_schema_reference_uses_equivalent_pattern(value, valid):
    path = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    before = path.read_bytes()
    profile = OpenAPIProfile(before)
    if valid:
        profile.validate("base64", {"$ref": "#/components/schemas/Prompt.Base64"}, value)
    else:
        with pytest.raises(ContractError, match="schema_mismatch"):
            profile.validate("base64", {"$ref": "#/components/schemas/Prompt.Base64"}, value)
    assert path.read_bytes() == before
    assert profile.sha256 == "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"


def test_twenty_mib_base64_installed_schema_stays_below_256mib_in_fresh_process():
    program = """
import json,resource,sys
from pathlib import Path
from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
profile=OpenAPIProfile.from_file(Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json"))
value="A"*(4*((MAX_ATTACHMENT_BYTES+2)//3)-1)+"="
profile.validate("maximum-base64",{"$ref":"#/components/schemas/Prompt.Base64"},value)
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
kib=rss//1024 if sys.platform=="darwin" else rss
assert kib < 256*1024, kib
print(json.dumps({"passed":True,"peak_rss_kib":kib,"schema_sha256":profile.sha256}))
"""
    # Linux ru_maxrss can include the image inherited from a large pytest
    # parent before exec. A small launcher gives the measured interpreter an
    # independent, small pre-exec image without changing its memory bound.
    launcher = (
        "import subprocess,sys;raise SystemExit(subprocess.call([sys.executable,'-c',sys.argv[1]]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", launcher, program], text=True, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    assert proof["passed"] and proof["peak_rss_kib"] < 256 * 1024
