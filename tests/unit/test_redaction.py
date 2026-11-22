import copy
import math

import pytest

from jt_oz_bridge.security.redaction import (
    MARKER,
    RedactionError,
    canonical_json,
    redact_json,
    redact_text,
)


@pytest.mark.parametrize(
    "text",
    [
        'prefix {"api_key": "short-real-key"}',
        'prefix {"password": "unfinished pass phrase',
        "prefix {'access_token': 'value'}",
    ],
)
def test_named_json_credentials_are_redacted_even_when_the_stream_has_not_closed_the_quote(text):
    rendered, count = redact_text(text)
    assert count and "[REDACTED]" in rendered
    assert "short-real-key" not in rendered and "unfinished pass phrase" not in rendered
    assert "'value'" not in rendered


@pytest.mark.parametrize(
    "text", ["sk-proj-abcd", "ghp_abcd", "eyJabc", "Bearer abc", "https://alice:pass"]
)
def test_live_recognizable_credential_prefixes_never_wait_for_a_complete_token(text):
    from jt_oz_bridge.security.redaction import redact_live_text

    rendered, count = redact_live_text(text)
    assert count and "[REDACTED]" in rendered and text not in rendered


@pytest.mark.parametrize(
    "source,secret",
    [
        ('curl --password "two private words" --delete path', "two private words"),
        ("TOKEN=private-value&operation=delete", "private-value"),
        ("Authorization: Bearer short-secret", "short-secret"),
        ("Proxy-Authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("https://username:password@example.test/path", "username:password"),
        ("sk-proj-" + ("a" * 32), "sk-proj-" + ("a" * 32)),
        ("ghp_" + ("b" * 32), "ghp_" + ("b" * 32)),
        (
            "-----BEGIN PRIVATE KEY-----\nPRIVATEKEYBODY\n-----END PRIVATE KEY-----",
            "PRIVATEKEYBODY",
        ),
    ],
)
def test_recognizable_private_values_are_redacted_without_dropping_following_effect(source, secret):
    result, count = redact_text(source)
    assert secret not in result and MARKER in result and count >= 1
    if "operation=delete" in source:
        assert "operation=delete" in result
    if "--delete path" in source:
        assert "--delete path" in result
    if "example.test/path" in source:
        assert "example.test/path" in result


def test_structured_redaction_is_nonmutating_preserves_false_zero_and_visible_controls():
    original = {
        "command": 'printf "x\u202ey\x1bz"',
        "env": {"API_KEY": "PRIVATE_KEY", "PATH": "/workspace/bin"},
        "nested": [False, 0, {"password": "PRIVATE_PASSWORD"}],
    }
    before = copy.deepcopy(original)
    result = redact_json(original)
    assert original == before
    assert result.value["nested"][:2] == [False, 0]
    assert result.value["env"]["PATH"] == "/workspace/bin"
    assert result.value["env"]["API_KEY"] == MARKER
    assert result.value["nested"][2]["password"] == MARKER
    assert result.redactions == 2 and result.control_escapes == 2
    assert "\u202e" not in result.value["command"] and "\x1b" not in result.value["command"]
    assert r"\u202e" in result.value["command"] and r"\u001b" in result.value["command"]


def test_plain_commands_and_explanations_are_not_misclassified_as_basic_auth():
    for source in [
        "Run basic tests",
        "pytest -q",
        "git status",
        "The bearer of this message has a question",
    ]:
        assert redact_text(source) == (source, 0)


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        {1: "private"},
        object(),
        {"secret_" + str(i): "value" for i in range(10001)},
    ],
)
def test_non_json_or_excessive_structures_fail_without_echoing_values(value):
    with pytest.raises(RedactionError) as captured:
        redact_json(value)
    assert "private" not in str(captured.value)


def test_depth_and_size_and_incomplete_key_are_explicitly_rejected():
    nested = {}
    for _ in range(40):
        nested = {"child": nested}
    with pytest.raises(RedactionError):
        redact_json(nested)
    with pytest.raises(RedactionError):
        canonical_json({"body": "PRIVATE_TOO_LARGE"}, max_bytes=2)
    with pytest.raises(RedactionError):
        canonical_json({"number": math.nan}, max_bytes=100)
    with pytest.raises(RedactionError):
        redact_text("-----BEGIN PRIVATE KEY-----\ntruncated private material")


@pytest.mark.parametrize(
    "source,secret",
    [
        (
            "https://storage.test/file?X-Amz-Signature=PRIVATE_SIGNED_VALUE&operation=read",
            "PRIVATE_SIGNED_VALUE",
        ),
        (
            "https://storage.test/file?X-Goog-Credential=PRIVATE_GOOG_CREDENTIAL&expires=1",
            "PRIVATE_GOOG_CREDENTIAL",
        ),
        (
            "https://storage.test/file?sv=1&sig=PRIVATE_AZURE_SIGNATURE&operation=read",
            "PRIVATE_AZURE_SIGNATURE",
        ),
    ],
)
def test_signed_url_query_values_do_not_leak_and_other_query_scope_survives(source, secret):
    result, count = redact_text(source)
    assert secret not in result and MARKER in result and count >= 1
    assert "storage.test/file?" in result
    assert "operation=read" in result if "operation=read" in source else "expires=1" in result


@pytest.mark.parametrize("encoded", ["[]", '{"x":NaN}', "not-json"])
def test_permission_details_require_finite_json_objects(encoded):
    from pydantic import ValidationError

    from jt_oz_bridge.domain.control import PermissionDetails

    with pytest.raises(ValidationError):
        PermissionDetails(source_digest="b" * 64, metadata_json=encoded)


def test_long_noncredential_candidates_complete_without_changing_scope_text():
    # No match may repeatedly scan an unbounded suffix from every candidate.
    for source in [
        "TOKEN" * 10000,
        "a." * 25000,
        "?" * 50000,
        "https://host.test/path?" + "?" * 50000,
    ]:
        assert redact_text(source) == (source, 0)
