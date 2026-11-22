import base64
import os

import pytest
from pydantic import SecretStr

from jt_oz_bridge.security.cipher import CipherError, EnvelopeCipher, decode_key

SCOPE = {
    "purpose": "artifact",
    "object_id": "opaque-id",
    "realm_id": "realm",
    "project_id": "project",
    "binding_id": "original-binding",
    "binding_revision": 1,
}


def test_aead_round_trip_uses_fresh_envelopes_and_never_contains_plaintext():
    cipher = EnvelopeCipher({"primary": os.urandom(32)}, "primary")
    plaintext = b"PRIVATE-MARKER long original output\n" * 10
    first, second = cipher.seal(plaintext, SCOPE), cipher.seal(plaintext, SCOPE)
    assert first != second and plaintext not in first and b"PRIVATE-MARKER" not in first
    assert len(first) == len(plaintext) + cipher.overhead("primary")
    assert cipher.open(first, SCOPE, max_plaintext_bytes=len(plaintext)) == plaintext
    assert "PRIVATE-MARKER" not in repr(cipher)


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "other"),
        ("realm_id", "other"),
        ("project_id", "other"),
        ("binding_id", "other"),
        ("binding_revision", 2),
        ("object_id", "other"),
    ],
)
def test_cross_scope_substitution_never_releases_plaintext(field, value):
    cipher = EnvelopeCipher({"primary": os.urandom(32)}, "primary")
    encrypted = cipher.seal(b"PRIVATE-MARKER", SCOPE)
    with pytest.raises(CipherError) as error:
        cipher.open(encrypted, {**SCOPE, field: value}, max_plaintext_bytes=100)
    assert "PRIVATE-MARKER" not in str(error.value)


def test_tampering_truncation_unknown_key_and_oversized_plaintext_fail_closed():
    key = os.urandom(32)
    cipher = EnvelopeCipher({"primary": key}, "primary")
    encrypted = cipher.seal(b"PRIVATE-MARKER", SCOPE)
    for offset in [0, 6, 15, 30, len(encrypted) - 1]:
        corrupted = bytearray(encrypted)
        corrupted[offset] ^= 1
        with pytest.raises(CipherError):
            cipher.open(bytes(corrupted), SCOPE, max_plaintext_bytes=100)
    for corrupted in [b"PRIVATE-MARKER", encrypted[:8], encrypted[:-1]]:
        with pytest.raises(CipherError):
            cipher.open(corrupted, SCOPE, max_plaintext_bytes=100)
    with pytest.raises(CipherError):
        EnvelopeCipher({"new": key}, "new").open(encrypted, SCOPE, max_plaintext_bytes=100)
    with pytest.raises(CipherError):
        cipher.open(encrypted, SCOPE, max_plaintext_bytes=1)


def test_explicit_keyring_retains_old_key_for_reads_and_uses_new_key_for_writes():
    old, new = os.urandom(32), os.urandom(32)
    original = EnvelopeCipher({"old": old}, "old").seal(b"old content", SCOPE)
    rotated = EnvelopeCipher({"old": old, "new": new}, "new")
    assert rotated.open(original, SCOPE, max_plaintext_bytes=100) == b"old content"
    current = rotated.seal(b"new content", SCOPE)
    with pytest.raises(CipherError):
        EnvelopeCipher({"old": old}, "old").open(current, SCOPE, max_plaintext_bytes=100)
    assert (
        EnvelopeCipher({"new": new}, "new").open(current, SCOPE, max_plaintext_bytes=100)
        == b"new content"
    )


def test_key_references_require_real_base64_random_key_material_not_a_password():
    key = os.urandom(32)
    assert decode_key(SecretStr(base64.urlsafe_b64encode(key).decode())) == key
    for value in ["service-password", "PRIVATE-MARKER", "a" * 32, "繁體中文"]:
        with pytest.raises(CipherError) as error:
            decode_key(SecretStr(value))
        assert value not in str(error.value)
