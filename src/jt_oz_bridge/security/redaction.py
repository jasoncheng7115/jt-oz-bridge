"""Bounded display-only redaction; never rewrite original agent input/operations.

This detects named sensitive fields and recognizable credential syntax. It is
not a claim to discover every secret in arbitrary free text or encoded content.
"""

import json
import math
import re
from dataclasses import dataclass
from typing import Any

MARKER = "[REDACTED]"
SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|access[_-]?key",
    re.I,
)
PATTERNS = (
    (
        re.compile(
            r"""(["'](?:password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|cookie|credential|private[_-]?key)["']\s*:\s*)(?:"[^"\r\n]*"?|'[^'\r\n]*'?|[^\s,;}\]]+)""",
            re.I,
        ),
        True,
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), False),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), False),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), False),
    (
        re.compile(
            r"""([?&][^=&#?\s]{0,128}?(?:token|secret|password|credential|signature|api[_-]?key|access[_-]?key)[^=&#?\s]{0,128}=)[^&#\s\"']+""",
            re.I,
        ),
        True,
    ),
    (re.compile(r"""([?&](?:sig|auth)=)[^&#\s\"']+""", re.I), True),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{10,}\b"), False),
    (
        re.compile(
            r"\b((?:Authorization|Proxy-Authorization)\s*[:=]\s*(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+",
            re.I,
        ),
        True,
    ),
    (re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}", re.I), True),
    (
        re.compile(
            r"""((?:--(?:password|passwd|token|api-key|secret))(?:=|\s+))(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;&]+)""",
            re.I,
        ),
        True,
    ),
    (
        re.compile(
            r"""\b([A-Z0-9_]{0,64}(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|ACCESS[_-]?KEY)[A-Z0-9_]{0,64}\s*=\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;&]+)""",
            re.I,
        ),
        True,
    ),
)


# Process-lifetime count for /metrics only: no text, rule or caller is recorded.
_redactions = 0


def redactions_total() -> int:
    return _redactions


def _counted(changes: int) -> int:
    global _redactions
    _redactions += changes
    return changes


PRIVATE_HEADER = re.compile(r"-----BEGIN ([A-Z0-9 ]{0,80}PRIVATE KEY)-----")
URL_USERINFO = re.compile(r"\b([a-z][a-z0-9+.-]{0,31}://)[^/\s@]+@", re.I)


def visible_controls(value: str) -> tuple[str, int]:
    count = 0
    result = []
    for char in value:
        code = ord(char)
        if (
            code < 32
            and char not in "\n\t"
            or 0x7F <= code <= 0x9F
            or 0x202A <= code <= 0x202E
            or 0x2066 <= code <= 0x2069
        ):
            result.append(f"\\u{code:04x}")
            count += 1
        else:
            result.append(char)
    return "".join(result), count


class RedactionError(ValueError):
    pass


def canonical_json(value: Any, *, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
        if len(encoded) > max_bytes:
            raise ValueError("oversized")
        return encoded
    except (ValueError, TypeError, RecursionError):
        raise RedactionError("json_not_safely_previewable") from None


def redact_text(value: str) -> tuple[str, int]:
    if len(value) > 1000000:
        raise RedactionError("text_not_safely_previewable")
    changes = 0
    pieces: list[str] = []
    cursor = 0
    for match in PRIVATE_HEADER.finditer(value):
        if match.start() < cursor:
            continue
        ending = "-----END " + match[1] + "-----"
        end = value.find(ending, match.end())
        if end < 0:
            raise RedactionError("incomplete_private_key_not_previewable")
        pieces.extend((value[cursor : match.start()], MARKER))
        cursor = end + len(ending)
        changes += 1
    if cursor:
        value = "".join(pieces) + value[cursor:]
    for pattern, keep_prefix in PATTERNS:
        replacement = r"\g<1>" + MARKER if keep_prefix else MARKER
        value, count = pattern.subn(replacement, value)
        changes += count
    value, count = URL_USERINFO.subn(r"\g<1>" + MARKER + "@", value)
    changes += count
    return value, _counted(changes)


LIVE_CREDENTIAL_PREFIX = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]*|gh[pousr]_[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*|AKIA[A-Z0-9]*|eyJ[A-Za-z0-9_.-]*)"
)
LIVE_UNFINISHED_USERINFO = re.compile(r"\b([a-z][a-z0-9+.-]{0,31}://)[^/\s@:]+:[^/\s@]*$", re.I)
LIVE_BEARER = re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.I)


def redact_live_text(value: str) -> tuple[str, int]:
    """Hide recognizable credential prefixes before a stream finishes a token.

    Edits leave version history, so waiting for a complete key's usual minimum
    length would already expose early key material. These display-only rules
    deliberately overmask some unfinished public strings; original input and
    encrypted source evidence are untouched. Arbitrary free text is not DLP.
    """
    if len(value) > 1000000:
        raise RedactionError("text_not_safely_previewable")
    value, first = LIVE_CREDENTIAL_PREFIX.subn(MARKER, value)
    value, second = LIVE_UNFINISHED_USERINFO.subn(r"\g<1>" + MARKER, value)
    value, third = LIVE_BEARER.subn(r"\g<1>" + MARKER, value)
    value, rest = redact_text(value)  # Counts its own share.
    return value, _counted(first + second + third) + rest


@dataclass(frozen=True)
class RedactedJSON:
    value: Any
    redactions: int
    control_escapes: int = 0


def redact_json(value: Any) -> RedactedJSON:
    nodes, changes, controls = 0, 0, 0

    def walk(item: Any, depth: int) -> Any:
        nonlocal nodes, changes, controls
        nodes += 1
        if depth > 32 or nodes > 10000:
            raise RedactionError("json_not_safely_previewable")
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for key, child in item.items():
                nodes += 1
                if nodes > 10000:
                    raise RedactionError("json_not_safely_previewable")
                if not isinstance(key, str):
                    raise RedactionError("json_not_safely_previewable")
                if SENSITIVE_KEY.search(key):
                    result[key] = MARKER
                    changes += _counted(1)
                else:
                    result[key] = walk(child, depth + 1)
            return result
        if isinstance(item, list):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, str):
            text, count = redact_text(item)
            changes += count
            visible, count_controls = visible_controls(text)
            controls += count_controls
            return visible
        if (
            item is None
            or isinstance(item, bool | int)
            or isinstance(item, float)
            and math.isfinite(item)
        ):
            return item
        raise RedactionError("json_not_safely_previewable")

    result = walk(value, 0)
    return RedactedJSON(result, changes, controls)
