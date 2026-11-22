"""Equivalent bounded-memory handling of the installed Base64 schema pattern.

Python's grouped repetition records backtracking state for every four bytes.
Keep the schema itself intact and delegate every other pattern unchanged.
"""

import re
from collections.abc import Callable, Iterator
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend

BASE64_PATTERN = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
_ALPHABET = re.compile(r"[A-Za-z0-9+/]*")


def base64_pattern_matches(value: str) -> bool:
    # jsonschema uses re.search. Python's $ also matches before one final LF;
    # preserve that schema behavior. The byte codec separately rejects it.
    end = len(value) - int(value.endswith("\n"))
    if end % 4:
        return False
    padding = (
        2 if end >= 2 and value[end - 2 : end] == "==" else int(end > 0 and value[end - 1] == "=")
    )
    return _ALPHABET.fullmatch(value, 0, end - padding) is not None


def bounded_pattern(
    validator: Any, pattern: str, instance: Any, schema: Any
) -> Iterator[ValidationError]:
    if pattern == BASE64_PATTERN and isinstance(instance, str):
        if not base64_pattern_matches(instance):
            yield ValidationError("schema_base64_pattern_mismatch")
    else:
        yield from Draft202012Validator.VALIDATORS["pattern"](validator, pattern, instance, schema)


# The installed types-jsonschema package leaves extend untyped. Describe only
# the two-argument extension API used here; keep the resulting validator typed.
PatternRule = Callable[[Any, str, Any, Any], Iterator[ValidationError]]
_extend = cast(Callable[[type[Validator], dict[str, PatternRule]], type[Validator]], extend)
BoundedDraft202012Validator = _extend(Draft202012Validator, {"pattern": bounded_pattern})
