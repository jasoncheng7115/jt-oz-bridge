"""Strict upstream JSON: no duplicate keys or non-finite numeric extensions."""

import json
import math
from typing import Any, NoReturn


def reject_constant(value: str) -> NoReturn:
    raise ValueError("non_finite_json_number")


def finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non_finite_json_number")
    return number


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_object_key")
        result[key] = value
    return result


def strict_loads(value: str | bytes | bytearray) -> Any:
    return json.loads(
        value,
        parse_constant=reject_constant,
        parse_float=finite_float,
        object_pairs_hook=unique_object,
    )
