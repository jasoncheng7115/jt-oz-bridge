"""A bounded non-sensitive index for encrypted operation payloads."""

from typing import Any

OPERATIONS = frozenset({"prompt", "permission.reply", "form.reply", "interrupt"})


def operation_kind(payload: dict[str, Any]) -> str:
    value = payload.get("operation")
    return value if isinstance(value, str) and value in OPERATIONS else "unknown"
