"""Offline OpenAPI contracts with source hashes and no remote-reference retrieval."""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from jsonschema import Draft202012Validator
from jsonschema.protocols import Validator
from referencing import Registry

from jt_oz_bridge.security.schema_patterns import BoundedDraft202012Validator


class ContractError(ValueError):
    pass


class SnapshotBoundaryChanged(ContractError):
    """Fresh resource reads crossed a mutable boundary; never retry the mutation."""


@dataclass(frozen=True)
class PreparedOperation:
    operation_id: str
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    body: dict[str, Any] | None


class OpenAPIProfile:
    def __init__(self, content: bytes) -> None:
        if len(content) > 16 * 1024 * 1024:
            raise ContractError("contract_too_large")
        try:
            data = json.loads(content)
        except (ValueError, UnicodeError, RecursionError):
            raise ContractError("contract_not_json") from None
        if not isinstance(data, dict) or data.get("openapi") != "3.1.0":
            raise ContractError("unsupported_contract_format")
        self.sha256 = hashlib.sha256(content).hexdigest()
        self.document: dict[str, Any] = data
        self.operations: dict[str, tuple[str, str, dict[str, Any]]] = {}
        for path, methods in data.get("paths", {}).items():
            for method, operation in methods.items():
                if method not in {"get", "post", "patch", "put", "delete"}:
                    continue
                identity = operation.get("operationId")
                if not identity or identity in self.operations:
                    raise ContractError("ambiguous_operation_identity")
                self.operations[identity] = (method.upper(), path, operation)
        if not self.operations:
            raise ContractError("contract_has_no_operations")
        self._validators: dict[str, Validator] = {}
        # An explicit empty referencing registry has no retrieval callback; unlike
        # jsonschema's implicit convenience registry, it cannot fetch remote URLs.
        self._registry: Registry[Any] = Registry()
        self._check_references(data)

    @classmethod
    def from_file(cls, path: Path) -> "OpenAPIProfile":
        with path.open("rb") as stream:
            return cls(stream.read(16 * 1024 * 1024 + 1))

    def _check_references(self, value: Any, depth: int = 0) -> None:
        if depth > 100:
            raise ContractError("contract_nesting_exceeded")
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and (
                    not isinstance(child, str) or not child.startswith("#/")
                ):
                    raise ContractError("external_contract_reference_forbidden")
                self._check_references(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                self._check_references(child, depth + 1)

    def validate(self, key: str, schema: dict[str, Any], value: Any) -> None:
        validator = self._validators.get(key)
        if validator is None:
            root = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "components": self.document.get("components", {}),
                "$defs": {"target": schema},
                "$ref": "#/$defs/target",
            }
            Draft202012Validator.check_schema(root)
            validator = BoundedDraft202012Validator(root, registry=self._registry)
            self._validators[key] = validator
        try:
            valid = validator.is_valid(value)
        except Exception:
            raise ContractError("contract_validation_failed") from None
        if not valid:
            # jsonschema errors can contain prompt/credential values. Never return them.
            raise ContractError("contract_schema_mismatch")

    def prepare(
        self,
        operation_id: str,
        *,
        path: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> PreparedOperation:
        if operation_id not in self.operations:
            raise ContractError("operation_absent_from_contract")
        method, template, operation = self.operations[operation_id]
        path, query = path or {}, query or {}
        if body is not None:
            try:
                body = json.loads(json.dumps(body, allow_nan=False))
            except (TypeError, ValueError, RecursionError):
                raise ContractError("non_json_request_value") from None
        parameters = operation.get("parameters", [])
        for location, values in [("path", path), ("query", query)]:
            declared = {item["name"]: item for item in parameters if item["in"] == location}
            if not values.keys() <= declared.keys():
                raise ContractError("undeclared_request_parameter")
            for name, parameter in declared.items():
                if parameter.get("required") and name not in values:
                    raise ContractError("required_request_parameter_missing")
                if name in values:
                    self.validate(
                        f"{operation_id}:{location}:{name}", parameter["schema"], values[name]
                    )
        for name, value in path.items():
            if not value or any(c in value for c in "/\\?#\x00\r\n"):
                raise ContractError("unsafe_path_parameter")
            template = template.replace("{" + name + "}", quote(value, safe=""))
        if re.search(r"[{}]", template) or not template.startswith("/api/"):
            raise ContractError("unsupported_request_path")
        request_body = operation.get("requestBody")
        if request_body is None and body is not None:
            raise ContractError("request_body_not_declared")
        if request_body:
            if request_body.get("required") and body is None:
                raise ContractError("request_body_required")
            if body is not None:
                schema = request_body.get("content", {}).get("application/json", {}).get("schema")
                if not isinstance(schema, dict):
                    raise ContractError("unsupported_request_encoding")
                self.validate(f"{operation_id}:request", schema, body)
                try:
                    json.dumps(body, allow_nan=False)
                except (TypeError, ValueError):
                    raise ContractError("non_json_request_value") from None
        pairs: list[tuple[str, str]] = []
        for key, value in query.items():
            append_query(pairs, key, value)
        return PreparedOperation(operation_id, method, template, tuple(pairs), body)

    def response(self, operation_id: str, status: int, value: Any) -> None:
        operation = self.operations[operation_id][2]
        response = operation.get("responses", {}).get(str(status))
        if not response:
            raise ContractError("undocumented_response_status")
        if status == 204:
            if value is not None:
                raise ContractError("unexpected_response_body")
            return
        schema = response.get("content", {}).get("application/json", {}).get("schema")
        if not isinstance(schema, dict):
            raise ContractError("unsupported_response_encoding")
        self.validate(f"{operation_id}:response:{status}", schema, value)

    def sse_frame(self, operation_id: str, *, event: str, data: str, event_id: str | None) -> None:
        schema = (
            self.operations[operation_id][2]
            .get("responses", {})
            .get("200", {})
            .get("content", {})
            .get("text/event-stream", {})
            .get("schema")
        )
        if not isinstance(schema, dict):
            raise ContractError("event_stream_not_declared")
        self.validate(f"{operation_id}:sse", schema, {"event": event, "data": data, "id": event_id})


def append_query(pairs: list[tuple[str, str]], key: str, value: Any, depth: int = 0) -> None:
    """Match the official generated V2 client (object brackets, repeated arrays)."""
    if depth > 10 or len(pairs) > 1000:
        raise ContractError("query_limits_exceeded")
    if value is None:
        pairs.append((key, "null"))
    elif isinstance(value, dict):
        for child, item in value.items():
            append_query(pairs, f"{key}[{child}]", item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            append_query(pairs, key, item, depth + 1)
    elif isinstance(value, bool):
        pairs.append((key, "true" if value else "false"))
    elif isinstance(value, int | float | str):
        if isinstance(value, float) and not math.isfinite(value):
            raise ContractError("non_finite_query_value")
        pairs.append((key, str(value)))
    else:
        raise ContractError("unsupported_query_value")
