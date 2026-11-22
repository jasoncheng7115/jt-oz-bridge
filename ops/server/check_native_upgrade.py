"""Evaluate a candidate OpenCode Native contract against the pinned installed one.

Read-only operator tool. It issues HTTP GET only (the OpenAPI document and
``/api/info``), writes nothing, never opens the Native database and never prints
the credential. A clean result is not a qualification: it says what to requalify.

    python check_native_upgrade.py                        # live loopback Native
    python check_native_upgrade.py --url http://127.0.0.1:4097 --credential-ref file:/etc/jt-oz-bridge/secrets/opencode
    python check_native_upgrade.py --file candidate.json --json

Exit codes: 0 same contract; 1 requalification needed, differences look additive;
2 breaking differences; 3 could not evaluate (never read 3 as compatible).
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, NoReturn
from urllib.parse import urlsplit

EXIT_SAME, EXIT_REQUALIFY, EXIT_BREAKING, EXIT_UNEVALUATED = 0, 1, 2, 3
try:
    from jt_oz_bridge.adapters.opencode import contracts as contract_module
    from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
    from jt_oz_bridge.adapters.opencode.transport import MUTATION_OPERATIONS, READ_OPERATIONS
    from jt_oz_bridge.config import load_settings, validate_endpoint
    from jt_oz_bridge.security.schema_patterns import BASE64_PATTERN
    from jt_oz_bridge.security.secrets import SecretUnavailable, resolve_secret
except Exception as error:
    # Python's own failure exit is 1, which here would read as "additive differences".
    print(f"could not evaluate: project_import_failed_{type(error).__name__}", file=sys.stderr)
    raise SystemExit(EXIT_UNEVALUATED) from None

PINNED_VERSION = "2.0.32"
DEFAULT_CONFIG = Path("/etc/jt-oz-bridge/config.toml")
DEFAULT_URL = "http://127.0.0.1:4096"
# Not declared in paths; this is the route the 2.0.32 CLI itself fetches (string in its ELF).
OPENAPI_PATH = "/openapi.json"
INFO_PATH = "/api/info"
MAX_CONTRACT_BYTES = 16 * 1024 * 1024
MAX_INFO_BYTES = 64 * 1024
PACKAGE = Path(contract_module.__file__).parents[2]
ADAPTERS = "adapters/opencode"
# .parent, not parents[2]: an operator may copy this single file to a shallow path.
REPOSITORY = Path(__file__).resolve().parent.parent.parent
PINNED_FIXTURE = REPOSITORY / "tests/fixtures/contracts/opencode-v2.0.32-installed.json"

Direction = Literal["request", "response", "error"]
OPERATION_DIRECTIONS: tuple[str, ...] = ("request", "response", "error")
Severity = Literal["breaking", "additive", "info"]
# Severity by direction. Bridge sends requests and consumes responses, so the same
# edit reads differently: a new enum value is harmless to send and unknown to read.
SEVERITY: dict[str, dict[Direction, Severity]] = {
    "value_added": {"request": "additive", "response": "breaking", "error": "additive"},
    "value_removed": {"request": "breaking", "response": "breaking", "error": "breaking"},
    "property_added_optional": {"request": "additive", "response": "additive", "error": "additive"},
    "property_added_required": {"request": "breaking", "response": "additive", "error": "additive"},
    "property_removed": {"request": "breaking", "response": "breaking", "error": "breaking"},
    "became_required": {"request": "breaking", "response": "additive", "error": "additive"},
    "became_optional": {"request": "additive", "response": "breaking", "error": "additive"},
    "bound_tightened": {"request": "breaking", "response": "additive", "error": "additive"},
    "bound_relaxed": {"request": "additive", "response": "breaking", "error": "additive"},
    "opaque_changed": {"request": "breaking", "response": "breaking", "error": "additive"},
}
DOC_KEYS = frozenset(
    {"description", "title", "summary", "tags", "examples", "example", "externalDocs"}
)
INFO_KEYS = frozenset({"default", "deprecated", "readOnly", "writeOnly"})
LOWER_BOUNDS = ("minLength", "minimum", "exclusiveMinimum", "minItems", "minProperties")
UPPER_BOUNDS = ("maxLength", "maximum", "exclusiveMaximum", "maxItems", "maxProperties")
STRUCTURAL = frozenset(
    {
        "$ref",
        "anyOf",
        "oneOf",
        "allOf",
        "properties",
        "required",
        "additionalProperties",
        "type",
        "enum",
        "const",
        "items",
        "prefixItems",
        *LOWER_BOUNDS,
        *UPPER_BOUNDS,
    }
)
# Session messages, their parts and the event/log envelopes Bridge reads.
CORE_SCHEMA = re.compile(
    r"^(Session\.Message\b|Session\.Inbox\b|Session\.Info$|Session\.Revert$|SessionMessagesResponse$"
    r"|SessionsResponse$|SessionActive$|SessionLogItemEncoded$|Event\.|V2EventEncoded$|Tool\.)"
)
# (label, schema, path to its union); "parts" are the assistant message content blocks.
CORE_UNIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("message_types", "Session.Message.Info", ()),
    ("assistant_parts", "Session.Message.Assistant", ("properties", "content", "items")),
    ("inbox_types", "Session.Inbox.Info", ()),
    ("tool_content", "Tool.Content", ()),
)
OPAQUE_EVENT_SCHEMAS = ("V2EventEncoded", "SessionLogItemEncoded")


class CheckFailure(Exception):
    """A fixed code that holds no response body, credential or URL userinfo."""


@dataclass(frozen=True)
class Certificate:
    kind: str
    format: str | None
    enrollment: str
    modules: tuple[str, ...]
    pins: str


def _adapters(*names: str) -> tuple[str, ...]:
    return tuple(f"{ADAPTERS}/{name}.py" for name in names)


# Every entry binds the contract hash or the Native version, directly or through its
# semantics digest, so a changed contract invalidates all of them. `modules` says
# which ones point at code that may itself need a change (and then a new component hash).
CERTIFICATES: tuple[Certificate, ...] = (
    Certificate(
        "owner-enrollment",
        "linux-opencode-owner-v2",
        "services/runtime_enrollment.py",
        _adapters("host_owner"),
        "executable_sha256, unit_sha256, version",
    ),
    Certificate(
        "consumer-runtime-manifest",
        "qualified-consumer-runtime-v7",
        "services/runtime_enrollment.py",
        _adapters("contracts", "transport", "live", "resources", "execution"),
        "schema_file, verified_operations, operation and outcome evidence",
    ),
    Certificate(
        "native-project-policy",
        "native-project-policy-v1",
        "services/runtime_enrollment.py",
        _adapters("project_policy", "agent_settings"),
        "contract_sha256, permission_source_sha256, fingerprint_sha256",
    ),
    Certificate(
        "model-settings",
        None,
        "services/runtime_enrollment.py",
        _adapters("model_settings", "model_catalog"),
        "model_evidence, MODEL_SETTING_SEMANTICS",
    ),
    Certificate(
        "checks",
        None,
        "services/runtime_enrollment.py",
        _adapters("checks", "check_idle_anchor"),
        "checks evidence, CHECK_SEMANTICS",
    ),
    Certificate(
        "native-file-read",
        "qualified-native-file-read-v2",
        "services/file_enrollment.py",
        _adapters("files"),
        "contract_sha256, candidate_module_sha256, file_semantics_sha256",
    ),
    Certificate(
        "workspace-catalog",
        "qualified-original-workspace-catalog-v2",
        "services/catalog_enrollment.py",
        _adapters("workspace_catalog", "directory_scope"),
        "contract_sha256, catalog_component_sha256, directory_component_sha256",
    ),
    Certificate(
        "workspace",
        "qualified-original-workspace-v1",
        "services/workspace_enrollment.py",
        _adapters("native_workspace"),
        "contract_sha256, workspace_component_sha256",
    ),
    Certificate(
        "generated-outputs",
        "qualified-generated-outputs-v1",
        "services/generated_enrollment.py",
        _adapters("generated_files", "turn_resources"),
        "contract_sha256, component_sha256",
    ),
    Certificate(
        "git-review",
        "qualified-original-git-review-v1",
        "services/runtime_enrollment.py",
        _adapters("git_review", "directory_scope"),
        "contract_sha256, git_component_sha256, directory_component_sha256",
    ),
    Certificate(
        "git-patch",
        "qualified-original-git-patch-v1",
        "services/runtime_enrollment.py",
        _adapters("git_review"),
        "contract_sha256, git_component_sha256",
    ),
    Certificate(
        "git-evidence",
        "installed-original-git-evidence-qualification-v1",
        "services/git_evidence_enrollment.py",
        _adapters("directory_scope", "host_owner"),
        "contract_sha256",
    ),
    Certificate(
        "session-lineage",
        "qualified-original-session-lineage-v1",
        "services/runtime_enrollment.py",
        _adapters("lineage_resources", "lineage_policy", "graph_generation"),
        "contract_sha256, LINEAGE_SEMANTICS",
    ),
    Certificate(
        "root-creation-rpc",
        "installed-root-creation-rpc-v1",
        "services/runtime_enrollment.py",
        _adapters("session_creation", "creation_policy"),
        "contract_sha256",
    ),
)


@dataclass
class Finding:
    severity: Severity
    where: str
    kind: str
    detail: str
    direction: str = ""
    operations: list[str] = field(default_factory=list)


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def strip_docs(value: Any, *, names: bool = False) -> Any:
    """Drop documentation keywords, keeping properties that merely share such a name."""
    if isinstance(value, list):
        return [strip_docs(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_docs(child, names=key == "properties" and not names)
            for key, child in value.items()
            if names or key not in DOC_KEYS
        }
    return value


def ref_name(schema: Any) -> str | None:
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            return ref.removeprefix("#/components/schemas/")
    return None


def references(value: Any) -> Iterator[str]:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            name = ref_name(item)
            if name is not None:
                yield name
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def schemas_of(document: Mapping[str, Any]) -> dict[str, Any]:
    return document.get("components", {}).get("schemas", {})


def closure(document: Mapping[str, Any], value: Any) -> set[str]:
    schemas, seen = schemas_of(document), set[str]()
    pending = list(references(value))
    while pending:
        name = pending.pop()
        if name not in seen:
            seen.add(name)
            pending.extend(references(schemas.get(name)))
    return seen


def operations_of(document: Mapping[str, Any]) -> dict[str, tuple[str, str, dict[str, Any]]]:
    return {
        operation["operationId"]: (method.upper(), path, operation)
        for path, methods in document.get("paths", {}).items()
        for method, operation in methods.items()
        if isinstance(operation, dict) and "operationId" in operation
    }


def is_success(status: str) -> bool:
    return status.startswith("2")


def operation_parts(operation: Mapping[str, Any]) -> dict[Direction, list[Any]]:
    parts: dict[Direction, list[Any]] = {"request": [], "response": [], "error": []}
    parts["request"] += [operation.get("parameters", []), operation.get("requestBody", {})]
    for status, response in operation.get("responses", {}).items():
        parts["response" if is_success(status) else "error"].append(response)
    return parts


def discriminator(schema: Any) -> str | None:
    if not isinstance(schema, dict):
        return None
    for name in ("type", "_tag", "kind"):
        tag = schema.get("properties", {}).get(name)
        if isinstance(tag, dict):
            values = tag.get("enum") or ([tag["const"]] if "const" in tag else [])
            if len(values) == 1:
                return f"{name}={values[0]}"
    return None


class ContractDiff:
    """Direction-aware structural diff; components are compared once per direction."""

    def __init__(self, old: Mapping[str, Any], new: Mapping[str, Any]) -> None:
        self.old, self.new = old, new
        self.old_schemas, self.new_schemas = schemas_of(old), schemas_of(new)
        self.findings: list[Finding] = []
        self.pending: list[tuple[str, Direction]] = []
        self.visited: set[tuple[str, Direction]] = set()
        self.compared: set[tuple[str, str, Direction]] = set()

    def change(self, kind: str, direction: Direction, where: str, detail: str) -> None:
        self.findings.append(Finding(SEVERITY[kind][direction], where, kind, detail, direction))

    def fixed(self, severity: Severity, where: str, kind: str, detail: str) -> None:
        self.findings.append(Finding(severity, where, kind, detail))

    def enqueue(self, name: str, direction: Direction) -> None:
        if (name, direction) not in self.visited:
            self.visited.add((name, direction))
            self.pending.append((name, direction))

    def drain(self) -> None:
        while self.pending:
            name, direction = self.pending.pop()
            where = f"schema:{name}"
            if name not in self.old_schemas or name not in self.new_schemas:
                # Unreferenced additions never get here; a dangling ref is a broken contract.
                self.change("opaque_changed", direction, where, "component is missing on one side")
                continue
            self.walk(self.old_schemas[name], self.new_schemas[name], where, direction)

    def walk(self, old: Any, new: Any, where: str, direction: Direction) -> None:
        if not isinstance(old, dict) or not isinstance(new, dict):
            if old != new:
                self.change(
                    "opaque_changed", direction, where, f"{canonical(old)} -> {canonical(new)}"
                )
            return
        old_ref, new_ref = ref_name(old), ref_name(new)
        if old_ref is not None and old_ref == new_ref:
            self.enqueue(old_ref, direction)
            return
        if old_ref is not None or new_ref is not None:
            self.follow(old, new, old_ref, new_ref, where, direction)
            return
        self.compare(old, new, where, direction)

    def follow(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        old_ref: str | None,
        new_ref: str | None,
        where: str,
        direction: Direction,
    ) -> None:
        # Effect numbers generated names (ProviderState_4), so a new target name alone
        # means nothing; compare what the refs resolve to and stop on a repeated pair.
        key = (old_ref or canonical(old), new_ref or canonical(new), direction)
        if key in self.compared:
            return
        self.compared.add(key)
        old_target = old if old_ref is None else self.old_schemas.get(old_ref)
        new_target = new if new_ref is None else self.new_schemas.get(new_ref)
        if old_target is None or new_target is None:
            self.change("opaque_changed", direction, where, "reference target is missing")
            return
        self.fixed(
            "info", where, "reference_changed", f"{old_ref or 'inline'} -> {new_ref or 'inline'}"
        )
        self.walk(old_target, new_target, where, direction)

    def compare(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        old_union = old.get("anyOf", old.get("oneOf"))
        new_union = new.get("anyOf", new.get("oneOf"))
        if old_union or new_union:
            if old_union and new_union and ("oneOf" in old) != ("oneOf" in new):
                self.change("opaque_changed", direction, where, "union keyword changed")
            union_keys = {"anyOf", "oneOf"}
            old_rest = {k: v for k, v in old.items() if k not in union_keys}
            new_rest = {k: v for k, v in new.items() if k not in union_keys}
            if not old_union:
                old_union, old_rest = [old_rest], {}
            if not new_union:
                new_union, new_rest = [new_rest], {}
            self.union(old_union, new_union, where, direction)
            old, new = old_rest, new_rest
        self.properties(old, new, where, direction)
        self.additional(old, new, where, direction)
        self.values(old, new, where, direction)
        self.bounds(old, new, where, direction)
        self.children(old, new, where, direction)
        for key in sorted((set(old) | set(new)) - STRUCTURAL - DOC_KEYS):
            if old.get(key) != new.get(key):
                detail = f"{key}: {canonical(old.get(key))} -> {canonical(new.get(key))}"
                if key in INFO_KEYS or key.startswith("x-"):
                    self.fixed("info", where, "annotation_changed", detail)
                else:
                    self.change("opaque_changed", direction, where, detail)

    def union(self, old: list[Any], new: list[Any], where: str, direction: Direction) -> None:
        old_keys, new_keys = (
            self.branches(old, self.old_schemas),
            self.branches(new, self.new_schemas),
        )
        for key in old_keys.keys() & new_keys.keys():
            self.walk(old_keys[key], new_keys[key], f"{where}/anyOf[{key}]", direction)
        removed, added = old_keys.keys() - new_keys.keys(), new_keys.keys() - old_keys.keys()
        renamed = self.renamed(old_keys, new_keys, removed, added)
        for old_key, new_key in renamed:
            self.walk(old_keys[old_key], new_keys[new_key], f"{where}/anyOf[{new_key}]", direction)
            removed.discard(old_key)
            added.discard(new_key)
        for key in sorted(removed):
            self.change("value_removed", direction, where, f"union branch removed: {key}")
        for key in sorted(added):
            self.change("value_added", direction, where, f"union branch added: {key}")

    def renamed(
        self,
        old_keys: Mapping[str, Any],
        new_keys: Mapping[str, Any],
        removed: Iterable[str],
        added: Iterable[str],
    ) -> list[tuple[str, str]]:
        def tag(branch: Any, schemas: Mapping[str, Any]) -> str | None:
            name = ref_name(branch)
            return discriminator(schemas.get(name) if name else branch)

        by_tag = {tag(new_keys[key], self.new_schemas): key for key in sorted(added)}
        pairs = []
        for key in sorted(removed):
            match = by_tag.get(tag(old_keys[key], self.old_schemas))
            if match is not None and tag(old_keys[key], self.old_schemas) is not None:
                pairs.append((key, match))
        return pairs

    @staticmethod
    def branches(values: list[Any], schemas: Mapping[str, Any]) -> dict[str, Any]:
        keys: dict[str, Any] = {}
        for value in values:
            name = ref_name(value)
            tag = discriminator(value)
            if name is not None:
                key = f"ref:{name}"
            elif tag is not None:
                key = f"tag:{tag}"
            elif isinstance(value, dict) and "type" in value:
                key = f"type:{canonical(value['type'])}"
            else:
                key = "inline:" + hashlib.sha256(canonical(value).encode()).hexdigest()[:12]
            unique, serial = key, 1
            while unique in keys:
                serial += 1
                unique = f"{key}#{serial}"
            keys[unique] = value
        return keys

    def properties(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        old_props, new_props = old.get("properties", {}), new.get("properties", {})
        old_required, new_required = set(old.get("required", [])), set(new.get("required", []))
        for name in sorted(old_props.keys() - new_props.keys()):
            self.change("property_removed", direction, f"{where}/{name}", "property removed")
        for name in sorted(new_props.keys() - old_props.keys()):
            kind = "property_added_required" if name in new_required else "property_added_optional"
            self.change(kind, direction, f"{where}/{name}", "property added")
        for name in sorted(old_props.keys() & new_props.keys()):
            self.walk(old_props[name], new_props[name], f"{where}/{name}", direction)
        for name in sorted(new_required - old_required - (new_props.keys() - old_props.keys())):
            self.change("became_required", direction, f"{where}/{name}", "property became required")
        for name in sorted(old_required - new_required):
            if name in new_props:
                self.change(
                    "became_optional", direction, f"{where}/{name}", "property became optional"
                )

    def additional(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        def closed(value: Any) -> Any:
            return True if value in (True, {}) else value

        before = closed(old.get("additionalProperties", True))
        after = closed(new.get("additionalProperties", True))
        if before == after:
            return
        if isinstance(before, dict) and isinstance(after, dict):
            self.walk(before, after, f"{where}/additionalProperties", direction)
        elif before is False or after is True:
            self.change("bound_relaxed", direction, where, "additional properties widened")
        else:
            self.change("bound_tightened", direction, where, "additional properties narrowed")

    @staticmethod
    def allowed(schema: dict[str, Any], key: str) -> set[str] | None:
        if key == "type":
            value = schema.get("type")
            if value is None:
                return None
            return {canonical(item) for item in (value if isinstance(value, list) else [value])}
        if "enum" in schema:
            return {canonical(item) for item in schema["enum"]}
        return {canonical(schema["const"])} if "const" in schema else None

    def values(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        for key in ("type", "enum"):
            before, after = self.allowed(old, key), self.allowed(new, key)
            if before == after:
                continue
            if before is None:
                self.change(
                    "bound_tightened",
                    direction,
                    where,
                    f"{key} constraint added: {sorted(after or ())}",
                )
            elif after is None:
                self.change(
                    "bound_relaxed", direction, where, f"{key} constraint removed: {sorted(before)}"
                )
            else:
                for value in sorted(before - after):
                    self.change("value_removed", direction, where, f"{key} value removed: {value}")
                for value in sorted(after - before):
                    self.change("value_added", direction, where, f"{key} value added: {value}")

    def bounds(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        for keys, tighter in ((LOWER_BOUNDS, float.__gt__), (UPPER_BOUNDS, float.__lt__)):
            for key in keys:
                before, after = old.get(key), new.get(key)
                if before == after:
                    continue
                tightened = before is None or (
                    after is not None and tighter(float(after), float(before))
                )
                self.change(
                    "bound_tightened" if tightened else "bound_relaxed",
                    direction,
                    where,
                    f"{key}: {before} -> {after}",
                )

    def children(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        if "items" in old or "items" in new:
            if "items" in old and "items" in new:
                self.walk(old["items"], new["items"], f"{where}/items", direction)
            else:
                self.change("opaque_changed", direction, where, "items keyword added or removed")
        for key in ("prefixItems", "allOf"):
            before, after = old.get(key, []), new.get(key, [])
            if len(before) != len(after):
                self.change("opaque_changed", direction, where, f"{key} length changed")
            for index, (left, right) in enumerate(zip(before, after, strict=False)):
                self.walk(left, right, f"{where}/{key}[{index}]", direction)

    def operation(
        self,
        name: str,
        old: tuple[str, str, dict[str, Any]],
        new: tuple[str, str, dict[str, Any]],
    ) -> None:
        where = f"operation:{name}"
        if old[:2] != new[:2]:
            self.fixed(
                "breaking", where, "operation_moved", f"{old[0]} {old[1]} -> {new[0]} {new[1]}"
            )
        before, after = old[2], new[2]
        if before.get("security") != after.get("security"):
            self.fixed(
                "breaking", where, "operation_security_changed", "security requirement changed"
            )
        self.parameters(before, after, where)
        self.body(before, after, where)
        self.responses(before, after, where)

    def parameters(self, old: dict[str, Any], new: dict[str, Any], where: str) -> None:
        def table(operation: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
            return {(p["in"], p["name"]): p for p in operation.get("parameters", [])}

        before, after = table(old), table(new)
        for key in sorted(before.keys() - after.keys()):
            self.change(
                "property_removed",
                "request",
                f"{where}/parameters/{key[0]}/{key[1]}",
                "parameter removed",
            )
        for key in sorted(after.keys() - before.keys()):
            kind = (
                "property_added_required"
                if after[key].get("required")
                else "property_added_optional"
            )
            self.change(kind, "request", f"{where}/parameters/{key[0]}/{key[1]}", "parameter added")
        for key in sorted(before.keys() & after.keys()):
            at = f"{where}/parameters/{key[0]}/{key[1]}"
            if bool(before[key].get("required")) != bool(after[key].get("required")):
                kind = "became_required" if after[key].get("required") else "became_optional"
                self.change(kind, "request", at, "parameter requirement changed")
            for attribute in ("style", "explode", "content"):
                if before[key].get(attribute) != after[key].get(attribute):
                    self.change("opaque_changed", "request", at, f"{attribute} changed")
            self.walk(before[key].get("schema", {}), after[key].get("schema", {}), at, "request")

    def body(self, old: dict[str, Any], new: dict[str, Any], where: str) -> None:
        before, after = old.get("requestBody"), new.get("requestBody")
        at = f"{where}/requestBody"
        if before is None and after is None:
            return
        if before is None or after is None:
            required = bool(after and after.get("required"))
            self.fixed(
                "breaking" if before is not None or required else "additive",
                at,
                "request_body_removed" if after is None else "request_body_added",
                "request body presence changed",
            )
            return
        if bool(before.get("required")) != bool(after.get("required")):
            kind = "became_required" if after.get("required") else "became_optional"
            self.change(kind, "request", at, "request body requirement changed")
        self.content(before, after, at, "request")

    def content(
        self, old: dict[str, Any], new: dict[str, Any], where: str, direction: Direction
    ) -> None:
        before, after = old.get("content", {}), new.get("content", {})
        for media in sorted(before.keys() - after.keys()):
            self.change("value_removed", direction, where, f"media type removed: {media}")
        for media in sorted(after.keys() - before.keys()):
            self.change("value_added", direction, where, f"media type added: {media}")
        for media in sorted(before.keys() & after.keys()):
            at = f"{where}/{media}"
            self.walk(
                before[media].get("schema", {}), after[media].get("schema", {}), at, direction
            )
            for key in sorted(
                k for k in before[media].keys() | after[media].keys() if k != "schema"
            ):
                if before[media].get(key) != after[media].get(key):
                    self.fixed("info", at, "annotation_changed", f"{key} changed")

    def responses(self, old: dict[str, Any], new: dict[str, Any], where: str) -> None:
        before, after = old.get("responses", {}), new.get("responses", {})
        for status in sorted(before.keys() - after.keys()):
            at = f"{where}/responses/{status}"
            self.fixed(
                "breaking" if is_success(status) else "additive",
                at,
                "response_status_removed",
                "documented status removed",
            )
        for status in sorted(after.keys() - before.keys()):
            at = f"{where}/responses/{status}"
            self.fixed(
                "breaking" if is_success(status) else "additive",
                at,
                "response_status_added",
                "documented status added",
            )
        for status in sorted(before.keys() & after.keys()):
            direction: Direction = "response" if is_success(status) else "error"
            self.content(before[status], after[status], f"{where}/responses/{status}", direction)

    def attach_operations(self, used: Iterable[str]) -> None:
        old_ops, new_ops = operations_of(self.old), operations_of(self.new)
        reach: dict[tuple[str, str], set[str]] = {}
        for name in used:
            for document, table in ((self.old, old_ops), (self.new, new_ops)):
                if name not in table:
                    continue
                for direction, parts in operation_parts(table[name][2]).items():
                    for schema in closure(document, parts):
                        reach.setdefault((schema, direction), set()).add(name)
        for finding in self.findings:
            if finding.where.startswith("operation:"):
                finding.operations = [finding.where.split("/")[0].removeprefix("operation:")]
            elif finding.where.startswith("schema:"):
                schema = finding.where.removeprefix("schema:").partition("/")[0]
                directions = (finding.direction,) if finding.direction else OPERATION_DIRECTIONS
                finding.operations = sorted(
                    {op for way in directions for op in reach.get((schema, way), set())}
                )


@dataclass(frozen=True)
class SourceScan:
    usage: dict[str, list[str]]
    contract_pins: list[str]
    version_pins: list[str]


def scan_source(operations: set[str], package: Path = PACKAGE) -> SourceScan:
    """Find real references in the installed package source, never a maintained copy."""
    usage: dict[str, set[str]] = {}
    contract_pins, version_pins = set[str](), set[str]()
    adapters = package / ADAPTERS
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package).as_posix()
        tree = ast.parse(path.read_bytes())
        in_adapters = path.is_relative_to(adapters)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if in_adapters and node.value in operations:
                    usage.setdefault(node.value, set()).add(relative)
                if node.value == INSTALLED_SCHEMA:
                    contract_pins.add(relative)
                if node.value == PINNED_VERSION:
                    version_pins.add(relative)
            elif isinstance(node, ast.Name) and node.id == "INSTALLED_SCHEMA":
                contract_pins.add(relative)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"request", "events"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in operations
            ):
                usage.setdefault(str(node.args[0].value), set()).add(relative)
    return SourceScan(
        {name: sorted(modules) for name, modules in usage.items()},
        sorted(contract_pins),
        sorted(version_pins),
    )


def union_tags(document: Mapping[str, Any], name: str, path: tuple[str, ...]) -> list[str] | None:
    schemas = schemas_of(document)
    node: Any = schemas.get(name)
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    if not isinstance(node, dict):
        return None
    tags = []
    for branch in node.get("anyOf", node.get("oneOf", [])):
        target = ref_name(branch)
        tags.append(
            discriminator(schemas.get(target) if target else branch) or target or "untagged"
        )
    return sorted(tags)


def core_summary(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    before, after = schemas_of(old), schemas_of(new)
    names = sorted(n for n in before.keys() | after.keys() if CORE_SCHEMA.match(n))
    changes = {}
    for name in names:
        if name not in after:
            changes[name] = "removed"
        elif name not in before:
            changes[name] = "added"
        elif strip_docs(before[name]) != strip_docs(after[name]):
            changes[name] = "changed"
    unions = {}
    for label, name, path in CORE_UNIONS:
        left, right = union_tags(old, name, path), union_tags(new, name, path)
        unions[label] = {
            "added": sorted(set(right or ()) - set(left or ())),
            "removed": sorted(set(left or ()) - set(right or ())),
            "count": len(right or ()),
        }
    return {"checked": len(names), "changes": changes, "unions": unions}


def opaque_event_schemas(document: Mapping[str, Any]) -> list[str]:
    schemas = schemas_of(document)
    return [
        name
        for name in OPAQUE_EVENT_SCHEMAS
        if isinstance(schemas.get(name), dict)
        and schemas[name].get("type") == "string"
        and "contentSchema" not in schemas[name]
    ]


def unused_changes(
    old: Mapping[str, Any], new: Mapping[str, Any], names: Iterable[str]
) -> list[str]:
    def fingerprint(document: Mapping[str, Any], name: str) -> str:
        method, path, operation = operations_of(document)[name]
        schemas = schemas_of(document)
        reach = sorted(closure(document, operation))
        return canonical(
            strip_docs([method, path, operation, [schemas.get(n) for n in reach], reach])
        )

    return sorted(n for n in names if fingerprint(old, n) != fingerprint(new, n))


def evaluate(
    pinned: bytes,
    candidate: bytes,
    *,
    server_version: str | None = None,
    package: Path = PACKAGE,
) -> dict[str, Any]:
    """Pure comparison of two contract byte strings; performs no network or file writes."""
    pinned_profile = OpenAPIProfile(pinned)
    report: dict[str, Any] = {
        "format": "native-upgrade-check-v1",
        "pinned": {
            "sha256": pinned_profile.sha256,
            "is_installed_schema": pinned_profile.sha256 == INSTALLED_SCHEMA,
            "operations": len(pinned_profile.operations),
            "version": PINNED_VERSION,
        },
        "candidate": {
            "sha256": hashlib.sha256(candidate).hexdigest(),
            "server_version": server_version,
        },
    }
    version_changed = server_version not in {None, PINNED_VERSION}
    report["version_changed"] = version_changed
    try:
        candidate_profile = OpenAPIProfile(candidate)
    except ContractError as error:
        if str(error) == "contract_not_json":
            raise CheckFailure("candidate_not_json") from None
        finding = Finding(
            "breaking", "contract", "contract_rejected", f"OpenAPIProfile refused it: {error}"
        )
        return finish(report, "breaking", [finding], set(), None, None)

    report["candidate"]["operations"] = len(candidate_profile.operations)
    old, new = pinned_profile.document, candidate_profile.document
    old_ops, new_ops = operations_of(old), operations_of(new)
    allowlisted = set(READ_OPERATIONS | MUTATION_OPERATIONS)
    scan = scan_source(set(old_ops) | set(new_ops) | allowlisted, package)
    used = set(scan.usage) | allowlisted
    same = report["pinned"]["sha256"] == report["candidate"]["sha256"]
    identical = old == new
    report["contract_changed"] = not same
    report["semantically_identical"] = identical
    report["documentation_only"] = not identical and strip_docs(old) == strip_docs(new)

    diff = ContractDiff(old, new)
    for name in sorted(used & old_ops.keys() & new_ops.keys()):
        diff.operation(name, old_ops[name], new_ops[name])
    for name in sorted((used & old_ops.keys()) - new_ops.keys()):
        kind = "mutation" if old_ops[name][0] != "GET" else "read"
        moved = [other for other, row in new_ops.items() if row[:2] == old_ops[name][:2]]
        detail = f"{kind} operation removed ({old_ops[name][0]} {old_ops[name][1]})"
        if moved:
            detail += f"; same route now named {moved[0]}"
        diff.fixed("breaking", f"operation:{name}", "operation_removed", detail)
    if old.get("components", {}).get("securitySchemes") != new.get("components", {}).get(
        "securitySchemes"
    ):
        diff.fixed("breaking", "contract", "security_schemes_changed", "security schemes changed")
    if old.get("security") != new.get("security"):
        diff.fixed("breaking", "contract", "global_security_changed", "global security changed")
    diff.drain()
    diff.attach_operations(used)
    pattern = schemas_of(new).get("Prompt.Base64", {}).get("pattern")
    if "Prompt.Base64" in schemas_of(new) and pattern != BASE64_PATTERN:
        diff.fixed(
            "breaking",
            "schema:Prompt.Base64",
            "hardcoded_pattern_changed",
            "security/schema_patterns.py only bounds the exact pinned pattern; memory use is unqualified",
        )

    core = core_summary(old, new)
    report["operations"] = {
        "used": len(used & (old_ops.keys() | new_ops.keys())),
        "called": sorted(n for n, m in scan.usage.items() if m != [f"{ADAPTERS}/transport.py"]),
        "transport_allowlist_only": sorted(
            n for n, m in scan.usage.items() if m == [f"{ADAPTERS}/transport.py"]
        ),
        "allowlisted_absent_from_pinned": sorted(allowlisted - old_ops.keys()),
        "removed_used": sorted((used & old_ops.keys()) - new_ops.keys()),
        "added_unused": sorted(new_ops.keys() - old_ops.keys() - used),
        "added_used": sorted((new_ops.keys() - old_ops.keys()) & used),
        "removed_unused": sorted(old_ops.keys() - new_ops.keys() - used),
        "changed_unused": unused_changes(
            old, new, sorted((old_ops.keys() & new_ops.keys()) - used)
        ),
    }
    report["core_schemas"] = core
    report["opaque_event_schemas"] = opaque_event_schemas(new)
    changed_ops = {op for f in diff.findings for op in f.operations if f.severity != "info"}
    transport = f"{ADAPTERS}/transport.py"
    # Every used operation is named in transport.py's allowlist; a schema edit rarely
    # touches it, so name it only when it is the sole reference or the route itself moved.
    modules = {
        m
        for op in changed_ops
        for m in (set(scan.usage.get(op, ())) - {transport} or scan.usage.get(op, ()))
    }
    if any(f.kind in {"operation_removed", "operation_moved"} for f in diff.findings):
        modules.add(transport)
    if not same or version_changed:
        verdict = (
            "breaking"
            if any(f.severity == "breaking" for f in diff.findings)
            else "additive"
            if not same
            else "version_only"
        )
    else:
        verdict = "same"
    return finish(report, verdict, diff.findings, modules, scan, changed_ops)


def finish(
    report: dict[str, Any],
    verdict: str,
    findings: list[Finding],
    modules: set[str],
    scan: SourceScan | None,
    changed_ops: set[str] | None,
) -> dict[str, Any]:
    exit_code = {
        "same": EXIT_SAME,
        "additive": EXIT_REQUALIFY,
        "version_only": EXIT_REQUALIFY,
        "breaking": EXIT_BREAKING,
    }[verdict]
    order = {"breaking": 0, "additive": 1, "info": 2}
    report["verdict"] = verdict
    report["exit_code"] = exit_code
    report["findings"] = [
        asdict(f) for f in sorted(findings, key=lambda f: (order[f.severity], f.where, f.detail))
    ]
    report["counts"] = {
        severity: sum(1 for f in findings if f.severity == severity) for severity in order
    }
    requalify = verdict != "same"
    report["affected"] = {
        "certificates": [
            {
                "kind": c.kind,
                "format": c.format,
                "enrollment": c.enrollment,
                "pins": c.pins,
                "code_review_required": bool(modules & set(c.modules)),
            }
            for c in (CERTIFICATES if requalify else ())
        ],
        "adapter_modules": sorted(modules),
        "changed_operations": sorted(changed_ops or ()),
        "contract_pin_modules": scan.contract_pins if scan and requalify else [],
        "version_pin_modules": scan.version_pins if scan and requalify else [],
    }
    report["next_steps"] = next_steps(verdict, report)
    report["limits"] = limits(report)
    return report


def next_steps(verdict: str, report: Mapping[str, Any]) -> list[str]:
    what_if = report["pinned"]["is_installed_schema"] is False
    if verdict == "same":
        steps = ["The candidate is byte-identical to the compared contract."]
        if what_if:
            steps.append("The compared contract is not INSTALLED_SCHEMA: this says nothing live.")
        return steps
    steps = []
    if verdict == "breaking":
        steps.append("Do not upgrade this host. Fix the listed adapter modules on a branch first.")
    if verdict == "version_only":
        steps.append(
            "The contract matches but the version does not: the owner proof pins the executable"
            " and version, and semantics digests embed the version, so Bridge still refuses it."
        )
    if report.get("semantically_identical"):
        steps.append(
            "Only the bytes differ, yet the pin is a byte hash, so Bridge still refuses it."
        )
    if what_if:
        steps.append("The compared contract is not INSTALLED_SCHEMA: this was a what-if.")
    steps += [
        "Stay on the pinned Native. Do not restart or replace it to test the candidate.",
        "Run the candidate on a separate host or port with synthetic data; never point it at the"
        " original data directory.",
        "Update the pinned fixture, INSTALLED_SCHEMA and every version pin listed, then run the"
        " full gate as a non-root unit.",
        "Re-issue every certificate listed from fresh GET-only evidence; old evidence never carries"
        " over. Keep the previous selected release and manifest for rollback.",
        "See docs/NATIVE_UPGRADE.md for the full order and the rollback.",
    ]
    return steps


def limits(report: Mapping[str, Any]) -> list[str]:
    notes = [
        "This compares declared contracts only. It observes no behaviour and qualifies nothing.",
    ]
    if report.get("opaque_event_schemas"):
        notes.append(
            "Event and log payloads are declared as an opaque JSON string ("
            + ", ".join(report["opaque_event_schemas"])
            + "): event-type and payload changes are invisible here. Requalify"
            " adapters/opencode/event_semantics.py against the candidate's source."
        )
    if report["candidate"].get("server_version") is None:
        notes.append("No server version was read, so a version-only change cannot be excluded.")
    return notes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        # A redirect could carry the Authorization header to another origin.
        return None


def http_get(url: str, authorization: str | None, limit: int) -> bytes:
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    if authorization is not None:
        request.add_unredirected_header("Authorization", authorization)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise CheckFailure(f"candidate_http_{error.code}") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise CheckFailure("candidate_unreachable") from None
    if len(raw) > limit:
        raise CheckFailure("candidate_response_too_large")
    return raw


def origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc


def basic(secret: str) -> str:
    return "Basic " + base64.b64encode(f"opencode:{secret}".encode()).decode()


def resolve_authorization(url: str, explicit: str | None, configured: Any) -> str | None:
    """Send the live credential only to its own origin; other targets need explicit opt-in."""
    reference = explicit
    if reference is None and configured is not None and origin(url) == origin(configured.base_url):
        reference = configured.credential_ref
    if reference is None:
        return None
    try:
        return basic(resolve_secret(reference).get_secret_value())
    except SecretUnavailable:
        raise CheckFailure("credential_unavailable") from None


def configured_backend(config: Path, backend_id: str | None) -> Any:
    try:
        settings = load_settings(config)
    except (OSError, ValueError):
        raise CheckFailure("configuration_unavailable") from None
    rows = [
        b for b in settings.opencode_backends if (b.id == backend_id if backend_id else b.enabled)
    ]
    if not rows:
        raise CheckFailure("configured_backend_not_found")
    return rows[0]


def load_pinned(explicit: Path | None, config: Path) -> tuple[bytes, str]:
    if explicit is not None:
        return read_limited(explicit, "pinned_contract_unreadable"), str(explicit)
    if PINNED_FIXTURE.is_file():
        return read_limited(PINNED_FIXTURE, "pinned_contract_unreadable"), str(PINNED_FIXTURE)
    # An installed wheel has no tests/: use the runtime manifest's own pinned file.
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment

    try:
        enrollment_file = load_settings(config).runtime.enrollment_file
        if enrollment_file is None:
            raise CheckFailure("pinned_contract_unavailable")
        schema = RuntimeEnrollment.model_validate_json(enrollment_file.read_bytes())
        row = schema.backends[0].schema_file
        return row.read(), str(row.path)
    except (OSError, ValueError, IndexError):
        raise CheckFailure("pinned_contract_unavailable") from None


def read_limited(path: Path, code: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CONTRACT_BYTES + 1)
    except OSError:
        raise CheckFailure(code) from None
    return raw


def read_server_version(base: str, authorization: str | None) -> str | None:
    try:
        info = json.loads(http_get(base.rstrip("/") + INFO_PATH, authorization, MAX_INFO_BYTES))
    except (CheckFailure, ValueError, RecursionError):
        return None
    version = info.get("version") if isinstance(info, dict) else None
    if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+_-]{1,64}", version):
        return version
    return None


def render(report: Mapping[str, Any]) -> str:
    lines = [
        f"verdict: {report['verdict']} (exit {report['exit_code']})",
        f"pinned:    {report['pinned']['sha256']}  ({report['pinned'].get('source', '-')})",
        f"candidate: {report['candidate']['sha256']}  ({report['candidate'].get('source', '-')})",
        f"server version: {report['candidate'].get('server_version') or 'not read'}"
        f" (pinned {report['pinned']['version']})",
    ]
    if report["pinned"]["is_installed_schema"] is False:
        lines.append("WARNING: the pinned contract is not INSTALLED_SCHEMA; this is a what-if.")
    counts = report["counts"]
    lines.append(
        f"findings: {counts['breaking']} breaking, {counts['additive']} additive, {counts['info']} info"
    )
    for severity in ("breaking", "additive"):
        rows = [f for f in report["findings"] if f["severity"] == severity]
        if rows:
            lines.append(f"\n{severity.upper()}")
        for row in rows:
            used = ", ".join(row["operations"]) or "no used operation"
            lines.append(f"  {row['where']}: {row['detail']} [{row['kind']}; {used}]")
    operations = report.get("operations")
    if operations:
        lines.append(f"\nOPERATIONS (Bridge uses {operations['used']})")
        for key in (
            "removed_used",
            "added_used",
            "removed_unused",
            "changed_unused",
            "added_unused",
        ):
            if operations[key]:
                lines.append(f"  {key}: {', '.join(operations[key])}")
    core = report.get("core_schemas")
    if core:
        lines.append(f"\nSESSION MESSAGE, PART AND EVENT SCHEMAS ({core['checked']} checked)")
        lines += [f"  {name}: {state}" for name, state in core["changes"].items()] or [
            "  unchanged"
        ]
        for label, row in core["unions"].items():
            if row["added"] or row["removed"]:
                lines.append(f"  {label}: added {row['added']} removed {row['removed']}")
    affected = report["affected"]
    if affected["certificates"]:
        lines.append("\nCERTIFICATES TO RE-ISSUE (* points at code needing review)")
        for row in affected["certificates"]:
            mark = "*" if row["code_review_required"] else " "
            lines.append(f" {mark} {row['kind']}: {row['pins']}")
    if affected["adapter_modules"]:
        lines.append("\nADAPTER MODULES TO REVIEW")
        lines += [f"  {module}" for module in affected["adapter_modules"]]
    for key, title in (
        ("contract_pin_modules", "MODULES PINNING THE CONTRACT HASH"),
        ("version_pin_modules", "MODULES PINNING THE VERSION"),
    ):
        if affected[key]:
            lines.append(f"\n{title}\n  " + ", ".join(affected[key]))
    lines.append("\nNEXT STEPS")
    lines += [f"  {index}. {step}" for index, step in enumerate(report["next_steps"], 1)]
    lines.append("\nLIMITS")
    lines += [f"  - {note}" for note in report["limits"]]
    # Schema names and enum values come from the candidate; keep them off the terminal raw.
    return re.sub(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", "?", "\n".join(lines))


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's default exit code 2 would read as "breaking differences".
        self.print_usage(sys.stderr)
        print(f"{self.prog}: {message}", file=sys.stderr)
        raise SystemExit(EXIT_UNEVALUATED)


def parser() -> argparse.ArgumentParser:
    result = _Parser(description="Evaluate a candidate OpenCode contract; GET only, never mutates.")
    source = result.add_mutually_exclusive_group()
    source.add_argument("--file", type=Path, help="candidate OpenAPI JSON file")
    source.add_argument("--url", help="candidate Native base URL (default: configured backend)")
    result.add_argument(
        "--openapi-path", default=OPENAPI_PATH, help="route of the OpenAPI document"
    )
    result.add_argument("--pinned", type=Path, help="compare against this contract (what-if)")
    result.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    result.add_argument("--backend", help="configured backend id (default: first enabled)")
    result.add_argument(
        "--credential-ref", help="env:NAME or file:/path for a --url other than the backend's"
    )
    result.add_argument("--json", action="store_true", help="print the report as JSON")
    return result


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.openapi_path.startswith("/") or re.search(r"[?#\s]|\.\.", args.openapi_path):
        raise CheckFailure("openapi_path_rejected")
    pinned, pinned_source = load_pinned(args.pinned, args.config)
    server_version = None
    if args.file is not None:
        candidate = read_limited(args.file, "candidate_file_unreadable")
        source = str(args.file)
    else:
        configured = None
        if args.url is None or args.config.exists():
            configured = configured_backend(args.config, args.backend)
        base = args.url or (configured.base_url if configured is not None else DEFAULT_URL)
        try:
            validate_endpoint(base)
        except ValueError:
            raise CheckFailure("candidate_url_rejected") from None
        authorization = resolve_authorization(base, args.credential_ref, configured)
        candidate = http_get(
            base.rstrip("/") + args.openapi_path, authorization, MAX_CONTRACT_BYTES
        )
        server_version = read_server_version(base, authorization)
        source = base.rstrip("/") + args.openapi_path
    try:
        report = evaluate(pinned, candidate, server_version=server_version)
    except ContractError:
        raise CheckFailure("pinned_contract_rejected") from None
    report["pinned"]["source"] = pinned_source
    report["candidate"]["source"] = source
    return report


def unevaluated(code: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"verdict": "error", "exit_code": EXIT_UNEVALUATED, "error": code}))
    else:
        print(f"could not evaluate: {code}", file=sys.stderr)
    return EXIT_UNEVALUATED


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        report = run(args)
    except CheckFailure as failure:
        return unevaluated(str(failure), args.json)
    except Exception as error:
        # A malformed candidate must not surface as Python's exit 1, which means "additive".
        return unevaluated(f"evaluation_failed_{type(error).__name__}", args.json)
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render(report))
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
