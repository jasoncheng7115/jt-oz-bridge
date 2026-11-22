"""Native upgrade evaluation: real fixture contracts plus targeted synthetic edits."""

import base64
import copy
import functools
import importlib.util
import json
import subprocess
import sys
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/fixtures/contracts"
INSTALLED = FIXTURES / "opencode-v2.0.32-installed.json"
OLDER = FIXTURES / "opencode-v2.0.30-openapi.json"
TOOL = ROOT / "ops/server/check_native_upgrade.py"
SPEC = importlib.util.spec_from_file_location("check_native_upgrade", TOOL)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)

PINNED = INSTALLED.read_bytes()
SECRET = "unit-test-native-credential-value"
REAL_SCAN = tool.scan_source


@functools.cache
def scan_once(operations: frozenset[str], package: Path) -> Any:
    return REAL_SCAN(set(operations), package)


@pytest.fixture(autouse=True)
def cached_source_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    # Parsing every package module costs seconds. Each distinct operation set still gets
    # one real scan; only the repeats across these synthetic contract edits are reused.
    monkeypatch.setattr(
        tool,
        "scan_source",
        lambda names, package=tool.PACKAGE: scan_once(frozenset(names), package),
    )


def edited(change: Callable[[dict[str, Any]], Any]) -> bytes:
    document = copy.deepcopy(json.loads(PINNED))
    change(document)
    return json.dumps(document).encode()


def evaluate(change: Callable[[dict[str, Any]], Any], **options: Any) -> dict[str, Any]:
    return tool.evaluate(PINNED, edited(change), **options)


def operation(document: dict[str, Any], name: str) -> dict[str, Any]:
    return tool.operations_of(document)[name][2]


def schemas(document: dict[str, Any]) -> dict[str, Any]:
    return document["components"]["schemas"]


def findings(report: dict[str, Any], severity: str | None = None) -> list[dict[str, Any]]:
    return [f for f in report["findings"] if severity in {None, f["severity"]}]


def kinds(report: dict[str, Any], severity: str | None = None) -> set[str]:
    return {f["kind"] for f in findings(report, severity)}


def test_identical_bytes_are_the_same_contract() -> None:
    report = tool.evaluate(PINNED, PINNED)
    assert (report["verdict"], report["exit_code"]) == ("same", 0)
    assert report["findings"] == []
    assert report["affected"]["certificates"] == []
    assert report["pinned"]["is_installed_schema"] is True


def test_older_fixture_as_candidate_is_breaking_for_model_operations() -> None:
    report = tool.evaluate(PINNED, OLDER.read_bytes())
    assert (report["verdict"], report["exit_code"]) == ("breaking", 2)
    [finding] = findings(report, "breaking")
    assert finding["where"] == "schema:Model.Capabilities/temperature"
    assert finding["kind"] == "property_removed"
    assert {"model.list", "model.default"} <= set(finding["operations"])
    assert report["operations"]["removed_unused"] == ["experimental.voice.session"]
    assert "config.get" in report["operations"]["changed_unused"]
    assert report["core_schemas"]["changes"] == {}


def test_real_upgrade_direction_is_additive_and_flagged_as_what_if() -> None:
    report = tool.evaluate(OLDER.read_bytes(), PINNED)
    assert (report["verdict"], report["exit_code"]) == ("additive", 1)
    assert report["pinned"]["is_installed_schema"] is False
    [finding] = findings(report, "additive")
    assert finding["kind"] == "property_added_optional"
    assert report["operations"]["added_unused"] == ["experimental.voice.session"]
    assert findings(report, "breaking") == []
    assert any("what-if" in step for step in report["next_steps"])


def test_any_changed_contract_invalidates_every_certificate_and_marks_touched_code() -> None:
    report = tool.evaluate(OLDER.read_bytes(), PINNED)
    rows = {row["kind"]: row for row in report["affected"]["certificates"]}
    assert set(rows) == {c.kind for c in tool.CERTIFICATES}
    assert rows["model-settings"]["code_review_required"] is True
    assert rows["native-file-read"]["code_review_required"] is False
    assert "adapters/opencode/model_catalog.py" in report["affected"]["adapter_modules"]
    assert "adapters/opencode/transport.py" not in report["affected"]["adapter_modules"]
    assert "adapters/opencode/resources.py" in report["affected"]["contract_pin_modules"]
    assert "adapters/opencode/files.py" in report["affected"]["version_pin_modules"]


def test_reformatted_bytes_still_need_requalification_because_the_pin_is_a_byte_hash() -> None:
    report = tool.evaluate(PINNED, json.dumps(json.loads(PINNED), indent=1).encode())
    assert (report["verdict"], report["exit_code"]) == ("additive", 1)
    assert report["semantically_identical"] is True
    assert report["findings"] == []
    assert any("byte hash" in step for step in report["next_steps"])


def test_documentation_only_edits_are_not_findings_and_a_property_named_description_counts() -> (
    None
):
    report = evaluate(
        lambda d: (
            operation(d, "session.get").update(description="reworded")
            or schemas(d)["Session.Info"].update(description="reworded")
        )
    )
    assert report["documentation_only"] is True
    assert report["findings"] == []
    assert report["exit_code"] == 1

    def drop_property(document: dict[str, Any]) -> None:
        schemas(document)["ServerInfo"]["properties"]["description"] = {"type": "string"}

    assert tool.strip_docs(json.loads(edited(drop_property))) != tool.strip_docs(json.loads(PINNED))


def test_same_contract_with_a_new_server_version_still_requires_requalification() -> None:
    assert tool.evaluate(PINNED, PINNED, server_version="2.0.32")["verdict"] == "same"
    report = tool.evaluate(PINNED, PINNED, server_version="2.0.33")
    assert (report["verdict"], report["exit_code"]) == ("version_only", 1)
    assert report["affected"]["certificates"]
    assert any("executable" in step for step in report["next_steps"])


def remove_operation(document: dict[str, Any], name: str) -> None:
    _, path, _ = tool.operations_of(document)[name]
    method = tool.operations_of(document)[name][0].lower()
    del document["paths"][path][method]


def test_removed_used_operation_is_breaking_and_says_read_or_mutation() -> None:
    report = evaluate(lambda d: remove_operation(d, "session.prompt"))
    assert report["exit_code"] == 2
    assert report["operations"]["removed_used"] == ["session.prompt"]
    [finding] = [f for f in findings(report, "breaking") if f["kind"] == "operation_removed"]
    assert finding["detail"].startswith("mutation operation removed")
    assert finding["operations"] == ["session.prompt"]
    assert "adapters/opencode/execution.py" in report["affected"]["adapter_modules"]
    assert "adapters/opencode/transport.py" in report["affected"]["adapter_modules"]


def test_renaming_an_operation_on_the_same_route_is_named_in_the_finding() -> None:
    report = evaluate(lambda d: operation(d, "session.get").update(operationId="session.read"))
    [finding] = [f for f in findings(report, "breaking") if f["kind"] == "operation_removed"]
    assert finding["detail"].startswith("read operation removed")
    assert finding["detail"].endswith("same route now named session.read")


def test_moved_route_is_breaking() -> None:
    def move(document: dict[str, Any]) -> None:
        _, path, _ = tool.operations_of(document)["session.get"]
        document["paths"]["/api/v3/session/{sessionID}"] = {
            "get": document["paths"][path].pop("get")
        }

    report = evaluate(move)
    assert kinds(report, "breaking") == {"operation_moved"}


def test_unused_operation_changes_are_informational_only() -> None:
    def change(document: dict[str, Any]) -> None:
        remove_operation(document, "experimental.voice.session")
        document["paths"]["/api/new-thing"] = {
            "get": {"operationId": "new.thing", "responses": {"204": {"description": "ok"}}}
        }

    report = evaluate(change)
    assert (report["verdict"], report["exit_code"]) == ("additive", 1)
    assert report["findings"] == []
    assert report["operations"]["added_unused"] == ["new.thing"]
    assert report["operations"]["removed_unused"] == ["experimental.voice.session"]


def parameter(document: dict[str, Any], op: str, name: str) -> dict[str, Any]:
    return next(p for p in operation(document, op)["parameters"] if p["name"] == name)


@pytest.mark.parametrize(
    ("change", "severity", "kind"),
    [
        (
            lambda d: operation(d, "session.message.list")["parameters"].append(
                {"name": "extra", "in": "query", "schema": {"type": "string"}}
            ),
            "additive",
            "property_added_optional",
        ),
        (
            lambda d: operation(d, "session.message.list")["parameters"].append(
                {"name": "extra", "in": "query", "required": True, "schema": {"type": "string"}}
            ),
            "breaking",
            "property_added_required",
        ),
        (
            lambda d: operation(d, "session.message.list")["parameters"].remove(
                parameter(d, "session.message.list", "limit")
            ),
            "breaking",
            "property_removed",
        ),
        (
            lambda d: parameter(d, "session.message.list", "limit").update(required=True),
            "breaking",
            "became_required",
        ),
        (
            lambda d: parameter(d, "session.message.list", "order")["schema"]["anyOf"][0][
                "enum"
            ].remove("desc"),
            "breaking",
            "value_removed",
        ),
        (
            lambda d: parameter(d, "session.message.list", "order")["schema"]["anyOf"][0][
                "enum"
            ].append("random"),
            "additive",
            "value_added",
        ),
    ],
)
def test_request_parameters_are_compared_from_the_sender_side(
    change: Callable[[dict[str, Any]], Any], severity: str, kind: str
) -> None:
    report = evaluate(change)
    assert kinds(report) == {kind}
    [finding] = findings(report)
    assert finding["severity"] == severity
    assert finding["operations"] == ["session.message.list"]
    assert report["exit_code"] == (2 if severity == "breaking" else 1)


def test_same_edit_reads_differently_on_the_consumer_side() -> None:
    def add_status(document: dict[str, Any]) -> None:
        schema = schemas(document)["Session.Message.Assistant"]["properties"]["type"]
        schema["enum"].append("assistant-v2")

    report = evaluate(add_status)
    assert report["exit_code"] == 2
    assert kinds(report, "breaking") == {"value_added"}
    assert "session.message.list" in findings(report, "breaking")[0]["operations"]


def test_new_message_type_and_part_are_reported_as_breaking_unions() -> None:
    def change(document: dict[str, Any]) -> None:
        body = schemas(document)
        body["Session.Message.Hologram"] = {
            "type": "object",
            "properties": {"type": {"type": "string", "enum": ["hologram"]}},
        }
        ref = {"$ref": "#/components/schemas/Session.Message.Hologram"}
        body["Session.Message.Info"]["anyOf"].append(ref)
        body["Session.Message.Assistant"]["properties"]["content"]["items"]["anyOf"].append(ref)

    report = evaluate(change)
    assert report["exit_code"] == 2
    unions = report["core_schemas"]["unions"]
    assert unions["message_types"]["added"] == ["type=hologram"]
    assert unions["assistant_parts"]["added"] == ["type=hologram"]
    assert report["core_schemas"]["changes"]["Session.Message.Hologram"] == "added"
    assert "union branch added: ref:Session.Message.Hologram" in {
        f["detail"] for f in findings(report, "breaking")
    }


def test_removed_required_and_response_properties() -> None:
    required = schemas(json.loads(PINNED))["Session.Info"]["required"][0]

    def drop(document: dict[str, Any]) -> None:
        del schemas(document)["Session.Info"]["properties"][required]
        schemas(document)["Session.Info"]["required"].remove(required)

    report = evaluate(drop)
    assert kinds(report, "breaking") == {"property_removed"}
    assert "session.get" in findings(report, "breaking")[0]["operations"]
    assert "Session.Info" in report["core_schemas"]["changes"]

    report = evaluate(lambda d: schemas(d)["Session.Info"]["required"].remove(required))
    assert kinds(report, "breaking") == {"became_optional"}


def test_new_required_response_property_is_additive_for_the_consumer() -> None:
    def add(document: dict[str, Any]) -> None:
        schema = schemas(document)["ServerInfo"]
        schema["properties"]["build"] = {"type": "string"}
        schema["required"].append("build")

    report = evaluate(add)
    assert kinds(report) == {"property_added_required"}
    assert report["exit_code"] == 1


def test_new_required_request_body_property_is_breaking_for_the_sender() -> None:
    def add(document: dict[str, Any]) -> None:
        content = operation(document, "session.create")["requestBody"]["content"]
        schema = content["application/json"]["schema"]
        schema["properties"]["mandatory"] = {"type": "string"}
        schema.setdefault("required", []).append("mandatory")

    report = evaluate(add)
    assert kinds(report, "breaking") == {"property_added_required"}
    assert report["exit_code"] == 2


def test_responses_status_and_media_types() -> None:
    report = evaluate(lambda d: operation(d, "session.get")["responses"].pop("200"))
    assert kinds(report, "breaking") == {"response_status_removed"}

    report = evaluate(
        lambda d: operation(d, "session.get")["responses"].update({"418": {"description": "tea"}})
    )
    assert kinds(report) == {"response_status_added"}
    assert report["exit_code"] == 1

    def binary_to_json(document: dict[str, Any]) -> None:
        response = operation(document, "fs.read")["responses"]["200"]
        response["content"]["application/json"] = response["content"].pop(
            "application/octet-stream"
        )

    report = evaluate(binary_to_json)
    assert report["exit_code"] == 2
    assert {f["detail"] for f in findings(report, "breaking")} == {
        "media type added: application/json",
        "media type removed: application/octet-stream",
    }

    def binary_format(document: dict[str, Any]) -> None:
        content = operation(document, "fs.read")["responses"]["200"]["content"]
        content["application/octet-stream"]["schema"]["format"] = "base64"

    assert kinds(evaluate(binary_format), "breaking") == {"opaque_changed"}


def test_changed_security_is_breaking() -> None:
    report = evaluate(lambda d: operation(d, "session.get").update(security=[{"basic": []}]))
    assert kinds(report, "breaking") == {"operation_security_changed"}
    report = evaluate(lambda d: d["components"].update(securitySchemes={"basic": {"type": "http"}}))
    assert kinds(report, "breaking") == {"security_schemes_changed"}
    report = evaluate(lambda d: d.update(security=[{"basic": []}]))
    assert kinds(report, "breaking") == {"global_security_changed"}


def test_changing_the_base64_pattern_flags_the_hardcoded_memory_bound() -> None:
    report = evaluate(lambda d: schemas(d)["Prompt.Base64"].update(pattern="^[A-Za-z0-9+/=]*$"))
    assert report["exit_code"] == 2
    assert "hardcoded_pattern_changed" in kinds(report, "breaking")


def test_regenerated_schema_names_are_followed_structurally() -> None:
    def renumber(document: dict[str, Any]) -> None:
        body = schemas(document)
        body["Session.Message.ProviderState_99"] = body.pop("Session.Message.ProviderState_1")
        raw = json.dumps(document).replace(
            '#/components/schemas/Session.Message.ProviderState_1"',
            '#/components/schemas/Session.Message.ProviderState_99"',
        )
        document.clear()
        document.update(json.loads(raw))

    report = evaluate(renumber)
    assert findings(report, "breaking") == []
    assert findings(report, "additive") == []
    assert "reference_changed" in kinds(report, "info")
    assert report["exit_code"] == 1


def test_recursive_references_terminate() -> None:
    def recursive(document: dict[str, Any]) -> None:
        body = schemas(document)
        loop = {"$ref": "#/components/schemas/Loop"}
        body["Loop"] = {"type": "object", "properties": {"next": loop}}
        body["Session.Info"]["properties"]["loop"] = loop

    report = evaluate(recursive)
    assert kinds(report) == {"property_added_optional"}


def test_widening_a_scalar_to_nullable_is_a_new_response_branch() -> None:
    def nullable(document: dict[str, Any]) -> None:
        version = schemas(document)["ServerInfo"]["properties"]["version"]
        schemas(document)["ServerInfo"]["properties"]["version"] = {
            "anyOf": [version, {"type": "null"}]
        }

    report = evaluate(nullable)
    assert report["exit_code"] == 2
    assert {f["detail"] for f in findings(report, "breaking")} == {
        'union branch added: type:"null"'
    }


def test_additional_properties_treat_absent_and_true_alike() -> None:
    def explicit_true(document: dict[str, Any]) -> None:
        schemas(document)["Session.Message.Assistant"]["properties"]["metadata"][
            "additionalProperties"
        ] = True

    assert findings(evaluate(explicit_true)) == []
    report = evaluate(lambda d: schemas(d)["ServerInfo"].update(additionalProperties=True))
    assert kinds(report, "breaking") == {"bound_relaxed"}


def test_rejected_contract_is_breaking() -> None:
    report = evaluate(lambda d: d.update(openapi="3.0.3"))
    assert (report["verdict"], report["exit_code"]) == ("breaking", 2)
    assert kinds(report) == {"contract_rejected"}
    assert "unsupported_contract_format" in report["findings"][0]["detail"]
    assert report["affected"]["certificates"]


def test_opaque_event_payloads_are_stated_as_a_limit() -> None:
    report = tool.evaluate(PINNED, PINNED)
    assert report["opaque_event_schemas"] == ["V2EventEncoded", "SessionLogItemEncoded"]
    assert any("event_semantics" in note for note in report["limits"])


def test_source_scan_finds_real_references_only() -> None:
    report = tool.evaluate(PINNED, PINNED)["operations"]
    assert {"event.subscribe", "fs.read", "session.prompt", "session.message.list"} <= set(
        report["called"]
    )
    # A real, declared operation that no adapter names stays out of "used".
    used = {*report["called"], *report["transport_allowlist_only"]}
    assert "experimental.voice.session" not in used
    assert set(report["allowlisted_absent_from_pinned"]) == {
        "filesystem.find",
        "filesystem.list",
        "filesystem.read",
    }


def test_source_scan_distinguishes_adapters_from_service_call_sites(tmp_path: Path) -> None:
    adapters = tmp_path / "adapters/opencode"
    adapters.mkdir(parents=True)
    (tmp_path / "services").mkdir()
    (adapters / "reader.py").write_text('NAME = "a.b"\n')
    (tmp_path / "services/worker.py").write_text(
        'await_me = client.request("c.d")\nLABEL = "e.f"\nPIN = "2.0.32"\n'
    )
    scan = tool.scan_source({"a.b", "c.d", "e.f"}, tmp_path)
    assert scan.usage == {"a.b": ["adapters/opencode/reader.py"], "c.d": ["services/worker.py"]}
    assert scan.version_pins == ["services/worker.py"]


def test_certificate_table_matches_the_source() -> None:
    package = ROOT / "src/jt_oz_bridge"
    source = "\n".join(p.read_text() for p in package.rglob("*.py"))
    assert len({c.kind for c in tool.CERTIFICATES}) == len(tool.CERTIFICATES)
    for certificate in tool.CERTIFICATES:
        assert certificate.format is None or f'"{certificate.format}"' in source
        assert (package / certificate.enrollment).is_file()
        for module in certificate.modules:
            assert (package / module).is_file(), module


def test_pins_match_the_preserved_fixture() -> None:
    report = tool.evaluate(PINNED, PINNED)
    assert report["pinned"]["sha256"] == tool.INSTALLED_SCHEMA
    assert tool.PINNED_FIXTURE == INSTALLED


def test_severity_table_is_total() -> None:
    for row in tool.SEVERITY.values():
        assert set(row) == {"request", "response", "error"}
        assert set(row.values()) <= {"breaking", "additive"}


def test_rendered_output_cannot_carry_terminal_controls() -> None:
    report = tool.evaluate(
        PINNED,
        edited(lambda d: schemas(d)["ServerInfo"]["properties"].update({"x\x1b[2J": {}})),
    )
    report["pinned"]["source"] = report["candidate"]["source"] = "test"
    text = tool.render(report)
    assert "\x1b" not in text
    assert "x?[2J" in text


class FakeNative:
    """Records every request; serves the requested bytes on the real HTTP stack."""

    def __init__(self, contract: bytes, *, status: int = 200, redirect: bool = False) -> None:
        self.requests: list[tuple[str, str, str | None]] = []
        native = self

        class Handler(BaseHTTPRequestHandler):
            def do_any(self) -> None:
                native.requests.append((self.command, self.path, self.headers.get("Authorization")))
                if redirect and self.path == "/openapi.json":
                    self.send_response(302)
                    self.send_header("Location", "/stolen")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = {
                    "/openapi.json": contract,
                    "/api/info": json.dumps({"version": "2.0.32"}).encode(),
                }.get(self.path, b"{}")
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_any

            def log_message(self, *_: Any) -> None:
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeNative":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "credential"
    path.write_text(SECRET)
    path.chmod(0o600)
    return path


def expected_header() -> str:
    return "Basic " + base64.b64encode(f"opencode:{SECRET}".encode()).decode()


def test_live_check_uses_configured_credential_get_only_and_never_prints_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.toml"
    config.write_text("")
    with FakeNative(PINNED) as native:
        backend = SimpleNamespace(
            id="server",
            enabled=True,
            base_url=native.base,
            credential_ref=f"file:{secret_file(tmp_path)}",
        )
        monkeypatch.setattr(
            tool, "load_settings", lambda _: SimpleNamespace(opencode_backends=[backend])
        )
        for flags in ([], ["--json"]):
            assert tool.main(["--config", str(config), *flags]) == 0
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err
    assert base64.b64encode(f"opencode:{SECRET}".encode()).decode() not in out.out + out.err
    assert json.loads(out.out[out.out.index('{\n  "format"') :])["candidate"]["server_version"] == (
        "2.0.32"
    )
    assert native.requests
    assert {method for method, _, _ in native.requests} == {"GET"}
    assert {path for _, path, _ in native.requests} == {"/openapi.json", "/api/info"}
    assert {auth for _, _, auth in native.requests} == {expected_header()}


def test_live_credential_never_goes_to_another_origin(tmp_path: Path) -> None:
    backend = SimpleNamespace(
        base_url="http://127.0.0.1:4096", credential_ref=f"file:{secret_file(tmp_path)}"
    )
    assert tool.resolve_authorization("http://127.0.0.1:4096", None, backend) == expected_header()
    assert tool.resolve_authorization("http://127.0.0.1:4097", None, backend) is None
    assert tool.resolve_authorization("http://localhost:4096", None, backend) is None
    assert tool.resolve_authorization("http://127.0.0.1:4097", None, None) is None
    explicit = f"file:{secret_file(tmp_path)}"
    assert tool.resolve_authorization("http://127.0.0.1:4097", explicit, None) == expected_header()


def test_unavailable_credential_cannot_evaluate(tmp_path: Path) -> None:
    with pytest.raises(tool.CheckFailure, match="credential_unavailable"):
        tool.resolve_authorization("http://127.0.0.1:4097", f"file:{tmp_path}/absent", None)


def test_url_that_would_expose_a_credential_is_refused(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    config = tmp_path / "absent.toml"
    for url in ("http://203.0.113.9:4096", "http://user:pw@127.0.0.1:4096", "file:///etc/passwd"):
        assert tool.main(["--url", url, "--config", str(config)]) == 3
    assert "candidate_url_rejected" in capsys.readouterr().err


def test_breaking_candidate_over_http_exits_two(tmp_path: Path) -> None:
    config = tmp_path / "absent.toml"
    with FakeNative(OLDER.read_bytes()) as native:
        assert tool.main(["--url", native.base, "--config", str(config)]) == 2
    assert {auth for _, _, auth in native.requests} == {None}


@pytest.mark.parametrize("status", [401, 404, 500])
def test_http_failure_is_never_read_as_compatible(tmp_path: Path, status: int) -> None:
    config = tmp_path / "absent.toml"
    with FakeNative(PINNED, status=status) as native:
        assert tool.main(["--url", native.base, "--config", str(config)]) == 3


def test_redirect_is_not_followed_so_the_credential_cannot_leak(tmp_path: Path) -> None:
    config = tmp_path / "absent.toml"
    reference = f"file:{secret_file(tmp_path)}"
    with FakeNative(PINNED, redirect=True) as native:
        code = tool.main(
            ["--url", native.base, "--credential-ref", reference, "--config", str(config)]
        )
    assert code == 3
    assert [path for _, path, _ in native.requests] == ["/openapi.json"]


def test_unreachable_candidate_exits_three(tmp_path: Path) -> None:
    with FakeNative(PINNED) as native:
        base = native.base
    assert tool.main(["--url", base, "--config", str(tmp_path / "absent.toml")]) == 3


def test_candidate_file_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert tool.main(["--file", str(INSTALLED)]) == 0
    assert tool.main(["--file", str(OLDER)]) == 2
    assert tool.main(["--pinned", str(OLDER), "--file", str(INSTALLED)]) == 1
    capsys.readouterr()
    assert tool.main(["--file", str(OLDER), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "native-upgrade-check-v1"
    assert report["pinned"]["source"] == str(INSTALLED)

    junk = tmp_path / "junk.json"
    junk.write_bytes(b"<html>login</html>")
    assert tool.main(["--file", str(junk)]) == 3
    assert "candidate_not_json" in capsys.readouterr().err
    assert tool.main(["--file", str(tmp_path / "absent.json"), "--json"]) == 3
    assert json.loads(capsys.readouterr().out)["error"] == "candidate_file_unreadable"


def test_malformed_candidate_is_unevaluated_not_a_python_exit_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(
        edited(lambda d: operation(d, "session.message.list")["parameters"].append({"in": "query"}))
    )
    assert tool.main(["--file", str(malformed)]) == 3
    assert "evaluation_failed_KeyError" in capsys.readouterr().err


def test_argument_errors_do_not_look_like_breaking_differences(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        tool.main(["--no-such-flag"])
    assert stopped.value.code == 3
    with pytest.raises(SystemExit) as stopped:
        tool.main(["--file", "a", "--url", "b"])
    assert stopped.value.code == 3
    capsys.readouterr()


def test_openapi_path_is_constrained(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for path in ("relative", "/a/../b", "/a?x=1"):
        assert tool.main(["--openapi-path", path, "--file", str(INSTALLED)]) == 3
    assert "openapi_path_rejected" in capsys.readouterr().err


def test_missing_pinned_contract_cannot_evaluate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(tool, "PINNED_FIXTURE", tmp_path / "absent.json")
    code = tool.main(["--file", str(INSTALLED), "--config", str(tmp_path / "absent.toml")])
    assert code == 3
    assert "pinned_contract_unavailable" in capsys.readouterr().err


def test_installed_wheel_uses_the_runtime_manifest_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jt_oz_bridge.services.runtime_enrollment import RuntimeEnrollment

    monkeypatch.setattr(tool, "PINNED_FIXTURE", tmp_path / "absent.json")
    manifest = tmp_path / "runtime.json"
    manifest.write_text("{}")
    monkeypatch.setattr(
        tool,
        "load_settings",
        lambda _: SimpleNamespace(runtime=SimpleNamespace(enrollment_file=manifest)),
    )
    row = SimpleNamespace(read=lambda: PINNED, path=Path("/etc/pinned/schema.json"))
    monkeypatch.setattr(
        RuntimeEnrollment,
        "model_validate_json",
        lambda _: SimpleNamespace(backends=[SimpleNamespace(schema_file=row)]),
    )
    assert tool.load_pinned(None, tmp_path / "config.toml") == (PINNED, "/etc/pinned/schema.json")
    assert (
        "schema_file"
        in RuntimeEnrollment.model_fields["backends"].annotation.__args__[0].model_fields
    )


def test_missing_project_code_exits_three_not_python_exit_one() -> None:
    # -I -S hides the project; Python's default failure exit 1 would read as "additive".
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(TOOL), "--file", str(INSTALLED)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert done.returncode == 3
    assert "project_import_failed_ModuleNotFoundError" in done.stderr
    assert "Traceback" not in done.stderr
