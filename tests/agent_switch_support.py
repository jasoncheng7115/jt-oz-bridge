"""Synthetic original Root + real adapters; never Native, Human or mobile evidence."""

import copy
import json
from dataclasses import dataclass, field, replace
from typing import Any

import httpx

from jt_oz_bridge.adapters.opencode.agent_configuration import AgentConfigurationCell
from jt_oz_bridge.adapters.opencode.agent_settings import (
    AGENT_SETTING_SEMANTICS,
    AGENT_SETTING_SOURCES,
    AgentSettingsAttestation,
    agent_policy_endpoint,
)
from jt_oz_bridge.adapters.opencode.agent_switch import AGENT_SWITCH_OPERATIONS, V2AgentSettings
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS
from jt_oz_bridge.domain.agent_selection import AgentPolicyEndpoint, AgentTransitionEnrollment
from tests.contract.test_native_project_policy import setup as policy_setup

ACTIVE = {"type": "running"}
BUILD_RULES = [{"action": "*", "resource": "*", "effect": "allow"}]
PLAN_RULES = [
    {"action": "*", "resource": "*", "effect": "allow"},
    {"action": "write", "resource": "*", "effect": "deny"},
]


def agent_row(identity: str, *, rules=None, mode="primary", hidden=False, **extra):
    # The build row matches the policy fixture, whose enrollment pins this exact policy.
    return {
        "id": identity,
        "name": identity.title(),
        "request": {"settings": {}, "headers": {}, "body": {}},
        "mode": mode,
        "hidden": hidden,
        "permissions": copy.deepcopy(rules if rules is not None else BUILD_RULES),
        **extra,
    }


@dataclass
class Root:
    proofs: Any
    transport: Any
    data: dict[str, Any]
    guard: Any
    client: V2ExecutionClient
    writes: list[Any]
    cell: AgentConfigurationCell
    settings: V2AgentSettings
    agents: dict[str, dict[str, Any]]
    rows: list[dict[str, Any]]
    # "ok", "lost_ack", "reject", "wrong_readback", "foreign_previous" or "no_record"
    post_mode: list[str] = field(default_factory=lambda: ["ok"])
    calls: list[str] = field(default_factory=list)

    @property
    def reference(self):
        return self.settings.reference

    def agent_posts(self) -> list[Any]:
        return [w for w in self.writes if w.url.path.endswith("/agent")]

    def prompt_posts(self) -> list[Any]:
        return [w for w in self.writes if w.url.path.endswith("/prompt")]

    def endpoint(self, identity: str) -> AgentPolicyEndpoint:
        info = {**self.data["session.get"]["data"], "agent": identity}
        return agent_policy_endpoint(
            self.transport.profile,
            self.reference,
            "global",
            info,
            {"location": self.data["plugin.list"]["location"], "data": self.agents[identity]},
            self.data["plugin.list"],
            self.data["permission.saved.list"],
            self.data["mcp.list"],
        )

    def transition(self, before: str, after: str) -> AgentTransitionEnrollment:
        return AgentTransitionEnrollment(
            format="native-agent-transition-v1",
            contract_sha256=self.transport.profile.sha256,
            permission_source_sha256=AGENT_SETTING_SOURCES["permission.ts"],
            before=self.endpoint(before),
            after=self.endpoint(after),
            installed_evidence_sha256="e" * 64,
        )

    def external_switch(self, identity: str) -> None:
        """Another Native client changed the Agent; the Bridge sent nothing."""
        self.record_switch(identity)

    def record_switch(self, identity: str) -> None:
        info = self.data["session.get"]["data"]
        created = info["time"]["updated"] + 1
        self.rows.insert(
            0,
            {
                "id": f"msg_switch_{len(self.rows)}",
                "type": "agent-switched",
                "time": {"created": created},
                "agent": identity,
                "previous": info["agent"],
            },
        )
        info["agent"] = identity
        info["time"]["updated"] = created


async def native_root(
    *, transitions: tuple[tuple[str, str], ...] = (("build", "plan"),), qualified: bool = True
) -> Root:
    p, t, d, guard, client, _policy, writes = await policy_setup()
    idle = copy.deepcopy(d["session.message.list"]["data"])
    agents = {
        "build": agent_row("build"),
        "plan": agent_row("plan", rules=PLAN_RULES),
        "review": agent_row("review", rules=PLAN_RULES),
        "helper": agent_row("helper", mode="subagent"),
        "secret": agent_row("secret", hidden=True),
    }
    d["agent.get"]["data"] = copy.deepcopy(agents["build"])
    # The session rules stay deny-all throughout: an Agent switch never expands them.
    state: dict[str, Any] = {}
    previous = t.client._transport

    def handler(request):
        path = request.url.path
        root: Root = state["root"]
        if request.method == "POST" and path.endswith("/agent"):
            writes.append(request)
            mode = root.post_mode.pop(0) if len(root.post_mode) > 1 else root.post_mode[0]
            if mode == "reject":
                return httpx.Response(
                    404,
                    json={
                        "_tag": "SessionNotFoundError",
                        "sessionID": root.reference.upstream_session_id,
                        "message": "synthetic",
                    },
                )
            body = json.loads(request.content)
            if mode != "no_record":
                root.record_switch(body["agent"])
            if mode == "foreign_previous":
                root.rows[0]["previous"] = "review"
            if mode == "wrong_readback":
                root.agents[body["agent"]]["permissions"].append(
                    {"action": "bash", "resource": "*", "effect": "allow"}
                )
            if mode == "lost_ack":
                raise httpx.ReadTimeout("synthetic lost acknowledgement", request=request)
            return httpx.Response(204)
        if request.method == "GET" and path == "/api/agent":
            return httpx.Response(
                200,
                json={
                    "location": d["plugin.list"]["location"],
                    "data": copy.deepcopy(list(root.agents.values())),
                },
            )
        if request.method == "GET" and path.startswith("/api/agent/"):
            identity = path.rsplit("/", 1)[1]
            return httpx.Response(
                200,
                json={
                    "location": d["plugin.list"]["location"],
                    "data": copy.deepcopy(root.agents[identity]),
                },
            )
        if request.method == "GET" and path.endswith("/message"):
            limit = int(request.url.params.get("limit", "50"))
            return httpx.Response(
                200, json={"data": copy.deepcopy(root.rows[:limit]), "cursor": {}}
            )
        return previous.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    t.attestation = replace(
        t.attestation,
        verified_operations=t.attestation.verified_operations
        | POLICY_READS
        | set(AGENT_SWITCH_OPERATIONS)
        | {"session.switchModel", "model.list", "model.default"},
    )
    reference = next(iter(guard.enrollments))
    attestation = AgentSettingsAttestation(
        reference=reference,
        native_project_id="global",
        contract_sha256=t.profile.sha256,
        semantics_sha256=AGENT_SETTING_SEMANTICS,
        switch_evidence_sha256="a" * 64,
        mixed_tail_evidence_sha256="b" * 64,
        policy_transition_evidence_sha256="c" * 64,
    )
    p.model_settings = ModelSettingsAttestation(
        reference, t.profile.sha256, MODEL_SETTING_SEMANTICS, "d" * 64
    )
    cell = AgentConfigurationCell({reference: attestation} if qualified else {})
    p.feed.agent_configuration = cell
    root = Root(
        p,
        t,
        d,
        guard,
        client,
        writes,
        cell,
        V2AgentSettings(client, reference, attestation, ()),
        agents,
        idle,
    )
    state["root"] = root
    await p.watch(reference)
    root.settings.transitions = tuple(root.transition(a, b) for a, b in transitions)
    return root


@dataclass
class Topic:
    root: Root
    router: Any
    source: Any
    binding: Any
    bindings: Any
    registry: Any
    coordinator: Any
    worker: Any
    commands: Any
    audience: Any
    db: Any
    fence: Any


async def bound_topic(db, root: Root, *, holder: str = "agent-switch") -> Topic:
    """Real local DB/router/dispatcher over the synthetic Root; no Zulip or Native I/O."""
    from jt_oz_bridge.services.agent_commands import AgentCommands
    from jt_oz_bridge.services.agent_configuration import AgentConfigurationRegistry
    from jt_oz_bridge.services.agent_switch_coordinator import AgentSwitchCoordinator
    from jt_oz_bridge.services.bindings import BindingService
    from jt_oz_bridge.services.command_receipts import CommandInbox
    from jt_oz_bridge.services.dispatch import Dispatcher
    from jt_oz_bridge.services.router import CommandRouter
    from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence
    from jt_oz_bridge.storage.models import Grant
    from jt_oz_bridge.storage.session_configuration_heads import SessionConfigurationHeads
    from tests.integration.test_router import Source
    from tests.support import SyntheticAudience

    ref = root.reference
    root.client.contract_hash = root.transport.profile.sha256  # type: ignore[attr-defined]
    audience = SyntheticAudience()
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=ref.backend_id,
                identity=ref.backend_identity,
                contract_hash=root.transport.profile.sha256,
                enabled=True,
                verified=True,
                version="synthetic-contract-test",
            )
        )
        session.add(
            EnrolledProject(
                id=ref.project_id,
                backend_id=ref.backend_id,
                realm_id="realm",
                canonical_directory=ref.canonical_directory,
                enabled=True,
            )
        )
        for user, role in ((7, "operator"), (7, "approver"), (8, "viewer")):
            session.add(Grant(realm_id="realm", user_id=user, project_id=ref.project_id, role=role))
    bindings = BindingService(db, root.client, audience)
    binding = await bindings.bind("realm", 7, 10, "Original work", ref)
    fencing = await DurableStore(db).acquire_lease(holder, ttl=120)
    assert fencing is not None
    fence = ConsumerFence(holder, fencing)
    source = Source()
    router = CommandRouter(
        bindings,
        source,
        CommandInbox(db, holder, fencing),
        capabilities=root.client.capabilities,
    )
    heads = SessionConfigurationHeads(db, fence, enabled=True)
    registry = AgentConfigurationRegistry(
        heads,
        root.cell,
        {ref: root.settings},
        {ref: ("1" * 64, "2" * 64)},
        {ref: root.guard.enrollments[ref].fingerprint_sha256},
    )
    commands = AgentCommands(bindings, registry, router.tokens, source)
    router.agents = commands
    coordinator = AgentSwitchCoordinator(bindings, registry, source, fence, realm_id="realm")
    worker = Dispatcher(bindings, root.client, source, holder, fencing)
    return Topic(
        root,
        router,
        source,
        binding,
        bindings,
        registry,
        coordinator,
        worker,
        commands,
        audience,
        db,
        fence,
    )
