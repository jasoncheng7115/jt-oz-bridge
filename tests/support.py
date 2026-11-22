from jt_oz_bridge.domain.control import AudienceSnapshot, ExecutionState, SessionSnapshot
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.models import Grant

REF = SessionRef(
    backend_id="backend",
    backend_identity="enrolled-installation",
    upstream_session_id="original-session",
    project_id="project",
    canonical_directory="/workspace/project",
)


class SyntheticControl:
    """Domain test double only; never a certification fixture or live adapter."""

    contract_hash = "a" * 64

    def contract_for(self, reference):
        return self.contract_hash

    def __init__(self):
        self.ref = REF
        self.descendants = ()
        self.resolved = False
        self.requests = {}
        self.calls = []

    async def snapshot(self, reference):
        self.calls.append(("snapshot", reference))
        return SessionSnapshot(
            reference=self.ref,
            title="Original running work",
            state=ExecutionState.RUNNING,
            cursor="snapshot-plus-stream:1",
            reconciled=True,
            descendants=self.descendants,
        )

    async def interaction(self, reference, request_id):
        self.calls.append(("interaction", reference))
        return self.requests[request_id].model_copy(update={"pending": not self.resolved})


class SyntheticAudience:
    def __init__(self):
        self.users = frozenset({7, 8})
        self.private = True
        self.revision = "audience:1"

    async def inspect(self, realm, channel, topic):
        return AudienceSnapshot(
            realm_id=realm,
            channel_id=channel,
            canonical_topic=topic,
            user_ids=self.users,
            private=self.private,
            revision=self.revision,
        )


async def service(db, control=None, audience=None):
    control = control or SyntheticControl()
    audience = audience or SyntheticAudience()
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id="backend",
                identity=REF.backend_identity,
                contract_hash=control.contract_hash,
                enabled=True,
                verified=True,
                version="synthetic-contract-test",
            )
        )
        session.add(
            EnrolledProject(
                id="project",
                backend_id="backend",
                realm_id="realm",
                canonical_directory=REF.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            for role in ("operator", "approver", "administrator"):
                session.add(Grant(realm_id="realm", user_id=user, project_id="project", role=role))
    return BindingService(db, control, audience), control, audience


async def bound(db, control=None, audience=None):
    bindings, control, audience = await service(db, control, audience)
    binding = await bindings.bind("realm", 7, 10, "Original work", REF)
    return bindings, binding, control, audience
