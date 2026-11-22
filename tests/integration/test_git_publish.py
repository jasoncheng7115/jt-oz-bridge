"""Synthetic Humans, Git readings and Native with a real isolated encrypted DB and outbox.

The fake review reader stands in for qualified `vcs.*` GETs; the fake turn reader
for the resource proof that a turn ended. Nothing here is live Native/Human evidence.
"""

import hashlib
import re
from html import unescape
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.git_publish import V2GitPublishState
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.git_publish import GitPublishPlan, GitPublishRequest
from jt_oz_bridge.domain.git_review import NativeDiffSummary, NativeGitReview
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.git_publish_commands import GitPublishCommands
from jt_oz_bridge.services.git_publish_results import GitPublishResultPublisher, GitPublishResults
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import ControlToken
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Delivery
from jt_oz_bridge.storage.publication_models import ModelSettingPublication
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import REF, bound


def summary(path, content, status="modified"):
    patch = f"--- {path}\n+++ {path}\n+{content}\n"
    return NativeDiffSummary(
        path=path,
        additions=1,
        deletions=0,
        status=status,
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        patch_bytes=len(patch.encode()),
    )


class Repository:
    """A model of what 2.0.32 `vcs.*` shows: changed files, branch names, base diffs."""

    def __init__(self):
        self.branch = "main"
        self.working = {"a.py": summary("a.py", "one"), "b.txt": summary("b.txt", "two", "added")}
        self.hidden = 0
        self.conflicts = 0
        self.branches = ["main", "origin/main"]
        self.base = None
        # Per comparison base: merge-base(base, HEAD) → HEAD.
        self.committed = {"origin/main": {}}
        self.reads = []

    def commit(self, *paths):
        for path in paths:
            self.committed["origin/main"][path] = self.working.pop(path)

    def push(self):
        self.committed["origin/main"] = {}
        if "origin/main" not in self.branches:
            self.branches.append("origin/main")

    def qualified(self, ref):
        return ref == REF

    async def read(self, ref, *, mode="working", base=None, search="", limit=50):
        self.reads.append((mode, base, search))
        files = self.working if mode == "working" else self.committed.get(base)
        if files is None:
            raise ContractError("synthetic unknown base")
        branches = [b for b in self.branches if search in b]
        return NativeGitReview(
            reference=ref,
            current_branch=self.branch,
            default_branch="main",
            saved_worktrees=(),
            hidden_worktrees=0,
            branches=tuple(branches[:limit]),
            branches_complete=len(branches) <= limit,
            inferred_base=self.base,
            mode=mode,
            requested_base=base,
            files=tuple(sorted(files.values(), key=lambda f: f.path)),
            hidden_files=self.hidden,
            conflict_files=self.conflicts,
        )


class GitExecution(SyntheticExecution):
    def __init__(self):
        super().__init__()
        self.state = ExecutionState.IDLE
        self.effect = None
        self.enabled = True

    def capabilities(self, ref):
        result = super().capabilities(ref)
        result["git.publish"] = Capability(
            supported=self.enabled,
            scope="session",
            reason="synthetic only",
            verification="synthetic_test",
        )
        return result

    async def submit(self, ref, payload, identity):
        assert ref == self.ref and payload["operation"] == "git.publish"
        self.submitted.append((ref, payload, identity))
        if self.effect is not None:
            self.effect()
        return Admission(
            status="admitted",
            upstream_id="msg_user_" + str(len(self.submitted)),
            details={"operation": "git.publish", "delivery": "queue", "turn_completed": False},
        )


class Turns:
    """Stands in for the qualified resource reader: raises until the turn ended."""

    def __init__(self):
        self.outcome = None
        self.captured = []

    async def capture(self, correlation):
        self.captured.append(correlation)
        if self.outcome is None:
            raise ContractError("native_resource_turn_not_idle")
        return SimpleNamespace(
            turn=SimpleNamespace(user_id=correlation.upstream_id, outcome=self.outcome)
        )

    def current(self, evidence):
        return True


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


class Harness:
    def __init__(self, db):
        self.db, self.next_id = db, 100

    async def start(self):
        self.execution, self.repo, self.turns = GitExecution(), Repository(), Turns()
        self.bindings, self.binding, _, _ = await bound(self.db, control=self.execution)
        self.lease = await DurableStore(self.db).acquire_lease("git", ttl=120)
        self.inbox, self.source = CommandInbox(self.db, "git", self.lease), Source()
        tokens = TokenService(self.db, fence=self.inbox.fence)
        self.readers = {REF: V2GitPublishState(self.repo)}
        self.commands = GitPublishCommands(
            self.bindings, self.readers, tokens, self.source, self.execution.capabilities
        )
        self.router = CommandRouter(
            self.bindings, self.source, self.inbox, git_publish=self.commands
        )
        self.restart()
        self.publisher = GitPublishResultPublisher(
            RoutedOutbox(
                Outbox(self.bindings, 77, fence=self.inbox.fence),
                realm_id="realm",
                message_limit=4000,
                topic_limit=60,
            )
        )
        return self

    def restart(self):
        """New dispatcher and checker objects over the same durable database."""
        self.worker = Dispatcher(self.bindings, self.execution, self.source, "git", self.lease)
        self.results = GitPublishResults(
            self.bindings, self.readers, {"backend": self.turns}, self.inbox.fence
        )

    async def say(self, text, **changes):
        self.next_id += 1
        item = message(text, self.next_id, **changes)
        routed = await send(self.router, self.source, item)
        # Read the reply as Zulip shows it; `raw` is the exact stored text.
        return item, SimpleNamespace(text=unescape(routed.text or ""), raw=routed)

    async def notice(self, action_id):
        assert await self.publisher.next_pending() == action_id
        await self.publisher.publish(action_id)
        return unescape(" ".join(x.payload["content"] for x in await rows(self.db, Delivery)))

    async def confirmed(self, text='!oz git commit -m "Fix the parser" a.py'):
        preview = (await self.say(text))[1].text
        assert "!ok" in preview, preview
        reply = (await self.say("!confirm"))[1].text
        assert "Confirmed" in reply, reply
        return (await rows(self.db, Action))[-1]


async def harness(db):
    return await Harness(db).start()


async def test_commit_preview_confirm_send_once_and_verify(db):
    h = await harness(db)
    preview = (await h.say('!oz git commit -m "Fix the parser" a.py'))[1].text
    assert "Git commit preview" in preview and "main" in preview and "Fix the parser" in preview
    assert "a.py" in preview and "b.txt" not in preview.split("Not included")[0].split("a.py")[1]
    command = "git --literal-pathspecs -C /workspace/project"
    assert f"{command} add -- a.py && {command} commit -m 'Fix the parser' -- a.py" in preview
    assert "--force" not in preview and "--no-verify" not in preview
    assert not await rows(db, Action) and not h.execution.submitted
    confirm, reply = await h.say("!confirm")
    assert "Confirmed" in reply.text
    action = (await rows(db, Action))[0]
    assert action.operation == "git.publish" and action.state == "queued"
    assert await h.worker.advance(action.id) == "admitted"
    assert len(h.execution.submitted) == 1
    request = GitPublishRequest.model_validate(h.execution.submitted[0][1])
    assert request.text == request.plan.prompt() and request.plan.paths == ("a.py",)
    assert request.plan.command() in request.text
    # The turn has not ended: nothing is concluded, and nothing is sent again.
    with pytest.raises(ContractError):
        await h.results.collect(action.id, "realm")
    assert await h.publisher.next_pending() is None
    h.repo.commit("a.py")
    h.turns.outcome = "succeeded"
    assert await h.results.collect(action.id, "realm")
    content = await h.notice(action.id)
    assert "Commit verified" in content and "origin/main" in content
    assert "commit ID" in content and "commit message" in content
    first = await h.publisher.publish(action.id)
    assert first == await h.publisher.publish(action.id)
    assert len(await rows(db, ModelSettingPublication)) == 1
    # A redelivered confirmation replays its reply and creates nothing.
    assert (await send(h.router, h.source, confirm)).text == reply.raw.text
    await h.worker.advance(action.id)
    assert len(await rows(db, Action)) == len(h.execution.submitted) == 1


async def test_commit_without_paths_takes_every_shown_change_and_never_hidden_ones(db):
    h = await harness(db)
    h.repo.hidden = 1
    preview = (await h.say('!oz git commit -m "All of it"'))[1].text
    assert "a.py" in preview and "b.txt" in preview and "1 protected file" in preview
    await h.say("!confirm")
    action = (await rows(db, Action))[0]
    assert GitPublishRequest.model_validate(action.payload).plan.paths == ("a.py", "b.txt")
    assert ".env" not in GitPublishRequest.model_validate(action.payload).text


async def test_changed_state_voids_the_confirmation_and_previews_again(db):
    h = await harness(db)
    await h.say('!oz git commit -m "Fix" a.py')
    h.repo.working["a.py"] = summary("a.py", "edited after the preview")
    reply = (await h.say("!confirm"))[1].text
    assert "Something changed" in reply and "!ok" in reply
    assert not await rows(db, Action) and not h.execution.submitted
    # The new preview is for the new reading; only it can be confirmed.
    assert "Confirmed" in (await h.say("!ok"))[1].text
    action = (await rows(db, Action))[0]
    request = GitPublishRequest.model_validate(action.payload)
    assert request.before.changed()["a.py"] == V2_FILE(h.repo.working["a.py"])


def V2_FILE(row):  # noqa: N802 - a projection helper, named for what it mirrors
    from jt_oz_bridge.adapters.opencode.git_publish import files

    return files((row,))[0]


async def test_branch_change_voids_the_confirmation(db):
    h = await harness(db)
    await h.say('!oz git commit -m "Fix" a.py')
    h.repo.branch = "other"
    reply = (await h.say("!confirm"))[1].text
    assert "Something changed" in reply and not await rows(db, Action)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".env", "protected"),
        ("config/.env.local", "protected"),
        (".git/config", "protected"),
        ("deploy/id_ed25519", "protected"),
        ("secrets/token.txt", "protected"),
        ("certs/site.key", "protected"),
        ("../outside.py", "isn't a path inside"),
        ("/etc/passwd", "isn't a path inside"),
    ],
)
async def test_protected_and_outside_paths_are_refused_before_any_read(db, path, expected):
    h = await harness(db)
    reply = (await h.say(f'!oz git commit -m "Fix" {path}'))[1].text
    assert expected in reply and "!ok" not in reply
    assert not h.repo.reads and not await rows(db, ControlToken)


async def test_unchanged_path_and_bad_messages_are_refused(db):
    h = await harness(db)
    assert "no uncommitted change" in (await h.say('!oz git commit -m "Fix" c.py'))[1].text
    assert "one-line" in (await h.say('!oz git commit -m " "'))[1].text
    assert "no options" in (await h.say('!oz git commit -m "Fix" --amend'))[1].text
    usage = (await h.say("!oz git commit a.py"))[1].text
    assert "!ok" not in usage
    assert not await rows(db, Action)


@pytest.mark.parametrize(
    "text",
    [
        "!oz git push --force",
        "!oz git push -f",
        "!oz git push origin +main",
        "!oz git push --force-with-lease origin main",
        "!oz git push origin main --force",
    ],
)
async def test_force_push_is_never_offered(db, text):
    h = await harness(db)
    reply = (await h.say(text))[1].text
    assert "never offered" in reply and "!ok" not in reply and not h.repo.reads


def test_no_plan_can_carry_a_force_or_refspec():
    for branch in ("+main", "main:main", "-f", "--force", "a..b", ".hidden", "x.lock"):
        with pytest.raises(ValueError):
            GitPublishPlan(
                kind="push",
                directory="/workspace/project",
                branch=branch,
                remote="origin",
                state_sha256="a" * 64,
            )
    plan = GitPublishPlan(
        kind="push",
        directory="/workspace/project",
        branch="main",
        remote="origin",
        state_sha256="a" * 64,
    )
    assert plan.command() == "git --literal-pathspecs -C /workspace/project push origin main"
    assert "force" not in plan.command()


async def test_push_preview_confirm_and_verify_against_the_tracking_ref(db):
    h = await harness(db)
    h.repo.committed["origin/main"] = {"a.py": summary("a.py", "one")}
    preview = (await h.say("!oz git push"))[1].text
    assert "Git push preview" in preview and "origin/main" in preview and "a.py" in preview
    assert "fast-forward" in preview and "push origin main" in preview
    await h.say("!confirm")
    action = (await rows(db, Action))[0]
    assert await h.worker.advance(action.id) == "admitted"
    h.repo.push()
    h.turns.outcome = "succeeded"
    assert await h.results.collect(action.id, "realm")
    content = await h.notice(action.id)
    assert "Push verified" in content and "remote server itself" in content


async def test_push_needs_an_upstream_unless_named_and_then_verifies_creation(db):
    h = await harness(db)
    h.repo.branches = ["main"]
    h.repo.committed = {}
    refused = (await h.say("!oz git push"))[1].text
    assert "There's no origin/main" in refused and "!ok" not in refused
    preview = (await h.say("!oz git push origin main"))[1].text
    assert "doesn't exist yet" in preview and "!ok" in preview
    await h.say("!confirm")
    action = (await rows(db, Action))[0]
    await h.worker.advance(action.id)
    h.repo.committed["origin/main"] = {}
    h.repo.push()
    h.turns.outcome = "succeeded"
    await h.results.collect(action.id, "realm")
    assert "Push verified" in await h.notice(action.id)


async def test_push_of_another_branch_or_nothing_new_is_refused(db):
    h = await harness(db)
    assert "Only the current branch" in (await h.say("!oz git push origin dev"))[1].text
    assert "Nothing to push" in (await h.say("!oz git push"))[1].text
    assert not await rows(db, ControlToken)


async def test_detached_conflicted_or_busy_states_are_refused(db):
    h = await harness(db)
    h.repo.branch = None
    assert "detached HEAD" in (await h.say('!oz git commit -m "Fix"'))[1].text
    h.repo.branch, h.repo.conflicts = "main", 1
    assert "conflict markers" in (await h.say('!oz git commit -m "Fix"'))[1].text
    h.repo.conflicts, h.execution.state = 0, ExecutionState.RUNNING
    assert "still working" in (await h.say('!oz git commit -m "Fix"'))[1].text
    h.repo.working = {}
    h.execution.state = ExecutionState.IDLE
    assert "no changes to commit" in (await h.say('!oz git commit -m "Fix"'))[1].text
    assert not await rows(db, ControlToken) and not await rows(db, Action)


@pytest.mark.parametrize(
    ("outcome", "says"),
    [
        ("interrupted", "permission was declined"),
        # A Root1-style deny-all agent finishes its turn without running anything.
        ("succeeded", "may not be allowed to run commands"),
        ("failed", "failed"),
    ],
)
async def test_nothing_changed_is_reported_as_not_done(db, outcome, says):
    h = await harness(db)
    action = await h.confirmed()
    assert await h.worker.advance(action.id) == "admitted"
    h.turns.outcome = outcome
    assert await h.results.collect(action.id, "realm")
    content = await h.notice(action.id)
    assert "Not committed" in content and says in content and "verified" not in content.lower()


async def test_a_change_that_differs_from_the_preview_is_not_verified(db):
    h = await harness(db)
    action = await h.confirmed()
    await h.worker.advance(action.id)
    h.repo.commit("a.py")
    h.repo.working["b.txt"] = summary("b.txt", "also edited by the agent", "added")
    h.turns.outcome = "succeeded"
    await h.results.collect(action.id, "realm")
    content = await h.notice(action.id)
    assert "Commit not verified" in content and "other files also changed" in content


async def test_discarded_files_without_a_comparison_are_not_called_a_commit(db):
    h = await harness(db)
    h.repo.branches = ["main"]
    action = await h.confirmed()
    await h.worker.advance(action.id)
    h.repo.working.pop("a.py")  # Committed or discarded: 2.0.32 GETs can't tell.
    h.turns.outcome = "succeeded"
    await h.results.collect(action.id, "realm")
    content = await h.notice(action.id)
    assert "Commit not verified" in content and "can't be seen" in content


async def test_restart_between_prompt_and_check_neither_resends_nor_loses_it(db):
    h = await harness(db)
    action = await h.confirmed()
    assert await h.worker.advance(action.id) == "admitted"
    h.restart()
    assert await h.worker.advance(action.id) == "admitted"
    assert len(h.execution.submitted) == 1
    assert await h.results.pending("realm") == [action.id]
    h.repo.commit("a.py")
    h.turns.outcome = "succeeded"
    assert await h.results.collect(action.id, "realm")
    assert await h.results.pending("realm") == []
    assert "Commit verified" in await h.notice(action.id)
    assert len(h.execution.submitted) == 1


async def test_duplicate_confirm_with_the_token_is_idempotent(db):
    h = await harness(db)
    preview = (await h.say('!oz git commit -m "Fix" a.py'))[1].text
    token = re.search(r"!(?:oz confirm|ok) ([A-Za-z0-9_-]+)", preview).group(1)
    assert "Confirmed" in (await h.say(f"!confirm {token}"))[1].text
    again = (await h.say(f"!oz confirm {token}"))[1].text
    assert "already used" in again
    assert len(await rows(db, Action)) == 1


async def test_another_persons_confirm_cannot_use_the_preview(db):
    h = await harness(db)
    preview = (await h.say('!oz git commit -m "Fix" a.py'))[1].text
    token = re.search(r"!(?:oz confirm|ok) ([A-Za-z0-9_-]+)", preview).group(1)
    reply = (await h.say(f"!confirm {token}", author_id=8))[1].text
    assert "Confirmed" not in reply and not await rows(db, Action)


async def test_edited_preview_command_stops_the_dispatch(db):
    h = await harness(db)
    action = await h.confirmed()
    opening = GitPublishRequest.model_validate(action.payload).preview
    h.source.messages[opening.message_id] = opening.model_copy(update={"revision": 1})
    assert await h.worker.advance(action.id) == "rejected"
    assert not h.execution.submitted


async def test_unavailable_root_reads_nothing(db):
    h = await harness(db)
    h.execution.enabled = False
    reply = (await h.say('!oz git commit -m "Fix" a.py'))[1].text
    assert "aren't available" in reply and not h.repo.reads


async def test_a_later_lifecycle_or_agent_preview_retires_the_git_confirmation(db):
    from jt_oz_bridge.services.session_lifecycle_controls import SessionLifecycleControls

    h = await harness(db)
    await h.say('!oz git commit -m "Fix" a.py')
    controls = SessionLifecycleControls(
        h.bindings, h.commands.tokens, h.source, h.execution.capabilities
    )
    async with db.sessions.begin() as session:
        await controls._retire(session, h.binding, message("!compact", 999))
    assert "Confirmed" not in (await h.say("!ok"))[1].text
    assert not await rows(db, Action)
