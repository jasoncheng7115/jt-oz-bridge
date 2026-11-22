"""Qualified aborted-turn tail left by a declined installed v2.0.32 permission.

Installed ``Permission.reply`` fails a declined request without feedback with a
``DeclinedError`` that dies through the tool leaf. The step fails as exactly
``{"type": "aborted", "message": "Step interrupted"}`` and the busy period ends
with an interrupt that carries no reason, which ``terminal()`` reports as
``shutdown``. That projection appends no ``idle`` message, keeps the session's
idle time and retained outcome from the previous turn and keeps the execution
claim. Only this exact shape is reconciled here: a completed aborted assistant
at the head, then only user and assistant entries of such turns, then the
positive idle the session info still names (or, for a session without any
idle, the complete history). The caller must already prove the Root inactive
with no inbox, pending permission/form or running shell. This function alone
grants no ownership, authorization or right to mutate.
"""

from typing import Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.storage.durable import digest

ABORTED_TURN_SOURCES = {
    "permission.ts": "d69278896f9a541dac7cf46056c859834d840ecc16ac57a639cbabc1afdda9a5",
    "execution.ts": "f86c35f46c9bae634f955328979c3eade27d5df06e115d677eece7f4e4f1ce3a",
    "run-coordinator.ts": "20dc6417c597e6d5bc6f349e31ed5d3e88db4be31b548be1f35262e87fcc3c4b",
    "projector.ts": "b2145973cd8ae49fdbde760cb4277ed61113669447583805fcbd2669ced304b1",
    "message-updater.ts": "40d7a2ae2852db7b4c985ed0c2c8cfbebb92a91a3d60e3007b37b4f282703ee2",
}
ABORTED_TURN_SEMANTICS = digest({"version": "2.0.32", "sources": ABORTED_TURN_SOURCES})
STEP_ABORTED = {"type": "aborted", "message": "Step interrupted"}
TAIL_LIMIT = 51


def aborted_head(row: dict[str, Any]) -> bool:
    """Only a shape eligible for reconciliation; never Idle by itself."""
    return row.get("type") == "assistant" and row.get("error") == STEP_ABORTED


def reconcile_aborted_suffix(
    info: dict[str, Any], rows: list[dict[str, Any]], cursor: dict[str, Any], newer_time: int
) -> dict[str, Any]:
    """Validate descending store rows starting at the aborted assistant.

    ``newer_time`` bounds the head: the session's ``time.updated``, or the
    creation time of a newer setting entry already validated by its own tail.
    Retained facts are identities, types, times and the fixed Native error.
    """
    if not 1 <= len(rows) <= TAIL_LIMIT or len({row["id"] for row in rows}) != len(rows):
        raise ContractError("native_aborted_turn_tail_boundary_or_duplicate_identity")
    head = rows[0]
    completed = head["time"].get("completed")
    if (
        not aborted_head(head)
        or head.get("finish") != "error"
        or "retry" in head
        or type(completed) is not int
        or completed > newer_time
        or type(head["time"]["created"]) is not int
        or head["time"]["created"] > completed
    ):
        raise ContractError("native_aborted_turn_head_unqualified")
    turn: list[dict[str, Any]] = []
    newest = newer_time
    for index, row in enumerate(rows):
        created = row["time"]["created"]
        if type(created) is not int or created > newest:
            raise ContractError("native_aborted_turn_time_boundary_changed")
        newest = created
        if row["type"] == "idle":
            # Every aborted turn begins with its delivered user input.
            if rows[index - 1]["type"] != "user":
                raise ContractError("native_aborted_turn_user_input_missing")
            if row["outcome"] != info.get("outcome") or created != info["time"].get("idle"):
                raise ContractError("native_aborted_turn_idle_boundary_changed")
            return {
                "aborted": {k: head[k] for k in ("id", "type", "time", "error", "finish")},
                "turn": turn,
                "idle": {k: row[k] for k in ("id", "type", "time", "outcome")},
                "pristine": False,
            }
        if row["type"] == "assistant":
            # An earlier step of the same turn, or an earlier turn declined the
            # same way. Any other error or an unfinished step is not this tail.
            if (
                type(row["time"].get("completed")) is not int
                or "retry" in row
                or "error" in row
                and (row["error"] != STEP_ABORTED or row.get("finish") != "error")
            ):
                raise ContractError("native_aborted_turn_assistant_not_terminal")
        elif row["type"] != "user":
            raise ContractError("native_aborted_turn_intervening_entry")
        turn.append({"id": row["id"], "type": row["type"], "time": row["time"]})
    if (
        cursor.get("next") is None
        and rows[-1]["type"] == "user"
        and "outcome" not in info
        and "idle" not in info["time"]
    ):
        return {
            "aborted": {k: head[k] for k in ("id", "type", "time", "error", "finish")},
            "turn": turn,
            "idle": None,
            "pristine": True,
        }
    raise ContractError("native_aborted_turn_positive_idle_not_found")


def reconcile_aborted_turn_tail(info: dict[str, Any], page: dict[str, Any]) -> dict[str, Any]:
    """A descending, unfiltered page whose newest entry is the aborted assistant.

    The session's ``time.updated`` is an upper bound, not an equality: a later
    rename, metadata or permission update touches only session columns and must
    not trap an idle Root again. Any execution leaves an entry, inbox or activity.
    """
    rows = page["data"]
    if not 2 <= len(rows) <= TAIL_LIMIT:
        raise ContractError("native_aborted_turn_tail_boundary_or_duplicate_identity")
    return reconcile_aborted_suffix(info, rows, page["cursor"], info["time"]["updated"])
