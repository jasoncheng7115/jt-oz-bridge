"""Qualified non-executing model-setting tails after a positive Native idle.

Changing a model appends a message without waking the Native coordinator. Only
that exact installed behavior is eligible here; agent changes, execution inputs
and arbitrary control records are deliberately not treated as harmless settings.
"""

from dataclasses import dataclass
from typing import Any, Literal

from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head, reconcile_aborted_suffix
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

MODEL_SETTING_SOURCES = {
    "session.ts": "53d67aef56a1a6b518fad623d51a15b26f071db25c7e5f1c71a21c36ac3a9d11",
    "info.ts": "d14557573746c0b2ed65f42f8a881012813f36235bb67d2f2a27661c017c80a6",
    "projector.ts": "b2145973cd8ae49fdbde760cb4277ed61113669447583805fcbd2669ced304b1",
    "message-updater.ts": "40d7a2ae2852db7b4c985ed0c2c8cfbebb92a91a3d60e3007b37b4f282703ee2",
}
MODEL_SETTING_SEMANTICS = digest({"version": "2.0.32", "sources": MODEL_SETTING_SOURCES})
MODEL_SETTING_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"


@dataclass(frozen=True)
class ModelSettingsAttestation:
    """Trusted installed observation input; never accept this from chat."""

    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    qualification_scope: Literal["session", "backend"] = "session"

    @property
    def enrollment_sha256(self) -> str:
        data = {
            "reference": self.reference.model_dump(mode="json"),
            "contract_sha256": self.contract_sha256,
            "semantics_sha256": self.semantics_sha256,
            "installed_evidence_sha256": self.installed_evidence_sha256,
        }
        if self.qualification_scope != "session":
            data["qualification_scope"] = self.qualification_scope
        return digest(data)

    def require(self, reference: SessionRef, schema_sha256: str) -> None:
        scoped = self.reference == reference
        if self.qualification_scope == "backend":
            # This certifies the installed model-setting codec, not permission
            # to operate on a newly discovered session. Its Root policy/proof
            # and exact session registry still authorize every operation.
            scoped = (
                self.reference.backend_id == reference.backend_id
                and self.reference.backend_identity == reference.backend_identity
            )
        if (
            self.qualification_scope not in {"session", "backend"}
            or not scoped
            or schema_sha256 != MODEL_SETTING_SCHEMA
            or self.contract_sha256 != schema_sha256
            or self.semantics_sha256 != MODEL_SETTING_SEMANTICS
            or len(self.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.installed_evidence_sha256)
        ):
            raise ContractError("native_model_setting_semantics_unqualified")


def reconcile_model_tail(info: dict[str, Any], page: dict[str, Any]) -> dict[str, Any]:
    """Validate a descending, unfiltered Native store page; keep safe facts only.

    The caller supplies the qualified exact scope/schema/owner and verifies the
    page boundary against its earlier latest-message read. This function alone
    grants no ownership, authorization or right to mutate.
    """
    rows = page["data"]
    if not 1 <= len(rows) <= 51 or rows[0]["type"] != "model-switched":
        raise ContractError("native_model_setting_tail_boundary_invalid")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ContractError("native_model_setting_tail_duplicate_identity")
    expected = native_ref(info["model"]) if "model" in info else None
    controls: list[dict[str, Any]] = []
    newer_time = info["time"]["updated"]
    for index, row in enumerate(rows):
        created = row["time"]["created"]
        if created > newer_time:
            raise ContractError("native_model_setting_time_boundary_changed")
        if controls and aborted_head(row):
            # Settings changed after a declined permission ended its turn
            # without a new idle; that exact tail must still reach one.
            turn = reconcile_aborted_suffix(info, rows[index:], page["cursor"], newer_time)
            if turn["idle"] is None:
                raise ContractError("native_model_setting_positive_idle_not_found")
            return {
                "controls": controls,
                "idle": turn["idle"],
                "pristine": False,
                "aborted_turn": turn,
            }
        newer_time = created
        if row["type"] == "idle":
            if row["outcome"] != info.get("outcome") or created != info["time"].get("idle"):
                raise ContractError("native_model_setting_idle_boundary_changed")
            return {
                "controls": controls,
                "idle": {k: row[k] for k in ("id", "type", "time", "outcome")},
                "pristine": False,
            }
        if row["type"] != "model-switched" or len(controls) >= 50:
            raise ContractError("native_model_setting_intervening_input_or_capacity")
        selected = native_ref(row["model"])
        if not selected.same_native_selection(expected):
            raise ContractError("native_model_setting_selection_chain_changed")
        previous = native_ref(row["previous"]) if "previous" in row else None
        controls.append(
            {
                "id": row["id"],
                "type": row["type"],
                "time": row["time"],
                "model": selected.wire(),
                "previous": previous.wire() if previous is not None else None,
            }
        )
        expected = previous
    if (
        page["cursor"].get("next") is None
        and "outcome" not in info
        and "idle" not in info["time"]
        and expected is None
    ):
        return {"controls": controls, "idle": None, "pristine": True}
    raise ContractError("native_model_setting_positive_idle_not_found")
