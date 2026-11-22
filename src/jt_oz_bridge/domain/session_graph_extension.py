"""Strict original-tree additions; identity records never confer live authority."""

from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord


def require_original_extension(
    previous: SessionAdoptionRecord, new: SessionAdoptionRecord
) -> tuple[OriginalSessionNode, ...]:
    # Frozen DTOs can still have been produced with model_construct/model_copy.
    # Dumping first also takes an independent snapshot of nested input values.
    previous = SessionAdoptionRecord.model_validate(previous.model_dump(mode="python"))
    new = SessionAdoptionRecord.model_validate(new.model_dump(mode="python"))
    if any(
        getattr(previous, field) != getattr(new, field)
        for field in ("root", "native_project_id", "contract_sha256", "qualification_sha256")
    ):
        raise ValueError("original_graph_extension_scope_changed")
    old = {node.reference: node for node in previous.nodes}
    current = {node.reference: node for node in new.nodes}
    if any(current.get(reference) != node for reference, node in old.items()):
        raise ValueError("original_graph_extension_existing_node_changed")
    additions = tuple(node for node in new.nodes if node.reference not in old)
    if not additions:
        raise ValueError("original_graph_extension_requires_new_nodes")
    return additions
