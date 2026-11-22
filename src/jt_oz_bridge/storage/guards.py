"""Enrollment predicates evaluated in the same statement as a mutation claim."""

from sqlalchemy import select
from sqlalchemy.sql.selectable import Exists

from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject


def enrollment(binding: Binding, contract_hash: str) -> tuple[Exists, Exists]:
    backend = (
        select(EnrolledBackend.id)
        .where(
            EnrolledBackend.id == binding.backend_id,
            EnrolledBackend.identity == binding.backend_identity,
            EnrolledBackend.contract_hash == contract_hash,
            EnrolledBackend.enabled.is_(True),
            EnrolledBackend.verified.is_(True),
        )
        .exists()
    )
    project = (
        select(EnrolledProject.id)
        .where(
            EnrolledProject.id == binding.project_id,
            EnrolledProject.backend_id == binding.backend_id,
            EnrolledProject.realm_id == binding.realm_id,
            EnrolledProject.canonical_directory == binding.canonical_directory,
            EnrolledProject.enabled.is_(True),
        )
        .exists()
    )
    return backend, project
