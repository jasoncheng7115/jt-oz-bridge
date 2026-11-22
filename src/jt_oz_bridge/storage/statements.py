from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from jt_oz_bridge.storage.database import Database


def insert(db: Database, model: Any) -> Any:
    """Dialect-local conflict handling; PostgreSQL runtime certification remains separate."""
    return sqlite_insert(model) if db.engine.dialect.name == "sqlite" else pg_insert(model)
