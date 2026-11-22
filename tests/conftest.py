from pathlib import Path

import pytest_asyncio

from tests.database_template import build_empty_database_template


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def empty_database_template(tmp_path_factory):
    path = tmp_path_factory.mktemp("empty-current-schema") / "template.db"
    return await build_empty_database_template(path)


@pytest_asyncio.fixture
async def db(tmp_path: Path, empty_database_template):
    value = await empty_database_template.database(tmp_path / "test.db")
    try:
        yield value
    finally:
        await value.close()
