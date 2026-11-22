"""Bounded typed own-data records; archives never supply SQL, DDL or pickle.

Ciphertext columns are byte strings, not ORM-decoded JSON. The current fixed
metadata supplies every table, column, type and FK; an archive cannot add one.
"""

import hashlib
import json
import math
import os
import re
import struct
import time
from collections.abc import Iterator, Mapping
from functools import cache
from typing import Any, BinaryIO

import sqlalchemy as sa
from sqlalchemy import MetaData, Table

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.backup_files import FileRecord, PrivateDirectory
from jt_oz_bridge.storage.cipher_types import (
    KEY_CHECK,
    MAX_PAYLOAD,
    EncryptedJSON,
    checked_json,
    payload_scope,
)
from jt_oz_bridge.storage.schema import Base

MAGIC = b"JT-OZ-ROWS\x01"
MAX_CELL = MAX_PAYLOAD + 4096
MAX_ROW = 160 * 1024**2
MAX_ROWS = 10_000_000


class LogicalArchiveError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def checksum(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def kind(column: sa.Column[Any]) -> str:
    value = column.type
    if isinstance(value, EncryptedJSON):
        return "cipher"
    if isinstance(value, sa.LargeBinary):
        return "bytes"
    if isinstance(value, sa.Boolean):
        return "bool"
    if isinstance(value, sa.Integer):
        return "int64" if isinstance(value, sa.BigInteger) else "int32"
    if isinstance(value, sa.Float):
        return "float"
    if isinstance(value, sa.String):
        return "str"
    if isinstance(value, sa.JSON):
        return "json"
    raise LogicalArchiveError("unsupported_current_metadata_type")


def raw_metadata() -> MetaData:
    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        clone = table.to_metadata(metadata)
        for column in clone.columns:
            if isinstance(column.type, EncryptedJSON):
                column.type = sa.LargeBinary()
            # Every imported field must be present. Never run a Python default.
            column.default = None
            column.onupdate = None
    sa.Table("alembic_version", metadata, sa.Column("version_num", sa.String(32), primary_key=True))
    return metadata


def table_spec(table: Table) -> dict[str, Any]:
    return {
        "columns": [
            {
                "name": c.name,
                "kind": kind(c),
                "length": getattr(c.type, "length", None),
                "nullable": c.nullable,
                "primary": c.primary_key,
            }
            for c in table.columns
        ],
        "foreign_keys": sorted(
            [
                [c.name, fk.target_fullname, fk.ondelete, fk.onupdate]
                for c in table.columns
                for fk in c.foreign_keys
            ],
            key=repr,
        ),
        "unique": sorted(
            [
                list(c.columns.keys())
                for c in table.constraints
                if isinstance(c, sa.UniqueConstraint)
            ]
        ),
        "checks": sorted(
            hashlib.sha256(str(c.sqltext).encode()).hexdigest()
            for c in table.constraints
            if isinstance(c, sa.CheckConstraint)
        ),
    }


@cache
def schema_spec() -> dict[str, Any]:
    value = {name: table_spec(table) for name, table in Base.metadata.tables.items()}
    value["alembic_version"] = {
        "columns": [
            {"name": "version_num", "kind": "str", "length": 32, "nullable": False, "primary": True}
        ],
        "foreign_keys": [],
        "unique": [],
        "checks": [],
    }
    return value


def row_file(table: str) -> str:
    if table not in schema_spec() or re.fullmatch(r"[a-z][a-z0-9_]*", table) is None:
        raise LogicalArchiveError("unknown_owned_table")
    return "rows-" + table + ".bin"


def columns(table: str) -> list[dict[str, Any]]:
    return schema_spec()[table]["columns"]  # type: ignore[no-any-return]


def normalized(value: Any, column: dict[str, Any], *, sqlite: bool = False) -> Any:
    if value is None:
        if not column["nullable"]:
            raise LogicalArchiveError("null_in_required_column")
        return None
    category = column["kind"]
    if sqlite and category == "bool" and type(value) is int and value in {0, 1}:
        value = bool(value)
    if sqlite and category == "json" and isinstance(value, str):
        value = strict_loads(value.encode())
    if category in {"cipher", "bytes"}:
        if isinstance(value, memoryview):
            value = bytes(value)
        if type(value) is not bytes or len(value) > MAX_CELL:
            raise LogicalArchiveError("bounded_ciphertext_bytes_required")
    elif category == "bool":
        if type(value) is not bool:
            raise LogicalArchiveError("boolean_cell_required")
    elif category in {"int32", "int64"}:
        bits = 32 if category == "int32" else 64
        if type(value) is not int or not -(2 ** (bits - 1)) <= value < 2 ** (bits - 1):
            raise LogicalArchiveError("integer_cell_range")
    elif category == "float":
        if type(value) not in {float, int} or not math.isfinite(value):
            raise LogicalArchiveError("finite_float_cell_required")
        value = float(value)
    elif category == "str":
        if not isinstance(value, str) or len(value.encode()) > MAX_CELL:
            raise LogicalArchiveError("bounded_string_cell_required")
        if column["length"] is not None and len(value) > column["length"]:
            raise LogicalArchiveError("string_column_range")
    elif category == "json":
        if len(canonical(value)) > MAX_CELL:
            raise LogicalArchiveError("bounded_json_cell_required")
    else:
        raise LogicalArchiveError("unknown_cell_kind")
    return value


def encode_row(table: str, row: Mapping[str, Any], *, sqlite: bool = False) -> Iterator[bytes]:
    expected = columns(table)
    if set(row) != {c["name"] for c in expected}:
        raise LogicalArchiveError("exact_row_columns_required")
    total = 0
    yield b"R"
    for column in expected:
        value = normalized(row[column["name"]], column, sqlite=sqlite)
        if value is None:
            data, tag = b"", b"N"
        elif column["kind"] in {"cipher", "bytes"}:
            data, tag = value, b"B"
        elif column["kind"] == "bool":
            data, tag = bytes([int(value)]), b"T"
        elif column["kind"] in {"int32", "int64"}:
            data, tag = struct.pack(">q", value), b"I"
        elif column["kind"] == "float":
            data, tag = struct.pack(">d", value), b"F"
        elif column["kind"] == "str":
            data, tag = value.encode(), b"S"
        else:
            data, tag = canonical(value), b"J"
        total += len(data) + 9
        if total > MAX_ROW:
            raise LogicalArchiveError("row_size_limit")
        yield tag + struct.pack(">Q", len(data))
        yield data


def authenticate_row(table: str, row: Mapping[str, Any], cipher: EnvelopeCipher) -> set[str]:
    key_ids: set[str] = set()
    for column in columns(table):
        value = row[column["name"]]
        if value is not None and column["kind"] == "cipher":
            raw = cipher.open(
                value, payload_scope(table, column["name"]), max_plaintext_bytes=MAX_PAYLOAD
            )
            checked_json(strict_loads(raw))
    if table == "payload_key_checks":
        key = row["key_id"]
        if (
            cipher.open(
                row["challenge"],
                {"purpose": "database-key-check", "key_id": key},
                max_plaintext_bytes=len(KEY_CHECK),
            )
            != KEY_CHECK
        ):
            raise LogicalArchiveError("database_key_canary_invalid")
        key_ids.add(key)
    return key_ids


class TableWriter:
    def __init__(self, archive: PrivateDirectory, table: str, maximum: int, deadline: float):
        self.archive, self.table, self.maximum, self.deadline = archive, table, maximum, deadline
        self.name = row_file(table)
        self.fd = os.open(
            self.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=archive.fd,
        )
        self.size, self.count, self.digest = 0, 0, hashlib.sha256()
        try:
            self.write(MAGIC + bytes.fromhex(checksum(schema_spec())) + table.encode() + b"\0")
        except BaseException:
            self.close()
            raise

    def write(self, value: bytes) -> None:
        if time.monotonic() >= self.deadline or self.size + len(value) > self.maximum:
            raise LogicalArchiveError("archive_deadline_or_byte_limit")
        for offset in range(0, len(value), 1024**2):
            block = memoryview(value)[offset : offset + 1024**2]
            self.digest.update(block)
            while block:
                written = os.write(self.fd, block)
                if written <= 0:
                    raise LogicalArchiveError("archive_short_write")
                block = block[written:]
        self.size += len(value)

    def row(self, value: Mapping[str, Any]) -> None:
        if self.count >= MAX_ROWS:
            raise LogicalArchiveError("archive_row_count_limit")
        for part in encode_row(self.table, value):
            self.write(part)
        self.count += 1

    def finish(self) -> FileRecord:
        self.write(b"E" + struct.pack(">Q", self.count))
        os.fsync(self.fd)
        os.close(self.fd)
        self.fd = -1
        return {"size": self.size, "sha256": self.digest.hexdigest()}

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def read_rows(
    archive: PrivateDirectory, table: str, count: int, record: FileRecord, deadline: float
) -> Iterator[dict[str, Any]]:
    digest = hashlib.sha256()
    consumed = 0
    expected = columns(table)

    def take(stream: BinaryIO, length: int) -> bytes:
        nonlocal consumed
        if length > MAX_ROW or time.monotonic() >= deadline:
            raise LogicalArchiveError("archive_record_deadline_or_size")
        raw = stream.read(length)
        if len(raw) != length or consumed + length > record["size"]:
            raise LogicalArchiveError("archive_truncated_or_oversized")
        consumed += length
        digest.update(raw)
        return raw

    fd = archive.open_file(row_file(table))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        header = MAGIC + bytes.fromhex(checksum(schema_spec())) + table.encode() + b"\0"
        if before.st_size != record["size"] or take(stream, len(header)) != header:
            raise LogicalArchiveError("archive_table_or_schema_changed")
        if type(count) is not int or not 0 <= count <= MAX_ROWS:
            raise LogicalArchiveError("archive_row_count_limit")
        for _ in range(count):
            if take(stream, 1) != b"R":
                raise LogicalArchiveError("archive_record_marker")
            row, size = {}, 0
            for column in expected:
                tag = take(stream, 1)
                length = struct.unpack(">Q", take(stream, 8))[0]
                size += length + 9
                if length > MAX_CELL or size > MAX_ROW:
                    raise LogicalArchiveError("archive_cell_or_row_size_limit")
                data = take(stream, length)
                category = column["kind"]
                value: Any
                if tag == b"N" and not data:
                    value = None
                elif category in {"cipher", "bytes"} and tag == b"B":
                    value = data
                elif category == "bool" and tag == b"T" and data in {b"\0", b"\1"}:
                    value = bool(data[0])
                elif category in {"int32", "int64"} and tag == b"I" and len(data) == 8:
                    value = struct.unpack(">q", data)[0]
                elif category == "float" and tag == b"F" and len(data) == 8:
                    value = struct.unpack(">d", data)[0]
                elif category == "str" and tag == b"S":
                    value = data.decode()
                elif category == "json" and tag == b"J":
                    value = strict_loads(data)
                    if canonical(value) != data:
                        raise LogicalArchiveError("archive_noncanonical_json_cell")
                else:
                    raise LogicalArchiveError("archive_cell_type_tag")
                row[column["name"]] = normalized(value, column)
            yield row
        if take(stream, 9) != b"E" + struct.pack(">Q", count) or stream.read(1):
            raise LogicalArchiveError("archive_trailing_or_missing_records")
        after = os.fstat(stream.fileno())
        if (
            consumed != record["size"]
            or digest.hexdigest() != record["sha256"]
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise LogicalArchiveError("archive_records_changed_during_read")
