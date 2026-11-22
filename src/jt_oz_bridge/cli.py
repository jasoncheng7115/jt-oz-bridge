import argparse
import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path

import uvicorn
from pydantic import ValidationError
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from jt_oz_bridge.config import Settings, load_settings
from jt_oz_bridge.local_cli import add_inspection_commands, inspection_main
from jt_oz_bridge.security.admin import AdminAuth
from jt_oz_bridge.security.cipher import EnvelopeCipher, decode_key
from jt_oz_bridge.security.key_files import generate_key_file
from jt_oz_bridge.security.secrets import resolve_secret
from jt_oz_bridge.services.backups import BackupService, restore_sqlite_backup
from jt_oz_bridge.services.runtime_enrollment import enroll_runtime, runtime_factory
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.web.app import create_app


def configured_database(settings: Settings) -> Database:
    value = settings.database.url
    if settings.database.url_ref:
        value = resolve_secret(settings.database.url_ref).get_secret_value()
    if not value:
        value = f"sqlite+aiosqlite:///{settings.app.state_dir / 'bridge.db'}"
    parsed = make_url(value)
    if parsed.drivername == "sqlite+aiosqlite":
        target = Path(parsed.database or "")
        if not target.is_absolute() or target.is_symlink():
            raise ValueError("SQLite requires a local absolute regular path")
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if target.parent.stat().st_mode & 0o077:
            raise ValueError("SQLite directory must be owner-only")
    cipher = EnvelopeCipher(
        {"v1": decode_key(resolve_secret(settings.security.secret_key_ref))}, "v1"
    )
    return Database(value, settings.database.sqlite_busy_timeout_ms, cipher=cipher)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="jt-oz-bridge — OpenCode / Zulip bridge and local session inspector"
        " / OpenCode／Zulip 橋接與本機會話檢視"
    )
    parser.add_argument("--config", type=Path)
    sub = parser.add_subparsers(dest="command")
    add_inspection_commands(parser, sub)
    sub.add_parser("validate")
    sub.add_parser("migrate")
    sub.add_parser("serve")
    observer = sub.add_parser(
        "observe-serve", help="Run the Linux local observer / 啟動本機 observer"
    )
    observer.add_argument("--policy", type=Path, required=True)
    sub.add_parser("enroll-runtime")
    key = sub.add_parser("generate-key")
    key.add_argument("--secret-output", type=Path, required=True)
    bootstrap = sub.add_parser("bootstrap-admin")
    bootstrap.add_argument("--username", default="admin")
    backup = sub.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    backup.add_argument("--artifacts-dir", type=Path)
    backup.add_argument("--max-bytes", type=int, default=64 * 1024**3)
    backup.add_argument("--maximum-seconds", type=float, default=300)
    restore = sub.add_parser("restore")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--max-bytes", type=int, default=64 * 1024**3)
    restore.add_argument("--maximum-seconds", type=float, default=300)
    postgres_restore = sub.add_parser(
        "restore-postgres", help="Import an authenticated archive into an empty PostgreSQL database"
    )
    postgres_restore.add_argument("--backup", type=Path, required=True)
    postgres_restore.add_argument("--destination", type=Path, required=True)
    postgres_restore.add_argument("--max-bytes", type=int, default=64 * 1024**3)
    postgres_restore.add_argument("--maximum-seconds", type=float, default=300)
    review = sub.add_parser("complete-restore")
    review.add_argument("--backup-id", required=True)
    args = parser.parse_args()
    if args.command in {None, "sessions", "session", "doctor"}:
        inspection_main(args)
        return
    os.umask(0o077)
    try:
        settings = load_settings(args.config)
        if args.command == "generate-key":
            generate_key_file(args.secret_output)
            print(
                "Encryption key created in the owner-only file. Keep a separate protected backup."
            )
            return
        if args.command == "validate":
            print("Configuration valid. No connections or credentials resolved.")
            return
        if args.command == "restore":
            cipher = EnvelopeCipher(
                {"v1": decode_key(resolve_secret(settings.security.secret_key_ref))}, "v1"
            )
            result = asyncio.run(
                restore_sqlite_backup(
                    args.backup,
                    args.destination,
                    cipher,
                    key_ref=settings.security.secret_key_ref,
                    max_bytes=args.max_bytes,
                    maximum_seconds=args.maximum_seconds,
                )
            )
            print(json.dumps(result, sort_keys=True))
            return
        if args.command == "observe-serve":
            from jt_oz_bridge.services.inspection_runtime import serve_observer

            asyncio.run(serve_observer(settings, args.policy))
            return
        database = configured_database(settings)
        if args.command == "serve":
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                raise ValueError("run the bridge as a dedicated non-root user")
            runtime_failed = False

            def failed_runtime() -> None:
                nonlocal runtime_failed
                runtime_failed = True
                server.should_exit = True

            application = create_app(
                settings,
                database,
                runtime_factory=runtime_factory(settings) if settings.runtime.enabled else None,
                on_runtime_failure=failed_runtime,
            )
            server = uvicorn.Server(
                uvicorn.Config(
                    application,
                    host=settings.app.bind_host,
                    port=settings.app.bind_port,
                    workers=1,
                    proxy_headers=False,
                    access_log=False,
                )
            )
            server.run()
            if runtime_failed or not server.started:
                raise SystemExit(1)

        else:

            async def operation() -> None:
                try:
                    if args.command == "migrate":
                        await migrate(database.engine)
                        print("Database migrated.")
                    elif args.command == "enroll-runtime":
                        if not await database.ready():
                            raise ValueError("database not ready")
                        await enroll_runtime(settings, database)
                        print("Explicit qualified runtime scope enrolled; no Native mutation sent.")
                    elif args.command == "backup":
                        artifact_path = args.artifacts_dir or settings.app.state_dir / "artifacts"
                        result = await BackupService(database).create(
                            args.output,
                            settings,
                            artifacts=artifact_path if artifact_path.exists() else None,
                            max_bytes=args.max_bytes,
                            maximum_seconds=args.maximum_seconds,
                        )
                        print(json.dumps(result, sort_keys=True))
                    elif args.command == "restore-postgres":
                        from jt_oz_bridge.services.postgres_backups import restore_postgres_backup

                        result = await restore_postgres_backup(
                            args.backup,
                            args.destination,
                            database,
                            settings,
                            max_bytes=args.max_bytes,
                            maximum_seconds=args.maximum_seconds,
                        )
                        print(json.dumps(result, sort_keys=True))
                    elif args.command == "complete-restore":
                        result = await BackupService(database).complete_review(
                            args.backup_id, settings
                        )
                        print(json.dumps(result, sort_keys=True))
                    else:
                        if not await database.ready():
                            raise ValueError("database not ready")
                        password = await AdminAuth(database).create(args.username)
                        print("One-time administrator password (must be reset on first login):")
                        print(password)
                finally:
                    await database.close()

            asyncio.run(operation())
    except (ValidationError, ValueError, OSError, sqlite3.Error, SQLAlchemyError):
        # Config errors may include a bad DSN/password. Print no submitted values.
        print(
            "Configuration/operation rejected. Check documented paths, permissions and settings.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
