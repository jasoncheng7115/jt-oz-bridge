import asyncio
import contextlib
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParameter
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from sqlalchemy import and_, false, func, literal, or_, select
from sqlalchemy.exc import SQLAlchemyError

from jt_oz_bridge import __version__
from jt_oz_bridge.config import Locale, Settings
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.runtime_readiness import (
    MAX_ROOTS,
    RuntimeModeSnapshot,
    lease_fingerprint,
    scope_key,
)
from jt_oz_bridge.i18n import Translator, get_locale, save_locale
from jt_oz_bridge.security.admin import AdminAuth, LoginRejected, token_hash
from jt_oz_bridge.services.admin_decisions import UUID_KEY, AdminDecisions, Operation
from jt_oz_bridge.services.diagnostics import DiagnosticUnavailable, collect_diagnostics
from jt_oz_bridge.services.metrics import collect_storage_metrics, process_samples, render
from jt_oz_bridge.services.runtime import BridgeRuntime, RuntimeFactory, error_label
from jt_oz_bridge.services.runtime_configuration import (
    RuntimeConfiguration,
    SettingKey,
    SettingValue,
    valid_value,
)
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AdminAccount, AdminSession, WorkerLease
from jt_oz_bridge.web.catalog import (
    FILTER_NAMES,
    FILTERS,
    MAX_CURSOR,
    SECTIONS,
    SESSION_FILTERS,
    AdminCatalog,
    CatalogPage,
)
from jt_oz_bridge.web.limits import BodyLimit

HEARTBEAT_INTERVAL_SECONDS = 5.0
LOG = logging.getLogger(__name__)
# Bridge API v1 list routes and the catalog section that supplies each one.
API_LISTS = {
    "backends": "backends",
    "projects": "projects",
    "bindings": "bindings",
    "actions": "actions",
    "interactions": "interactions",
    "audit": "audit",
}
RECORD_ID = r"^[A-Za-z0-9_-]{1,36}$"
# Writes that would bypass Zulip Human authority or operator-reviewed, root-owned
# enrollment evidence. They are refused without reading the body.
REFUSED_WRITES = {
    "backend_enrollment": "backend_enrollment_requires_operator_reviewed_manifest",
    "backend_probe": "backend_probe_requires_operator_runtime_qualification",
    "binding_create": "binding_requires_zulip_human_confirmation",
    "queue_resume": "queue_resume_requires_zulip_human",
    "action_create": "actions_require_zulip_human",
    "interaction_reply": "interaction_reply_requires_zulip_human",
}


def query_filters(request: Request, spec: dict[str, str], *, strict: bool) -> dict[str, str]:
    """Collect exact filters from the query; repeated or unsupported names are refused."""
    chosen: dict[str, str] = {}
    for name, value in request.query_params.multi_items():
        if name in {"limit", "after"} or (name == "event" and not strict):
            continue
        if name in chosen or (name not in spec and (strict or name in FILTER_NAMES)):
            raise HTTPException(status_code=422, detail="unsupported_admin_filter")
        if name in spec:
            chosen[name] = value
    return chosen


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    password: str = Field(min_length=12, max_length=1024)


class LocaleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    locale: Locale


class DiagnosticInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class AdminPreviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    client_action_id: str = Field(pattern=UUID_KEY)
    operation: Operation
    binding_revision: int = Field(strict=True, ge=1)
    queue_revision: int = Field(strict=True, ge=0)


class AdminConfirmationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    confirmation_token: str = Field(min_length=1, max_length=128)
    version: int = Field(strict=True, ge=1)


class BindingPatchInput(BaseModel):
    """PATCH /api/v1/bindings/{id}: only pausing creates a reviewed preview."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    client_action_id: str = Field(pattern=UUID_KEY)
    dispatch_paused: StrictBool
    binding_revision: int = Field(strict=True, ge=1)
    queue_revision: int = Field(strict=True, ge=0)


class BindingDeleteInput(BaseModel):
    """DELETE /api/v1/bindings/{id}: unbind preview; never deletes an original session."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    client_action_id: str = Field(pattern=UUID_KEY)
    binding_revision: int = Field(strict=True, ge=1)
    queue_revision: int = Field(strict=True, ge=0)


class RuntimePreviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    client_action_id: str = Field(pattern=UUID_KEY)
    key: SettingKey
    value: SettingValue | None
    configuration_revision: int = Field(strict=True, ge=0)
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def typed_value(self) -> "RuntimePreviewInput":
        if self.value is not None and not valid_value(self.key, self.value):
            raise ValueError("unsupported_runtime_setting_value")
        return self


def create_app(
    settings: Settings,
    database: Database,
    *,
    runtime_factory: RuntimeFactory | None = None,
    on_runtime_failure: Callable[[], None] | None = None,
) -> FastAPI:
    store, auth, translator = DurableStore(database), AdminAuth(database), Translator()
    templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
    catalog = AdminCatalog(database, settings)
    decisions = AdminDecisions(database, settings)
    runtime_settings = RuntimeConfiguration(database, settings)
    holder, fencing = str(uuid.uuid4()), None
    lease_valid = False
    runtime: BridgeRuntime | None = None
    runtime_started = False
    failure_notified = False

    async def failed_runtime() -> None:
        nonlocal failure_notified
        if failure_notified:
            return
        failure_notified = True
        if runtime is not None:
            await runtime.close()
        if on_runtime_failure is not None:
            on_runtime_failure()

    async def heartbeat() -> None:
        nonlocal lease_valid
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            failure: Exception | None = None
            try:
                lease_valid = fencing is not None and await store.renew_lease(holder, fencing)
            except Exception as error:
                lease_valid = False
                failure = error
            if not lease_valid:
                # No exception/body/holder/SQL/DSN is included in diagnostics.
                LOG.warning(
                    "consumer_lease_lost reason=%s error_type=%s",
                    "renewal_error" if failure is not None else "renewal_rejected",
                    error_label(failure),
                )
                if runtime is not None and runtime_started:
                    await failed_runtime()
                return

    async def supervise_runtime() -> None:
        if runtime is not None:
            await runtime.wait_stopped()
            await failed_runtime()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        nonlocal fencing, lease_valid, runtime, runtime_started
        tasks: list[asyncio.Task[None]] = []
        try:
            if not await database.ready():
                raise RuntimeError("database migration required")
            fencing = await store.acquire_lease(holder)
            if fencing is None:
                raise RuntimeError("another active bridge process holds the consumer lease")
            lease_valid = True
            await store.recover()
            tasks.append(asyncio.create_task(heartbeat()))
            if runtime_factory is not None:
                runtime = runtime_factory(database, ConsumerFence(holder, fencing))
                if runtime.db is not database or runtime.fence != ConsumerFence(holder, fencing):
                    raise RuntimeError("runtime_must_share_process_database_and_consumer_fence")
                await runtime.start()
                runtime_started = True
                if not lease_valid or not runtime.healthy:
                    raise RuntimeError("runtime_not_ready_after_startup")
                tasks.append(asyncio.create_task(supervise_runtime()))
            yield
        finally:
            # Join all workers and their cancellation receipts before releasing
            # ownership or closing the database; never stop the original backend.
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if runtime is not None:
                await runtime.close()
            if fencing is not None:
                with contextlib.suppress(SQLAlchemyError):
                    await store.release_lease(holder, fencing)
            lease_valid = False
            await database.close()

    app = FastAPI(
        title="jt-oz-bridge",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        # No proxy identity headers are trusted. JSON mutation routes require CSRF.
        if (
            request.headers.get("content-length", "0").isdigit()
            and int(request.headers.get("content-length", "0")) > 65536
        ):
            return JSONResponse({"code": "request_too_large"}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(LoginRejected)
    async def auth_error(request: Request, error: LoginRejected) -> JSONResponse:
        code = str(error)
        return JSONResponse(
            {
                "code": code,
                "message_key": "error.generic",
                "params": {},
                "message": translator.render("error.generic"),
                "trace_id": str(uuid.uuid4()),
            },
            status_code=429 if code == "login_throttled" else 403,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
        # Pydantic error details can contain submitted passwords; never return the input.
        return JSONResponse(
            {
                "code": "invalid_request",
                "message_key": "error.generic",
                "params": {},
                "message": translator.render("error.generic"),
                "trace_id": str(uuid.uuid4()),
            },
            status_code=422,
        )

    @app.exception_handler(Conflict)
    async def decision_conflict(request: Request, error: Conflict) -> JSONResponse:
        # Conflict labels are ours, never an upstream response/SQL/secret.
        return JSONResponse(
            {
                "code": "administrative_conflict",
                "message_key": "error.generic",
                "message": translator.render("error.generic"),
                "trace_id": str(uuid.uuid4()),
            },
            status_code=409,
        )

    async def account(request: Request) -> AdminAccount:
        if not settings.admin.enabled:
            raise LoginRejected("admin_disabled")
        return await auth.authenticate(request.cookies.get("jtoz_session", ""))

    async def active_account(value: Annotated[AdminAccount, Depends(account)]) -> AdminAccount:
        if value.must_reset:
            raise LoginRejected("password_reset_required")
        return value

    async def csrf(request: Request, value: Annotated[AdminAccount, Depends(account)]) -> None:
        if request.headers.get("origin"):
            expected = settings.admin.public_url or str(request.base_url).rstrip("/")
            if request.headers["origin"] != expected.rstrip("/"):
                raise LoginRejected("origin_rejected")
        await auth.check_csrf(
            request.cookies.get("jtoz_session", ""), request.headers.get("x-csrf-token", "")
        )

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz")
    async def ready() -> JSONResponse:
        try:
            ok = lease_valid and (runtime is None or runtime.healthy) and await database.ready()
        except SQLAlchemyError:
            ok = False
        return JSONResponse(
            {
                "ready": ok,
                "mode": "managed" if runtime_factory is not None else "foundation",
                "agent_consumers": bool(ok and runtime is not None and runtime.healthy),
            },
            status_code=200 if ok else 503,
        )

    async def metrics_account(request: Request) -> AdminAccount:
        # Reject before authentication (which reads ownDB). Only the actual ASGI
        # transport peer is considered; forwarding headers confer no authority.
        if not settings.observability.metrics_enabled:
            raise HTTPException(status_code=404)
        if (
            request.client is None
            or request.client.host != settings.observability.metrics_bind_host
        ):
            raise HTTPException(status_code=403)
        return await active_account(await account(request))

    @app.get("/metrics")
    async def metrics(
        _account: Annotated[AdminAccount, Depends(metrics_account)],
    ) -> Response:
        states = ("queued", "held", "ambiguous")
        counts: dict[str, int] | None = None
        lease = None
        database_ready = False
        try:
            database_ready = await database.ready()
            if database_ready:
                async with database.sessions() as session:
                    lease = (
                        await session.execute(
                            select(
                                WorkerLease.holder, WorkerLease.fencing, WorkerLease.expires_at
                            ).where(WorkerLease.role == "consumer")
                        )
                    ).one_or_none()
                    # Select only grouped columns: never load/decrypt Action payloads.
                    rows = await session.execute(
                        select(Action.state, func.count(Action.id))
                        .where(Action.state.in_(states))
                        .group_by(Action.state)
                    )
                    counts = dict(rows.tuples().all())
        except SQLAlchemyError:
            # Missing samples are not fabricated zero backlog/valid ownership.
            counts = None
        available = database_ready and counts is not None
        samples = [
            ("runtime_configured", int(runtime_factory is not None)),
            ("database_ready", int(database_ready)),
            ("database_sample_available", int(available)),
        ]
        if runtime is not None:
            samples.append(("runtime_healthy", int(runtime.healthy)))
        if available:
            samples.append(
                (
                    "consumer_lease_valid",
                    int(
                        lease_valid
                        and lease is not None
                        and lease.holder == holder
                        and lease.fencing == fencing
                        and lease.expires_at > time.time()
                    ),
                )
            )
        lines: list[str] = []
        for name, value in samples:
            lines.extend((f"# TYPE jt_oz_bridge_{name} gauge", f"jt_oz_bridge_{name} {value}"))
        if counts is not None:
            lines.append("# TYPE jt_oz_bridge_actions gauge")
            lines.extend(
                f'jt_oz_bridge_actions{{state="{state}"}} {counts.get(state, 0)}'
                for state in states
            )
        if available:
            try:
                storage = await collect_storage_metrics(database, settings, time.time())
            except (SQLAlchemyError, TimeoutError, ValueError, OSError):
                storage = None  # Omitted, never a fabricated zero backlog or size.
            lines.extend(
                (
                    "# TYPE jt_oz_bridge_storage_sample_available gauge",
                    f"jt_oz_bridge_storage_sample_available {int(storage is not None)}",
                )
            )
            lines.extend(render(storage or []))
        lines.extend(render(process_samples(runtime)))
        # Process/ownDB observations only: no per-Root writability or Native proof.
        return Response(
            "\n".join(lines) + "\n",
            status_code=200 if available else 503,
            media_type="text/plain; version=0.0.4",
        )

    @app.post("/api/v1/admin/diagnostics/export", dependencies=[Depends(csrf)])
    async def diagnostic_export(
        _body: DiagnosticInput,
        request: Request,
        principal: Annotated[AdminAccount, Depends(active_account)],
    ) -> Response:
        try:
            content = await collect_diagnostics(
                database,
                settings,
                process_lease_current=lease_valid,
                runtime_healthy=runtime.healthy if runtime is not None else None,
            )
        except DiagnosticUnavailable:
            # No SQL exception, settings value, prompt or path is returned.
            raise HTTPException(status_code=503, detail="diagnostic_export_unavailable") from None
        # Reauthenticate the original cookie after database/file observations.
        fresh = await active_account(await account(request))
        if fresh.id != principal.id:
            raise LoginRejected("active_administrator_session_required")
        return Response(
            content,
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="jt-oz-bridge-diagnostics.json"',
                "Cache-Control": "no-store",
            },
        )

    @app.post("/api/v1/auth/login")
    async def login(body: LoginInput, request: Request) -> JSONResponse:
        if not settings.admin.enabled:
            raise LoginRejected("admin_disabled")
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise LoginRejected("json_required")
        # JSON content type prevents HTML form-based login CSRF. Never trust X-Forwarded-For.
        if request.headers.get("origin") and request.headers["origin"] != (
            settings.admin.public_url or str(request.base_url).rstrip("/")
        ):
            raise LoginRejected("origin_rejected")
        token, csrf_token, must_reset = await auth.login(
            body.username, body.password, request.client.host if request.client else "unknown"
        )
        response = JSONResponse({"csrf_token": csrf_token, "password_reset_required": must_reset})
        response.set_cookie(
            "jtoz_session", token, max_age=3600, secure=True, httponly=True, samesite="strict"
        )
        response.set_cookie("jtoz_csrf", csrf_token, max_age=3600, secure=True, samesite="strict")
        return response

    @app.post("/api/v1/auth/password", dependencies=[Depends(csrf)])
    async def password(
        body: PasswordInput, value: Annotated[AdminAccount, Depends(account)]
    ) -> dict[str, str]:
        await auth.reset_password(value, body.password)
        return {"status": "password_changed_sign_in_again"}

    @app.post("/api/v1/auth/logout", dependencies=[Depends(csrf)])
    async def logout(request: Request) -> JSONResponse:
        await auth.logout(request.cookies.get("jtoz_session", ""))
        response = JSONResponse({"status": "signed_out"})
        response.delete_cookie("jtoz_session", secure=True, httponly=True, samesite="strict")
        response.delete_cookie("jtoz_csrf", secure=True, samesite="strict")
        return response

    @app.get("/api/v1/capabilities", dependencies=[Depends(active_account)])
    async def capabilities() -> dict[str, Any]:
        return {
            "mode": "managed" if runtime_factory is not None else "foundation",
            "live_operations_enabled": bool(
                lease_valid and runtime is not None and runtime.healthy
            ),
            "live_operations_scope": "consumer_health_only",
            "grants_operation_authority": False,
            "runtime_modes_url": "/api/v1/admin/runtime-modes",
            "backends": [
                {
                    "id": b.id,
                    "certified": False,
                    "reason": "partial_runtime_qualification_not_full_acceptance"
                    if runtime_factory is not None
                    else "installed_contract_not_certified",
                }
                for b in settings.opencode_backends
            ],
        }

    @app.get("/api/v1/preferences/me")
    async def preferences(
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, str]:
        return {
            "locale": await get_locale(
                database, "admin:" + value.id, await runtime_settings.locale()
            )
        }

    @app.patch("/api/v1/preferences/me", dependencies=[Depends(csrf)])
    async def set_preferences(
        body: LocaleInput, value: Annotated[AdminAccount, Depends(active_account)]
    ) -> dict[str, str]:
        await save_locale(database, "admin:" + value.id, body.locale)
        return {"locale": body.locale}

    def active_fence() -> ConsumerFence:
        if not lease_valid or fencing is None:
            raise Conflict("consumer_lease_unavailable")
        return ConsumerFence(holder, fencing)

    @app.post("/api/v1/admin/settings/preview", dependencies=[Depends(csrf)])
    async def preview_setting(
        request: Request,
        body: RuntimePreviewInput,
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await runtime_settings.preview(
            request.cookies.get("jtoz_session", ""), value.id, active_fence(), **body.model_dump()
        )

    @app.post(
        "/api/v1/admin/settings/decisions/{decision_id}/confirm", dependencies=[Depends(csrf)]
    )
    async def confirm_setting(
        request: Request,
        body: AdminConfirmationInput,
        decision_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await runtime_settings.finish(
            request.cookies.get("jtoz_session", ""),
            value.id,
            active_fence(),
            decision_id=decision_id,
            **body.model_dump(),
        )

    @app.post("/api/v1/admin/settings/decisions/{decision_id}/cancel", dependencies=[Depends(csrf)])
    async def cancel_setting(
        request: Request,
        body: AdminConfirmationInput,
        decision_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await runtime_settings.finish(
            request.cookies.get("jtoz_session", ""),
            value.id,
            active_fence(),
            decision_id=decision_id,
            cancel=True,
            **body.model_dump(),
        )

    @app.post("/api/v1/admin/bindings/{binding_id}/preview", dependencies=[Depends(csrf)])
    async def preview_management(
        request: Request,
        body: AdminPreviewInput,
        binding_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await decisions.preview(
            request.cookies.get("jtoz_session", ""),
            value.id,
            active_fence(),
            binding_id=binding_id,
            **body.model_dump(),
        )

    @app.post("/api/v1/admin/decisions/{decision_id}/confirm", dependencies=[Depends(csrf)])
    async def confirm_management(
        request: Request,
        body: AdminConfirmationInput,
        decision_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await decisions.finish(
            request.cookies.get("jtoz_session", ""),
            value.id,
            active_fence(),
            decision_id=decision_id,
            **body.model_dump(),
        )

    @app.post("/api/v1/admin/decisions/{decision_id}/cancel", dependencies=[Depends(csrf)])
    async def cancel_management(
        request: Request,
        body: AdminConfirmationInput,
        decision_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return await decisions.finish(
            request.cookies.get("jtoz_session", ""),
            value.id,
            active_fence(),
            decision_id=decision_id,
            cancel=True,
            **body.model_dump(),
        )

    async def runtime_modes(
        request: Request, *, admin_id: str, limit: int, after: str
    ) -> dict[str, Any]:
        # This view is administrative metadata, not a Human grant or Native proof.
        # Enumerate authorized current bindings first; never enumerate snapshot hashes.
        backends = {b.id for b in settings.opencode_backends if b.enabled}
        realms = {r.id: r for r in settings.zulip_realms if r.enabled}
        allowed = [
            and_(
                Binding.project_id == p.id,
                Binding.backend_id == p.backend_id,
                Binding.realm_id == p.realm_id,
                Binding.channel_id.in_(realms[p.realm_id].allowed_channel_ids),
                or_(
                    Binding.canonical_directory == str(PurePosixPath(p.workspace_root)),
                    Binding.canonical_directory.startswith(
                        str(PurePosixPath(p.workspace_root)).rstrip("/") + "/", autoescape=True
                    ),
                ),
            )
            for p in settings.projects
            if p.enabled
            and p.backend_id in backends
            and p.realm_id in realms
            and p.workspace_root.startswith("/")
            and not p.workspace_root.startswith("//")
            and not {".", ".."}.intersection(p.workspace_root.split("/"))
        ]
        columns = (
            Binding.id,
            Binding.backend_id,
            Binding.backend_identity,
            Binding.session_id,
            Binding.project_id,
            Binding.canonical_directory,
            Binding.revision,
        )
        statement = (
            select(*columns)
            .join(EnrolledBackend, EnrolledBackend.id == Binding.backend_id)
            .join(EnrolledProject, EnrolledProject.id == Binding.project_id)
            .where(
                Binding.id > after,
                Binding.state == "active",
                EnrolledBackend.enabled.is_(True),
                EnrolledBackend.verified.is_(True),
                EnrolledBackend.identity == Binding.backend_identity,
                EnrolledProject.enabled.is_(True),
                EnrolledProject.backend_id == Binding.backend_id,
                EnrolledProject.realm_id == Binding.realm_id,
                EnrolledProject.canonical_directory == Binding.canonical_directory,
                # Lexical loaded-configuration boundary only, not physical FS proof.
                ~Binding.canonical_directory.contains("/../"),
                ~Binding.canonical_directory.endswith("/.."),
                ~Binding.canonical_directory.contains("/./"),
                ~Binding.canonical_directory.endswith("/."),
                ~Binding.canonical_directory.contains("//"),
                or_(*allowed) if allowed else false(),
            )
            .order_by(Binding.id)
            .limit(limit + 1)
        )

        async def current_rows() -> list[Any]:
            async with database.sessions() as session:
                return list((await session.execute(statement)).all())

        async def current_lease() -> float | None:
            eligible = bool(
                lease_valid and fencing is not None and runtime is not None and runtime.healthy
            )
            clock = (
                (func.julianday("now") - 2440587.5) * 86400.0
                if database.engine.dialect.name == "sqlite"
                else func.extract("epoch", func.clock_timestamp())
            )
            async with database.sessions() as session:
                live_lease = select(WorkerLease.expires_at).where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == holder,
                    WorkerLease.fencing == fencing,
                    WorkerLease.expires_at > clock,
                    literal(eligible),
                )
                principal = and_(
                    select(AdminAccount.id)
                    .where(AdminAccount.id == admin_id, AdminAccount.must_reset.is_(False))
                    .exists(),
                    select(AdminSession.token_hash)
                    .where(
                        AdminSession.token_hash
                        == token_hash(request.cookies.get("jtoz_session", "")),
                        AdminSession.admin_id == admin_id,
                        AdminSession.expires_at > clock,
                    )
                    .exists(),
                )
                active, expires = (
                    await session.execute(select(principal, live_lease.scalar_subquery()))
                ).one()
                if not active:
                    raise LoginRejected("active_administrator_session_required")
            return float(expires) if expires is not None else None

        rows = await current_rows()
        observed: RuntimeModeSnapshot | None = None
        fallback = "unavailable"
        expires = await current_lease()
        if expires is not None:
            callback = getattr(runtime, "runtime_mode_snapshot", None)
            if not callable(callback):
                fallback = "not-observed"
            else:
                try:
                    value = callback()  # Optional synchronous Main-owned observation only.
                    if (
                        type(value) is RuntimeModeSnapshot
                        and type(value.roots) is tuple
                        and len(value.roots) <= MAX_ROOTS
                    ):
                        observed = RuntimeModeSnapshot.model_validate(value.model_dump(mode="json"))
                except Exception:
                    # Do not expose exception text or consume any filesystem projection.
                    observed = None
        await active_account(await account(request))
        unchanged = rows == await current_rows()
        expires = await current_lease()
        now = time.time()  # Reject stale observations after every awaited metadata read.
        healthy = bool(
            expires is not None
            and now < expires
            and lease_valid
            and fencing is not None
            and runtime is not None
            and runtime.healthy
            and runtime.fence == ConsumerFence(holder, fencing)
        )
        valid = bool(
            healthy
            and observed is not None
            and observed.generated_at <= now < observed.generated_at + 5.0
            and fencing is not None
            and observed.lease_fingerprint == lease_fingerprint(holder, fencing)
        )
        facts = {fact.scope_key: fact for fact in observed.roots} if valid and observed else {}
        if not healthy:
            fallback = "unavailable"
        if not unchanged:
            rows = []  # A changed binding is not correlated against the old full reference.
        items = []
        for row in rows[:limit]:
            reference = SessionRef(
                backend_id=row.backend_id,
                backend_identity=row.backend_identity,
                upstream_session_id=row.session_id,
                project_id=row.project_id,
                canonical_directory=row.canonical_directory,
            )
            fact = facts.get(scope_key(reference))
            mode = fact.mode if fact else "not-observed" if valid else fallback
            items.append(
                {
                    "binding_id": row.id,
                    "mode": mode,
                    "reason": fact.reason
                    if fact
                    else "not-observed"
                    if mode == "not-observed"
                    else "diagnostics-unavailable",
                    "transition_at": fact.transition_at if fact else None,
                    "observed_at": observed.generated_at if fact and observed else None,
                }
            )
        now = time.time()  # Final gate after bounded full-reference hashing/projection too.
        if not (
            expires is not None
            and now < expires
            and lease_valid
            and fencing is not None
            and runtime is not None
            and runtime.healthy
            and runtime.fence == ConsumerFence(holder, fencing)
            and (observed is None or observed.generated_at <= now < observed.generated_at + 5.0)
        ):
            for item in items:
                item.update(
                    mode="unavailable",
                    reason="diagnostics-unavailable",
                    transition_at=None,
                    observed_at=None,
                )
        return {
            "read_only": True,
            "authority": "diagnostic_only",
            "source": "in_process_current_bindings",
            "items": items,
            "next_after": rows[limit - 1].id if len(rows) > limit else None,
        }

    @app.get("/api/v1/admin/runtime-modes")
    async def runtime_modes_api(
        request: Request,
        value: Annotated[AdminAccount, Depends(active_account)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        after: Annotated[str, Query(max_length=255)] = "",
    ) -> dict[str, Any]:
        return await runtime_modes(request, admin_id=value.id, limit=limit, after=after)

    @app.get("/admin/runtime-modes", response_class=HTMLResponse)
    async def runtime_modes_page(
        request: Request,
        value: Annotated[AdminAccount, Depends(active_account)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        after: Annotated[str, Query(max_length=255)] = "",
    ) -> HTMLResponse:
        locale = await get_locale(database, "admin:" + value.id, await runtime_settings.locale())
        result = await runtime_modes(request, admin_id=value.id, limit=limit, after=after)
        return templates.TemplateResponse(
            request=request,
            name="runtime-modes.html",
            context={
                "locale": locale,
                "t": lambda key: translator.render(key, locale),
                "result": result,
                "sections": SECTIONS,
                "next_url": "/admin/runtime-modes?"
                + urlencode({"limit": limit, "after": result["next_after"]})
                if result["next_after"]
                else None,
            },
        )

    async def catalog_page(
        section: str, *, limit: int, after: str, event: str = "", filters: dict[str, str]
    ) -> CatalogPage:
        try:
            return await catalog.page(
                section, limit=limit, after=after, event=event, filters=filters
            )
        except ValueError as error:
            # Labels are ours (invalid/unsupported filter or page), never the input.
            raise HTTPException(status_code=422, detail=str(error)) from None

    def api_list(resource: str, section: str) -> None:
        async def listing(
            request: Request,
            _value: Annotated[AdminAccount, Depends(active_account)],
            limit: Annotated[int, Query(ge=1, le=100)] = 25,
            after: Annotated[str, Query(max_length=255)] = "",
        ) -> dict[str, Any]:
            page = await catalog_page(
                section,
                limit=limit,
                after=after,
                filters=query_filters(request, FILTERS.get(section, {}), strict=True),
            )
            result = {**page.response(), "resource": resource, "limit": limit}
            if resource == "backends":
                # Enrollment comes from operator-reviewed root-owned evidence; this API
                # reports it but neither probes nor enrolls an upstream.
                result.update(
                    enrollment_source="operator_reviewed_runtime_manifest",
                    probe_available=False,
                )
            return result

        listing.__name__ = "api_list_" + resource
        app.get("/api/v1/" + resource)(listing)

    for resource, section in API_LISTS.items():
        api_list(resource, section)

    @app.get("/api/v1/sessions")
    async def sessions_api(
        request: Request,
        _value: Annotated[AdminAccount, Depends(active_account)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        after: Annotated[str, Query(max_length=MAX_CURSOR)] = "",
    ) -> dict[str, Any]:
        try:
            page = await catalog.sessions(
                limit=limit,
                after=after,
                filters=query_filters(request, SESSION_FILTERS, strict=True),
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return {**page.response(), "resource": "sessions", "limit": limit, "native_requests": 0}

    @app.get("/api/v1/actions/{action_id}", dependencies=[Depends(active_account)])
    async def action_detail(
        action_id: Annotated[str, PathParameter(pattern=RECORD_ID)],
    ) -> dict[str, Any]:
        item = await catalog.action(action_id)
        if item is None:
            raise HTTPException(status_code=404, detail="unknown_action")
        return {"item": item, "read_only": True, "source": "bridge_database"}

    @app.get("/api/v1/artifacts/{artifact_id}", dependencies=[Depends(active_account)])
    async def artifact_metadata(
        artifact_id: Annotated[str, PathParameter(pattern=RECORD_ID)],
    ) -> dict[str, Any]:
        item = await catalog.artifact(artifact_id)
        if item is None:
            raise HTTPException(status_code=404, detail="unknown_artifact")
        return {
            "item": item,
            "read_only": True,
            "source": "bridge_database",
            "descriptor_encrypted": True,
            # No HTTP artifact download path exists; HTML is never rendered here.
            "download": {"available": False, "reason": "no_http_artifact_download_endpoint"},
        }

    def refused(kind: str) -> JSONResponse:
        return JSONResponse(
            {
                "code": "administrative_write_refused",
                "reason": REFUSED_WRITES[kind],
                "message_key": "error.generic",
                "params": {},
                "message": translator.render("error.generic"),
                "trace_id": str(uuid.uuid4()),
            },
            status_code=403,
        )

    def preview_links(result: dict[str, Any]) -> dict[str, Any]:
        decision = result["decision_id"]
        return {
            **result,
            "confirm_path": f"/api/v1/admin/decisions/{decision}/confirm",
            "cancel_path": f"/api/v1/admin/decisions/{decision}/cancel",
        }

    @app.patch("/api/v1/bindings/{binding_id}", dependencies=[Depends(csrf)])
    async def patch_binding(
        request: Request,
        body: BindingPatchInput,
        binding_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> Any:
        if not body.dispatch_paused:
            # Releasing a held Human queue is a Zulip Human decision, not a web one.
            return refused("queue_resume")
        return preview_links(
            await decisions.preview(
                request.cookies.get("jtoz_session", ""),
                value.id,
                active_fence(),
                client_action_id=body.client_action_id,
                operation="pause",
                binding_id=binding_id,
                binding_revision=body.binding_revision,
                queue_revision=body.queue_revision,
            )
        )

    @app.delete("/api/v1/bindings/{binding_id}", dependencies=[Depends(csrf)])
    async def delete_binding(
        request: Request,
        body: BindingDeleteInput,
        binding_id: Annotated[str, PathParameter(pattern=UUID_KEY)],
        value: Annotated[AdminAccount, Depends(active_account)],
    ) -> dict[str, Any]:
        return preview_links(
            await decisions.preview(
                request.cookies.get("jtoz_session", ""),
                value.id,
                active_fence(),
                client_action_id=body.client_action_id,
                operation="unbind",
                binding_id=binding_id,
                binding_revision=body.binding_revision,
                queue_revision=body.queue_revision,
            )
        )

    @app.post("/api/v1/backends", dependencies=[Depends(csrf), Depends(active_account)])
    async def enroll_backend() -> JSONResponse:
        return refused("backend_enrollment")

    @app.post(
        "/api/v1/backends/{backend_id}/probe",
        dependencies=[Depends(csrf), Depends(active_account)],
    )
    async def probe_backend(
        backend_id: Annotated[str, PathParameter(min_length=1, max_length=255)],
    ) -> JSONResponse:
        return refused("backend_probe")

    @app.post("/api/v1/bindings", dependencies=[Depends(csrf), Depends(active_account)])
    async def create_binding() -> JSONResponse:
        return refused("binding_create")

    @app.post("/api/v1/actions", dependencies=[Depends(csrf), Depends(active_account)])
    async def create_action() -> JSONResponse:
        return refused("action_create")

    @app.post(
        "/api/v1/interactions/{interaction_id}/reply",
        dependencies=[Depends(csrf), Depends(active_account)],
    )
    async def reply_interaction(
        interaction_id: Annotated[str, PathParameter(pattern=RECORD_ID)],
    ) -> JSONResponse:
        return refused("interaction_reply")

    @app.get("/api/v1/admin/{section}", dependencies=[Depends(active_account)])
    async def admin_metadata(
        request: Request,
        section: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        after: Annotated[str, Query(max_length=255)] = "",
        event: Annotated[str, Query(max_length=64)] = "",
    ) -> dict[str, Any]:
        if section not in SECTIONS:
            raise HTTPException(status_code=404, detail="unknown_admin_section")
        if event and section != "audit":
            raise HTTPException(status_code=422, detail="audit_filter_only")
        filters = query_filters(request, FILTERS.get(section, {}), strict=False)
        return (
            await catalog_page(section, limit=limit, after=after, event=event, filters=filters)
        ).response()

    @app.get("/admin/{section}", response_class=HTMLResponse)
    async def admin_page(
        request: Request,
        section: str,
        value: Annotated[AdminAccount, Depends(active_account)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        after: Annotated[str, Query(max_length=255)] = "",
        event: Annotated[str, Query(max_length=64)] = "",
    ) -> HTMLResponse:
        if section not in SECTIONS:
            raise HTTPException(status_code=404, detail="unknown_admin_section")
        if event and section != "audit":
            raise HTTPException(status_code=422, detail="audit_filter_only")
        filters = query_filters(request, FILTERS.get(section, {}), strict=False)
        locale = await get_locale(database, "admin:" + value.id, await runtime_settings.locale())
        page = await catalog_page(section, limit=limit, after=after, event=event, filters=filters)
        submitted = {
            name: raw
            for name, raw in ({"event": event} | filters).items()
            if raw != "" and name in page.filters
        }
        next_url = (
            "/admin/"
            + section
            + "?"
            + urlencode({"limit": limit, "after": page.next_after, **submitted})
            if page.next_after
            else None
        )
        filter_inputs = [
            (name, kind, submitted.get(name, "")) for name, kind in FILTERS.get(section, {}).items()
        ]
        return templates.TemplateResponse(
            request=request,
            name="catalog.html",
            context={
                "locale": locale,
                "t": lambda key: translator.render(key, locale),
                "page": page,
                "sections": SECTIONS,
                "next_url": next_url,
                "limit": limit,
                "event": event,
                "filter_inputs": filter_inputs,
                "api_path": "/api/v1/" + section if section in API_LISTS else None,
            },
        )

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request) -> HTMLResponse:
        try:
            value = await active_account(await account(request))
            locale = await get_locale(
                database, "admin:" + value.id, await runtime_settings.locale()
            )
        except LoginRejected:
            locale = await runtime_settings.locale()
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"locale": locale, "t": lambda key: translator.render(key, locale)},
            )
        return templates.TemplateResponse(
            request=request,
            name="overview.html",
            context={
                "locale": locale,
                "t": lambda key: translator.render(key, locale),
                "version": __version__,
                "sections": SECTIONS,
                "managed": runtime_factory is not None,
            },
        )

    from fastapi.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app
