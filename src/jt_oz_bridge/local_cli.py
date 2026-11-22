"""Unprivileged local observer client; never loads Bridge config or secrets."""

import argparse
import asyncio
import json
import pwd
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Literal

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.inspection import (
    InspectionClock,
    InspectionProtocolResponse,
    InspectionQuery,
    InspectionQueryV2,
    InspectionResponseV2,
    InspectionSessionV2,
    fresh_inspection_response,
)
from jt_oz_bridge.services.inspection_socket import DEFAULT_SOCKET, error, inspect_query


def safe_terminal(value: object, maximum: int = 512) -> str:
    text = str(value)
    result = []
    for char in text[:maximum]:
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}:
            result.append(f"\\u{ord(char):04x}")
        else:
            result.append(char)
    return "".join(result) + ("…" if len(text) > maximum else "")


def labels(locale: Locale) -> dict[str, str]:
    if locale == "zh-TW":
        return {
            "runtime_modes": "Root 控制器觀察",
            "mode_warning": "控制器觀察不代表 Native 閒置或可寫；每次操作仍須獨立授權證明。",
            "mode_error": "執行模式無法取得；需要支援 inspector-v2 的 observer，請檢查版本、服務與權限。",
            "title": "OpenCode／Zulip 會話",
            "empty": "此頁沒有符合的會話。",
            "bridge": "Bridge 就緒／租約有效",
            "process_only": "程序就緒／租約有效不代表此 Root 已取得派送授權。",
            "recorded_work": "Bridge 記錄的待處理／待確認工作",
            "recorded_warning": "Bridge 工作紀錄不等於 Native 正在執行。",
            "native_unverified": "Native 執行狀態待確認；不可據此認定閒置或可派送。",
            "native": "Native 狀態",
            "binding": "Zulip 綁定紀錄",
            "directory": "目錄",
            "warning": "注意",
            "next": "下一頁",
            "unknown": "未知",
            "counts": "佇列與投遞",
            "access": "即時存取權尚未核驗",
            "coverage": "涵蓋範圍",
            "age": "原始觀測距今秒數",
            "stale": "觀測已過期或時鐘不可信；未知不代表 Native 閒置。",
            "error": "本機 observer 無法使用；請檢查服務、socket 與本機帳號權限。",
            "scope_error": "指定的後端或專案不在 observer 已納管範圍內；名稱或標題不是識別碼。",
            "invalid": "查詢參數無效；請依說明使用範圍內的數值與精確識別碼。",
        }
    return {
        "runtime_modes": "Root controller observation",
        "mode_warning": "Controller observations do not prove Native idle or writable; each operation requires its own authority proof.",
        "mode_error": "Runtime modes unavailable; an inspector-v2 observer is required. Check version, service and permissions.",
        "title": "OpenCode / Zulip sessions",
        "empty": "No matching sessions on this page.",
        "bridge": "Bridge ready / lease current",
        "process_only": "Process readiness and a current lease are not session mutation authority.",
        "recorded_work": "Bridge recorded pending / uncertain work",
        "recorded_warning": "Bridge work records do not prove that Native is executing.",
        "native_unverified": "Native execution is unverified; do not infer idle or mutation readiness.",
        "native": "Native state",
        "binding": "Zulip binding record",
        "directory": "Directory",
        "warning": "Warning",
        "next": "Next page",
        "unknown": "unknown",
        "counts": "Queue and delivery",
        "access": "live access not verified",
        "coverage": "Coverage",
        "age": "Original observation age in seconds",
        "stale": "Observation expired or clock uncertain; unknown does not imply Native idle.",
        "error": "Local observer unavailable; check service, socket and local account permissions.",
        "scope_error": "Requested backend or project is outside the observer's enrolled scope; names and titles are not identifiers.",
        "invalid": "Invalid inspection request; use the documented bounds and exact identifiers.",
    }


def runtime_mode_label(mode: str, locale: Locale) -> str:
    if locale == "zh-TW":
        return {
            "unstarted": "尚未啟動",
            "strict": "嚴格觀察",
            "readonly-owned-check": "唯讀：恢復既有檢查",
            "readonly-awaiting-idle": "唯讀：等待正向閒置證據",
            "unavailable": "無法取得",
            "not-observed": "未觀察",
        }[mode]
    return {
        "unstarted": "Not started",
        "strict": "Strict observation",
        "readonly-owned-check": "Read only: recovering owned check",
        "readonly-awaiting-idle": "Read only: awaiting positive idle evidence",
        "unavailable": "Unavailable",
        "not-observed": "Not observed",
    }[mode]


def render(response: InspectionProtocolResponse, locale: Locale, *, details: bool = False) -> str:
    tr = labels(locale)
    lines = [
        tr["title"],
        f"{tr['bridge']}: {response.bridge_ready} / {response.bridge_lease_current}",
        tr["process_only"],
        f"observed_at={response.observed_at:.3f}",
    ]
    if isinstance(response, InspectionResponseV2):
        lines.append(tr["mode_warning"])
    codes = {issue.code for issue in response.issues}
    if not response.rows:
        lines.append(
            tr["empty"]
            if response.status != "error"
            else tr["scope_error"]
            if "scope_unavailable" in codes
            else tr["invalid"]
            if "invalid_request" in codes
            else tr["mode_error"]
            if isinstance(response, InspectionResponseV2)
            else tr["error"]
        )
    for row in response.rows:
        association = (
            "bound-record"
            if row.bound
            else "unbound"
            if row.binding_coverage == "complete"
            else "association-unknown"
        )
        lines.append(f"\n{safe_terminal(row.session_id)}  [{row.state.value}]  [{association}]")
        lines.append(f"  {tr['age']}: {time.time() - row.observed_at:.3f}")
        lines.append(f"  {safe_terminal(row.title, 160)}")
        lines.append(
            f"  backend={safe_terminal(row.backend_id)}  {tr['directory']}: {safe_terminal(row.directory)}"
        )
        if row.provider_id and row.model_id:
            lines.append(
                f"  model={safe_terminal(row.provider_id)}/{safe_terminal(row.model_id)}  agent={safe_terminal(row.agent_id or tr['unknown'])}"
            )
        if isinstance(row, InspectionSessionV2):
            mode = row.runtime_mode
            lines.append(
                f"  {tr['runtime_modes']}: {runtime_mode_label(mode.mode, locale)} [{mode.mode}] ({mode.reason}) transition_at={mode.transition_at} observed_at={mode.observed_at}"
            )
        for binding in row.bindings:
            lines.append(
                f"  {tr['binding']}: {safe_terminal(binding.realm_id)} / #{binding.channel_id} / {safe_terminal(binding.topic)} [{binding.state}] paused={binding.paused}"
            )
            if details:
                lines.append(f"    revision={binding.revision}  {tr['access']}")
                if binding.conversation_url:
                    lines.append("    " + safe_terminal(binding.conversation_url, 4096))
                lines.append(
                    f"    {tr['counts']}: "
                    + json.dumps(binding.counts.model_dump(), sort_keys=True)
                )
        pending = {
            key: sum(getattr(binding.counts, key) for binding in row.bindings)
            for key in ("queued", "held", "active", "ambiguous")
        }
        if any(pending.values()):
            lines.append(f"  {tr['recorded_work']}: " + json.dumps(pending, sort_keys=True))
            lines.append("  " + tr["recorded_warning"])
            if row.state.value == "unknown":
                lines.append("  " + tr["native_unverified"])
        if details:
            lines.append(
                f"  state_evidence={row.state_reason}  last_outcome={row.last_outcome or '-'}  execution_registration={row.execution_registration}"
            )
            if row.parent_id or row.fork_source_id:
                lines.append(
                    f"  parent={safe_terminal(row.parent_id or '-')} fork_source={safe_terminal(row.fork_source_id or '-')}"
                )
    for coverage in response.coverage:
        lines.append(
            f"{tr['coverage']}: {safe_terminal(coverage.backend_id)} scanned={coverage.scanned} complete={coverage.complete} ({coverage.reason})"
        )
        if coverage.owner_epoch:
            lines.append(f"  native_pid={coverage.native_pid} owner_epoch={coverage.owner_epoch}")
        if coverage.next_cursor:
            # Display a JSON literal instead of a shell-ready command assembled
            # from an upstream cursor. Users can pass it as --cursor themselves.
            lines.append(
                f"  {tr['next']}: --backend {safe_terminal(coverage.backend_id)} --cursor "
                + json.dumps(coverage.next_cursor, ensure_ascii=True)
            )
    for issue in response.issues:
        if issue.code == "stale_observation":
            lines.append(tr["stale"])
        lines.append(
            f"{tr['warning']}: {issue.code}"
            + (" / " + safe_terminal(issue.backend_id) if issue.backend_id else "")
        )
    return "\n".join(lines)


def common(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    def default(value: Any) -> Any:
        return argparse.SUPPRESS if suppress else value

    parser.add_argument(
        "--socket",
        dest="inspection_socket",
        type=Path,
        default=default(DEFAULT_SOCKET),
        help="Local observer socket / 本機 observer socket",
    )
    parser.add_argument(
        "--json",
        dest="inspection_json",
        action="store_true",
        default=default(False),
        help="Versioned JSON / 版本化 JSON",
    )
    parser.add_argument(
        "--runtime-modes",
        dest="inspection_runtime_modes",
        action="store_true",
        default=default(False),
        help="Controller diagnostic modes (inspector-v2 required) / 控制器觀察模式（需 inspector-v2）",
    )
    parser.add_argument(
        "--locale",
        dest="inspection_locale",
        choices=("en", "zh-TW"),
        default=default("en"),
        help="Display language / 顯示語言",
    )


def add_inspection_commands(parser: argparse.ArgumentParser, sub: Any) -> None:
    common(parser)
    listing = sub.add_parser(
        "sessions", help="List Native sessions and Zulip mappings / 列出會話與對應"
    )
    common(listing, suppress=True)
    listing.add_argument("--backend", dest="backend_id", help="Exact backend ID / 精確後端 ID")
    listing.add_argument(
        "--project", dest="project_id", help="Exact enrolled project ID / 精確已納管專案 ID"
    )
    association = listing.add_mutually_exclusive_group()
    association.add_argument(
        "--bound",
        dest="association",
        action="store_const",
        const="bound",
        help="Only active Zulip binding records / 只列有效 Zulip 綁定紀錄",
    )
    association.add_argument(
        "--unbound",
        dest="association",
        action="store_const",
        const="unbound",
        help="Only sessions confirmed without an active binding / 只列確認未綁定的會話",
    )
    listing.set_defaults(association="all")
    listing.add_argument(
        "--active",
        action="store_true",
        help="Native activity or recorded Bridge work / Native 活動或 Bridge 待處理工作",
    )
    listing.add_argument(
        "--limit", type=int, default=10, help="Native page size, 1–50 / 每頁查詢數"
    )
    listing.add_argument("--cursor", help="Opaque next-page cursor / 下一頁 cursor")
    listing.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum pages scanned by filters, 1–10 / 篩選最多掃描頁數",
    )
    listing.add_argument(
        "--watch",
        nargs="?",
        const=5.0,
        type=float,
        help="Refresh seconds, minimum 2 / 更新間隔秒數",
    )
    listing.add_argument(
        "--count", type=int, help="Stop after this many snapshots / 取得指定次數後結束"
    )
    detail = sub.add_parser("session", help="Inspect one exact Native session / 單一會話詳情")
    common(detail, suppress=True)
    detail.add_argument("session_id", help="Exact Native session ID / 精確 Native 會話 ID")
    detail.add_argument("--backend", dest="backend_id", help="Exact backend ID / 精確後端 ID")
    doctor = sub.add_parser(
        "doctor", help="Read-only observer/Native/Bridge diagnostics / 唯讀連線診斷"
    )
    common(doctor, suppress=True)
    doctor.add_argument("--backend", dest="backend_id", help="Exact backend ID / 精確後端 ID")


def expected_observer_uid() -> int:
    return pwd.getpwnam("jtoz").pw_uid


async def run_inspection(args: argparse.Namespace) -> int:
    command: Literal["sessions", "session", "doctor"]
    if args.command in {None, "sessions"}:
        command = "sessions"
    elif args.command == "session":
        command = "session"
    elif args.command == "doctor":
        command = "doctor"
    else:
        raise ValueError("unknown_inspection_command")
    watch = getattr(args, "watch", None)
    count = getattr(args, "count", None)
    if (
        watch is not None
        and (not 2 <= watch <= 3600)
        or count is not None
        and (watch is None or not 1 <= count <= 10000)
    ):
        raise ValueError("bounded_watch_interval_and_count_required")
    runtime_modes = getattr(args, "inspection_runtime_modes", False)
    query_type = InspectionQueryV2 if runtime_modes else InspectionQuery
    query = query_type(
        command=command,
        backend_id=getattr(args, "backend_id", None),
        project_id=getattr(args, "project_id", None),
        session_id=getattr(args, "session_id", None),
        association=getattr(args, "association", "all"),
        active=getattr(args, "active", False),
        limit=getattr(args, "limit", 10),
        cursor=getattr(args, "cursor", None),
        max_pages=getattr(args, "max_pages", 10),
    )
    iterations, exit_code = 0, 0
    while True:
        started = InspectionClock.capture(time.time, time.monotonic)
        try:
            uid = expected_observer_uid()
            response = await inspect_query(args.inspection_socket, query, expected_uid=uid)
        except KeyError:
            response = error("observer_unavailable", runtime_modes=runtime_modes)
        # inspect_query may already have returned before this process is scheduled
        # to print. Recheck here, preserving every original row timestamp.
        response = fresh_inspection_response(
            response, started, InspectionClock.capture(time.time, time.monotonic)
        )

        def formatted(value: InspectionProtocolResponse) -> str:
            return (
                json.dumps(value.model_dump(mode="json"), ensure_ascii=True, allow_nan=False)
                if args.inspection_json
                else render(value, args.inspection_locale, details=command == "session")
            )

        text = formatted(response)
        closing = fresh_inspection_response(
            response, started, InspectionClock.capture(time.time, time.monotonic)
        )
        if closing != response:
            response = closing
            text = formatted(response)
        print(text, flush=True)
        exit_code = (
            0
            if response.status == "ok"
            else 4
            if any(i.code == "unauthorized" for i in response.issues)
            else 3
            if response.status == "partial"
            else 2
        )
        iterations += 1
        if watch is None or response.status == "error" or count is not None and iterations >= count:
            return exit_code
        await asyncio.sleep(watch)


def inspection_main(args: argparse.Namespace) -> None:
    try:
        result = asyncio.run(run_inspection(args))
    except KeyboardInterrupt:
        result = 130
    except (ValueError, OSError) as exc:
        if args.inspection_json:
            print(
                error(
                    "invalid_request",
                    runtime_modes=getattr(args, "inspection_runtime_modes", False),
                ).model_dump_json()
            )
        else:
            # A rejected local argument is not an observer outage.
            label = "invalid" if isinstance(exc, ValueError) else "error"
            print(labels(args.inspection_locale)[label], file=sys.stderr)
        result = 2
    raise SystemExit(result)
