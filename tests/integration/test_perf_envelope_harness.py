"""Smoke of the synthetic envelope harness: it runs, and its checks can really fail.

Tiny load against in-process synthetic peers. Not the target workload, not a
performance measurement and not acceptance, Human or mobile evidence.
"""

import copy
import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "ops/perf/run_envelope.py"
SPEC = importlib.util.spec_from_file_location("jt_oz_perf_run_envelope", PATH)
assert SPEC is not None and SPEC.loader is not None
envelope = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = envelope
SPEC.loader.exec_module(envelope)

SMOKE = envelope.Config(
    duration=1.5,
    topics=2,
    active=1,
    rate=8.0,
    events_per_turn=6,
    budget_requests=100000,
    human_per_minute=0.0,
    interactions_per_minute=0.0,
    zulip_latency_ms=0.0,
    native_latency_ms=0.0,
    interval=0.05,
    delivery_interval=0.0,
    draft_interval=0.05,
    drain_seconds=12.0,
    warmup_seconds=12.0,
    sample_seconds=0.5,
    load_tolerance=0.5,
)


def clean_report():
    """Every section evaluate() reads, in the shape build_report() produces."""
    return {
        "observed": {
            "finals": {"missing": [], "duplicates": [], "out_of_order_topics": [], "finished": 4},
            "human": {"never_submitted": [], "duplicate_submits": [], "out_of_order_topics": []},
            "draft_regressions": 0,
            "drain_complete": True,
            "memory": {"peak_rss_mib": 200.0, "slope_mib_per_minute_later_half": 0.1},
            "budget": {"server_peak_requests_in_window": 150, "requests_during_429_cooldown": 0},
            "interactions": {
                "injected": 2,
                "undelivered": 0,
                "latency": {"count": 2, "p95": 1.0},
                "priority": {"inversions": 0, "overtaken": 1},
            },
            "load": {"achieved_events_per_second": 100.0, "sse_backlog_peak": 10},
            "runtime_healthy": True,
            "runtime_failure": None,
        }
    }


def failed(report):
    return {
        name
        for name, row in envelope.evaluate(report, envelope.Config()).items()
        if row["status"] == "FAIL"
    }


async def test_real_pipeline_run_is_labelled_synthetic_and_a_dropped_message_fails_it(
    tmp_path, empty_database_template
):
    report = await envelope.run(
        replace(SMOKE, fault="drop-final", workdir=str(tmp_path)),
        database=empty_database_template.database,
    )
    assert report["evidence_class"] == "synthetic"
    assert report["real_zulip"] is False and report["real_native"] is False
    assert report["load_acceptance"] == "not run"
    assert "NOT a real-Zulip or real-Native result" in report["label"]
    assert report["harness_failure"] is None
    # The real pipeline carried everything else; only the injected drop is missing.
    finals = report["observed"]["finals"]
    assert finals["finished"] >= 2 and finals["delivered"] == finals["finished"] - 1
    assert report["latency_seconds"]["native_final_to_delivered"]["count"] == finals["delivered"]
    assert report["latency_seconds"]["native_event_to_durable_receipt"]["count"] >= 1
    assert report["observed"]["wire"]["requests_by_worker"]["jtoz:result-publications"] >= 1
    assert report["samples"] and report["hardware"]["logical_cpus"] >= 1
    check = report["checks"]["no_message_lost"]
    assert check["status"] == "FAIL" and check["missing_final_count"] == 1
    assert report["passed"] is False
    others = {name: row["status"] for name, row in report["checks"].items()}
    del others["no_message_lost"]
    # The smoke shares the pytest process, so its RSS includes every earlier test and
    # says nothing about Bridge; test_each_assertion_can_fail covers that check.
    assert "peak_rss_mib" in report["checks"]["memory_bounded"]
    del others["memory_bounded"]
    assert set(others.values()) == {"PASS"}, report["checks"]


def test_clean_report_passes_every_check():
    assert failed(clean_report()) == set()


@pytest.mark.parametrize(
    ("section", "key", "value", "expected"),
    [
        ("finals", "missing", ["t0:n1"], "no_message_lost"),
        ("human", "never_submitted", ["PERF-H:t0:h0"], "no_message_lost"),
        ("finals", "duplicates", ["t0:n1"], "no_duplicates"),
        ("human", "duplicate_submits", ["PERF-H:t0:h0"], "no_duplicates"),
        ("finals", "out_of_order_topics", [3], "order_preserved_within_topic"),
        ("human", "out_of_order_topics", [3], "order_preserved_within_topic"),
        ("memory", "peak_rss_mib", 751.0, "memory_bounded"),
        ("memory", "slope_mib_per_minute_later_half", 6.0, "memory_bounded"),
        ("budget", "server_peak_requests_in_window", 183, "budget_honoured"),
        ("budget", "requests_during_429_cooldown", 1, "budget_honoured"),
        ("interactions", "undelivered", 1, "interactions_prioritised"),
        ("load", "achieved_events_per_second", 50.0, "load_offered"),
        ("load", "sse_backlog_peak", 3000, "load_offered"),
    ],
)
def test_each_assertion_can_fail(section, key, value, expected):
    report = clean_report()
    report["observed"][section][key] = value
    assert failed(report) == {expected}


def test_priority_and_interaction_latency_and_health_can_fail():
    inverted = clean_report()
    inverted["observed"]["interactions"]["priority"]["inversions"] = 1
    assert failed(inverted) == {"interactions_prioritised"}
    slow = clean_report()
    slow["observed"]["interactions"]["latency"]["p95"] = 5.1
    assert failed(slow) == {"interactions_prioritised"}
    dead = copy.deepcopy(clean_report())
    dead["observed"]["runtime_healthy"] = False
    assert failed(dead) == {"runtime_healthy"}
    regressed = clean_report()
    regressed["observed"]["draft_regressions"] = 1
    assert failed(regressed) == {"order_preserved_within_topic"}


def test_percentiles_and_short_runs_do_not_invent_memory_slope():
    assert envelope.percentiles([]) == {"count": 0}
    summary = envelope.percentiles(list(range(1, 101)))
    assert (summary["p50"], summary["p95"], summary["max"]) == (50, 95, 100)
    short = [{"t": float(i), "rss_mib": 100.0 + i} for i in range(8)]
    assert envelope.rss_slope(short) is None
    climbing = [{"t": i * 30.0, "rss_mib": 100.0 + i * 5} for i in range(10)]
    assert envelope.rss_slope(climbing) == pytest.approx(10.0)
