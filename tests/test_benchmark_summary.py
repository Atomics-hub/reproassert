from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def _load_summarizer() -> ModuleType:
    path = ROOT / "scripts" / "summarize_benchmark.py"
    spec = importlib.util.spec_from_file_location("reproassert_benchmark_summary", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUMMARY = _load_summarizer()
SUMMARY_SCHEMA = json.loads((ROOT / "schemas" / "benchmark-summary.schema.json").read_text())
CASE_IDS = [f"rk-v0.1-{index:03d}" for index in range(1, 21)]
T0 = "2026-07-10T00:00:00.000Z"


def _after_ms(duration_ms: int) -> str:
    started = datetime(2026, 7, 10, tzinfo=timezone.utc)
    return (
        (started + timedelta(milliseconds=duration_ms))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _write_fixture_root(tmp_path: Path) -> dict[str, Path]:
    paths = {
        "manifest": tmp_path / "manifest.json",
        "results": tmp_path / "results.jsonl",
        "scored": tmp_path / "scored-events.jsonl",
        "smoke": tmp_path / "smoke-events.jsonl",
    }
    manifest = {
        "benchmark_version": "0.1.0",
        "cases": [{"id": case_id, "smoke": False} for case_id in CASE_IDS],
    }
    paths["manifest"].write_bytes(SUMMARY.canonical_json_bytes(manifest) + b"\n")
    paths["results"].write_bytes(b"")
    paths["scored"].write_bytes(b"")
    paths["smoke"].write_bytes(b"")
    return paths


def _append_event(
    events: list[dict[str, Any]],
    *,
    lane: str,
    attempt_id: str,
    case_id: str,
    event_type: str,
    payload: dict[str, Any],
    batch_id: str = "synthetic-run",
) -> dict[str, Any]:
    event = {
        "schema_version": "1.0.0",
        "benchmark_version": "0.1.0",
        "lane": lane,
        "sequence": len(events) + 1,
        "recorded_at": "2026-07-10T00:00:00Z",
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
        "batch_id": batch_id,
        "attempt_id": attempt_id,
        "case_id": case_id,
        "event_type": event_type,
        "payload": payload,
    }
    event["event_sha256"] = SUMMARY._event_sha256(event)
    events.append(event)
    return event


def _write_events(path: Path, events: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(SUMMARY.canonical_json_bytes(event) + b"\n" for event in events))


def _rechain(events: list[dict[str, Any]]) -> None:
    previous: str | None = None
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
        event["previous_event_sha256"] = previous
        event.pop("event_sha256", None)
        event["event_sha256"] = SUMMARY._event_sha256(event)
        previous = event["event_sha256"]


def _write_results(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(SUMMARY.canonical_json_bytes(row) + b"\n" for row in rows))


def _result(
    case_id: str,
    *,
    outcome: str,
    claim_level: str,
    plausible_f2p: bool,
) -> dict[str, Any]:
    return {
        "benchmark_version": "0.1.0",
        "case_id": case_id,
        "claim_level": claim_level,
        "outcome": outcome,
        "plausible_f2p": plausible_f2p,
        "run_id": "synthetic-run",
        "schema_version": "0.1.0",
    }


def _add_attempt(
    events: list[dict[str, Any]],
    *,
    case_id: str,
    attempt_id: str,
    duration_ms: int,
    cost_microusd: int | None,
    cost_status: str = "measured",
    terminal_row: dict[str, Any] | None = None,
    infrastructure_error: bool = False,
    model_call: str | None = None,
    finish_model_call: bool = True,
) -> None:
    _append_event(
        events,
        lane="scored",
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="attempt_started",
        payload={},
    )
    outcome = "benchmark_infrastructure_error" if infrastructure_error else terminal_row["outcome"]
    required_phases = SUMMARY.REQUIRED_WARM_PHASES_BY_OUTCOME.get(outcome, {"generation"})
    for phase in sorted(required_phases):
        phase_duration_ms = duration_ms if phase == "generation" else 0
        _append_event(
            events,
            lane="scored",
            attempt_id=attempt_id,
            case_id=case_id,
            event_type="phase_started",
            payload={"phase": phase, "phase_ordinal": 1, "started_at": T0},
        )
        if phase == "generation" and model_call is not None:
            _append_event(
                events,
                lane="scored",
                attempt_id=attempt_id,
                case_id=case_id,
                event_type="model_call_started",
                payload={"call_id": model_call, "started_at": T0},
            )
            if finish_model_call:
                _append_event(
                    events,
                    lane="scored",
                    attempt_id=attempt_id,
                    case_id=case_id,
                    event_type="model_call_finished",
                    payload={
                        "call_id": model_call,
                        "started_at": T0,
                        "completed_at": _after_ms(phase_duration_ms),
                        "duration_ms": phase_duration_ms,
                        "usage": {
                            "cached_input_tokens": 10,
                            "input_tokens": 100,
                            "output_tokens": 20,
                            "status": "reported",
                            "total_tokens": 120,
                        },
                    },
                )
        _append_event(
            events,
            lane="scored",
            attempt_id=attempt_id,
            case_id=case_id,
            event_type="phase_finished",
            payload={
                "started_at": T0,
                "completed_at": _after_ms(phase_duration_ms),
                "duration_ms": phase_duration_ms,
                "phase": phase,
                "phase_ordinal": 1,
            },
        )
    if cost_status:
        charged_category = "model_inference" if model_call is not None else "sandbox_compute"
        for category in sorted(SUMMARY.REQUIRED_ATTRIBUTABLE_COST_CATEGORIES):
            is_charged = category == charged_category
            _append_event(
                events,
                lane="scored",
                attempt_id=attempt_id,
                case_id=case_id,
                event_type="cost_recorded",
                payload={
                    "amount_microusd": cost_microusd if is_charged else 0,
                    "attribution": "scored",
                    "category": category,
                    "source_call_id": model_call if category == "model_inference" else None,
                    "status": cost_status if is_charged else "zero_verified",
                },
            )
    if infrastructure_error:
        finish_payload = {
            "claim_level": "rejected",
            "outcome": "benchmark_infrastructure_error",
            "plausible_f2p": False,
            "result_row_sha256": None,
            "scoring_disposition": "retriable_infrastructure",
        }
    else:
        assert terminal_row is not None
        finish_payload = {
            "claim_level": terminal_row["claim_level"],
            "outcome": terminal_row["outcome"],
            "plausible_f2p": terminal_row["plausible_f2p"],
            "result_row_sha256": SUMMARY.canonical_row_sha256(terminal_row),
            "scoring_disposition": "counted",
        }
    _append_event(
        events,
        lane="scored",
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="attempt_finished",
        payload=finish_payload,
    )


def _summarize(paths: dict[str, Path]) -> dict[str, Any]:
    return SUMMARY.summarize_files(
        manifest_path=paths["manifest"],
        results_path=paths["results"],
        scored_ledger_path=paths["scored"],
        smoke_ledger_path=paths["smoke"],
    )


def _complete_fixture(
    paths: dict[str, Path],
    *,
    semantic_valid: int,
    semantic_invalid: int = 0,
    duration_multiplier: int = 100,
    cost_microusd: int = 100_000,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, case_id in enumerate(CASE_IDS, start=1):
        if index <= semantic_valid:
            row = _result(
                case_id,
                outcome="semantic_valid",
                claim_level="L2",
                plausible_f2p=True,
            )
        elif index <= semantic_valid + semantic_invalid:
            row = _result(
                case_id,
                outcome="plausible_f2p_semantic_invalid",
                claim_level="L1",
                plausible_f2p=True,
            )
        else:
            row = _result(
                case_id,
                outcome="no_output",
                claim_level="rejected",
                plausible_f2p=False,
            )
        rows.append(row)
        _add_attempt(
            events,
            case_id=case_id,
            attempt_id=f"attempt-{index:03d}",
            duration_ms=index * duration_multiplier,
            cost_microusd=cost_microusd,
            terminal_row=row,
        )
    _write_events(paths["scored"], events)
    _write_results(paths["results"], rows)
    return events, rows


def test_empty_repository_summary_matches_committed_golden_and_schema() -> None:
    benchmark_root = ROOT / "benchmarks" / "v0.1"
    summary = SUMMARY.summarize_files(
        manifest_path=benchmark_root / "manifest.json",
        results_path=benchmark_root / "results.jsonl",
        scored_ledger_path=benchmark_root / "ledger" / "scored-events.jsonl",
        smoke_ledger_path=benchmark_root / "ledger" / "smoke-events.jsonl",
    )

    assert summary["completeness"]["status"] == "preregistered_no_results"
    assert summary["primary_metric"] == {
        "confidence_interval_95_exact": None,
        "denominator": 20,
        "gate": {
            "not_evaluable_reasons": ["benchmark_incomplete"],
            "operator": ">=",
            "status": "not_evaluable",
            "threshold": 6,
        },
        "id": "semantic_valid_success_at_1",
        "numerator": 0,
        "rate": None,
    }
    assert summary["cost"]["cost_per_semantic_valid_microusd"] is None
    assert SUMMARY.render_summary(summary) == (benchmark_root / "summary.json").read_bytes()
    Draft202012Validator(SUMMARY_SCHEMA).validate(summary)


def test_complete_twenty_case_projection_passes_gates_and_exact_interval(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    _complete_fixture(paths, semantic_valid=6, semantic_invalid=2)

    summary = _summarize(paths)

    assert summary["completeness"]["status"] == "complete"
    assert summary["completeness"]["terminal_case_count"] == 20
    assert summary["claims"] == {"L0": 8, "L1": 8, "L2": 6}
    assert summary["primary_metric"]["numerator"] == 6
    assert summary["primary_metric"]["denominator"] == 20
    assert summary["primary_metric"]["rate"] == 0.3
    interval = summary["primary_metric"]["confidence_interval_95_exact"]
    assert interval["method"] == "clopper_pearson_exact"
    assert 0.11 < interval["lower"] < 0.13
    assert 0.53 < interval["upper"] < 0.56
    assert summary["primary_metric"]["gate"]["status"] == "pass"
    assert summary["runtime"]["p50_ms"] == 1050
    assert summary["runtime"]["p90_ms"] == 1810
    assert summary["runtime"]["gate"]["status"] == "pass"
    assert summary["cost"]["attributable_total_microusd"] == 2_000_000
    assert summary["cost"]["cost_per_attempted_case_microusd"] == 100_000
    assert summary["cost"]["cost_per_semantic_valid_microusd"] == 333_333
    assert summary["cost"]["gate"]["status"] == "pass"
    assert summary["quality"]["semantic_false_reproduction_count"] == 2
    assert summary["quality"]["semantic_false_reproduction_rate"] == 0.25
    Draft202012Validator(SUMMARY_SCHEMA).validate(summary)


def test_zero_l2_keeps_cost_per_success_null_and_cost_gate_unevaluable(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    _complete_fixture(paths, semantic_valid=0)

    summary = _summarize(paths)

    assert summary["completeness"]["complete"] is True
    assert summary["primary_metric"]["rate"] == 0.0
    assert summary["primary_metric"]["gate"]["status"] == "fail"
    assert summary["cost"]["fully_measured"] is True
    assert summary["cost"]["cost_per_semantic_valid_microusd"] is None
    assert summary["cost"]["gate"]["status"] == "not_evaluable"
    assert summary["cost"]["gate"]["not_evaluable_reasons"] == ["zero_semantic_valid_successes"]


def test_infrastructure_retry_runtime_and_failed_attempt_cost_are_included(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    events: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, case_id in enumerate(CASE_IDS, start=1):
        row = _result(
            case_id,
            outcome="no_output",
            claim_level="rejected",
            plausible_f2p=False,
        )
        rows.append(row)
        if index == 1:
            _add_attempt(
                events,
                case_id=case_id,
                attempt_id="attempt-001-infra",
                duration_ms=900,
                cost_microusd=400,
                infrastructure_error=True,
            )
        _add_attempt(
            events,
            case_id=case_id,
            attempt_id=f"attempt-{index:03d}-final",
            duration_ms=100,
            cost_microusd=600 if index == 1 else 100,
            terminal_row=row,
        )
    _write_events(paths["scored"], events)
    _write_results(paths["results"], rows)

    summary = _summarize(paths)

    assert summary["outcomes"]["attempt_finished_counts"]["benchmark_infrastructure_error"] == 1
    assert summary["outcomes"]["attempt_finished_counts"]["no_output"] == 20
    assert summary["outcomes"]["case_terminal_counts"]["benchmark_infrastructure_error"] == 0
    assert summary["runtime"]["total_observed_ms"] == 2_900
    assert summary["cost"]["entry_count"] == 84
    assert summary["cost"]["attributable_total_microusd"] == 2_900


def test_unmatched_call_unknown_estimated_and_missing_cost_block_cost_gate(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    events: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, case_id in enumerate(CASE_IDS, start=1):
        row = _result(
            case_id,
            outcome="no_output",
            claim_level="rejected",
            plausible_f2p=False,
        )
        rows.append(row)
        kwargs: dict[str, Any] = {}
        if index == 1:
            kwargs.update(
                model_call="model-call-001",
                finish_model_call=False,
                cost_microusd=None,
                cost_status="unknown",
            )
        elif index == 2:
            kwargs.update(cost_microusd=None, cost_status="")
        elif index == 3:
            kwargs.update(cost_microusd=250, cost_status="estimated")
        else:
            kwargs.update(cost_microusd=100, cost_status="measured")
        _add_attempt(
            events,
            case_id=case_id,
            attempt_id=f"attempt-{index:03d}",
            duration_ms=100,
            terminal_row=row,
            **kwargs,
        )
    _write_events(paths["scored"], events)
    _write_results(paths["results"], rows)

    summary = _summarize(paths)

    assert summary["completeness"]["complete"] is False
    assert summary["completeness"]["unmatched_model_call_ids"] == ["model-call-001"]
    assert summary["completeness"]["missing_cost_attempt_ids"] == ["attempt-002"]
    assert summary["cost"]["unknown_entry_count"] == 1
    assert summary["cost"]["estimated_entry_count"] == 1
    assert summary["cost"]["fully_measured"] is False
    assert summary["cost"]["cost_per_attempted_case_microusd"] is None
    assert summary["cost"]["gate"]["status"] == "not_evaluable"
    assert summary["usage"]["unknown_call_count"] == 1
    assert summary["runtime"]["unknown_case_ids"] == ["rk-v0.1-001"]
    assert summary["runtime"]["gate"]["status"] == "not_evaluable"


def test_smoke_ledger_is_integrity_metadata_only(tmp_path: Path) -> None:
    paths = _write_fixture_root(tmp_path)
    smoke_events: list[dict[str, Any]] = []
    attempt_id = "smoke-attempt-001"
    case_id = CASE_IDS[0]
    _append_event(
        smoke_events,
        lane="smoke",
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="attempt_started",
        payload={},
    )
    _append_event(
        smoke_events,
        lane="smoke",
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="cost_recorded",
        payload={
            "amount_microusd": 9_000_000,
            "attribution": "scored",
            "category": "model_inference",
            "source_call_id": "smoke-call",
            "status": "measured",
        },
    )
    _append_event(
        smoke_events,
        lane="smoke",
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="attempt_finished",
        payload={
            "claim_level": "L2",
            "outcome": "semantic_valid",
            "plausible_f2p": True,
            "result_row_sha256": None,
            "scoring_disposition": "non_scoring",
        },
    )
    _write_events(paths["smoke"], smoke_events)

    summary = _summarize(paths)

    assert summary["completeness"]["status"] == "preregistered_no_results"
    assert summary["completeness"]["smoke_event_count_excluded"] == 3
    assert summary["inputs"]["ledgers"]["smoke"]["event_count"] == 3
    assert summary["claims"] == {"L0": 0, "L1": 0, "L2": 0}
    assert summary["cost"]["recorded_amount_total_microusd"] == 0
    assert summary["primary_metric"]["numerator"] == 0


def test_rendering_is_byte_identical_for_identical_inputs(tmp_path: Path) -> None:
    paths = _write_fixture_root(tmp_path)
    _complete_fixture(paths, semantic_valid=6)

    first = SUMMARY.render_summary(_summarize(paths))
    second = SUMMARY.render_summary(_summarize(paths))

    assert first == second
    assert first.endswith(b"\n")
    assert first.count(b"\n") == 1
    assert b"generated_at" not in first
    assert first == SUMMARY.canonical_json_bytes(json.loads(first)) + b"\n"


def test_missing_attributable_cost_category_keeps_cost_gate_unevaluable(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    events, _ = _complete_fixture(paths, semantic_valid=6)
    events[:] = [
        event
        for event in events
        if not (
            event["attempt_id"] == "attempt-001"
            and event["event_type"] == "cost_recorded"
            and event["payload"].get("category") == "paid_storage"
        )
    ]
    _rechain(events)
    _write_events(paths["scored"], events)

    summary = _summarize(paths)

    assert summary["completeness"]["complete"] is True
    assert summary["completeness"]["missing_cost_attempt_ids"] == ["attempt-001"]
    assert summary["cost"]["fully_measured"] is False
    assert summary["cost"]["gate"]["status"] == "not_evaluable"


def test_missing_outcome_required_phase_keeps_runtime_gate_unevaluable(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    events, _ = _complete_fixture(paths, semantic_valid=6)
    events[:] = [
        event
        for event in events
        if not (
            event["attempt_id"] == "attempt-001"
            and event["event_type"] in {"phase_started", "phase_finished"}
            and event["payload"].get("phase") == "base_verify"
        )
    ]
    _rechain(events)
    _write_events(paths["scored"], events)

    summary = _summarize(paths)

    assert "rk-v0.1-001" in summary["runtime"]["unknown_case_ids"]
    assert summary["runtime"]["gate"]["status"] == "not_evaluable"


def test_model_duration_outside_generation_is_counted_and_blocks_runtime_gate(
    tmp_path: Path,
) -> None:
    paths = _write_fixture_root(tmp_path)
    events, _ = _complete_fixture(paths, semantic_valid=6)
    generation_finish_index = next(
        index
        for index, event in enumerate(events)
        if event["case_id"] == "rk-v0.1-001"
        and event["event_type"] == "phase_finished"
        and event["payload"].get("phase") == "generation"
    )
    call_events: list[dict[str, Any]] = []
    _append_event(
        call_events,
        lane="scored",
        attempt_id="attempt-001",
        case_id="rk-v0.1-001",
        event_type="model_call_started",
        payload={"call_id": "model-call-001", "started_at": T0},
    )
    _append_event(
        call_events,
        lane="scored",
        attempt_id="attempt-001",
        case_id="rk-v0.1-001",
        event_type="model_call_finished",
        payload={
            "call_id": "model-call-001",
            "started_at": T0,
            "completed_at": _after_ms(600_000),
            "duration_ms": 600_000,
            "usage": {
                "cached_input_tokens": 0,
                "input_tokens": 1,
                "output_tokens": 1,
                "status": "reported",
                "total_tokens": 2,
            },
        },
    )
    events[generation_finish_index:generation_finish_index] = call_events
    _rechain(events)
    _write_events(paths["scored"], events)

    summary = _summarize(paths)

    assert "rk-v0.1-001" in summary["runtime"]["unknown_case_ids"]
    assert summary["runtime"]["total_observed_ms"] >= 600_000
    assert summary["runtime"]["gate"]["status"] == "not_evaluable"
