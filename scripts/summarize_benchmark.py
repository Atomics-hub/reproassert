#!/usr/bin/env python3
"""Build the deterministic public ReproAssert benchmark summary.

The summary is a projection, never a second source of truth. It reads the frozen
manifest, append-only result rows, and the scored/smoke event ledgers. Public
smoke events are represented in input-integrity metadata but never contribute to
scored metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_VERSION = "0.1.0"
SUMMARY_SCHEMA_VERSION = "1.0.0"
EXPECTED_CASE_COUNT = 20

OUTCOMES = (
    "benchmark_infrastructure_error",
    "no_output",
    "invalid_patch",
    "policy_violation",
    "setup_failure",
    "collect_failure",
    "pass_on_base",
    "wrong_failure",
    "flaky_base",
    "fail_on_fix",
    "flaky_fix",
    "plausible_f2p_semantic_invalid",
    "semantic_valid",
)
WARM_PHASES = (
    "preflight",
    "issue_snapshot",
    "generation",
    "candidate_policy",
    "collection",
    "base_verify",
    "fixed_verify",
    "causal_controls",
)
EXCLUDED_RUNTIME_PHASES = ("dependency_prep", "semantic_review", "gold_unblind")
COST_CATEGORIES = (
    "model_inference",
    "sandbox_compute",
    "artifact_transfer",
    "paid_storage",
    "dependency_prep",
    "human_review",
)
COST_ATTRIBUTIONS = ("scored", "cold_prep_excluded", "human_labor_excluded")
COST_STATUSES = ("measured", "estimated", "unknown", "zero_verified")
USAGE_STATUSES = ("reported", "estimated", "unknown", "not_applicable")
REQUIRED_ATTRIBUTABLE_COST_CATEGORIES = frozenset(
    {"model_inference", "sandbox_compute", "artifact_transfer", "paid_storage"}
)
REQUIRED_WARM_PHASES_BY_OUTCOME = {
    "no_output": {"preflight", "issue_snapshot", "generation"},
    "invalid_patch": {"preflight", "issue_snapshot", "generation", "candidate_policy"},
    "policy_violation": {"preflight", "issue_snapshot", "generation", "candidate_policy"},
    "setup_failure": {
        "preflight",
        "issue_snapshot",
        "generation",
        "candidate_policy",
        "collection",
    },
    "collect_failure": {
        "preflight",
        "issue_snapshot",
        "generation",
        "candidate_policy",
        "collection",
    },
    "pass_on_base": set(WARM_PHASES[:6]),
    "wrong_failure": set(WARM_PHASES[:6]),
    "flaky_base": set(WARM_PHASES[:6]),
    "fail_on_fix": set(WARM_PHASES[:7]),
    "flaky_fix": set(WARM_PHASES[:7]),
    "plausible_f2p_semantic_invalid": set(WARM_PHASES),
    "semantic_valid": set(WARM_PHASES),
}


class SummaryError(ValueError):
    """Raised when an input cannot support an auditable projection."""


def canonical_json_bytes(value: object) -> bytes:
    """Encode JSON with the repository's stable, hashable representation."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise SummaryError("summary contains non-canonical JSON data") from exc
    return rendered.encode("ascii")


def render_summary(summary: dict[str, Any]) -> bytes:
    """Return the sole public summary encoding: canonical JSON plus one newline."""

    return canonical_json_bytes(summary) + b"\n"


def canonical_row_sha256(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(row)).hexdigest()


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SummaryError(f"cannot read {path}: {exc}") from exc


def _load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    encoded = _read_bytes(path)
    try:
        manifest = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SummaryError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SummaryError("manifest root must be an object")
    if manifest.get("benchmark_version") != BENCHMARK_VERSION:
        raise SummaryError("manifest benchmark_version is not 0.1.0")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT:
        raise SummaryError("manifest must contain the frozen 20-case cohort")
    return manifest, encoded


def _load_results(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    encoded = _read_bytes(path)
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(encoded.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise SummaryError(f"results line {line_number} is invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise SummaryError(f"results line {line_number} must be an object")
        rows.append(row)
    return rows, encoded


def _event_sha256(event: dict[str, Any]) -> str:
    unsigned = dict(event)
    unsigned.pop("event_sha256", None)
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def _load_ledger(path: Path, *, lane: str) -> tuple[list[dict[str, Any]], bytes]:
    encoded = _read_bytes(path)
    if encoded and not encoded.endswith(b"\n"):
        raise SummaryError(f"{lane} ledger must end with a newline")

    events: list[dict[str, Any]] = []
    previous_hash: str | None = None
    for line_number, raw_line in enumerate(encoded.splitlines(), start=1):
        if not raw_line:
            raise SummaryError(f"{lane} ledger line {line_number} is blank")
        try:
            event = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise SummaryError(f"{lane} ledger line {line_number} is invalid JSON: {exc}") from exc
        if not isinstance(event, dict):
            raise SummaryError(f"{lane} ledger line {line_number} must be an object")
        if canonical_json_bytes(event) != raw_line:
            raise SummaryError(f"{lane} ledger line {line_number} is not canonical JSON")
        if event.get("sequence") != line_number:
            raise SummaryError(f"{lane} ledger line {line_number} has a non-contiguous sequence")
        if event.get("lane") != lane:
            raise SummaryError(f"{lane} ledger line {line_number} has the wrong lane")
        if event.get("previous_event_sha256") != previous_hash:
            raise SummaryError(f"{lane} ledger line {line_number} breaks the hash chain")
        expected_hash = _event_sha256(event)
        if event.get("event_sha256") != expected_hash:
            raise SummaryError(f"{lane} ledger line {line_number} has an invalid event hash")
        previous_hash = expected_hash
        events.append(event)
    return events, encoded


def _input_metadata(encoded: bytes, *, count: int, head: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if head is not None or count >= 0:
        result["event_count"] = count
        result["head_event_sha256"] = head
    return result


def _attempt_index(
    events: list[dict[str, Any]], known_case_ids: set[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    attempts: dict[str, dict[str, Any]] = {}
    call_owner: dict[str, str] = {}

    for event in events:
        event_type = event.get("event_type")
        attempt_id = event.get("attempt_id")
        case_id = event.get("case_id")
        payload = event.get("payload")
        if not isinstance(attempt_id, str) or not isinstance(case_id, str):
            raise SummaryError("event identity fields must be strings")
        if case_id not in known_case_ids:
            raise SummaryError(f"event references unknown case {case_id}")
        if not isinstance(payload, dict):
            raise SummaryError(f"event {event.get('sequence')} payload must be an object")

        if event_type == "attempt_started":
            if attempt_id in attempts:
                raise SummaryError(f"attempt {attempt_id} starts more than once")
            attempts[attempt_id] = {
                "case_id": case_id,
                "costs": [],
                "finish": None,
                "model_finishes": {},
                "model_starts": {},
                "phase_finishes": {},
                "phase_starts": {},
            }
            continue

        attempt = attempts.get(attempt_id)
        if attempt is None:
            raise SummaryError(f"attempt {attempt_id} has an event before attempt_started")
        if attempt["case_id"] != case_id:
            raise SummaryError(f"attempt {attempt_id} changes case identity")
        if attempt["finish"] is not None:
            raise SummaryError(f"attempt {attempt_id} has an event after attempt_finished")

        if event_type == "phase_started":
            key = (payload.get("phase"), payload.get("phase_ordinal"))
            if key in attempt["phase_starts"]:
                raise SummaryError(f"attempt {attempt_id} starts phase {key!r} twice")
            attempt["phase_starts"][key] = event
        elif event_type == "phase_finished":
            key = (payload.get("phase"), payload.get("phase_ordinal"))
            if key in attempt["phase_finishes"]:
                raise SummaryError(f"attempt {attempt_id} finishes phase {key!r} twice")
            attempt["phase_finishes"][key] = event
        elif event_type == "model_call_started":
            call_id = payload.get("call_id")
            if not isinstance(call_id, str):
                raise SummaryError("model_call_started is missing call_id")
            if call_id in call_owner:
                raise SummaryError(f"model call {call_id} starts more than once")
            call_owner[call_id] = attempt_id
            attempt["model_starts"][call_id] = event
        elif event_type == "model_call_finished":
            call_id = payload.get("call_id")
            if not isinstance(call_id, str) or call_owner.get(call_id) != attempt_id:
                raise SummaryError("model_call_finished has no matching start")
            if call_id in attempt["model_finishes"]:
                raise SummaryError(f"model call {call_id} finishes more than once")
            attempt["model_finishes"][call_id] = event
        elif event_type == "cost_recorded":
            attempt["costs"].append(event)
        elif event_type == "attempt_finished":
            attempt["finish"] = event

    return attempts, call_owner


def _result_index(
    rows: list[dict[str, Any]], known_case_ids: set[str]
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or case_id not in known_case_ids:
            raise SummaryError(f"result references unknown case {case_id!r}")
        if case_id in indexed:
            raise SummaryError(f"case {case_id} has more than one result row")
        indexed[case_id] = row
    return indexed


def _finished_attempts(
    attempts: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], Counter[str], Counter[str]]:
    counted: dict[str, dict[str, Any]] = {}
    attempt_outcomes: Counter[str] = Counter()
    infrastructure_cases: Counter[str] = Counter()
    for attempt in attempts.values():
        finish = attempt["finish"]
        if not isinstance(finish, dict):
            continue
        payload = finish["payload"]
        outcome = payload.get("outcome")
        if isinstance(outcome, str):
            attempt_outcomes[outcome] += 1
        disposition = payload.get("scoring_disposition")
        case_id = attempt["case_id"]
        if disposition == "retriable_infrastructure":
            infrastructure_cases[case_id] += 1
        elif disposition == "counted":
            if case_id in counted:
                raise SummaryError(f"case {case_id} has more than one counted finish")
            counted[case_id] = finish
    return counted, attempt_outcomes, infrastructure_cases


def _reconcile_results(
    result_by_case: dict[str, dict[str, Any]], counted_by_case: dict[str, dict[str, Any]]
) -> None:
    for case_id in result_by_case.keys() & counted_by_case.keys():
        row = result_by_case[case_id]
        event = counted_by_case[case_id]
        payload = event["payload"]
        if payload.get("result_row_sha256") != canonical_row_sha256(row):
            raise SummaryError(f"case {case_id} result hash does not match its terminal event")
        for field in ("outcome", "claim_level", "plausible_f2p"):
            if payload.get(field) != row.get(field):
                raise SummaryError(f"case {case_id} terminal {field} disagrees with result row")
        run_id = row.get("run_id")
        if isinstance(run_id, str) and event.get("batch_id") != run_id:
            raise SummaryError(f"case {case_id} run_id disagrees with terminal event batch")


def _percentile(values: list[int], probability: float) -> int | float | None:
    """Return the deterministic R-7 linear-interpolated percentile."""

    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * probability
    lower_index = math.floor(rank)
    upper_index = math.ceil(rank)
    if lower_index == upper_index:
        return ordered[lower_index]
    fraction = rank - lower_index
    value = ordered[lower_index] + (ordered[upper_index] - ordered[lower_index]) * fraction
    rounded = round(value, 6)
    return int(rounded) if rounded.is_integer() else rounded


def _beta_cdf_integer(x: float, a: int, b: int) -> float:
    """Regularized beta CDF for positive integer shape parameters."""

    degree = a + b - 1
    return sum(
        math.comb(degree, index) * x**index * (1.0 - x) ** (degree - index)
        for index in range(a, degree + 1)
    )


def _beta_quantile_integer(probability: float, a: int, b: int) -> float:
    lower = 0.0
    upper = 1.0
    for _ in range(120):
        midpoint = (lower + upper) / 2.0
        if _beta_cdf_integer(midpoint, a, b) < probability:
            lower = midpoint
        else:
            upper = midpoint
    return round((lower + upper) / 2.0, 15)


def _clopper_pearson_95(successes: int, trials: int) -> dict[str, Any]:
    alpha_tail = 0.025
    lower = 0.0
    upper = 1.0
    if successes > 0:
        lower = _beta_quantile_integer(alpha_tail, successes, trials - successes + 1)
    if successes < trials:
        upper = _beta_quantile_integer(1.0 - alpha_tail, successes + 1, trials - successes)
    return {
        "confidence": 0.95,
        "lower": lower,
        "method": "clopper_pearson_exact",
        "upper": upper,
    }


def _rounded_ratio(numerator: int, denominator: int) -> int:
    """Round a non-negative ratio to the nearest micro-USD, halves upward."""

    return (2 * numerator + denominator) // (2 * denominator)


def _gate(
    *, operator: str, threshold: int, value: int | float | None, reasons: list[str]
) -> dict[str, Any]:
    if reasons or value is None:
        status = "not_evaluable"
    elif operator == ">=":
        status = "pass" if value >= threshold else "fail"
    elif operator == "<":
        status = "pass" if value < threshold else "fail"
    elif operator == "<=":
        status = "pass" if value <= threshold else "fail"
    else:  # pragma: no cover - all callers use frozen operators
        raise SummaryError(f"unsupported gate operator {operator}")
    return {
        "not_evaluable_reasons": sorted(set(reasons)),
        "operator": operator,
        "status": status,
        "threshold": threshold,
    }


def _runtime_projection(
    *,
    attempts: dict[str, dict[str, Any]],
    terminal_case_ids: set[str],
    expected_case_ids: list[str],
    benchmark_complete: bool,
) -> dict[str, Any]:
    totals: defaultdict[str, int] = defaultdict(int)
    warm_finishes: Counter[str] = Counter()
    unknown_cases: set[str] = set(expected_case_ids) - terminal_case_ids
    unmatched_call_ids: list[str] = []

    for attempt in attempts.values():
        case_id = attempt["case_id"]
        if attempt["finish"] is None:
            unknown_cases.add(case_id)
        for call_id in attempt["model_starts"]:
            if call_id not in attempt["model_finishes"]:
                unmatched_call_ids.append(call_id)
                unknown_cases.add(case_id)
        for call_id, event in attempt["model_finishes"].items():
            if _model_call_is_enclosed_by_generation(attempt, call_id):
                continue
            unknown_cases.add(case_id)
            duration_ms = event["payload"].get("duration_ms")
            if (
                isinstance(duration_ms, int)
                and not isinstance(duration_ms, bool)
                and duration_ms >= 0
            ):
                totals[case_id] += duration_ms
        for key in attempt["phase_starts"]:
            phase = key[0]
            if phase in WARM_PHASES and key not in attempt["phase_finishes"]:
                unknown_cases.add(case_id)
        for key, event in attempt["phase_finishes"].items():
            phase = key[0]
            if phase not in WARM_PHASES:
                continue
            if key not in attempt["phase_starts"]:
                unknown_cases.add(case_id)
            duration_ms = event["payload"].get("duration_ms")
            start_event = attempt["phase_starts"].get(key)
            if (
                not isinstance(duration_ms, int)
                or isinstance(duration_ms, bool)
                or duration_ms < 0
                or not isinstance(start_event, dict)
                or start_event["payload"].get("started_at") != event["payload"].get("started_at")
                or _validated_interval(event["payload"]) is None
            ):
                unknown_cases.add(case_id)
                continue
            totals[case_id] += duration_ms
            warm_finishes[case_id] += 1

        finish = attempt["finish"]
        if isinstance(finish, dict):
            outcome = finish["payload"].get("outcome")
            required_phases = REQUIRED_WARM_PHASES_BY_OUTCOME.get(outcome, set())
            completed_phases = {
                key[0]
                for key, event in attempt["phase_finishes"].items()
                if event["payload"].get("status") in {None, "succeeded", "failed"}
            }
            if not required_phases <= completed_phases:
                unknown_cases.add(case_id)
            if outcome == "benchmark_infrastructure_error" and not (
                completed_phases & set(WARM_PHASES)
            ):
                unknown_cases.add(case_id)

    for case_id in terminal_case_ids:
        if warm_finishes[case_id] == 0:
            unknown_cases.add(case_id)

    known_case_ids = sorted(terminal_case_ids - unknown_cases)
    values = [totals[case_id] for case_id in known_case_ids]
    distribution_complete = len(known_case_ids) == EXPECTED_CASE_COUNT
    p50 = _percentile(values, 0.50) if distribution_complete else None
    p90 = _percentile(values, 0.90) if distribution_complete else None
    reasons: list[str] = []
    if not benchmark_complete:
        reasons.append("benchmark_incomplete")
    if unknown_cases:
        reasons.append("unknown_case_runtime")
    if unmatched_call_ids:
        reasons.append("unmatched_model_call")

    return {
        "excluded_phases": list(EXCLUDED_RUNTIME_PHASES),
        "gate": _gate(operator="<", threshold=600_000, value=p50, reasons=reasons),
        "included_phases": list(WARM_PHASES),
        "known_case_count": len(known_case_ids),
        "p50_ms": p50,
        "p90_ms": p90,
        "percentile_method": "linear_interpolation_r7",
        "scope": "all_scored_attempts_warm_machine_phases",
        "total_observed_ms": sum(totals.values()),
        "unknown_case_count": EXPECTED_CASE_COUNT - len(known_case_ids),
        "unknown_case_ids": sorted(set(expected_case_ids) - set(known_case_ids)),
    }


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None


def _validated_interval(payload: dict[str, Any]) -> tuple[datetime, datetime, int] | None:
    started = _parse_timestamp(payload.get("started_at"))
    completed = _parse_timestamp(payload.get("completed_at"))
    duration_ms = payload.get("duration_ms")
    if (
        started is None
        or completed is None
        or completed < started
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
    ):
        return None
    elapsed_ms = (completed - started).total_seconds() * 1_000
    if abs(elapsed_ms - duration_ms) > 1_000:
        return None
    return started, completed, duration_ms


def _model_call_is_enclosed_by_generation(attempt: dict[str, Any], call_id: str) -> bool:
    start_event = attempt["model_starts"].get(call_id)
    finish_event = attempt["model_finishes"].get(call_id)
    if not isinstance(start_event, dict) or not isinstance(finish_event, dict):
        return False
    start_payload = start_event.get("payload")
    finish_payload = finish_event.get("payload")
    if not isinstance(start_payload, dict) or not isinstance(finish_payload, dict):
        return False
    call_interval = _validated_interval(finish_payload)
    call_started = _parse_timestamp(start_payload.get("started_at"))
    if call_interval is None or call_started != call_interval[0]:
        return False

    matches = 0
    for key, generation_finish in attempt["phase_finishes"].items():
        if key[0] != "generation":
            continue
        generation_start = attempt["phase_starts"].get(key)
        if not isinstance(generation_start, dict) or not isinstance(generation_finish, dict):
            continue
        start_payload = generation_start.get("payload")
        finish_payload = generation_finish.get("payload")
        if not isinstance(start_payload, dict) or not isinstance(finish_payload, dict):
            continue
        generation_interval = _validated_interval(finish_payload)
        if (
            generation_interval is not None
            and start_payload.get("started_at") == finish_payload.get("started_at")
            and generation_interval[0] <= call_interval[0]
            and call_interval[1] <= generation_interval[1]
            and call_interval[2] <= generation_interval[2]
            and _event_sequence_before(generation_start, start_event)
            and _event_sequence_before(finish_event, generation_finish)
        ):
            matches += 1
    return matches == 1


def _event_sequence_before(first: dict[str, Any], second: dict[str, Any]) -> bool:
    first_sequence = first.get("sequence")
    second_sequence = second.get("sequence")
    return (
        isinstance(first_sequence, int)
        and not isinstance(first_sequence, bool)
        and isinstance(second_sequence, int)
        and not isinstance(second_sequence, bool)
        and first_sequence < second_sequence
    )


def _cost_and_usage_projection(
    *,
    attempts: dict[str, dict[str, Any]],
    attempted_case_ids: set[str],
    semantic_valid_count: int,
    benchmark_complete: bool,
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str], list[str]]:
    category_totals = {category: 0 for category in COST_CATEGORIES}
    attribution_totals = {attribution: 0 for attribution in COST_ATTRIBUTIONS}
    cost_statuses: Counter[str] = Counter()
    usage_statuses: Counter[str] = Counter()
    tokens = {
        "cached_input_tokens": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }
    all_call_starts: dict[str, dict[str, Any]] = {}
    all_call_finishes: dict[str, dict[str, Any]] = {}
    model_cost_call_ids: set[str] = set()
    missing_cost_attempt_ids: list[str] = []
    recorded_amount_total = 0
    entry_count = 0

    for attempt_id, attempt in attempts.items():
        attempt_scored_categories = {
            event["payload"].get("category")
            for event in attempt["costs"]
            if event["payload"].get("attribution") == "scored"
        }
        if not attempt_scored_categories.issuperset(REQUIRED_ATTRIBUTABLE_COST_CATEGORIES):
            missing_cost_attempt_ids.append(attempt_id)
        all_call_starts.update(attempt["model_starts"])
        all_call_finishes.update(attempt["model_finishes"])
        for event in attempt["costs"]:
            payload = event["payload"]
            category = payload.get("category")
            attribution = payload.get("attribution")
            status = payload.get("status")
            amount = payload.get("amount_microusd")
            if category not in category_totals or attribution not in attribution_totals:
                raise SummaryError("cost event uses an unknown category or attribution")
            if status not in COST_STATUSES:
                raise SummaryError("cost event uses an unknown measurement status")
            cost_statuses[status] += 1
            entry_count += 1
            if isinstance(amount, int) and amount >= 0:
                category_totals[category] += amount
                attribution_totals[attribution] += amount
                recorded_amount_total += amount
            elif status != "unknown":
                raise SummaryError("known cost event is missing amount_microusd")
            source_call_id = payload.get("source_call_id")
            if category == "model_inference" and isinstance(source_call_id, str):
                model_cost_call_ids.add(source_call_id)

    for call_id, event in all_call_finishes.items():
        usage = event["payload"].get("usage")
        if not isinstance(usage, dict) or usage.get("status") not in USAGE_STATUSES:
            raise SummaryError(f"model call {call_id} has invalid usage metadata")
        status = usage["status"]
        usage_statuses[status] += 1
        for key in tokens:
            value = usage.get(key)
            if isinstance(value, int) and value >= 0:
                tokens[key] += value

    unmatched_calls = sorted(set(all_call_starts) - set(all_call_finishes))
    missing_model_cost_calls = sorted(set(all_call_starts) - model_cost_call_ids)
    unknown_usage_calls = sorted(
        call_id
        for call_id, event in all_call_finishes.items()
        if event["payload"]["usage"].get("status") == "unknown"
    )
    usage_unknown_count = len(unmatched_calls) + len(unknown_usage_calls)
    unknown_cost_count = cost_statuses["unknown"]
    estimated_cost_count = cost_statuses["estimated"]
    fully_measured = bool(attempts) and not (
        missing_cost_attempt_ids
        or missing_model_cost_calls
        or unmatched_calls
        or unknown_cost_count
        or estimated_cost_count
    )
    attributable_total = attribution_totals["scored"]
    cost_per_attempted_case = None
    if fully_measured and attempted_case_ids:
        cost_per_attempted_case = _rounded_ratio(attributable_total, len(attempted_case_ids))
    cost_per_semantic_valid = None
    if fully_measured and semantic_valid_count > 0:
        cost_per_semantic_valid = _rounded_ratio(attributable_total, semantic_valid_count)

    cost_gate_reasons: list[str] = []
    if not benchmark_complete:
        cost_gate_reasons.append("benchmark_incomplete")
    if not fully_measured:
        cost_gate_reasons.append("cost_not_fully_measured")
    if semantic_valid_count == 0:
        cost_gate_reasons.append("zero_semantic_valid_successes")

    cost = {
        "attempted_case_count": len(attempted_case_ids),
        "attributable_total_microusd": attributable_total,
        "by_attribution_microusd": attribution_totals,
        "by_category_microusd": category_totals,
        "cost_per_attempted_case_microusd": cost_per_attempted_case,
        "cost_per_semantic_valid_microusd": cost_per_semantic_valid,
        "currency": "USD",
        "entry_count": entry_count,
        "estimated_entry_count": estimated_cost_count,
        "fully_measured": fully_measured,
        "gate": _gate(
            operator="<=",
            threshold=1_000_000,
            value=cost_per_semantic_valid,
            reasons=cost_gate_reasons,
        ),
        "ratio_rounding": "nearest_microusd_half_up",
        "recorded_amount_total_microusd": recorded_amount_total,
        "status_counts": {status: cost_statuses[status] for status in COST_STATUSES},
        "unit": "microUSD",
        "unknown_entry_count": unknown_cost_count,
    }
    usage = {
        "estimated_call_count": usage_statuses["estimated"],
        "model_call_finished_count": len(all_call_finishes),
        "model_call_started_count": len(all_call_starts),
        "status_counts": {status: usage_statuses[status] for status in USAGE_STATUSES},
        "tokens": tokens,
        "unknown_call_count": usage_unknown_count,
    }
    return (
        cost,
        usage,
        sorted(missing_cost_attempt_ids),
        missing_model_cost_calls,
        unmatched_calls,
    )


def build_summary(
    *,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    result_rows: list[dict[str, Any]],
    results_bytes: bytes,
    scored_events: list[dict[str, Any]],
    scored_bytes: bytes,
    smoke_events: list[dict[str, Any]],
    smoke_bytes: bytes,
) -> dict[str, Any]:
    cases = manifest["cases"]
    expected_case_ids = [case["id"] for case in cases]
    if len(set(expected_case_ids)) != EXPECTED_CASE_COUNT:
        raise SummaryError("manifest case IDs must be unique")
    known_case_ids = set(expected_case_ids)

    attempts, _ = _attempt_index(scored_events, known_case_ids)
    result_by_case = _result_index(result_rows, known_case_ids)
    counted_by_case, attempt_outcome_counts, infrastructure_cases = _finished_attempts(attempts)
    _reconcile_results(result_by_case, counted_by_case)

    terminal_case_ids = set(result_by_case) & set(counted_by_case)
    result_only = sorted(set(result_by_case) - set(counted_by_case))
    terminal_only = sorted(set(counted_by_case) - set(result_by_case))
    open_attempt_ids = sorted(
        attempt_id for attempt_id, attempt in attempts.items() if attempt["finish"] is None
    )
    pending_infrastructure = sorted(
        case_id for case_id in infrastructure_cases if case_id not in counted_by_case
    )
    attempted_case_ids = {attempt["case_id"] for attempt in attempts.values()}

    case_outcome_counts: Counter[str] = Counter()
    claim_counts = {"L0": 0, "L1": 0, "L2": 0}
    plausible_f2p_count = 0
    for row in result_by_case.values():
        outcome = row.get("outcome")
        if outcome in OUTCOMES:
            case_outcome_counts[outcome] += 1
        claim = row.get("claim_level")
        if claim in {"L0", "L1", "L2", "L3"}:
            claim_counts["L0"] += 1
        if claim in {"L1", "L2", "L3"}:
            claim_counts["L1"] += 1
        if claim in {"L2", "L3"}:
            claim_counts["L2"] += 1
        if row.get("plausible_f2p") is True:
            plausible_f2p_count += 1

    semantic_valid_count = case_outcome_counts["semantic_valid"]
    semantic_false_count = case_outcome_counts["plausible_f2p_semantic_invalid"]

    # A finished attempt with an unfinished call makes the trace incomplete even
    # if a terminal row was written after the crash boundary.
    raw_unmatched_calls = sorted(
        call_id
        for attempt in attempts.values()
        for call_id in attempt["model_starts"]
        if call_id not in attempt["model_finishes"]
    )
    complete = (
        len(terminal_case_ids) == EXPECTED_CASE_COUNT
        and not result_only
        and not terminal_only
        and not open_attempt_ids
        and not pending_infrastructure
        and not raw_unmatched_calls
    )
    missing_case_ids = sorted(known_case_ids - terminal_case_ids)
    if not scored_events and not result_rows:
        status = "preregistered_no_results"
    elif complete:
        status = "complete"
    elif (
        pending_infrastructure
        and set(missing_case_ids) == set(pending_infrastructure)
        and not open_attempt_ids
    ):
        status = "pending_infrastructure"
    else:
        status = "in_progress"

    runtime = _runtime_projection(
        attempts=attempts,
        terminal_case_ids=terminal_case_ids,
        expected_case_ids=expected_case_ids,
        benchmark_complete=complete,
    )
    cost, usage, missing_cost_attempts, missing_model_cost_calls, unmatched_calls = (
        _cost_and_usage_projection(
            attempts=attempts,
            attempted_case_ids=attempted_case_ids,
            semantic_valid_count=semantic_valid_count,
            benchmark_complete=complete,
        )
    )

    primary_reasons = [] if complete else ["benchmark_incomplete"]
    primary_rate = semantic_valid_count / EXPECTED_CASE_COUNT if complete else None
    confidence_interval = (
        _clopper_pearson_95(semantic_valid_count, EXPECTED_CASE_COUNT) if complete else None
    )
    false_reproduction_rate = (
        semantic_false_count / plausible_f2p_count if plausible_f2p_count else None
    )

    return {
        "benchmark_version": BENCHMARK_VERSION,
        "claims": claim_counts,
        "completeness": {
            "attempted_case_count": len(attempted_case_ids),
            "complete": complete,
            "expected_case_count": EXPECTED_CASE_COUNT,
            "missing_case_ids": missing_case_ids,
            "missing_cost_attempt_ids": missing_cost_attempts,
            "missing_model_cost_call_ids": missing_model_cost_calls,
            "open_attempt_ids": open_attempt_ids,
            "pending_infrastructure_case_ids": pending_infrastructure,
            "result_case_count": len(result_by_case),
            "result_only_case_ids": result_only,
            "smoke_event_count_excluded": len(smoke_events),
            "status": status,
            "terminal_case_count": len(terminal_case_ids),
            "terminal_only_case_ids": terminal_only,
            "unmatched_model_call_ids": unmatched_calls,
        },
        "cost": cost,
        "inputs": {
            "ledgers": {
                "scored": _input_metadata(
                    scored_bytes,
                    count=len(scored_events),
                    head=scored_events[-1]["event_sha256"] if scored_events else None,
                ),
                "smoke": _input_metadata(
                    smoke_bytes,
                    count=len(smoke_events),
                    head=smoke_events[-1]["event_sha256"] if smoke_events else None,
                ),
            },
            "manifest": {
                "bytes": len(manifest_bytes),
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
            "results": {
                "bytes": len(results_bytes),
                "row_count": len(result_rows),
                "sha256": hashlib.sha256(results_bytes).hexdigest(),
            },
        },
        "outcomes": {
            "attempt_finished_counts": {
                outcome: attempt_outcome_counts[outcome] for outcome in OUTCOMES
            },
            "case_terminal_counts": {outcome: case_outcome_counts[outcome] for outcome in OUTCOMES},
        },
        "primary_metric": {
            "confidence_interval_95_exact": confidence_interval,
            "denominator": EXPECTED_CASE_COUNT,
            "gate": _gate(
                operator=">=",
                threshold=6,
                value=semantic_valid_count if complete else None,
                reasons=primary_reasons,
            ),
            "id": "semantic_valid_success_at_1",
            "numerator": semantic_valid_count,
            "rate": primary_rate,
        },
        "quality": {
            "plausible_f2p_count": plausible_f2p_count,
            "semantic_false_reproduction_count": semantic_false_count,
            "semantic_false_reproduction_denominator": plausible_f2p_count,
            "semantic_false_reproduction_rate": false_reproduction_rate,
            "semantic_valid_count": semantic_valid_count,
        },
        "runtime": runtime,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "usage": usage,
    }


def summarize_files(
    *,
    manifest_path: Path,
    results_path: Path,
    scored_ledger_path: Path,
    smoke_ledger_path: Path,
) -> dict[str, Any]:
    manifest, manifest_bytes = _load_manifest(manifest_path)
    result_rows, results_bytes = _load_results(results_path)
    scored_events, scored_bytes = _load_ledger(scored_ledger_path, lane="scored")
    smoke_events, smoke_bytes = _load_ledger(smoke_ledger_path, lane="smoke")
    # Smoke identity/integrity is checked above. Its lifecycle is intentionally
    # not reduced into any scored metric.
    return build_summary(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        result_rows=result_rows,
        results_bytes=results_bytes,
        scored_events=scored_events,
        scored_bytes=scored_bytes,
        smoke_events=smoke_events,
        smoke_bytes=smoke_bytes,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    benchmark_root = ROOT / "benchmarks" / "v0.1"
    parser.add_argument("--manifest", type=Path, default=benchmark_root / "manifest.json")
    parser.add_argument("--results", type=Path, default=benchmark_root / "results.jsonl")
    parser.add_argument(
        "--scored-ledger", type=Path, default=benchmark_root / "ledger" / "scored-events.jsonl"
    )
    parser.add_argument(
        "--smoke-ledger", type=Path, default=benchmark_root / "ledger" / "smoke-events.jsonl"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = summarize_files(
            manifest_path=args.manifest,
            results_path=args.results,
            scored_ledger_path=args.scored_ledger,
            smoke_ledger_path=args.smoke_ledger,
        )
    except SummaryError as exc:
        print(f"benchmark summary failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(render_summary(summary))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the command
    raise SystemExit(main())
