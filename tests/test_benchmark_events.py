from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from reproassert.benchmark import (  # type: ignore[import-untyped]
    _append_event,
    sanitize_public_excerpt,
)

ROOT = Path(__file__).resolve().parents[1]
EVENT_SCHEMA = json.loads((ROOT / "schemas" / "benchmark-event.schema.json").read_text())
KNOWN_CASE_IDS = {f"rk-v0.1-{index:03d}" for index in range(1, 21)}
SMOKE_CASE_IDS = {
    "rk-v0.1-004",
    "rk-v0.1-006",
    "rk-v0.1-010",
    "rk-v0.1-011",
    "rk-v0.1-018",
}

T0 = "2026-07-10T12:00:00.000Z"
T1 = "2026-07-10T12:00:01.000Z"
T2 = "2026-07-10T12:00:02.000Z"
RESULT_HASH = "f" * 64
PATCH_HASH = "6" * 64


def _load_validator() -> ModuleType:
    path = ROOT / "scripts" / "validate_benchmark.py"
    spec = importlib.util.spec_from_file_location("reproassert_event_validator", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def _sha(character: str) -> str:
    assert len(character) == 1
    return character * 64


def _append(
    path: Path,
    event_type: str,
    payload: dict[str, Any],
    *,
    lane: str = "scored",
    batch_id: str = "batch-001",
    attempt_id: str = "attempt-001",
    case_id: str = "rk-v0.1-004",
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        _append_event(
            path,
            lane=lane,
            batch_id=batch_id,
            attempt_id=attempt_id,
            case_id=case_id,
            event_type=event_type,
            payload=payload,
            recorded_at=T0,
        ),
    )


def _attempt_payload(
    *,
    lane: str = "scored",
    ordinal: int = 1,
    disposition: str | None = None,
    retry_of: str | None = None,
    authorization: str = "offline_zero_cost",
    provider: str = "offline-fixture",
    config_sha256: str = _sha("3"),
    case_id: str = "rk-v0.1-004",
) -> dict[str, Any]:
    paid = authorization == "explicit_user_approval"
    if disposition is None:
        disposition = "smoke_only" if lane == "smoke" else "primary_score"
    return {
        "attempt_ordinal": ordinal,
        "disposition": disposition,
        "retry_of": retry_of,
        "campaign": {
            "campaign_id": "campaign-001",
            "cohort_tier": "public_smoke" if lane == "smoke" else "historical_scored",
            "max_model_calls_per_case": 1,
            "max_submitted_candidates_per_case": 1,
            "max_infrastructure_retries_per_case": 1,
            "max_case_wall_ms": 600_000,
            "max_case_attributable_microusd": 2_000_000 if paid else 0,
            "max_campaign_attributable_microusd": 20_000_000 if paid else 0,
            "spend_authorization": {
                "status": authorization,
                "authorization_ref": "test-authorization" if paid else None,
            },
        },
        "manifest_sha256": _sha("1"),
        "case_entry_sha256": _sha(case_id[-1]),
        "tool": {
            "name": "reproassert",
            "version": "0.1.0",
            "git_sha": "1" * 40,
        },
        "generator": {
            "adapter": "fixture-adapter" if not paid else "openai-responses",
            "provider": provider,
            "requested_model": "fixture-v1" if not paid else "gpt-test",
            "model_identity": {
                "status": "reported",
                "value": "fixture-v1" if not paid else "gpt-test-2026-07-10",
            },
            "prompt_template_sha256": _sha("2"),
            "config_sha256": config_sha256,
            "request_builder_sha256": _sha("4"),
            "context_algorithm_sha256": _sha("5"),
            "feedback_policy": "base_only_no_oracle",
            "submitted_candidate_budget": 1,
        },
        "policy_sha256": _sha("7"),
        "pricing_snapshot_sha256": _sha("8"),
    }


def _start_attempt(
    path: Path,
    *,
    lane: str = "scored",
    batch_id: str = "batch-001",
    attempt_id: str = "attempt-001",
    case_id: str = "rk-v0.1-004",
    ordinal: int = 1,
    disposition: str | None = None,
    retry_of: str | None = None,
    authorization: str = "offline_zero_cost",
    provider: str = "offline-fixture",
    config_sha256: str = _sha("3"),
) -> dict[str, Any]:
    return _append(
        path,
        "attempt_started",
        _attempt_payload(
            lane=lane,
            ordinal=ordinal,
            disposition=disposition,
            retry_of=retry_of,
            authorization=authorization,
            provider=provider,
            config_sha256=config_sha256,
            case_id=case_id,
        ),
        lane=lane,
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
    )


def _model_start_payload(
    *,
    call_id: str = "call-001",
    provider: str = "offline-fixture",
    reservation: int = 0,
) -> dict[str, Any]:
    paid = provider not in {"offline-fixture", "local-model"}
    return {
        "call_id": call_id,
        "started_at": T0,
        "provider": provider,
        "endpoint_host": "api.openai.com" if paid else "localhost",
        "requested_model": "gpt-test" if paid else "fixture-v1",
        "model_identity": {
            "status": "reported",
            "value": "gpt-test-2026-07-10" if paid else "fixture-v1",
        },
        "rendered_input_sha256": _sha("2"),
        "config_sha256": _sha("3"),
        "max_output_tokens": 1_000,
        "pricing_snapshot_sha256": _sha("8"),
        "reserved_worst_case_microusd": reservation,
    }


def _usage(
    *,
    status: str = "reported",
    input_tokens: int | None = 100,
    cached_input_tokens: int | None = 20,
    output_tokens: int | None = 50,
    total_tokens: int | None = 150,
) -> dict[str, Any]:
    return {
        "status": status,
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _model_finish_payload(
    *,
    call_id: str = "call-001",
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "call_id": call_id,
        "status": "succeeded",
        "started_at": T0,
        "completed_at": T1,
        "duration_ms": 1_000,
        "response_model": "fixture-v1",
        "response_id_sha256": _sha("9"),
        "classification_code": "candidate_returned",
        "usage": _usage() if usage is None else usage,
    }


def _cost_payload(
    *,
    entry_id: str = "cost-001",
    source_call_id: str | None = "call-001",
    category: str = "model_inference",
    status: str = "zero_verified",
    amount_microusd: int | None = 0,
    quantity: str | None = "0.00015",
    unit_price_microusd: int | None = 0,
    unit: str | None = None,
) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "source_call_id": source_call_id,
        "category": category,
        "attribution": "scored",
        "status": status,
        "quantity": quantity,
        "unit": unit or ("million_tokens" if category == "model_inference" else "second"),
        "unit_price_microusd": unit_price_microusd,
        "amount_microusd": amount_microusd,
        "source": "synthetic validator test fixture",
        "observed_at": T1,
    }


def _candidate_payload(*, generation_call_ids: list[str] | None = None) -> dict[str, Any]:
    return {
        "candidate_index": 1,
        "patch_sha256": PATCH_HASH,
        "artifact_path": "artifacts/rk-v0.1-004/candidate.patch",
        "changed_files": ["tests/test_issue_004.py"],
        "nodeids": ["tests/test_issue_004.py::test_reproduction"],
        "added_lines": 10,
        "deleted_lines": 0,
        "selected_rank": 1,
        "generation_call_ids": [] if generation_call_ids is None else generation_call_ids,
        "oracle_consulted": False,
    }


def _review_payload(
    reviewer_id: str,
    *,
    role: str = "primary",
    verdict: str = "valid",
) -> dict[str, Any]:
    valid = verdict == "valid"
    return {
        "reviewer_id": reviewer_id,
        "role": role,
        "blinded": True,
        "packet_sha256": _sha("a"),
        "trigger_faithful": valid,
        "oracle_supported": True,
        "failure_causal": True,
        "implementation_independent": True,
        "minimal_and_readable": True,
        "verdict": verdict,
        "confidence": 0.9,
        "rationale": "Synthetic blinded review used to exercise ordering invariants.",
    }


def _gold_payload(committed_event_sha256: str) -> dict[str, Any]:
    return {
        "committed_semantic_event_sha256": committed_event_sha256,
        "artifact_bundle_sha256": _sha("b"),
        "unblinded_at": T2,
    }


def _finish_payload(
    *,
    outcome: str = "no_output",
    claim_level: str = "rejected",
    scoring_disposition: str = "counted",
    plausible_f2p: bool = False,
    result_row_sha256: str | None = RESULT_HASH,
) -> dict[str, Any]:
    return {
        "completed_at": T2,
        "outcome": outcome,
        "claim_level": claim_level,
        "scoring_disposition": scoring_disposition,
        "plausible_f2p": plausible_f2p,
        "result_row_sha256": result_row_sha256,
        "limitations": ["Synthetic lifecycle test."],
    }


def _complete_phase(
    path: Path,
    phase: str,
    *,
    phase_ordinal: int = 1,
    artifacts: list[dict[str, Any]] | None = None,
    status: str = "succeeded",
    environment_sha256: str | None = None,
) -> None:
    _append(
        path,
        "phase_started",
        {"phase": phase, "phase_ordinal": phase_ordinal, "started_at": T0},
    )
    _append(
        path,
        "phase_finished",
        {
            "phase": phase,
            "phase_ordinal": phase_ordinal,
            "status": status,
            "started_at": T0,
            "completed_at": T1,
            "duration_ms": 1_000,
            "classification_code": None,
            "command_sha256": None,
            "environment_sha256": environment_sha256,
            "artifacts": [] if artifacts is None else artifacts,
            "log": None,
        },
    )


def _result_evidence_artifact(kind: str, value: Any) -> dict[str, Any]:
    encoded = VALIDATOR.canonical_json_bytes(value)
    return {
        "kind": kind,
        "path": f"evidence/{kind}.json",
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
    }


def _prepare_blinded_review(path: Path) -> None:
    for phase in (
        "candidate_policy",
        "collection",
        "base_verify",
        "fixed_verify",
        "causal_controls",
    ):
        _complete_phase(path, phase)
    _append(
        path,
        "phase_started",
        {"phase": "semantic_review", "phase_ordinal": 1, "started_at": T0},
    )


def _commit_blinded_review(path: Path) -> None:
    _append(
        path,
        "phase_finished",
        {
            "phase": "semantic_review",
            "phase_ordinal": 1,
            "status": "succeeded",
            "started_at": T0,
            "completed_at": T1,
            "duration_ms": 1_000,
            "classification_code": None,
            "command_sha256": None,
            "environment_sha256": None,
            "artifacts": [],
            "log": None,
        },
    )


def _validate(path: Path, *, lane: str = "scored") -> tuple[dict[str, Any], list[str]]:
    if not path.exists():
        path.touch()
    errors: list[str] = []
    index = VALIDATOR.validate_event_ledger(
        path,
        lane=lane,
        known_case_ids=KNOWN_CASE_IDS,
        smoke_case_ids=SMOKE_CASE_IDS,
        event_schema=EVENT_SCHEMA,
        errors=errors,
    )
    return index, errors


def _assert_error(errors: list[str], fragment: str) -> None:
    assert any(fragment in error for error in errors), errors


@pytest.mark.parametrize("lane", ["smoke", "scored"])
def test_empty_event_ledgers_are_valid(tmp_path: Path, lane: str) -> None:
    ledger = tmp_path / f"{lane}.jsonl"
    ledger.touch()

    index, errors = _validate(ledger, lane=lane)

    assert errors == []
    assert index["events"] == []
    assert index["attempts"] == {}
    assert index["cases"] == {}


def test_event_type_must_match_its_schema_payload(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    phase_finished_payload = {
        "phase": "generation",
        "phase_ordinal": 1,
        "status": "succeeded",
        "started_at": T0,
        "completed_at": T1,
        "duration_ms": 1_000,
        "classification_code": None,
        "command_sha256": None,
        "environment_sha256": None,
        "artifacts": [],
        "log": None,
    }
    _append(ledger, "phase_started", phase_finished_payload)

    _, errors = _validate(ledger)

    _assert_error(errors, "payload does not match event_type 'phase_started'")


def test_smoke_case_and_lane_are_isolated(tmp_path: Path) -> None:
    valid = tmp_path / "valid-smoke.jsonl"
    _start_attempt(valid, lane="smoke", case_id="rk-v0.1-004")
    _, valid_errors = _validate(valid, lane="smoke")
    assert valid_errors == []

    non_smoke = tmp_path / "non-smoke-case.jsonl"
    _start_attempt(non_smoke, lane="smoke", case_id="rk-v0.1-001")
    _, non_smoke_errors = _validate(non_smoke, lane="smoke")
    _assert_error(non_smoke_errors, "non-smoke case is forbidden in smoke ledger")

    wrong_lane = tmp_path / "wrong-lane.jsonl"
    _start_attempt(wrong_lane, lane="scored", case_id="rk-v0.1-004")
    _, wrong_lane_errors = _validate(wrong_lane, lane="smoke")
    _assert_error(wrong_lane_errors, "event lane does not match ledger lane smoke")


def test_attempt_started_must_be_the_first_attempt_event(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _append(
        ledger,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "first event for an attempt must be attempt_started")


def test_scored_configuration_is_frozen_across_cases(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger, attempt_id="attempt-004", case_id="rk-v0.1-004")
    _start_attempt(
        ledger,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        config_sha256=_sha("c"),
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "scored tool/model/prompt/config/budget freeze drifted")


def test_attempt_ordinals_are_contiguous_within_each_case(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger, attempt_id="attempt-001", ordinal=1)
    _start_attempt(ledger, attempt_id="attempt-003", ordinal=3)

    _, errors = _validate(ledger)

    _assert_error(errors, "attempt_ordinal must be contiguous within the case")


def test_v01_allows_exactly_one_started_model_call_per_case(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload(call_id="call-001"))
    _append(ledger, "model_call_started", _model_start_payload(call_id="call-002"))

    _, errors = _validate(ledger)

    _assert_error(errors, "v0.1 permits at most one model call per case")


@pytest.mark.parametrize(
    ("provider", "reservation", "expected"),
    [
        ("openai", 0, "zero-cost mode permits only declared offline providers"),
        ("offline-fixture", 1, "paid provider request is not authorized"),
    ],
)
def test_offline_zero_cost_rejects_paid_provider_or_reservation(
    tmp_path: Path,
    provider: str,
    reservation: int,
    expected: str,
) -> None:
    ledger = tmp_path / f"{provider}-{reservation}.jsonl"
    _start_attempt(ledger)
    _append(
        ledger,
        "model_call_started",
        _model_start_payload(provider=provider, reservation=reservation),
    )

    _, errors = _validate(ledger)

    _assert_error(errors, expected)


def test_unmatched_model_call_start_is_valid_but_marks_usage_and_cost_unknown(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())

    index, errors = _validate(ledger)

    assert errors == []
    case = index["cases"]["rk-v0.1-004"]
    assert case["unknown_usage"] is True
    assert case["unknown_cost"] is True


def test_finished_model_call_without_cost_is_valid_but_marks_cost_unknown(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    _append(ledger, "model_call_finished", _model_finish_payload())

    index, errors = _validate(ledger)

    assert errors == []
    case = index["cases"]["rk-v0.1-004"]
    assert case["unknown_usage"] is False
    assert case["unknown_cost"] is True
    assert case["input_tokens"] == 100
    assert case["output_tokens"] == 50


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        (_usage(total_tokens=149), "total tokens must equal input + output"),
        (_usage(cached_input_tokens=101), "cached tokens exceed input tokens"),
        (
            _usage(
                status="unknown",
                input_tokens=0,
                cached_input_tokens=0,
                output_tokens=0,
                total_tokens=0,
            ),
            "unknown usage must use null counts",
        ),
        (
            _usage(
                status="not_applicable",
                input_tokens=None,
                cached_input_tokens=None,
                output_tokens=None,
                total_tokens=None,
            ),
            "not_applicable usage must be zero",
        ),
    ],
)
def test_model_usage_status_and_arithmetic_are_consistent(
    tmp_path: Path,
    usage: dict[str, Any],
    expected: str,
) -> None:
    ledger = tmp_path / (expected.split()[0] + ".jsonl")
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    _append(ledger, "model_call_finished", _model_finish_payload(usage=usage))
    _append(ledger, "cost_recorded", _cost_payload())

    _, errors = _validate(ledger)

    _assert_error(errors, expected)


def test_duplicate_model_call_ids_are_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    _append(ledger, "model_call_started", _model_start_payload())

    _, errors = _validate(ledger)

    _assert_error(errors, "call_id is duplicated")


def test_duplicate_cost_entries_and_per_call_costs_are_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    _append(ledger, "model_call_finished", _model_finish_payload())
    _append(ledger, "cost_recorded", _cost_payload())
    _append(ledger, "cost_recorded", _cost_payload())

    _, errors = _validate(ledger)

    _assert_error(errors, "cost entry_id is duplicated")
    _assert_error(errors, "model call has two monetary records")


def test_duplicate_submitted_candidates_are_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "candidate_submitted", _candidate_payload())
    _append(ledger, "candidate_submitted", _candidate_payload())

    _, errors = _validate(ledger)

    _assert_error(errors, "attempt has two candidates")
    _assert_error(errors, "case has two submitted candidates")


@pytest.mark.parametrize("finish_call", [False, True])
def test_candidate_can_reference_only_finished_model_calls(
    tmp_path: Path,
    finish_call: bool,
) -> None:
    ledger = tmp_path / f"finished-{finish_call}.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    if finish_call:
        _append(ledger, "model_call_finished", _model_finish_payload())
    _append(
        ledger,
        "candidate_submitted",
        _candidate_payload(generation_call_ids=["call-001"]),
    )

    _, errors = _validate(ledger)

    if finish_call:
        assert errors == []
    else:
        _assert_error(errors, "candidate references an unfinished or foreign model call")


def test_semantic_review_requires_a_candidate(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-001"))

    _, errors = _validate(ledger)

    _assert_error(errors, "review requires a submitted candidate")


def test_tie_break_is_allowed_only_after_primary_disagreement(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "candidate_submitted", _candidate_payload())
    _prepare_blinded_review(ledger)
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-001"))
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-002"))
    _append(
        ledger,
        "semantic_review_recorded",
        _review_payload("reviewer-003", role="tie_break", verdict="invalid"),
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "tie-break reviewer is allowed only after primary disagreement")


def test_gold_unblind_requires_a_majority_and_commits_the_final_review(tmp_path: Path) -> None:
    too_early = tmp_path / "too-early.jsonl"
    _start_attempt(too_early)
    _append(too_early, "candidate_submitted", _candidate_payload())
    _prepare_blinded_review(too_early)
    first_review = _append(
        too_early,
        "semantic_review_recorded",
        _review_payload("reviewer-001"),
    )
    _commit_blinded_review(too_early)
    _append(too_early, "gold_unblinded", _gold_payload(first_review["event_sha256"]))
    _, too_early_errors = _validate(too_early)
    _assert_error(too_early_errors, "gold unblind requires a committed review verdict")

    wrong_commit = tmp_path / "wrong-commit.jsonl"
    _start_attempt(wrong_commit)
    _append(wrong_commit, "candidate_submitted", _candidate_payload())
    _prepare_blinded_review(wrong_commit)
    _append(
        wrong_commit,
        "semantic_review_recorded",
        _review_payload("reviewer-001"),
    )
    _append(
        wrong_commit,
        "semantic_review_recorded",
        _review_payload("reviewer-002"),
    )
    _commit_blinded_review(wrong_commit)
    _append(wrong_commit, "gold_unblinded", _gold_payload(_sha("0")))
    _, wrong_commit_errors = _validate(wrong_commit)
    _assert_error(wrong_commit_errors, "must commit to the final blinded review event")


def test_disagreeing_primaries_tie_break_then_gold_is_valid(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "candidate_submitted", _candidate_payload())
    _prepare_blinded_review(ledger)
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-001"))
    _append(
        ledger,
        "semantic_review_recorded",
        _review_payload("reviewer-002", verdict="invalid"),
    )
    tie_break = _append(
        ledger,
        "semantic_review_recorded",
        _review_payload("reviewer-003", role="tie_break"),
    )
    _commit_blinded_review(ledger)
    _append(ledger, "gold_unblinded", _gold_payload(tie_break["event_sha256"]))

    _, errors = _validate(ledger)

    assert errors == []


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"claim_level": "L0"}, "attempt outcome/claim_level is incoherent"),
        ({"plausible_f2p": True}, "attempt plausible_f2p is incoherent"),
        ({"scoring_disposition": "non_scoring"}, "terminal scored outcome must be counted"),
        ({"result_row_sha256": None}, "counted attempt must commit its result row hash"),
        (
            {"outcome": "benchmark_infrastructure_error"},
            "infrastructure error must remain retriable/incomplete",
        ),
    ],
)
def test_scored_attempt_finish_fields_are_coherent(
    tmp_path: Path,
    mutation: dict[str, Any],
    expected: str,
) -> None:
    ledger = tmp_path / (expected.split()[0] + ".jsonl")
    _start_attempt(ledger)
    payload = _finish_payload()
    payload.update(mutation)
    _append(ledger, "attempt_finished", payload)

    _, errors = _validate(ledger)

    _assert_error(errors, expected)


def test_baseline_scored_and_smoke_finishes_are_valid(tmp_path: Path) -> None:
    scored = tmp_path / "scored.jsonl"
    _start_attempt(scored)
    _append(scored, "attempt_finished", _finish_payload())
    _, scored_errors = _validate(scored)
    assert scored_errors == []

    smoke = tmp_path / "smoke.jsonl"
    _start_attempt(smoke, lane="smoke")
    _append(
        smoke,
        "attempt_finished",
        _finish_payload(scoring_disposition="non_scoring", result_row_sha256=None),
        lane="smoke",
    )
    _, smoke_errors = _validate(smoke, lane="smoke")
    assert smoke_errors == []


def test_l0_finish_requires_a_submitted_candidate(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(
        ledger,
        "attempt_finished",
        _finish_payload(outcome="fail_on_fix", claim_level="L0"),
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "verified claim requires a candidate")


def test_events_after_attempt_finish_are_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "attempt_finished", _finish_payload())
    _append(
        ledger,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "event appears after attempt_finished")


def test_linked_same_case_infrastructure_retry_is_valid(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger, attempt_id="attempt-001", ordinal=1)
    _append(
        ledger,
        "attempt_finished",
        _finish_payload(
            outcome="benchmark_infrastructure_error",
            scoring_disposition="retriable_infrastructure",
            result_row_sha256=None,
        ),
        attempt_id="attempt-001",
    )
    _start_attempt(
        ledger,
        attempt_id="attempt-002",
        ordinal=2,
        disposition="infrastructure_retry",
        retry_of="attempt-001",
    )

    _, errors = _validate(ledger)

    assert errors == []


@pytest.mark.parametrize(
    ("invalid_kind", "expected"),
    [
        ("missing", "infrastructure retry must link a prior attempt"),
        ("non_infra", "only a same-case infrastructure error may be retried"),
        ("cross_case", "only a same-case infrastructure error may be retried"),
        ("primary_with_link", "primary/smoke attempt cannot set retry_of"),
    ],
)
def test_only_linked_same_case_infrastructure_errors_can_retry(
    tmp_path: Path,
    invalid_kind: str,
    expected: str,
) -> None:
    ledger = tmp_path / f"{invalid_kind}.jsonl"
    if invalid_kind == "missing":
        _start_attempt(
            ledger,
            disposition="infrastructure_retry",
            retry_of="attempt-missing",
        )
    elif invalid_kind == "primary_with_link":
        _start_attempt(ledger, retry_of="attempt-missing")
    else:
        _start_attempt(ledger, attempt_id="attempt-001", ordinal=1)
        finish = _finish_payload(
            outcome="benchmark_infrastructure_error",
            scoring_disposition="retriable_infrastructure",
            result_row_sha256=None,
        )
        if invalid_kind == "non_infra":
            finish = _finish_payload()
        _append(
            ledger,
            "attempt_finished",
            finish,
            attempt_id="attempt-001",
        )
        retry_case = "rk-v0.1-006" if invalid_kind == "cross_case" else "rk-v0.1-004"
        _start_attempt(
            ledger,
            attempt_id="attempt-002",
            case_id=retry_case,
            ordinal=1 if invalid_kind == "cross_case" else 2,
            disposition="infrastructure_retry",
            retry_of="attempt-001",
        )

    _, errors = _validate(ledger)

    _assert_error(errors, expected)


def _reconciled_projection(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    ledger = tmp_path / "events.jsonl"
    candidate_event_payload = _candidate_payload(generation_call_ids=["call-001"])
    candidate = {
        field: candidate_event_payload[field] for field in VALIDATOR.CANDIDATE_RESULT_FIELDS
    }
    policy = {
        "passed": True,
        "violations": [],
        "production_files_changed": False,
        "dependency_files_changed": False,
        "unconditional_failure_detected": False,
        "network_use_detected": False,
    }
    base_evidence = [{"tree": "base", "status": "assertion_failure"}]
    fixed_evidence = [{"tree": "fixed", "status": "fail"}]
    environment = {"image_digest": "sha256:" + "c" * 64, "network": "disabled"}
    environment_sha256 = hashlib.sha256(VALIDATOR.canonical_json_bytes(environment)).hexdigest()
    issue_snapshot = {"sha256": _sha("d"), "fields": ["title", "body"]}
    result_row: dict[str, Any] = {
        "run_id": "batch-001",
        "case_id": "rk-v0.1-004",
        "started_at": T0,
        "completed_at": T2,
        "candidate": candidate,
        "environment": environment,
        "issue_snapshot": issue_snapshot,
        "tool": {"name": "reproassert", "version": "0.1.0", "git_sha": "1" * 40},
        "generator": {
            "provider": "openai",
            "model": "gpt-test",
            "model_version": "gpt-test-2026-07-10",
            "prompt_template_sha256": _sha("2"),
            "rendered_input_sha256": _sha("2"),
            "config_sha256": _sha("3"),
            "internal_attempts": 1,
        },
        "cost": {
            "input_tokens": 100,
            "output_tokens": 50,
            "model_usd": 0.4,
            "sandbox_compute_usd": 0.6,
            "artifact_transfer_usd": 0.0,
            "paid_storage_usd": 0.0,
            "attributable_total_usd": 1.0,
        },
        "policy": policy,
        "executions": {
            "base": base_evidence,
            "fixed": fixed_evidence,
            "causal_controls": [],
        },
        "claim_level": "L0",
        "outcome": "fail_on_fix",
        "plausible_f2p": False,
        "limitations": ["Synthetic lifecycle test."],
    }
    result_hash = VALIDATOR.canonical_row_sha256(result_row)

    _start_attempt(
        ledger,
        authorization="explicit_user_approval",
        provider="openai",
    )
    _complete_phase(ledger, "preflight")
    _complete_phase(
        ledger,
        "issue_snapshot",
        artifacts=[_result_evidence_artifact("result_issue_snapshot", issue_snapshot)],
    )
    _append(
        ledger,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )
    _append(
        ledger,
        "model_call_started",
        _model_start_payload(provider="openai", reservation=500_000),
    )
    _append(ledger, "model_call_finished", _model_finish_payload())
    _append(
        ledger,
        "cost_recorded",
        _cost_payload(
            status="measured",
            amount_microusd=400_000,
            unit_price_microusd=2_666_666_667,
        ),
    )
    _append(
        ledger,
        "cost_recorded",
        _cost_payload(
            entry_id="cost-002",
            source_call_id=None,
            category="sandbox_compute",
            status="measured",
            amount_microusd=600_000,
            quantity="60",
            unit_price_microusd=10_000,
        ),
    )
    for entry_id, category in (
        ("cost-003", "artifact_transfer"),
        ("cost-004", "paid_storage"),
    ):
        _append(
            ledger,
            "cost_recorded",
            _cost_payload(
                entry_id=entry_id,
                source_call_id=None,
                category=category,
                status="zero_verified",
                amount_microusd=0,
                quantity="0",
                unit_price_microusd=0,
            ),
        )
    _append(
        ledger,
        "phase_finished",
        {
            "phase": "generation",
            "phase_ordinal": 1,
            "status": "succeeded",
            "started_at": T0,
            "completed_at": T1,
            "duration_ms": 1_000,
            "classification_code": None,
            "command_sha256": None,
            "environment_sha256": None,
            "artifacts": [],
            "log": None,
        },
    )
    _append(
        ledger,
        "candidate_submitted",
        candidate_event_payload,
    )
    _complete_phase(
        ledger,
        "candidate_policy",
        artifacts=[_result_evidence_artifact("result_policy", policy)],
    )
    _complete_phase(ledger, "collection", environment_sha256=environment_sha256)
    _complete_phase(
        ledger,
        "base_verify",
        artifacts=[_result_evidence_artifact("result_base_executions", base_evidence)],
        environment_sha256=environment_sha256,
    )
    _complete_phase(
        ledger,
        "fixed_verify",
        artifacts=[_result_evidence_artifact("result_fixed_executions", fixed_evidence)],
        status="failed",
        environment_sha256=environment_sha256,
    )
    _append(
        ledger,
        "attempt_finished",
        _finish_payload(
            outcome="fail_on_fix",
            claim_level="L0",
            result_row_sha256=result_hash,
        ),
    )
    index, errors = _validate(ledger)
    assert errors == []
    return index, result_row


def test_counted_result_reconciles_candidate_tokens_and_all_attempt_cost(
    tmp_path: Path,
) -> None:
    index, result_row = _reconciled_projection(tmp_path)
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    assert errors == []
    case = index["cases"]["rk-v0.1-004"]
    assert case["known_scored_cost_microusd"] == 1_000_000
    assert case["input_tokens"] == 100
    assert case["output_tokens"] == 50
    assert case["unknown_cost"] is False


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("candidate", "selected candidate does not match event trace"),
        ("tokens", "result tokens do not equal all model calls"),
        ("cost", "result cost does not equal all-attempt ledger cost"),
        ("cost_category", "result model_usd does not match ledger category cost"),
        ("calls", "internal_attempts must equal started model calls"),
    ],
)
def test_reconciliation_rejects_projection_drift(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    index, original = _reconciled_projection(tmp_path)
    result_row = copy.deepcopy(original)
    if mutation == "candidate":
        result_row["candidate"]["patch_sha256"] = _sha("e")
    elif mutation == "tokens":
        result_row["cost"]["input_tokens"] = 101
    elif mutation == "cost":
        result_row["cost"]["attributable_total_usd"] = 0.9
    elif mutation == "cost_category":
        result_row["cost"]["model_usd"] = 0.3
        result_row["cost"]["sandbox_compute_usd"] = 0.7
    else:
        result_row["generator"]["internal_attempts"] = 0
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    _assert_error(errors, expected)


def test_hand_authored_model_call_cannot_drift_from_attempt_freeze(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(
        ledger,
        authorization="explicit_user_approval",
        provider="openai",
    )
    payload = _model_start_payload(provider="openai", reservation=500_000)
    payload["provider"] = "anthropic"

    _append(ledger, "model_call_started", payload)
    _, errors = _validate(ledger)

    _assert_error(errors, "model call drifted from the durable generator/pricing freeze")


def test_estimated_model_cost_does_not_release_next_case_budget(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(
        ledger,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization="explicit_user_approval",
        provider="openai",
    )
    _append(
        ledger,
        "model_call_started",
        _model_start_payload(provider="openai", reservation=500_000),
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
    )
    _append(
        ledger,
        "model_call_finished",
        _model_finish_payload(),
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
    )
    _append(
        ledger,
        "cost_recorded",
        _cost_payload(
            status="estimated",
            amount_microusd=400_000,
            unit_price_microusd=2_666_666_667,
        ),
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
    )
    _start_attempt(
        ledger,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization="explicit_user_approval",
        provider="openai",
    )
    _append(
        ledger,
        "model_call_started",
        _model_start_payload(
            call_id="call-002",
            provider="openai",
            reservation=500_000,
        ),
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "prior model call has unresolved usage or cost")


def test_model_cost_cannot_escape_scored_attribution(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    _append(ledger, "model_call_finished", _model_finish_payload())
    payload = _cost_payload()
    payload["attribution"] = "cold_prep_excluded"
    _append(ledger, "cost_recorded", payload)

    _, errors = _validate(ledger)

    _assert_error(errors, "model inference cost must be attributable")


def test_candidate_cannot_be_attributed_to_failed_provider_call(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "model_call_started", _model_start_payload())
    finish = _model_finish_payload()
    finish.update(status="provider_error", classification_code="openai_http")
    _append(ledger, "model_call_finished", finish)
    _append(
        ledger,
        "candidate_submitted",
        _candidate_payload(generation_call_ids=["call-001"]),
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "candidate references an unfinished or foreign model call")


def test_public_phase_log_recomputes_hash_and_reapplies_redaction(tmp_path: Path) -> None:
    valid = tmp_path / "valid.jsonl"
    _start_attempt(valid)
    _append(
        valid,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )
    safe_log = sanitize_public_excerpt(
        "Authorization: Bearer secret-value at /Users/alice/private/output.log"
    )
    phase = {
        "phase": "generation",
        "phase_ordinal": 1,
        "status": "succeeded",
        "started_at": T0,
        "completed_at": T1,
        "duration_ms": 1_000,
        "classification_code": None,
        "command_sha256": None,
        "environment_sha256": None,
        "artifacts": [],
        "log": safe_log,
    }
    _append(valid, "phase_finished", phase)
    _, valid_errors = _validate(valid)
    assert valid_errors == []

    poisoned = tmp_path / "poisoned.jsonl"
    _start_attempt(poisoned)
    _append(
        poisoned,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )
    bad_phase = copy.deepcopy(phase)
    bad_phase["log"]["excerpt"] = "Authorization: Bearer sk-live-secret"
    _append(poisoned, "phase_finished", bad_phase)
    _, poisoned_errors = _validate(poisoned)
    _assert_error(poisoned_errors, "excerpt_bytes does not match")
    _assert_error(poisoned_errors, "excerpt_sha256 does not match")
    _assert_error(poisoned_errors, "still contains secrets")


def test_review_requires_completed_blinded_evidence_phases(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "candidate_submitted", _candidate_payload())
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-001"))

    _, errors = _validate(ledger)

    _assert_error(errors, "review requires completed policy/base/fixed/control evidence")


def test_only_attempt_finish_may_follow_gold_unblind(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(ledger, "candidate_submitted", _candidate_payload())
    _prepare_blinded_review(ledger)
    _append(ledger, "semantic_review_recorded", _review_payload("reviewer-001"))
    second = _append(
        ledger,
        "semantic_review_recorded",
        _review_payload("reviewer-002"),
    )
    _commit_blinded_review(ledger)
    _append(ledger, "gold_unblinded", _gold_payload(second["event_sha256"]))
    _append(
        ledger,
        "phase_started",
        {"phase": "fixed_verify", "phase_ordinal": 2, "started_at": T2},
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "only attempt_finished may follow gold_unblinded")


def test_case_phase_time_cannot_exceed_frozen_wall_cap(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(
        ledger,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )
    payload = {
        "phase": "generation",
        "phase_ordinal": 1,
        "status": "succeeded",
        "started_at": T0,
        "completed_at": T1,
        "duration_ms": 600_001,
        "classification_code": None,
        "command_sha256": None,
        "environment_sha256": None,
        "artifacts": [],
        "log": None,
    }
    _append(ledger, "phase_finished", payload)

    _, errors = _validate(ledger)

    _assert_error(errors, "exceeds the frozen wall-time cap")


def test_model_call_cannot_hide_outside_a_one_millisecond_generation_phase(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "events.jsonl"
    _start_attempt(ledger)
    _append(
        ledger,
        "phase_started",
        {"phase": "generation", "phase_ordinal": 1, "started_at": T0},
    )
    _append(ledger, "model_call_started", _model_start_payload())
    finish = _model_finish_payload()
    finish.update(completed_at="2026-07-10T12:10:00.000Z", duration_ms=600_000)
    _append(ledger, "model_call_finished", finish)
    _append(ledger, "cost_recorded", _cost_payload())
    _append(
        ledger,
        "phase_finished",
        {
            "phase": "generation",
            "phase_ordinal": 1,
            "status": "succeeded",
            "started_at": T0,
            "completed_at": "2026-07-10T12:00:00.001Z",
            "duration_ms": 1,
            "classification_code": None,
            "command_sha256": None,
            "environment_sha256": None,
            "artifacts": [],
            "log": None,
        },
    )

    _, errors = _validate(ledger)

    _assert_error(errors, "must be enclosed by exactly one generation phase")
    _assert_error(errors, "exceeds the frozen wall-time cap")


def test_result_tool_and_generator_must_match_attempt_freeze(tmp_path: Path) -> None:
    index, result_row = _reconciled_projection(tmp_path)
    result_row["tool"]["git_sha"] = "f" * 40
    result_row["generator"]["provider"] = "anthropic"
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    _assert_error(errors, "result tool identity does not match")
    _assert_error(errors, "result generator identity does not match")


def test_result_evidence_commitment_rejects_execution_projection_drift(
    tmp_path: Path,
) -> None:
    index, result_row = _reconciled_projection(tmp_path)
    result_row["executions"]["base"][0]["status"] = "pass"
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    _assert_error(errors, "result_base_executions evidence commitment does not match")


def test_l0_result_cannot_use_failed_base_verification_commitment(tmp_path: Path) -> None:
    index, result_row = _reconciled_projection(tmp_path)
    attempt = index["attempts"]["attempt-001"]
    base_finish = next(
        event for key, event in attempt["phase_finishes"].items() if key[0] == "base_verify"
    )
    base_finish["payload"]["status"] = "failed"
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    _assert_error(errors, "base_verify must finish exactly once with status ['succeeded']")
    _assert_error(errors, "exactly one result_base_executions evidence commitment")


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("preflight", "preflight must finish exactly once with status ['succeeded']"),
        ("issue", "result_issue_snapshot evidence commitment does not match"),
        ("environment", "collection environment_sha256 does not match"),
    ],
)
def test_claim_input_and_environment_must_match_trace(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    index, result_row = _reconciled_projection(tmp_path)
    if mutation == "preflight":
        attempt = index["attempts"]["attempt-001"]
        preflight = next(
            event for key, event in attempt["phase_finishes"].items() if key[0] == "preflight"
        )
        preflight["payload"]["status"] = "failed"
    elif mutation == "issue":
        result_row["issue_snapshot"]["sha256"] = _sha("e")
    else:
        result_row["environment"]["network"] = "enabled"
    errors: list[str] = []

    VALIDATOR.reconcile_results_with_events([result_row], index, errors)

    _assert_error(errors, expected)


def test_semantic_reviewer_projection_must_match_review_events() -> None:
    event_reviewer = _review_payload("event-reviewer-001")
    row_reviewer = copy.deepcopy(event_reviewer)
    row_reviewer["reviewer_id"] = "row-reviewer-001"
    semantic_review = {
        "status": "invalid",
        "reviewers": [row_reviewer],
        "tie_break_required": False,
        "agreement": 1.0,
        "gold_unblinded_after_decision": True,
    }
    evidence_values = {
        "issue_snapshot": {},
        "policy": {},
        "base": [],
        "fixed": [],
        "causal_controls": [],
        "semantic_review": semantic_review,
    }
    phase_finishes: dict[tuple[str, int], dict[str, Any]] = {}
    environment: dict[str, Any] = {}
    environment_sha256 = hashlib.sha256(VALIDATOR.canonical_json_bytes(environment)).hexdigest()
    for ordinal, (name, value) in enumerate(evidence_values.items(), start=1):
        phase, kind = VALIDATOR.RESULT_EVIDENCE_PHASES[name]
        phase_finishes[(phase, ordinal)] = {
            "payload": {
                "status": "succeeded",
                "environment_sha256": (
                    environment_sha256
                    if phase in {"collection", "base_verify", "fixed_verify", "causal_controls"}
                    else None
                ),
                "artifacts": [_result_evidence_artifact(kind, value)],
            }
        }
    phase_finishes[("preflight", 99)] = {"payload": {"status": "succeeded"}}
    phase_finishes[("generation", 100)] = {"payload": {"status": "succeeded"}}
    phase_finishes[("collection", 101)] = {
        "payload": {"status": "succeeded", "environment_sha256": environment_sha256}
    }
    attempt = {
        "phase_finishes": phase_finishes,
        "reviews": [{"payload": event_reviewer}],
        "gold": {"payload": {}},
    }
    row = {
        "claim_level": "L1",
        "outcome": "plausible_f2p_semantic_invalid",
        "environment": environment,
        "issue_snapshot": evidence_values["issue_snapshot"],
        "policy": evidence_values["policy"],
        "executions": {
            "base": evidence_values["base"],
            "fixed": evidence_values["fixed"],
            "causal_controls": evidence_values["causal_controls"],
        },
        "semantic_review": semantic_review,
    }
    errors: list[str] = []

    VALIDATOR._reconcile_result_evidence(row, attempt, "synthetic row", errors)

    _assert_error(errors, "semantic reviewers do not match")
