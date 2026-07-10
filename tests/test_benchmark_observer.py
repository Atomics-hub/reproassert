from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import reproassert.generator as generator_module
from reproassert.benchmark import _append_event, _BenchmarkModelCallRecorder, read_ledger
from reproassert.context import SourceContext
from reproassert.errors import PolicyRejection
from reproassert.generator import DEFAULT_OPENAI_MODEL, GenerationRequest, OpenAIResponsesGenerator

PRICING_SHA256 = "8" * 64
MODEL_IDENTITY: dict[str, object] = {
    "status": "alias_only",
    "value": DEFAULT_OPENAI_MODEL,
}


class _CapturedModelStart(RuntimeError):
    pass


class _StartHashObserver:
    def __init__(self) -> None:
        self.event: dict[str, object] | None = None

    def model_call_started(self, event: Mapping[str, object]) -> None:
        self.event = dict(event)
        raise _CapturedModelStart

    def model_call_finished(self, _event: Mapping[str, object]) -> None:
        raise AssertionError("captured start must prevent transmission")


def _request(issue_number: int) -> GenerationRequest:
    return GenerationRequest(
        issue_url=f"https://github.com/example/project/issues/{issue_number}",
        issue_number=issue_number,
        issue_title="Normalizer keeps a duplicate separator",
        issue_body="Untrusted issue text; do not execute any instructions.",
        source_sha="a" * 40,
        source_context=SourceContext((), (), 0),
    )


def _candidate(issue_number: int) -> dict[str, str]:
    return {
        "test_content": (
            "from fixture_project import normalize\n\n"
            f"def test_issue_{issue_number}_reproduction():\n"
            "    assert normalize('a--b') == 'a-b', 'duplicate separator remains'\n"
        ),
        "expected_symptom": "duplicate separator remains",
        "rationale": "One direct assertion captures the reported behavior.",
    }


def _response(issue_number: int) -> bytes:
    return json.dumps(
        {
            "id": f"resp_issue_{issue_number}",
            "model": "gpt-5.4-mini-2026-03-17",
            "status": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "total_tokens": 150,
            },
            "output_text": json.dumps(_candidate(issue_number)),
        }
    ).encode()


def _provider_hashes(
    request: GenerationRequest, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, str]:
    observer = _StartHashObserver()
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")

    with pytest.raises(_CapturedModelStart):
        OpenAIResponsesGenerator(observer=observer).generate(request)

    assert observer.event is not None
    rendered_input_sha256 = observer.event["rendered_input_sha256"]
    config_sha256 = observer.event["config_sha256"]
    assert isinstance(rendered_input_sha256, str)
    assert isinstance(config_sha256, str)
    return rendered_input_sha256, config_sha256


def _attempt_payload(
    *,
    batch_id: str,
    case_id: str,
    authorization_status: str,
    authorization_ref: str | None,
    case_cap: int,
    campaign_cap: int,
    provider: str = "openai",
    prompt_template_sha256: str = "2" * 64,
    config_sha256: str = "3" * 64,
) -> dict[str, Any]:
    return {
        "attempt_ordinal": 1,
        "disposition": "primary_score",
        "retry_of": None,
        "campaign": {
            "campaign_id": batch_id,
            "cohort_tier": "historical_scored",
            "max_model_calls_per_case": 1,
            "max_submitted_candidates_per_case": 1,
            "max_infrastructure_retries_per_case": 1,
            "max_case_wall_ms": 600_000,
            "max_case_attributable_microusd": case_cap,
            "max_campaign_attributable_microusd": campaign_cap,
            "spend_authorization": {
                "status": authorization_status,
                "authorization_ref": authorization_ref,
            },
        },
        "manifest_sha256": "1" * 64,
        "case_entry_sha256": case_id[-1] * 64,
        "tool": {"name": "reproassert", "version": "0.1.0", "git_sha": "1" * 40},
        "generator": {
            "adapter": "openai-responses",
            "provider": provider,
            "requested_model": DEFAULT_OPENAI_MODEL,
            "model_identity": MODEL_IDENTITY,
            "prompt_template_sha256": prompt_template_sha256,
            "config_sha256": config_sha256,
            "request_builder_sha256": "4" * 64,
            "context_algorithm_sha256": "5" * 64,
            "feedback_policy": "base_only_no_oracle",
            "submitted_candidate_budget": 1,
        },
        "policy_sha256": "7" * 64,
        "pricing_snapshot_sha256": PRICING_SHA256,
    }


def _start_attempt(
    ledger: Path,
    *,
    batch_id: str,
    attempt_id: str,
    case_id: str,
    authorization_status: str,
    authorization_ref: str | None,
    case_cap: int,
    campaign_cap: int,
    provider: str = "openai",
    prompt_template_sha256: str = "2" * 64,
    config_sha256: str = "3" * 64,
) -> None:
    _append_event(
        ledger,
        lane="scored",
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="attempt_started",
        payload=_attempt_payload(
            batch_id=batch_id,
            case_id=case_id,
            authorization_status=authorization_status,
            authorization_ref=authorization_ref,
            case_cap=case_cap,
            campaign_cap=campaign_cap,
            provider=provider,
            prompt_template_sha256=prompt_template_sha256,
            config_sha256=config_sha256,
        ),
    )


def _recorder(
    ledger: Path,
    *,
    batch_id: str,
    attempt_id: str,
    case_id: str,
    authorization_status: str,
    authorization_ref: str | None,
    reserve: int,
    case_cap: int,
    campaign_cap: int,
) -> _BenchmarkModelCallRecorder:
    return _BenchmarkModelCallRecorder(
        ledger_path=ledger,
        lane="scored",
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
        model_identity=MODEL_IDENTITY,
        pricing_snapshot_sha256=PRICING_SHA256,
        reserved_worst_case_microusd=reserve,
        max_case_attributable_microusd=case_cap,
        max_campaign_attributable_microusd=campaign_cap,
        spend_authorization_status=authorization_status,
        spend_authorization_ref=authorization_ref,
    )


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"lane": "public"}, "benchmark_event_lane"),
        ({"batch_id": "x"}, "benchmark_event_identity"),
        ({"case_id": "not-a-case"}, "benchmark_event_identity"),
        ({"reserved_worst_case_microusd": -1}, "benchmark_spend_limit"),
        (
            {
                "reserved_worst_case_microusd": 2,
                "max_case_attributable_microusd": 1,
            },
            "benchmark_spend_limit",
        ),
        (
            {
                "reserved_worst_case_microusd": 2,
                "max_campaign_attributable_microusd": 1,
            },
            "benchmark_spend_limit",
        ),
        (
            {"spend_authorization_ref": "paid approval"},
            "benchmark_spend_authorization",
        ),
        (
            {
                "lane": "smoke",
                "spend_authorization_status": "explicit_user_approval",
                "spend_authorization_ref": "paid approval",
            },
            "benchmark_spend_authorization",
        ),
        (
            {
                "spend_authorization_status": "explicit_user_approval",
                "spend_authorization_ref": None,
            },
            "benchmark_spend_authorization",
        ),
        (
            {"spend_authorization_status": "not_authorized"},
            "benchmark_spend_authorization",
        ),
    ],
)
def test_recorder_rejects_invalid_identity_caps_and_authorization(
    tmp_path: Path,
    overrides: dict[str, object],
    expected_code: str,
) -> None:
    kwargs: dict[str, object] = {
        "ledger_path": tmp_path / "events.jsonl",
        "lane": "scored",
        "batch_id": "campaign-001",
        "attempt_id": "attempt-004",
        "case_id": "rk-v0.1-004",
        "model_identity": MODEL_IDENTITY,
        "pricing_snapshot_sha256": PRICING_SHA256,
        "reserved_worst_case_microusd": 0,
        "max_case_attributable_microusd": 0,
        "max_campaign_attributable_microusd": 0,
        "spend_authorization_status": "offline_zero_cost",
        "spend_authorization_ref": None,
    }
    kwargs.update(overrides)

    with pytest.raises(PolicyRejection) as caught:
        _BenchmarkModelCallRecorder(**kwargs)  # type: ignore[arg-type]

    assert caught.value.code == expected_code


def _model_start_event(call_id: str, rendered_input_sha256: str) -> dict[str, object]:
    return {
        "call_id": call_id,
        "started_at": "2026-07-10T12:00:00.000Z",
        "provider": "openai",
        "endpoint_host": "api.openai.com",
        "requested_model": DEFAULT_OPENAI_MODEL,
        "rendered_input_sha256": rendered_input_sha256,
        "config_sha256": "3" * 64,
        "max_output_tokens": 4_096,
    }


def _model_finish_event(call_id: str) -> dict[str, object]:
    return {
        "call_id": call_id,
        "status": "succeeded",
        "started_at": "2026-07-10T12:00:00.000Z",
        "completed_at": "2026-07-10T12:00:01.000Z",
        "duration_ms": 1_000,
        "response_model": "gpt-5.4-mini-2026-03-17",
        "response_id_sha256": "9" * 64,
        "classification_code": "candidate_accepted",
        "usage": {
            "status": "reported",
            "input_tokens": 100,
            "cached_input_tokens": 0,
            "output_tokens": 50,
            "total_tokens": 150,
        },
    }


def _append_model_cost(
    ledger: Path,
    *,
    batch_id: str,
    attempt_id: str,
    case_id: str,
    call_id: str,
    amount_microusd: int,
    status: str,
) -> None:
    _append_event(
        ledger,
        lane="scored",
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
        event_type="cost_recorded",
        payload={
            "entry_id": f"cost-{case_id[-3:]}",
            "source_call_id": call_id,
            "category": "model_inference",
            "attribution": "scored",
            "status": status,
            "quantity": "150",
            "unit": "token",
            "unit_price_microusd": 0 if amount_microusd == 0 else 7,
            "amount_microusd": amount_microusd,
            "source": "synthetic bridge test",
            "observed_at": "2026-07-10T12:00:01.000Z",
        },
    )


@pytest.mark.parametrize(
    ("cost_status", "second_call_allowed"),
    [("zero_verified", True), ("estimated", False)],
)
def test_rendered_inputs_vary_under_one_template_but_estimated_cost_stays_unresolved(
    tmp_path: Path,
    cost_status: str,
    second_call_allowed: bool,
) -> None:
    ledger = tmp_path / f"{cost_status}.jsonl"
    batch_id = "campaign-001"
    authorization_ref = "tom-approved-capped-test"
    for attempt_id, case_id in (
        ("attempt-004", "rk-v0.1-004"),
        ("attempt-006", "rk-v0.1-006"),
    ):
        _start_attempt(
            ledger,
            batch_id=batch_id,
            attempt_id=attempt_id,
            case_id=case_id,
            authorization_status="explicit_user_approval",
            authorization_ref=authorization_ref,
            case_cap=2_000,
            campaign_cap=10_000,
        )
    first = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    first_call_id = "call_" + "e" * 32
    first.model_call_started(_model_start_event(first_call_id, "a" * 64))
    first.model_call_finished(_model_finish_event(first_call_id))
    _append_model_cost(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        call_id=first_call_id,
        amount_microusd=0,
        status=cost_status,
    )
    second = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    second_event = _model_start_event("call_" + "f" * 32, "b" * 64)

    if second_call_allowed:
        second.model_call_started(second_event)
    else:
        with pytest.raises(PolicyRejection) as caught:
            second.model_call_started(second_event)
        assert caught.value.code == "benchmark_spend_unknown"

    starts = [
        event["payload"]
        for event in read_ledger(ledger, expected_lane="scored").events
        if event["event_type"] == "model_call_started"
    ]
    assert starts[0]["rendered_input_sha256"] == "a" * 64
    if second_call_allowed:
        assert starts[1]["rendered_input_sha256"] == "b" * 64
    else:
        assert len(starts) == 1


def test_explicit_capped_call_is_started_before_post_and_finished_without_cost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "scored.jsonl"
    batch_id = "campaign-001"
    attempt_id = "attempt-004"
    case_id = "rk-v0.1-004"
    generation_request = _request(4)
    _, config_sha256 = _provider_hashes(generation_request, monkeypatch)
    _start_attempt(
        ledger,
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        case_cap=2_000,
        campaign_cap=10_000,
        config_sha256=config_sha256,
    )
    recorder = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id=attempt_id,
        case_id=case_id,
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    post_count = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal post_count
        post_count += 1
        before_post = read_ledger(ledger, expected_lane="scored")
        assert before_post.errors == ()
        assert [event["event_type"] for event in before_post.events] == [
            "attempt_started",
            "model_call_started",
        ]
        assert before_post.events[-1]["payload"]["reserved_worst_case_microusd"] == 1_000
        return _response(4)

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)

    candidate = OpenAIResponsesGenerator(observer=recorder).generate(generation_request)

    assert candidate.test_function == "test_issue_4_reproduction"
    assert post_count == 1
    snapshot = read_ledger(ledger, expected_lane="scored")
    assert snapshot.errors == ()
    assert [event["event_type"] for event in snapshot.events] == [
        "attempt_started",
        "model_call_started",
        "model_call_finished",
    ]
    start = snapshot.events[1]["payload"]
    finish = snapshot.events[2]["payload"]
    assert start["call_id"] == finish["call_id"]
    assert start["model_identity"] == MODEL_IDENTITY
    assert start["pricing_snapshot_sha256"] == PRICING_SHA256
    assert finish["usage"] == {
        "status": "reported",
        "input_tokens": 100,
        "cached_input_tokens": 0,
        "output_tokens": 50,
        "total_tokens": 150,
    }
    assert all(event["event_type"] != "cost_recorded" for event in snapshot.events)

    next_request = _request(6)
    next_rendered_sha256, next_config_sha256 = _provider_hashes(next_request, monkeypatch)
    _start_attempt(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        case_cap=2_000,
        campaign_cap=10_000,
        config_sha256=next_config_sha256,
    )
    next_recorder = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    with pytest.raises(PolicyRejection) as unresolved_cost:
        next_recorder.model_call_started(
            {
                "call_id": "call_" + "b" * 32,
                "started_at": "2026-07-10T12:00:00.000Z",
                "provider": "openai",
                "endpoint_host": "api.openai.com",
                "requested_model": DEFAULT_OPENAI_MODEL,
                "rendered_input_sha256": next_rendered_sha256,
                "config_sha256": next_config_sha256,
                "max_output_tokens": 4_096,
            }
        )
    assert unresolved_cost.value.code == "benchmark_spend_unknown"
    assert [
        event["event_type"] for event in read_ledger(ledger, expected_lane="scored").events
    ].count("model_call_started") == 1


def test_paid_provider_is_blocked_under_zero_authorization_before_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "scored.jsonl"
    generation_request = _request(4)
    _, config_sha256 = _provider_hashes(generation_request, monkeypatch)
    _start_attempt(
        ledger,
        batch_id="campaign-001",
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="offline_zero_cost",
        authorization_ref=None,
        case_cap=0,
        campaign_cap=0,
        config_sha256=config_sha256,
    )
    recorder = _recorder(
        ledger,
        batch_id="campaign-001",
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="offline_zero_cost",
        authorization_ref=None,
        reserve=0,
        case_cap=0,
        campaign_cap=0,
    )
    post_count = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal post_count
        post_count += 1
        return _response(4)

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)

    with pytest.raises(PolicyRejection) as caught:
        OpenAIResponsesGenerator(observer=recorder).generate(generation_request)

    assert caught.value.code == "benchmark_spend_authorization"
    assert post_count == 0
    snapshot = read_ledger(ledger, expected_lane="scored")
    assert [event["event_type"] for event in snapshot.events] == ["attempt_started"]


def test_config_drift_is_blocked_before_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "scored.jsonl"
    generation_request = _request(4)
    _provider_hashes(generation_request, monkeypatch)
    _start_attempt(
        ledger,
        batch_id="campaign-001",
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        case_cap=2_000,
        campaign_cap=10_000,
        config_sha256="0" * 64,
    )
    recorder = _recorder(
        ledger,
        batch_id="campaign-001",
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="explicit_user_approval",
        authorization_ref="tom-approved-capped-test",
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    post_count = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal post_count
        post_count += 1
        return _response(4)

    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)

    with pytest.raises(PolicyRejection) as caught:
        OpenAIResponsesGenerator(observer=recorder).generate(generation_request)

    assert caught.value.code == "benchmark_campaign_freeze"
    assert post_count == 0
    snapshot = read_ledger(ledger, expected_lane="scored")
    assert [event["event_type"] for event in snapshot.events] == ["attempt_started"]


def test_prior_unknown_campaign_call_blocks_the_next_call_before_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "scored.jsonl"
    batch_id = "campaign-001"
    authorization_ref = "tom-approved-capped-test"
    requests = {4: _request(4), 6: _request(6)}
    hashes = {
        issue_number: _provider_hashes(request, monkeypatch)
        for issue_number, request in requests.items()
    }
    assert hashes[4][0] != hashes[6][0]
    assert hashes[4][1] == hashes[6][1]
    for attempt_id, case_id in (
        ("attempt-004", "rk-v0.1-004"),
        ("attempt-006", "rk-v0.1-006"),
    ):
        _start_attempt(
            ledger,
            batch_id=batch_id,
            attempt_id=attempt_id,
            case_id=case_id,
            authorization_status="explicit_user_approval",
            authorization_ref=authorization_ref,
            case_cap=2_000,
            campaign_cap=10_000,
            config_sha256=hashes[int(case_id[-1])][1],
        )

    first = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    first.model_call_started(
        {
            "call_id": "call_" + "a" * 32,
            "started_at": "2026-07-10T12:00:00.000Z",
            "provider": "openai",
            "endpoint_host": "api.openai.com",
            "requested_model": DEFAULT_OPENAI_MODEL,
            "rendered_input_sha256": hashes[4][0],
            "config_sha256": hashes[4][1],
            "max_output_tokens": 4_096,
        }
    )
    second = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=10_000,
    )
    post_count = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal post_count
        post_count += 1
        return _response(6)

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)

    with pytest.raises(PolicyRejection) as caught:
        OpenAIResponsesGenerator(observer=second).generate(requests[6])

    assert caught.value.code == "benchmark_spend_unknown"
    assert post_count == 0
    snapshot = read_ledger(ledger, expected_lane="scored")
    assert [event["event_type"] for event in snapshot.events].count("model_call_started") == 1


def test_known_campaign_spend_plus_new_reserve_cannot_exceed_cap(tmp_path: Path) -> None:
    ledger = tmp_path / "scored.jsonl"
    batch_id = "campaign-001"
    authorization_ref = "tom-approved-capped-test"
    for attempt_id, case_id in (
        ("attempt-004", "rk-v0.1-004"),
        ("attempt-006", "rk-v0.1-006"),
    ):
        _start_attempt(
            ledger,
            batch_id=batch_id,
            attempt_id=attempt_id,
            case_id=case_id,
            authorization_status="explicit_user_approval",
            authorization_ref=authorization_ref,
            case_cap=2_000,
            campaign_cap=1_500,
        )
    first = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=1_500,
    )
    call_id = "call_" + "c" * 32
    first.model_call_started(
        {
            "call_id": call_id,
            "started_at": "2026-07-10T12:00:00.000Z",
            "provider": "openai",
            "endpoint_host": "api.openai.com",
            "requested_model": DEFAULT_OPENAI_MODEL,
            "rendered_input_sha256": "2" * 64,
            "config_sha256": "3" * 64,
            "max_output_tokens": 4_096,
        }
    )
    first.model_call_finished(
        {
            "call_id": call_id,
            "status": "succeeded",
            "started_at": "2026-07-10T12:00:00.000Z",
            "completed_at": "2026-07-10T12:00:01.000Z",
            "duration_ms": 1_000,
            "response_model": "gpt-5.4-mini-2026-03-17",
            "response_id_sha256": "9" * 64,
            "classification_code": "candidate_accepted",
            "usage": {
                "status": "reported",
                "input_tokens": 100,
                "cached_input_tokens": 0,
                "output_tokens": 50,
                "total_tokens": 150,
            },
        }
    )
    _append_event(
        ledger,
        lane="scored",
        batch_id=batch_id,
        attempt_id="attempt-004",
        case_id="rk-v0.1-004",
        event_type="cost_recorded",
        payload={
            "entry_id": "cost-001",
            "source_call_id": call_id,
            "category": "model_inference",
            "attribution": "scored",
            "status": "measured",
            "quantity": "150",
            "unit": "token",
            "unit_price_microusd": 7,
            "amount_microusd": 1_000,
            "source": "synthetic bridge test",
            "observed_at": "2026-07-10T12:00:01.000Z",
        },
    )
    second = _recorder(
        ledger,
        batch_id=batch_id,
        attempt_id="attempt-006",
        case_id="rk-v0.1-006",
        authorization_status="explicit_user_approval",
        authorization_ref=authorization_ref,
        reserve=1_000,
        case_cap=2_000,
        campaign_cap=1_500,
    )

    with pytest.raises(PolicyRejection) as caught:
        second.model_call_started(
            {
                "call_id": "call_" + "d" * 32,
                "started_at": "2026-07-10T12:00:02.000Z",
                "provider": "openai",
                "endpoint_host": "api.openai.com",
                "requested_model": DEFAULT_OPENAI_MODEL,
                "rendered_input_sha256": "3" * 64,
                "config_sha256": "3" * 64,
                "max_output_tokens": 4_096,
            }
        )

    assert caught.value.code == "benchmark_spend_limit"
    snapshot = read_ledger(ledger, expected_lane="scored")
    assert [event["event_type"] for event in snapshot.events].count("model_call_started") == 1
