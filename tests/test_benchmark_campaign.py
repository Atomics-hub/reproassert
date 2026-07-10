from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = json.loads((ROOT / "benchmarks" / "v0.1" / "campaign.json").read_text())
SCHEMA = json.loads((ROOT / "schemas" / "benchmark-campaign.schema.json").read_text())
CASE_IDS = {f"rk-v0.1-{index:03d}" for index in range(1, 21)}


def _load_validator() -> ModuleType:
    path = ROOT / "scripts" / "validate_benchmark.py"
    spec = importlib.util.spec_from_file_location("reproassert_campaign_validator", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def _errors(
    campaign: dict[str, Any],
    *,
    scored_index: dict[str, Any] | None = None,
    result_rows: int = 0,
) -> list[str]:
    errors: list[str] = []
    VALIDATOR.validate_campaign(
        campaign,
        campaign_schema=SCHEMA,
        known_case_ids=CASE_IDS,
        scored_index=scored_index or {"events": [], "batch_id": None},
        result_row_count=result_rows,
        errors=errors,
    )
    return errors


def _ready_campaign(*, authorization: str = "offline_zero_cost") -> dict[str, Any]:
    campaign = copy.deepcopy(CAMPAIGN)
    campaign.update(
        status="frozen_ready",
        campaign_id="campaign-001",
        run_id="campaign-001",
        blockers=[],
    )
    campaign["prerequisites"] = {key: True for key in campaign["prerequisites"]}
    configuration = campaign["configuration"]
    for field in (
        "prompt_template_sha256",
        "request_builder_sha256",
        "config_sha256",
        "context_algorithm_sha256",
        "policy_sha256",
        "pricing_snapshot_sha256",
    ):
        configuration[field] = "a" * 64
    configuration.update(
        tool_git_sha="b" * 40,
        provider="local-model" if authorization == "offline_zero_cost" else "openai",
        requested_model="local-v1" if authorization == "offline_zero_cost" else "gpt-test",
        model_version="local-v1" if authorization == "offline_zero_cost" else "gpt-test-v1",
    )
    if authorization == "explicit_user_approval":
        configuration.update(
            max_case_attributable_microusd=100_000,
            max_campaign_attributable_microusd=2_000_000,
        )
        configuration["spend_authorization"] = {
            "status": authorization,
            "authorization_ref": "test-only-explicit-approval",
        }
    else:
        configuration["spend_authorization"] = {
            "status": authorization,
            "authorization_ref": None,
        }
    return campaign


def test_checked_in_campaign_is_schema_valid_and_fail_closed() -> None:
    schema_errors: list[str] = []
    VALIDATOR.validate_json_schema_instance(CAMPAIGN, SCHEMA, SCHEMA, "campaign", schema_errors)

    assert schema_errors == []
    assert _errors(CAMPAIGN) == []
    assert CAMPAIGN["configuration"]["max_campaign_attributable_microusd"] == 0
    assert CAMPAIGN["configuration"]["spend_authorization"]["status"] == "not_authorized"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("positive_blocked_cap", "zero spend caps"),
        ("blocked_paid_authorization", "paid spend unauthorized"),
        ("blocked_frozen_provider", "must not pretend"),
        ("missing_case", "exact frozen cohort"),
    ),
)
def test_blocked_campaign_mutations_fail(mutation: str, expected: str) -> None:
    campaign = copy.deepcopy(CAMPAIGN)
    if mutation == "positive_blocked_cap":
        campaign["configuration"]["max_campaign_attributable_microusd"] = 1
    elif mutation == "blocked_paid_authorization":
        campaign["configuration"]["spend_authorization"] = {
            "status": "explicit_user_approval",
            "authorization_ref": "not-real",
        }
    elif mutation == "blocked_frozen_provider":
        campaign["configuration"]["provider"] = "openai"
    elif mutation == "missing_case":
        campaign["case_ids"].pop()

    assert any(expected in error for error in _errors(campaign))


def test_ready_zero_cost_local_model_is_valid() -> None:
    assert _errors(_ready_campaign()) == []


def test_explicit_authorization_alone_cannot_bypass_missing_pricing_calculator() -> None:
    errors = _errors(_ready_campaign(authorization="explicit_user_approval"))

    assert any("component pricing and trusted reservation" in error for error in errors)


def test_ready_campaign_rejects_fixture_as_scored_generator() -> None:
    campaign = _ready_campaign()
    campaign["configuration"]["provider"] = "offline-fixture"

    assert any("real declared local model" in error for error in _errors(campaign))


def test_frozen_ready_campaign_cannot_have_scored_events() -> None:
    campaign = _ready_campaign()

    errors = _errors(
        campaign,
        scored_index={"events": [{}], "batch_id": "campaign-001"},
    )

    assert any("frozen-ready campaign cannot contain scored events" in error for error in errors)
    assert any("status running or complete" in error for error in errors)


def test_running_campaign_requires_started_at_and_matching_batch() -> None:
    campaign = _ready_campaign()
    campaign["status"] = "running"

    errors = _errors(
        campaign,
        scored_index={"events": [{}], "batch_id": "wrong-campaign"},
    )

    assert any("requires started_at" in error for error in errors)
    assert any("batch_id must match" in error for error in errors)


def test_complete_campaign_requires_all_results() -> None:
    campaign = _ready_campaign()
    campaign["status"] = "complete"
    campaign["started_at"] = "2026-07-10T12:00:00Z"

    assert any("all 20 result rows" in error for error in _errors(campaign, result_rows=19))


def test_complete_campaign_requires_complete_deterministic_summary() -> None:
    campaign = _ready_campaign()
    campaign["status"] = "complete"
    campaign["started_at"] = "2026-07-10T12:00:00Z"
    errors: list[str] = []

    VALIDATOR.validate_campaign(
        campaign,
        campaign_schema=SCHEMA,
        known_case_ids=CASE_IDS,
        scored_index={"events": [], "batch_id": None},
        result_row_count=20,
        errors=errors,
        summary={"completeness": {"complete": False, "status": "in_progress"}},
    )

    assert any("complete deterministic summary" in error for error in errors)


def test_campaign_history_allows_only_terminal_status_transition() -> None:
    running = _ready_campaign()
    running["status"] = "running"
    running["started_at"] = "2026-07-10T12:00:00Z"
    complete = copy.deepcopy(running)
    complete["status"] = "complete"

    encode = lambda value: json.dumps(value, sort_keys=True).encode()  # noqa: E731
    assert VALIDATOR._campaign_history_transition_allowed(encode(running), encode(running))
    assert VALIDATOR._campaign_history_transition_allowed(encode(running), encode(complete))

    changed_freeze = copy.deepcopy(complete)
    changed_freeze["configuration"]["max_case_wall_ms"] += 1
    assert not VALIDATOR._campaign_history_transition_allowed(
        encode(running), encode(changed_freeze)
    )
    assert not VALIDATOR._campaign_history_transition_allowed(encode(complete), encode(running))
