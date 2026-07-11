from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from reproassert import benchmark_v02_exact_campaign_controller as controller
from reproassert import benchmark_v02_runner as runner
from reproassert.cli import main
from reproassert.errors import PolicyRejection


def _config(tmp_path: Path) -> controller.ExactCampaignConfig:
    attempts = tmp_path / "attempts"
    attempts.mkdir(mode=0o700)
    progress_root = tmp_path / "progress"
    progress_root.mkdir(mode=0o700)
    placeholder = tmp_path / "placeholder"
    paths = controller.ExactCampaignPaths(
        campaign_freeze=placeholder,
        exact_preregistration=placeholder,
        cases_preparation=placeholder,
        cohort_plan=placeholder,
        chronology=placeholder,
        hidden_extraction_receipt=placeholder,
        issue_responses_root=placeholder,
        mapping_preparation=placeholder,
        mapping_consensus=placeholder,
        capability_index=placeholder,
        runtime_manifest=placeholder,
        runtime_manifest_sha256="a" * 64,
        gold_smoke_receipt=placeholder,
        gold_specs=placeholder,
        execution_freeze=placeholder,
        execution_authorization=placeholder,
        ledger=tmp_path / "ledger.jsonl",
        attempts_root=attempts,
        progress=progress_root / "progress.json",
    )
    cases = tuple(
        controller.ExactCampaignCase(
            case_id=f"rk-v0.2-{index:03d}",
            generator_projection=placeholder,
            object_source_receipt=placeholder,
            object_source_plan=placeholder,
            source_evidence_receipt=placeholder,
            object_source_receipt_sha256=None,
        )
        for index in range(1, 21)
    )
    return controller.ExactCampaignConfig(
        paths=paths,
        cases=cases,
        executed_at="2026-07-11T00:00:00Z",
        tool_git_sha="b" * 40,
    )


class _FakeRuntime:
    def __init__(self, attempts: dict[str, dict[str, object]]) -> None:
        self.attempts = attempts
        self.events: list[str] = []
        self.provider_calls = 0

    def preflight(self, _config: object) -> tuple[object, object, object, Any]:
        self.events.append("preflight")
        return object(), object(), object(), object()

    def source_context(self, case: controller.ExactCampaignCase) -> object:
        self.events.append(f"source:{case.case_id}")
        return object()

    def generate(
        self,
        _config: object,
        case: controller.ExactCampaignCase,
        _context: object,
        _policy: object,
    ) -> Any:
        self.events.append(f"generate:{case.case_id}")
        attempt_id = f"attempt_{case.case_id[-3:]}"
        self.attempts[case.case_id] = {"attempt_id": attempt_id, "disposition": True}
        return SimpleNamespace(attempt_id=attempt_id)

    def recover(
        self,
        _config: object,
        case: controller.ExactCampaignCase,
        _context: object,
        attempt_id: str,
        _policy: object,
    ) -> object:
        self.events.append(f"recover:{case.case_id}")
        self.attempts[case.case_id] = {"attempt_id": attempt_id, "disposition": True}
        return object()

    def freeze_barrier(self, _config: object, _policy: object) -> object:
        self.events.append("barrier")
        return SimpleNamespace(sha256="c" * 64)

    def evaluation_authorities(self, config: controller.ExactCampaignConfig) -> Any:
        self.events.append("hidden")
        return object(), {case.case_id: object() for case in config.cases}

    def evaluate(
        self, _config: object, case: controller.ExactCampaignCase, *_args: object
    ) -> object:
        self.events.append(f"evaluate:{case.case_id}")
        return object()


def test_controller_generates_all_cases_before_hidden_authority_and_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    attempts: dict[str, dict[str, object]] = {}
    runtime = _FakeRuntime(attempts)
    monkeypatch.setattr(controller, "_attempts", lambda _path: dict(attempts))
    monkeypatch.setattr(
        controller,
        "_audit_caps",
        lambda _path, allow_missing=False: {"campaign_microusd": 0, "case_microusd": {}},
    )

    result = controller._run_with_runtime(config, runtime)

    assert result["status"] == "complete"
    assert runtime.provider_calls == 0
    barrier_index = runtime.events.index("barrier")
    hidden_index = runtime.events.index("hidden")
    assert sum(event.startswith("generate:") for event in runtime.events[:barrier_index]) == 20
    assert hidden_index > barrier_index
    assert all(not event.startswith("evaluate:") for event in runtime.events[:hidden_index])
    persisted = json.loads(config.paths.progress.read_text())
    assert persisted["phase"] == "complete"
    assert all(row["status"] == "evaluated" for row in persisted["cases"].values())


def test_controller_resumes_disposition_and_recovers_incomplete_attempt_without_new_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    attempts = {
        "rk-v0.2-001": {"attempt_id": "attempt_001", "disposition": True},
        "rk-v0.2-002": {"attempt_id": "attempt_002", "disposition": False},
    }
    runtime = _FakeRuntime(attempts)
    monkeypatch.setattr(controller, "_attempts", lambda _path: dict(attempts))
    monkeypatch.setattr(
        controller,
        "_audit_caps",
        lambda _path, allow_missing=False: {"campaign_microusd": 0, "case_microusd": {}},
    )

    controller._run_with_runtime(config, runtime)

    assert "generate:rk-v0.2-001" not in runtime.events
    assert "recover:rk-v0.2-001" not in runtime.events
    assert "recover:rk-v0.2-002" in runtime.events
    assert "generate:rk-v0.2-002" not in runtime.events
    assert sum(event.startswith("generate:") for event in runtime.events) == 18
    assert runtime.provider_calls == 0


@pytest.mark.parametrize(
    ("case_amount", "other_amount", "message"),
    [
        (250_001, 0, "case spend"),
        (250_000, 250_001, "case spend"),
    ],
)
def test_cap_audit_fails_closed_before_overage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_amount: int,
    other_amount: int,
    message: str,
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("present")
    events = [
        {
            "event_type": "attempt_started",
            "attempt_id": "attempt_1",
            "payload": {"case": {"id": "rk-v0.2-001"}},
        },
        {
            "event_type": "attempt_started",
            "attempt_id": "attempt_2",
            "payload": {"case": {"id": "rk-v0.2-002"}},
        },
        {
            "event_type": "cost_recorded",
            "attempt_id": "attempt_1",
            "payload": {"amount_microusd": case_amount},
        },
        {
            "event_type": "cost_recorded",
            "attempt_id": "attempt_2",
            "payload": {"amount_microusd": other_amount},
        },
    ]
    monkeypatch.setattr(
        runner, "read_v02_scored_ledger", lambda _path: SimpleNamespace(events=events)
    )

    with pytest.raises(PolicyRejection, match=message):
        controller._audit_caps(ledger)


def test_unknown_cost_halts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("present")
    events = [
        {
            "event_type": "attempt_started",
            "attempt_id": "attempt_1",
            "payload": {"case": {"id": "rk-v0.2-001"}},
        },
        {
            "event_type": "cost_recorded",
            "attempt_id": "attempt_1",
            "payload": {"amount_microusd": None},
        },
    ]
    monkeypatch.setattr(
        runner, "read_v02_scored_ledger", lambda _path: SimpleNamespace(events=events)
    )
    with pytest.raises(PolicyRejection, match="Unknown or invalid"):
        controller._audit_caps(ledger)


def test_preflight_failure_never_reaches_generation_or_provider(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    runtime = _FakeRuntime({})

    def reject(_config: object) -> tuple[object, object, object, Any]:
        runtime.events.append("preflight")
        raise PolicyRejection("test", "fresh authorization verification failed")

    runtime.preflight = reject  # type: ignore[method-assign]
    with pytest.raises(PolicyRejection, match="authorization verification"):
        controller._run_with_runtime(config, runtime)

    assert runtime.events == ["preflight"]
    assert runtime.provider_calls == 0
    progress = json.loads(config.paths.progress.read_text())
    assert progress["status"] == "halted"
    assert progress["phase"] == "preflight"


def test_campaign_cap_is_independently_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("present")
    events: list[dict[str, object]] = []
    for index in range(1, 21):
        attempt_id = f"attempt_{index}"
        events.extend(
            [
                {
                    "event_type": "attempt_started",
                    "attempt_id": attempt_id,
                    "payload": {"case": {"id": f"rk-v0.2-{index:03d}"}},
                },
                {
                    "event_type": "cost_recorded",
                    "attempt_id": attempt_id,
                    "payload": {"amount_microusd": 250_001},
                },
            ]
        )
    monkeypatch.setattr(controller, "MAX_CASE_MICROUSD", 500_000)
    monkeypatch.setattr(
        runner, "read_v02_scored_ledger", lambda _path: SimpleNamespace(events=events)
    )
    with pytest.raises(PolicyRejection, match="campaign spend"):
        controller._audit_caps(ledger)


def test_cli_exposes_exact_campaign_controller() -> None:
    result = CliRunner().invoke(main, ["benchmark", "run-v02-exact-campaign", "--help"])
    assert result.exit_code == 0
    assert "safely resume" in result.output
