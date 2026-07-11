from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
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
    placeholder.write_text("placeholder")
    authorization = tmp_path / "execution-authorization.json"
    authorization.write_text('{"campaign_id":"campaign_test"}\n')
    preregistration = tmp_path / "exact-preregistration.json"
    preregistration.write_text("exact-preregistration\n")
    paths = controller.ExactCampaignPaths(
        campaign_freeze=placeholder,
        exact_preregistration=preregistration,
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
        execution_authorization=authorization,
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

    def preflight(
        self, config: controller.ExactCampaignConfig
    ) -> tuple[object, object, object, Any]:
        self.events.append("preflight")
        preregistration = SimpleNamespace(
            sha256=hashlib.sha256(config.paths.exact_preregistration.read_bytes()).hexdigest()
        )
        freeze = SimpleNamespace(campaign_id="campaign_test")
        authorization = SimpleNamespace(
            sha256=hashlib.sha256(config.paths.execution_authorization.read_bytes()).hexdigest()
        )
        return preregistration, freeze, authorization, freeze

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

    runtime.preflight = reject  # type: ignore[assignment]
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


def test_concurrent_loser_never_mutates_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    attempts: dict[str, dict[str, object]] = {}
    owner = _FakeRuntime(attempts)
    loser = _FakeRuntime(attempts)
    entered = threading.Event()
    release = threading.Event()
    original_source = owner.source_context

    def blocking_source(case: controller.ExactCampaignCase) -> object:
        if case.case_id == "rk-v0.2-001":
            entered.set()
            assert release.wait(timeout=5)
        return original_source(case)

    owner.source_context = blocking_source  # type: ignore[method-assign]
    monkeypatch.setattr(controller, "_attempts", lambda _path: dict(attempts))
    monkeypatch.setattr(
        controller,
        "_audit_caps",
        lambda _path, allow_missing=False: {"campaign_microusd": 0, "case_microusd": {}},
    )
    owner_errors: list[BaseException] = []

    def run_owner() -> None:
        try:
            controller._run_with_runtime(config, owner)
        except BaseException as exc:  # pragma: no cover - asserted below
            owner_errors.append(exc)

    thread = threading.Thread(target=run_owner)
    thread.start()
    assert entered.wait(timeout=5)
    before = config.paths.progress.read_bytes()
    with pytest.raises(PolicyRejection, match="owns the lock"):
        controller._run_with_runtime(config, loser)
    assert config.paths.progress.read_bytes() == before
    assert loser.events == []
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert owner_errors == []
    assert json.loads(config.paths.progress.read_text())["status"] == "complete"


@pytest.mark.parametrize("mutation", ["identity", "case_row"])
def test_resume_rejects_tampered_progress_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
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
    controller._run_with_runtime(config, runtime)
    progress = json.loads(config.paths.progress.read_text())
    if mutation == "identity":
        progress["identity"]["config_sha256"] = "d" * 64
        match = "identity differs"
    else:
        progress["cases"]["rk-v0.2-001"]["status"] = "invented"
        match = "progress row"
    tampered = json.dumps(progress, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    config.paths.progress.write_bytes(tampered)

    with pytest.raises(PolicyRejection, match=match):
        controller._run_with_runtime(config, _FakeRuntime(attempts))
    assert config.paths.progress.read_bytes() == tampered


def test_progress_temp_creation_is_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    path = root / "progress.json"
    monkeypatch.setattr(os, "getpid", lambda: 123)
    monkeypatch.setattr(uuid, "uuid4", lambda: SimpleNamespace(hex="fixed"))
    collision = root / ".progress.json.123.fixed.tmp"
    collision.write_text("do-not-truncate")

    with pytest.raises(FileExistsError):
        controller._write_progress(path, {"status": "running"})
    assert collision.read_text() == "do-not-truncate"
    assert not path.exists()
