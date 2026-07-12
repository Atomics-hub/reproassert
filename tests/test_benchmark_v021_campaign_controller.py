from __future__ import annotations

import fcntl
import os
from pathlib import Path

import pytest
from test_benchmark_v021_runtime import _fixture, _Ledger, _private_dirs

from reproassert import benchmark_v021_campaign_controller as controller
from reproassert import benchmark_v021_runtime as runtime
from reproassert.errors import PolicyRejection


def test_controller_runs_all_20_and_case014_has_no_waiver(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    responses, results = _private_dirs(tmp_path)
    progress_root = tmp_path / "progress"
    progress_root.mkdir(mode=0o700)
    calls: list[str] = []

    def provider(request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        calls.append(request.case_id)
        return runtime.V021ProviderResponse(f"response-{request.case_id}", "candidate", 1)

    run = controller.run_v021_generation_campaign(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        provider=provider,
        response_directory=responses,
        result_directory=results,
        progress_path=progress_root / "progress.json",
    )
    assert run.status == "generation_complete"
    assert run.barrier is not None
    assert len(run.results) == 20
    assert calls == [f"rk-v0.2-{index:03d}" for index in range(1, 21)]
    assert "rk-v0.2-014" in calls


def test_controller_never_forms_barrier_after_unknown_spend(tmp_path: Path) -> None:
    plan, authorization, rows = _fixture(tmp_path)
    ledger = _Ledger()
    ledger.states["rk-v0.2-001"] = runtime.V021LedgerCaseState("reserved")
    responses, results = _private_dirs(tmp_path)
    progress_root = tmp_path / "progress"
    progress_root.mkdir(mode=0o700)
    calls = 0

    def provider(_request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        nonlocal calls
        calls += 1
        return runtime.V021ProviderResponse("forbidden", "", 0)

    run = controller.run_v021_generation_campaign(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        provider=provider,
        response_directory=responses,
        result_directory=results,
        progress_path=progress_root / "progress.json",
    )
    assert run.status == "unknown_spend_halt"
    assert run.barrier is None
    assert len(run.results) == 1
    assert calls == 0
    assert len(rows) == 20


def test_concurrent_controller_is_rejected_before_provider(tmp_path: Path) -> None:
    plan, authorization, _ = _fixture(tmp_path)
    ledger = _Ledger()
    responses, results = _private_dirs(tmp_path)
    progress_root = tmp_path / "progress"
    progress_root.mkdir(mode=0o700)
    descriptor = controller._acquire_lock(progress_root, plan)
    calls = 0

    def provider(_request: runtime.V021ProviderRequest) -> runtime.V021ProviderResponse:
        nonlocal calls
        calls += 1
        return runtime.V021ProviderResponse("forbidden", "", 0)

    try:
        with pytest.raises(PolicyRejection, match=r"Another v0\.2\.1 campaign"):
            controller.run_v021_generation_campaign(
                plan=plan,
                authorization=authorization,
                ledger=ledger,
                provider=provider,
                response_directory=responses,
                result_directory=results,
                progress_path=progress_root / "progress.json",
            )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert calls == 0
