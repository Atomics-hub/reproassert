from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from reproassert import benchmark_v02_campaign as campaign
from reproassert import benchmark_v02_runner as runner
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_scored_preregistration import (
    _self_hash,
    load_v02_scored_preregistration,
)
from reproassert.context import SourceContext
from reproassert.generator import GenerationRequest


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _exact_preregistration(
    path: Path, *, model: str = "gpt-test"
) -> tuple[Path, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for index in range(1, 21):
        case_id = f"rk-v0.2-{index:03d}"
        contract = v02_candidate_contract(case_id=case_id, issue_number=index)
        request = GenerationRequest(
            issue_url=f"https://github.com/owner/repo/issues/{index}",
            issue_number=index,
            issue_title=f"Issue {index}",
            issue_body="Reported behavior",
            source_sha=f"{index:040x}",
            source_context=SourceContext((), (), 0),
            candidate_profile=contract.profile,
            required_test_function=(
                contract.test_function if contract.profile == "sympy-native-v1" else None
            ),
        )
        row: dict[str, Any] = {
            "base_sha": f"{index:040x}",
            "candidate_profile": contract.profile,
            "case_id": case_id,
            "difficulty": "lt_15m" if index <= 14 else "15m_to_1h",
            "evaluator_commitment_sha256": f"{index + 100:064x}",
            "evaluator_status": (
                "runtime_attested_gold_smoke_infrastructure_failure"
                if index == 14
                else "runtime_attested_evaluator_preflight_ready"
            ),
            "generator_projection_sha256": f"{index + 200:064x}",
            "instance_id": f"instance-{index}",
            "issue_url": request.issue_url,
            "mapping_selected_hunks_sha256": f"{index + 300:064x}",
            "outbound_request_sha256": runner._outbound_request_sha256(request, model),
            "rendered_input_sha256": runner._rendered_input_sha256(request),
            "repo": "owner/repo",
            "request_envelope_sha256": f"{index + 400:064x}",
            "smoke": index in {4, 6, 10, 11, 18},
            "source_projection_commitment_sha256": f"{index + 500:064x}",
            "test_command_profile": (
                "sympy-bin-test-v1" if contract.profile == "sympy-native-v1" else "pytest-v1"
            ),
        }
        row["case_commitment_sha256"] = runner._sha256_json(row)
        rows.append(row)
    record: dict[str, Any] = {
        "algorithm": "reproassert-v02-exact-image-preregistration-v1",
        "benchmark_version": "0.2",
        "case_count": 20,
        "case_set_sha256": runner._sha256_json(
            {
                "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
                "case_commitments": [row["case_commitment_sha256"] for row in rows],
            }
        ),
        "cases": rows,
        "claims": {},
        "cohort_sha256": "b" * 64,
        "evidence": {},
        "frozen_at": "2026-07-11T00:00:00Z",
        "policy": {},
        "request_set_sha256": "c" * 64,
        "schema_version": "1.0.0",
        "status": "frozen_preinference_exact_image",
        "tool_git_sha": "1" * 40,
    }
    record["preregistration_sha256"] = _self_hash(record)
    path.write_bytes(_canonical(record))
    return path, rows


def test_exact_scored_loader_drives_campaign_freeze_without_legacy_artifact(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    path, _rows = _exact_preregistration(tmp_path / "exact.json")
    loaded = load_v02_scored_preregistration(path)

    assert loaded.format == "exact-image-v1"
    assert loaded.raw_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert loaded.request_set_sha256 == "c" * 64
    assert [case.id for case in loaded.cases] == [f"rk-v0.2-{index:03d}" for index in range(1, 21)]
    assert loaded.exact_row("rk-v0.2-016")["candidate_profile"] == "sympy-native-v1"  # type: ignore[index]

    freeze_path = campaign.prepare_v02_campaign_freeze(
        path,
        tmp_path / "campaign-freeze.json",
        campaign_id="campaign_exact_test",
        prepared_at="2026-07-11T00:01:00Z",
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
    )
    verified = campaign.verify_v02_campaign_freeze(freeze_path, path)
    assert verified.preregistration_sha256 == loaded.raw_sha256
    assert verified.case_ids[15:17] == ("rk-v0.2-016", "rk-v0.2-017")


@pytest.mark.parametrize("case_index", [1, 16, 17])
def test_exact_context_rederives_rendered_and_outbound_request_bindings(
    tmp_path: Path, case_index: int
) -> None:
    os.chmod(tmp_path, 0o700)
    path, _rows = _exact_preregistration(tmp_path / "exact.json")
    loaded = load_v02_scored_preregistration(path)
    case = loaded.cases[case_index - 1]
    contract = v02_candidate_contract(case_id=case.id, issue_number=case_index)
    request = GenerationRequest(
        issue_url=case.issue_url,
        issue_number=case_index,
        issue_title=f"Issue {case_index}",
        issue_body="Reported behavior",
        source_sha=case.base_sha,
        source_context=SourceContext((), (), 0),
        candidate_profile=contract.profile,
        required_test_function=(
            contract.test_function if contract.profile == "sympy-native-v1" else None
        ),
    )
    context = SimpleNamespace(
        case=runner.V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha)
    )

    runner._validate_scored_context_request(loaded, cast(Any, context), case, request, "gpt-test")
    changed = GenerationRequest(**{**request.__dict__, "issue_body": "tampered after freeze"})
    with pytest.raises(runner.PolicyRejection, match="differs from exact preregistration"):
        runner._validate_scored_context_request(
            loaded, cast(Any, context), case, changed, "gpt-test"
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_root",
        "extra_case",
        "bad_base_sha",
        "wrong_difficulty",
        "wrong_smoke",
        "profile_command_mismatch",
        "case_commitment",
        "case_set_commitment",
    ],
)
def test_exact_scored_loader_rejects_structural_and_commitment_drift(
    tmp_path: Path, mutation: str
) -> None:
    os.chmod(tmp_path, 0o700)
    path, _rows = _exact_preregistration(tmp_path / "exact.json")
    record = json.loads(path.read_text())
    first = record["cases"][0]
    if mutation == "extra_root":
        record["unexpected"] = True
    elif mutation == "extra_case":
        first["unexpected"] = True
    elif mutation == "bad_base_sha":
        first["base_sha"] = "not-a-git-sha"
    elif mutation == "wrong_difficulty":
        first["difficulty"] = "15m_to_1h"
    elif mutation == "wrong_smoke":
        first["smoke"] = True
    elif mutation == "profile_command_mismatch":
        first["test_command_profile"] = "sympy-bin-test-v1"
    elif mutation == "case_commitment":
        first["case_commitment_sha256"] = "f" * 64
    else:
        record["case_set_sha256"] = "f" * 64
    record["preregistration_sha256"] = _self_hash(record)
    path.write_bytes(_canonical(record))

    with pytest.raises(runner.PolicyRejection):
        load_v02_scored_preregistration(path)
