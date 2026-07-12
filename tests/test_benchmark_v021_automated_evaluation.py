from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reproassert.benchmark_v021_automated_evaluation as evaluation
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_candidate_evaluator import CandidateEvaluationReceipt
from reproassert.errors import PolicyRejection

TOOL_SHA = "a" * 40
PLAN_SHA = "b" * 64
AUTH_SHA = "c" * 64
PREREG_SHA = "d" * 64
LINEAGE_SHA = "e" * 64
REQUEST_SET_SHA = "f" * 64
EVIDENCE_SHA = "1" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _write(path: Path, value: object) -> str:
    raw = _canonical(value) + b"\n"
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, ...]:
    responses = tmp_path / "responses"
    results_root = tmp_path / "results"
    receipts = tmp_path / "receipts"
    for directory in (responses, results_root, receipts):
        directory.mkdir(mode=0o700)
    case_ids = tuple(f"rk-v0.2-{number:03d}" for number in range(1, 21))
    plan_rows = []
    results = []
    result_bindings = {}
    case_inputs = {}
    for number, case_id in enumerate(case_ids, start=1):
        request_sha = hashlib.sha256(f"request-{case_id}".encode()).hexdigest()
        input_sha = hashlib.sha256(f"input-{case_id}".encode()).hexdigest()
        plan_rows.append(
            {"case_id": case_id, "request_sha256": request_sha, "input_sha256": input_sha}
        )
        contract = v02_candidate_contract(case_id=case_id, issue_number=number)
        output = json.dumps(
            {
                "expected_symptom": "observed symptom",
                "rationale": "Exercise the reported behavior.",
                "test_content": (
                    "from fixture_project import slugify\n\n"
                    f"def {contract.test_function}():\n"
                    '    assert slugify("a  b") == "a-b", "observed symptom"\n'
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        response = {
            "algorithm": "reproassert-v021-durable-provider-response-v1",
            "authorization_sha256": AUTH_SHA,
            "case_id": case_id,
            "input_sha256": input_sha,
            "lineage_commitment_sha256": LINEAGE_SHA,
            "output": output,
            "preregistration_sha256": PREREG_SHA,
            "request_sha256": request_sha,
        }
        response_sha = _write(responses / f"{case_id}.json", response)
        result_record = {
            "case_id": case_id,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        }
        result_path = results_root / f"{case_id}.json"
        result_sha = _write(result_path, result_record)
        result_bindings[case_id] = result_sha
        results.append(
            SimpleNamespace(
                case_id=case_id,
                outcome="provider_response_durable_unparsed",
                path=result_path,
                response_sha256=response_sha,
                sha256=result_sha,
            )
        )
        case_inputs[case_id] = evaluation.V021EvaluationCaseInputs(
            issue_number=number,
            evaluator_capability=None,  # type: ignore[arg-type]
            verified_hidden=None,  # type: ignore[arg-type]
            gold_smoke_receipt_path=tmp_path / "private-gold.json",
            gold_specs_path=tmp_path / "private-specs.json",
            manifest_path=tmp_path / "manifest.json",
            expected_manifest_sha256="2" * 64,
            amendment_authority=None,  # type: ignore[arg-type]
        )
    plan = SimpleNamespace(
        authorization_sha256=AUTH_SHA,
        preregistration_sha256=PREREG_SHA,
        lineage_commitment_sha256=LINEAGE_SHA,
        request_set_sha256=REQUEST_SET_SHA,
        preregistration_request_set_sha256=REQUEST_SET_SHA,
        cases=tuple(plan_rows),
    )
    barrier = SimpleNamespace(
        authorization_sha256=AUTH_SHA,
        request_set_sha256=REQUEST_SET_SHA,
        result_sha256_by_case=result_bindings,
        sha256="3" * 64,
    )
    evidence = SimpleNamespace(request_set_sha256=REQUEST_SET_SHA, sha256=EVIDENCE_SHA)
    monkeypatch.setattr(evaluation, "require_v021_runtime_plan", lambda value: value)
    monkeypatch.setattr(evaluation, "require_v021_generation_barrier", lambda value: value)
    monkeypatch.setattr(evaluation, "require_v021_generation_result", lambda value: value)
    monkeypatch.setattr(evaluation, "require_v021_automated_evidence", lambda value: value)
    return plan, barrier, evidence, tuple(results), case_inputs, responses, receipts


def _fake_evaluator(**kwargs: object) -> CandidateEvaluationReceipt:
    case_id = str(kwargs["case_id"])
    output_path = Path(cast(str | Path, kwargs["output_path"]))
    raw = _canonical({"case_id": case_id, "private_paths_emitted": False}) + b"\n"
    output_path.write_bytes(raw)
    accepted = int(case_id[-3:]) % 2 == 1
    return CandidateEvaluationReceipt(
        path=output_path,
        sha256=hashlib.sha256(raw).hexdigest(),
        case_id=case_id,
        classification="causal_reproduction" if accepted else "wrong_exit_pattern",
        accepted=accepted,
        evaluator_wall_ms=1,
    )


def _fake_verifier(path: Path) -> CandidateEvaluationReceipt:
    raw = path.read_bytes()
    case_id = json.loads(raw)["case_id"]
    accepted = int(case_id[-3:]) % 2 == 1
    return CandidateEvaluationReceipt(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        case_id=case_id,
        classification="causal_reproduction" if accepted else "wrong_exit_pattern",
        accepted=accepted,
        evaluator_wall_ms=1,
    )


def test_all_20_bridge_reports_full_denominator_without_human_or_l2_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, barrier, evidence, results, inputs, responses, receipts = _fixture(tmp_path, monkeypatch)
    aggregate_path = tmp_path / "aggregate.json"
    authority = evaluation._evaluate_v021_automated_campaign_with_ports(
        plan=plan,
        barrier=barrier,
        generation_results=results,
        automated_evidence_authority=evidence,
        response_directory=responses,
        case_inputs=inputs,
        receipt_directory=receipts,
        aggregate_path=aggregate_path,
        executed_at="2026-07-12T12:00:00Z",
        tool_git_sha=TOOL_SHA,
        evaluator=_fake_evaluator,
        receipt_verifier=_fake_verifier,
    )

    assert authority.accepted_count == 10
    assert authority.rejected_count == 10
    assert type(authority) is evaluation.StructuralV021AutomatedEvaluationSet
    with pytest.raises(PolicyRejection, match="verifier-issued"):
        evaluation.require_v021_automated_evaluation_set(authority)
    record = json.loads(aggregate_path.read_bytes())
    assert record["counts"] == {
        "accepted": 10,
        "oracle_executed": 20,
        "rejected": 10,
        "total": 20,
    }
    assert record["claims"] == {
        "automated_evidence_validated": True,
        "full_denominator_reported": True,
        "human_reviewed": False,
        "l2_causal_claim": False,
        "maintainer_validated": False,
    }
    case_record = json.loads((receipts / "rk-v0.2-001.json").read_bytes())
    serialized = json.dumps(case_record)
    assert "private-gold" not in serialized
    assert "private-specs" not in serialized
    assert case_record["outcome"]["claim_level"] == "l1_deterministic"
    assert case_record["outcome"]["remaining_required_controls"]


def test_bridge_rejects_response_tamper_before_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, barrier, evidence, results, inputs, responses, receipts = _fixture(tmp_path, monkeypatch)
    first = responses / "rk-v0.2-001.json"
    first.write_bytes(first.read_bytes() + b" ")
    called = False

    def evaluator(**_kwargs: object) -> CandidateEvaluationReceipt:
        nonlocal called
        called = True
        raise AssertionError

    with pytest.raises(PolicyRejection, match="differs from the generation result commitment"):
        evaluation._evaluate_v021_automated_campaign_with_ports(
            plan=plan,
            barrier=barrier,
            generation_results=results,
            automated_evidence_authority=evidence,
            response_directory=responses,
            case_inputs=inputs,
            receipt_directory=receipts,
            aggregate_path=tmp_path / "aggregate.json",
            executed_at="2026-07-12T12:00:00Z",
            tool_git_sha=TOOL_SHA,
            evaluator=evaluator,
            receipt_verifier=_fake_verifier,
        )
    assert called is False


def test_aggregate_verifier_rejects_case_receipt_toctou(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, barrier, evidence, results, inputs, responses, receipts = _fixture(tmp_path, monkeypatch)
    aggregate_path = tmp_path / "aggregate.json"
    evaluation._evaluate_v021_automated_campaign_with_ports(
        plan=plan,
        barrier=barrier,
        generation_results=results,
        automated_evidence_authority=evidence,
        response_directory=responses,
        case_inputs=inputs,
        receipt_directory=receipts,
        aggregate_path=aggregate_path,
        executed_at="2026-07-12T12:00:00Z",
        tool_git_sha=TOOL_SHA,
        evaluator=_fake_evaluator,
        receipt_verifier=_fake_verifier,
    )
    case_path = receipts / "rk-v0.2-020.json"
    case_path.write_bytes(case_path.read_bytes() + b" ")
    with pytest.raises(PolicyRejection, match="changed after aggregation"):
        evaluation._verify_v021_automated_evaluation_set(
            aggregate_path,
            receipt_directory=receipts,
            issuance=None,
            receipt_verifier=_fake_verifier,
        )


def test_invalid_candidate_is_counted_and_does_not_abort_full_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, barrier, evidence, results, inputs, responses, receipts = _fixture(tmp_path, monkeypatch)
    original = evaluation.parse_v021_candidate_output
    parse_calls = 0

    def parse(output: str, **kwargs: object):
        nonlocal parse_calls
        parse_calls += 1
        if parse_calls == 1:
            raise PolicyRejection("candidate", "invalid candidate")
        return original(output, **kwargs)  # type: ignore[arg-type]

    evaluator_calls = 0

    def evaluator(**kwargs: object) -> CandidateEvaluationReceipt:
        nonlocal evaluator_calls
        evaluator_calls += 1
        return _fake_evaluator(**kwargs)

    monkeypatch.setattr(evaluation, "parse_v021_candidate_output", parse)
    authority = evaluation._evaluate_v021_automated_campaign_with_ports(
        plan=plan,
        barrier=barrier,
        generation_results=results,
        automated_evidence_authority=evidence,
        response_directory=responses,
        case_inputs=inputs,
        receipt_directory=receipts,
        aggregate_path=tmp_path / "aggregate.json",
        executed_at="2026-07-12T12:00:00Z",
        tool_git_sha=TOOL_SHA,
        evaluator=evaluator,
        receipt_verifier=_fake_verifier,
    )

    first = json.loads((receipts / "rk-v0.2-001.json").read_bytes())
    assert authority.rejected_count >= 1
    assert evaluator_calls == 19
    assert first["outcome"]["classification"] == "candidate_contract_rejected"
    assert first["evaluator_receipt_sha256"] is None


def test_public_evaluation_api_has_no_callback_injection() -> None:
    parameters = inspect.signature(evaluation.evaluate_v021_automated_campaign).parameters
    assert "evaluator" not in parameters
    assert "receipt_verifier" not in parameters
