from __future__ import annotations

import copy
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import reproassert.benchmark_v02_exact_scored as scored
from reproassert.errors import PolicyRejection


def _record() -> dict[str, object]:
    value: dict[str, object] = {
        "algorithm": scored.ALGORITHM,
        "attempt_id": "attempt-001",
        "benchmark_version": "0.2",
        "campaign_id": "campaign-001",
        "candidate": None,
        "case": {
            "base_sha": "a" * 40,
            "difficulty": "lt_15m",
            "evaluator_commitment_sha256": "b" * 64,
            "generator_projection_sha256": "c" * 64,
            "id": "rk-v0.2-001",
            "issue_url": "https://github.com/project/repo/issues/1",
            "repo": "project/repo",
            "smoke": False,
            "source_context_sha256": "d" * 64,
        },
        "claim_level": "rejected",
        "claims": {
            "causal_controls_complete": False,
            "hidden_bytes_emitted": False,
            "network_enabled": False,
            "provider_calls_during_evaluation": 0,
            "semantic_review_complete": False,
        },
        "cost": {"complete": True, "total_attributable_microusd": 0},
        "evaluation": {
            "accepted": False,
            "classification": "no_candidate_generated",
            "kind": "no_candidate",
            "reason": "generation_produced_no_candidate",
            "receipt_sha256": None,
        },
        "exact_case_commitment_sha256": "1" * 64,
        "exact_preregistration_sha256": "2" * 64,
        "ledger_head_before_result_sha256": "3" * 64,
        "outcome": "no_output",
        "result_sha256": "0" * 64,
        "runner_input_sha256": "4" * 64,
        "schema_version": "1.0.0",
        "visibility": "public_safe_embargoed",
    }
    value["result_sha256"] = scored._result_self_hash(value)
    return value


def _write(path: Path, value: dict[str, object]) -> None:
    value["result_sha256"] = scored._result_self_hash(value)
    path.write_bytes(scored._canonical(value) + b"\n")


def test_public_executor_has_no_injection_and_live_authority_is_nominal() -> None:
    assert (
        "executor_factory"
        not in inspect.signature(scored.evaluate_v02_exact_frozen_case).parameters
    )
    with pytest.raises(TypeError, match="exact-executor-issued only"):
        scored.V02ExactScoredResult()
    with pytest.raises(PolicyRejection, match="execution authority"):
        scored.require_v02_exact_scored_execution(object())


def test_path_verifier_is_structural_and_has_no_trusted_verdict(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    _write(path, _record())
    checked = scored.verify_v02_exact_scored_result(path)
    assert checked.verification_scope == "structural_only_no_trusted_verdict"
    assert not hasattr(checked, "outcome")
    assert checked.record["outcome"] == "no_output"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.update(outcome="verified_reproduction"), "outcome and claim"),
        (lambda row: row.update(claim_level="differential_reproduction"), "outcome and claim"),
        (lambda row: row.update(ledger_head_before_result_sha256="z" * 64), "binding"),
        (lambda row: row.update(runner_input_sha256="short"), "binding"),
        (lambda row: row.update(case={}), "case binding"),
        (
            lambda row: row.update(cost={"complete": True, "total_attributable_microusd": None}),
            "cost completeness",
        ),
        (lambda row: row.update(candidate={"bytes": 1}), "No-candidate"),
    ],
)
def test_structural_verifier_rejects_rehashed_relation_attacks(
    tmp_path: Path, mutation: object, message: str
) -> None:
    value = copy.deepcopy(_record())
    assert callable(mutation)
    mutation(value)
    path = tmp_path / "mutated.json"
    _write(path, value)
    with pytest.raises(PolicyRejection, match=message):
        scored.verify_v02_exact_scored_result(path)


def test_structural_verifier_rejects_result_self_hash_tamper(tmp_path: Path) -> None:
    value = _record()
    value["result_sha256"] = "f" * 64
    path = tmp_path / "tampered.json"
    path.write_bytes(scored._canonical(value) + b"\n")
    with pytest.raises(PolicyRejection, match="identity"):
        scored.verify_v02_exact_scored_result(path)


def test_structural_verifier_binds_exact_candidate_receipt_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _record()
    value["candidate"] = {
        "bytes": 10,
        "path": "tests/reproassert/test_issue_1.py",
        "sha256": "a" * 64,
        "test_function": "test_issue_1_reproduction",
    }
    value["evaluation"] = {
        "accepted": True,
        "classification": "verified_reproduction",
        "kind": "exact_image_receipt",
        "reason": None,
        "receipt_sha256": "e" * 64,
    }
    value["outcome"] = "verified_reproduction"
    value["claim_level"] = "differential_reproduction"
    result_path = tmp_path / "result.json"
    _write(result_path, value)
    receipt_path = tmp_path / scored.RECEIPT_FILENAME
    receipt_path.write_bytes(scored._canonical({"candidate": {"sha256": "f" * 64}}))
    monkeypatch.setattr(
        scored,
        "verify_instance_candidate_receipt",
        lambda _path: SimpleNamespace(
            sha256="e" * 64,
            accepted=True,
            classification="verified_reproduction",
            case_id="rk-v0.2-001",
        ),
    )

    with pytest.raises(PolicyRejection, match="receipt bytes disagree"):
        scored.verify_v02_exact_scored_result(result_path)
