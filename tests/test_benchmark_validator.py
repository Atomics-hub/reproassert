from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = json.loads((ROOT / "schemas" / "benchmark-run.schema.json").read_text())
NODEID = "tests/reproassert/test_issue_24127.py::test_issue_24127_reproduction"
COMMAND = ["python", "-m", "pytest", NODEID]
FINGERPRINT = "f" * 64


def _load_validator() -> ModuleType:
    path = ROOT / "scripts" / "validate_benchmark.py"
    spec = importlib.util.spec_from_file_location("reproassert_benchmark_validator", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def _failure() -> dict[str, Any]:
    return {
        "phase": "call",
        "exception_type": "AssertionError",
        "normalized_message": "all-NaN bars should not raise",
        "top_project_frame": "lib/matplotlib/axes/_axes.py:2310",
        "nodeid": NODEID,
        "fingerprint_sha256": FINGERPRINT,
    }


def _execution(ordinal: int, tree: str) -> dict[str, Any]:
    is_base = tree == "base"
    return {
        "ordinal": ordinal,
        "tree": tree,
        "command": list(COMMAND),
        "status": "assertion_failure" if is_base else "pass",
        "exit_code": 1 if is_base else 0,
        "duration_seconds": 0.25,
        "timed_out": False,
        "oom_killed": False,
        "output_truncated": False,
        "output_sha256": f"{ordinal:064x}",
        "failure": _failure() if is_base else None,
    }


def _reviewer(reviewer_id: str) -> dict[str, Any]:
    return {
        "reviewer_id": reviewer_id,
        "role": "primary",
        "blinded": True,
        "packet_sha256": "a" * 64,
        "trigger_faithful": True,
        "oracle_supported": True,
        "failure_causal": True,
        "implementation_independent": True,
        "minimal_and_readable": True,
        "verdict": "valid",
        "confidence": 0.9,
        "rationale": "The trigger and public-behavior oracle faithfully encode the frozen issue.",
    }


@pytest.fixture
def semantic_valid_row() -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "benchmark_version": "0.1.0",
        "run_id": "canonical-smoke-run",
        "case_id": "rk-v0.1-004",
        "started_at": "2026-07-10T00:00:00Z",
        "completed_at": "2026-07-10T00:01:00Z",
        "tool": {
            "name": "reproassert",
            "version": "0.1.0",
            "git_sha": "1" * 40,
        },
        "generator": {
            "provider": "offline-fixture",
            "model": "deterministic",
            "model_version": "1",
            "prompt_template_sha256": "2" * 64,
            "rendered_input_sha256": "9" * 64,
            "config_sha256": "3" * 64,
            "temperature": 0,
            "submitted_candidates": 1,
            "internal_attempts": 1,
        },
        "environment": {
            "image_digest": "sha256:" + "4" * 64,
            "os": "linux",
            "architecture": "x86_64",
            "python": "3.12.10",
            "locale": "C.UTF-8",
            "timezone": "UTC",
            "network_after_dependency_prep": "disabled",
            "cpu_limit": 1,
            "memory_bytes": 1_073_741_824,
            "pids_limit": 128,
            "timeout_seconds": 60,
            "output_bytes_limit": 65_536,
        },
        "issue_snapshot": {
            "sha256": "5" * 64,
            "captured_at": "2026-07-09T23:00:00Z",
            "cutoff_at": "2022-10-01T00:00:00Z",
            "fields": ["title", "body"],
            "comments_included": False,
            "fix_backlinks_stripped": True,
        },
        "candidate": {
            "patch_sha256": "6" * 64,
            "artifact_path": "artifacts/rk-v0.1-004/candidate.patch",
            "changed_files": ["tests/reproassert/test_issue_24127.py"],
            "nodeids": [NODEID],
            "added_lines": 12,
            "deleted_lines": 0,
            "selected_rank": 1,
        },
        "timing": {
            "cold_cache": False,
            "dependency_prep_seconds": 1.0,
            "generation_seconds": 2.0,
            "verification_seconds": 3.0,
            "total_seconds": 6.0,
        },
        "cost": {
            "currency": "USD",
            "input_tokens": 100,
            "output_tokens": 50,
            "model_usd": 0.4,
            "sandbox_compute_usd": 0.5,
            "artifact_transfer_usd": 0.1,
            "paid_storage_usd": 0.0,
            "attributable_total_usd": 1.0,
            "cold_dependency_prep_usd": 0.2,
        },
        "policy": {
            "passed": True,
            "violations": [],
            "production_files_changed": False,
            "dependency_files_changed": False,
            "unconditional_failure_detected": False,
            "network_use_detected": False,
        },
        "executions": {
            "base": [
                _execution(1, "base"),
                _execution(4, "base"),
                _execution(5, "base"),
            ],
            "fixed": [
                _execution(2, "fixed"),
                _execution(3, "fixed"),
                _execution(6, "fixed"),
            ],
            "causal_controls": [
                {
                    "kind": "issue_hunks_only",
                    "status": "pass",
                    "artifact_sha256": "7" * 64,
                    "result": "candidate passes with only issue-relevant production hunks",
                    "notes": "Control prepared before gold-test unblinding.",
                },
                {
                    "kind": "fix_minus_issue_hunks",
                    "status": "fail",
                    "artifact_sha256": "8" * 64,
                    "result": "candidate retains the base failure fingerprint",
                    "notes": "Control prepared before gold-test unblinding.",
                },
            ],
        },
        "plausible_f2p": True,
        "semantic_review": {
            "status": "valid",
            "reviewers": [_reviewer("reviewer-a"), _reviewer("reviewer-b")],
            "tie_break_required": False,
            "agreement": 1.0,
            "gold_unblinded_after_decision": True,
        },
        "claim_level": "L2",
        "outcome": "semantic_valid",
        "limitations": ["Historical public benchmark; contamination exposure cannot be excluded."],
    }


def _invariant_errors(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    VALIDATOR.validate_result_invariants(row, "row", errors)
    return errors


def _schema_errors(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    VALIDATOR.validate_json_schema_instance(row, RUN_SCHEMA, RUN_SCHEMA, "row", errors)
    return errors


def test_fully_valid_semantic_row_passes_schema_and_invariants(
    semantic_valid_row: dict[str, Any],
) -> None:
    assert _schema_errors(semantic_valid_row) == []
    assert _invariant_errors(semantic_valid_row) == []


MUTATION_CASES = (
    ("null_candidate", "requires a candidate"),
    ("zero_executions", "requires exactly three base executions"),
    ("five_executions", "requires exactly three fixed executions"),
    ("wrong_schedule", "execution schedule must be"),
    ("base_pass", "base result must be an issue-aligned call failure"),
    ("base_non_call", "only call-phase failures"),
    ("base_fingerprint_mismatch", "must share one normalized fingerprint"),
    ("fixed_non_pass", "must pass"),
    ("no_controls", "requires at least one conclusive causal control"),
    ("inconclusive_controls", "requires at least one conclusive causal control"),
    ("zero_reviewers", "requires 2 independent reviewers"),
    ("duplicate_reviewers", "reviewer IDs must be distinct"),
    ("inconsistent_rubric", "valid verdict requires five yes answers"),
    ("gold_ordering_false", "requires gold unblinding only after decision"),
    ("semantic_valid_claim_l1", "requires claim_level 'L2'"),
    ("semantic_invalid_claim_l2", "requires claim_level 'L1'"),
    ("plausible_false", "requires plausible_f2p=true"),
    ("internal_l3", "internal benchmark rows cannot claim L3"),
    ("cost_arithmetic", "attributable cost must equal"),
    ("time_arithmetic", "total_seconds is smaller"),
    ("completion_before_start", "completed_at precedes started_at"),
)


def _mutate(row: dict[str, Any], mutation: str) -> None:
    if mutation == "null_candidate":
        row["candidate"] = None
    elif mutation == "zero_executions":
        row["executions"]["base"] = []
        row["executions"]["fixed"] = []
    elif mutation == "five_executions":
        row["executions"]["fixed"].pop()
    elif mutation == "wrong_schedule":
        row["executions"]["base"][1]["ordinal"] = 2
        row["executions"]["fixed"][0]["ordinal"] = 4
    elif mutation == "base_pass":
        row["executions"]["base"][0].update(status="pass", exit_code=0, failure=None)
    elif mutation == "base_non_call":
        row["executions"]["base"][0]["failure"]["phase"] = "setup"
    elif mutation == "base_fingerprint_mismatch":
        row["executions"]["base"][0]["failure"]["fingerprint_sha256"] = "9" * 64
    elif mutation == "fixed_non_pass":
        row["executions"]["fixed"][0].update(
            status="assertion_failure",
            exit_code=1,
            failure=_failure(),
        )
    elif mutation == "no_controls":
        row["executions"]["causal_controls"] = []
    elif mutation == "inconclusive_controls":
        for control in row["executions"]["causal_controls"]:
            control.update(status="inconclusive", artifact_sha256=None)
    elif mutation == "zero_reviewers":
        row["semantic_review"]["reviewers"] = []
    elif mutation == "duplicate_reviewers":
        row["semantic_review"]["reviewers"][1]["reviewer_id"] = "reviewer-a"
    elif mutation == "inconsistent_rubric":
        row["semantic_review"]["reviewers"][0]["trigger_faithful"] = False
    elif mutation == "gold_ordering_false":
        row["semantic_review"]["gold_unblinded_after_decision"] = False
    elif mutation == "semantic_valid_claim_l1":
        row["claim_level"] = "L1"
    elif mutation == "semantic_invalid_claim_l2":
        row["outcome"] = "plausible_f2p_semantic_invalid"
        row["semantic_review"]["status"] = "invalid"
    elif mutation == "plausible_false":
        row["plausible_f2p"] = False
    elif mutation == "internal_l3":
        row["claim_level"] = "L3"
    elif mutation == "cost_arithmetic":
        row["cost"]["attributable_total_usd"] = 0.5
    elif mutation == "time_arithmetic":
        row["timing"]["total_seconds"] = 5.0
    elif mutation == "completion_before_start":
        row["completed_at"] = "2026-07-09T23:59:59Z"
    else:  # pragma: no cover - keeps the mutation table exhaustive
        raise AssertionError(f"unknown mutation: {mutation}")


@pytest.mark.parametrize(("mutation", "expected"), MUTATION_CASES)
def test_semantic_valid_invariant_mutations_are_rejected(
    semantic_valid_row: dict[str, Any],
    mutation: str,
    expected: str,
) -> None:
    row = copy.deepcopy(semantic_valid_row)
    _mutate(row, mutation)

    errors = _invariant_errors(row)

    assert any(expected in error for error in errors), errors


def _validate_rows(tmp_path: Path, rows: list[dict[str, Any]]) -> tuple[int, list[str]]:
    results_path = tmp_path / "results.jsonl"
    results_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    errors: list[str] = []
    count = VALIDATOR.validate_results(
        results_path,
        {"rk-v0.1-004", "rk-v0.1-005"},
        RUN_SCHEMA,
        errors,
    )
    return count, errors


def test_validate_results_rejects_same_case_under_different_run_ids(
    tmp_path: Path,
    semantic_valid_row: dict[str, Any],
) -> None:
    second = copy.deepcopy(semantic_valid_row)
    second["run_id"] = "different-run"

    count, errors = _validate_rows(tmp_path, [semantic_valid_row, second])

    assert count == 2
    assert any("case_id already has a result" in error for error in errors), errors


def test_validate_results_rejects_different_run_ids_across_cases(
    tmp_path: Path,
    semantic_valid_row: dict[str, Any],
) -> None:
    second = copy.deepcopy(semantic_valid_row)
    second["run_id"] = "different-run"
    second["case_id"] = "rk-v0.1-005"

    count, errors = _validate_rows(tmp_path, [semantic_valid_row, second])

    assert count == 2
    assert any("every v0.1 result must use canonical run_id" in error for error in errors), errors


def test_validate_results_accepts_different_cases_in_the_canonical_run(
    tmp_path: Path,
    semantic_valid_row: dict[str, Any],
) -> None:
    second = copy.deepcopy(semantic_valid_row)
    second["case_id"] = "rk-v0.1-005"

    count, errors = _validate_rows(tmp_path, [semantic_valid_row, second])

    assert count == 2
    assert errors == []
