from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from reproassert import benchmark_v02_campaign as campaign
from reproassert import benchmark_v02_exact_preregistration as exact_preregistration
from reproassert import cli
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_package import (
    PreregisteredV02Case,
    build_v02_preregistration,
)
from reproassert.benchmark_v02_runner import V02LedgerSnapshot
from reproassert.benchmark_v02_scored_preregistration import load_v02_scored_preregistration
from reproassert.errors import PolicyRejection

ROOT = Path(__file__).parents[1]
AT = "2026-07-10T00:00:00Z"
DISPOSITION_AT = "2026-07-10T00:01:00Z"
BARRIER_AT = "2026-07-10T00:02:00Z"
COMPLETED_AT = "2026-07-10T00:05:00Z"
CONTROL_EXECUTED_AT = "2026-07-10T00:06:00Z"
CONTROL_SEALED_AT = "2026-07-10T00:07:00Z"
REVIEWED_AT = "2026-07-10T00:08:00Z"
SEALED_AT = "2026-07-10T00:09:00Z"
FINALIZED_AT = "2026-07-10T00:10:00Z"


@dataclass
class _Artifacts:
    preregistration: Path
    freeze_path: Path
    freeze: campaign.VerifiedV02CampaignFreeze
    attempts_root: Path
    control_path: Path
    review_path: Path
    ledger_path: Path
    output_root: Path
    events: list[dict[str, Any]]
    private_records: dict[str, dict[str, Any]]
    public_records: dict[str, dict[str, Any]]

    def snapshot(self) -> V02LedgerSnapshot:
        return V02LedgerSnapshot(
            events=tuple(self.events),
            encoded=b"",
            sha256="d" * 64,
            head_event_sha256=self.events[-1]["event_sha256"],
        )


def _cases() -> list[PreregisteredV02Case]:
    return [
        PreregisteredV02Case(
            id=f"rk-v0.2-{index:03d}",
            repo=f"owner/repo{(index + 1) // 2}",
            issue_url=(f"https://github.com/owner/repo{(index + 1) // 2}/issues/{index}"),
            base_sha=f"{index:040x}",
            difficulty="lt_15m" if index <= 14 else "15m_to_1h",
            smoke=index in {4, 6, 10, 11, 18},
            generator_projection_sha256=f"{index + 100:064x}",
            evaluator_commitment_sha256=f"{index + 200:064x}",
            source_context_sha256=f"{index + 300:064x}",
        )
        for index in range(1, 21)
    ]


def _exact_preregistration(cases: list[PreregisteredV02Case]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        contract = v02_candidate_contract(case_id=case.id, issue_number=index)
        row: dict[str, Any] = {
            "base_sha": case.base_sha,
            "candidate_profile": contract.profile,
            "case_id": case.id,
            "difficulty": case.difficulty,
            "evaluator_commitment_sha256": case.evaluator_commitment_sha256,
            "evaluator_status": (
                "runtime_attested_gold_smoke_infrastructure_failure"
                if index == 14
                else "runtime_attested_evaluator_preflight_ready"
            ),
            "generator_projection_sha256": case.generator_projection_sha256,
            "instance_id": f"instance-{index:03d}",
            "issue_url": case.issue_url,
            "mapping_selected_hunks_sha256": f"{index + 2100:064x}",
            "outbound_request_sha256": f"{index + 2200:064x}",
            "rendered_input_sha256": f"{index + 2300:064x}",
            "repo": case.repo,
            "request_envelope_sha256": f"{index + 2400:064x}",
            "smoke": case.smoke,
            "source_projection_commitment_sha256": case.source_context_sha256,
            "test_command_profile": (
                "sympy-bin-test-v1" if contract.profile == "sympy-native-v1" else "pytest-v1"
            ),
        }
        row["case_commitment_sha256"] = campaign._json_sha256(row)
        rows.append(row)
    record: dict[str, Any] = {
        "algorithm": "reproassert-v02-exact-image-preregistration-v1",
        "benchmark_version": "0.2",
        "case_count": 20,
        "case_set_sha256": campaign._json_sha256(
            {
                "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
                "case_commitments": [row["case_commitment_sha256"] for row in rows],
            }
        ),
        "cases": rows,
        "claims": {},
        "cohort_sha256": "a" * 64,
        "evidence": {},
        "frozen_at": AT,
        "policy": {},
        "request_set_sha256": "b" * 64,
        "schema_version": "1.0.0",
        "status": "frozen_preinference_exact_image",
        "tool_git_sha": "1" * 40,
    }
    record["preregistration_sha256"] = campaign._json_sha256(record)
    return record


def _write(path: Path, value: object, *, canonical: bool = True) -> None:
    content = (
        campaign.canonical_v02_campaign_bytes(value)
        if canonical
        else json.dumps(value, indent=2).encode()
    )
    path.write_bytes(content)
    path.chmod(0o600)


def _event(
    events: list[dict[str, Any]],
    *,
    case_id: str,
    attempt_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    sequence = len(events) + 1
    event = {
        "schema_version": "1.0.0",
        "benchmark_version": "0.2.0-draft",
        "algorithm": "reproassert-v02-scored-event-chain-v1",
        "sequence": sequence,
        "recorded_at": AT,
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
        "campaign_id": "campaign_v02_final",
        "attempt_id": attempt_id,
        "case_id": case_id,
        "event_type": event_type,
        "payload": payload,
        "event_sha256": f"{sequence:064x}",
    }
    events.append(event)
    return event


def _configuration(campaign_freeze_sha256: str) -> dict[str, Any]:
    authorization_ref = "test-only-explicit-approval"
    authorization_ref_sha256 = hashlib.sha256(authorization_ref.encode()).hexdigest()
    pricing_snapshot = {
        "algorithm": "reproassert-v02-component-pricing-v1",
        "provider": "openai",
        "requested_model": "gpt-test",
        "effective_at": AT,
        "source": "test fixture pricing",
        "input_microusd_per_million_tokens": 1,
        "cached_input_microusd_per_million_tokens": 1,
        "output_microusd_per_million_tokens": 1,
        "sandbox_microusd_per_second": 1,
        "artifact_microusd_per_million_bytes": 1,
        "paid_storage_microusd": 1,
        "dependency_prep_microusd": 1,
    }
    pricing_snapshot_sha256 = campaign._json_sha256(pricing_snapshot)
    execution_authorization = {
        "sha256": "5" * 64,
        "kind": "explicit_user_approval",
        "authorized_at": AT,
        "authorization_ref_sha256": authorization_ref_sha256,
        "authorization_text_sha256": "6" * 64,
        "request_set_sha256": "7" * 64,
    }
    adapter_config_sha256 = "2" * 64
    return {
        "algorithm": "reproassert-v02-scored-runner-v1",
        "campaign_freeze_sha256": campaign_freeze_sha256,
        "execution_authorization": execution_authorization,
        "tool_git_sha": "1" * 40,
        "authorization": {
            "status": "explicit_user_approval",
            "authorization_ref": authorization_ref,
        },
        "generator": {
            "mode": "trusted_builtin_provider_adapter",
            "provider": "openai",
            "requested_model": "gpt-test",
            "adapter_config_sha256": adapter_config_sha256,
            "feedback_policy": "none_one_shot",
            "submitted_candidate_budget": 1,
        },
        "pricing_snapshot": pricing_snapshot,
        "pricing_snapshot_sha256": pricing_snapshot_sha256,
        "run_provenance": {
            "execution_authorization_sha256": execution_authorization["sha256"],
            "authorized_at": execution_authorization["authorized_at"],
            "authorization_ref_sha256": execution_authorization["authorization_ref_sha256"],
            "authorization_text_sha256": execution_authorization["authorization_text_sha256"],
            "request_set_sha256": execution_authorization["request_set_sha256"],
            "provider": "openai",
            "requested_model": "gpt-test",
            "adapter_config_sha256": adapter_config_sha256,
            "pricing_snapshot_sha256": pricing_snapshot_sha256,
            "pricing_effective_at": pricing_snapshot["effective_at"],
            "pricing_source": pricing_snapshot["source"],
        },
        "reserved_worst_case_microusd": 100,
        "max_case_attributable_microusd": 100,
        "max_campaign_attributable_microusd": 2_000,
        "max_case_wall_ms": 600_000,
        "provider_timeout_ms": 120_000,
    }


def _candidate(index: int) -> dict[str, Any]:
    contract = v02_candidate_contract(case_id=f"rk-v0.2-{index:03d}", issue_number=index)
    content = (
        "from sympy import Symbol\n\n"
        f"def {contract.test_function}():\n"
        "    assert Symbol('x').is_commutative is False, 'wrong normalized output'\n"
        if contract.profile == "sympy-native-v1"
        else "from demo import normalize\n\n"
        f"def {contract.test_function}():\n"
        "    assert normalize('bug') == 'fixed', 'wrong normalized output'\n"
    )
    return {
        "path": contract.relative_path,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "bytes": len(content.encode()),
        "test_content": content,
        "expected_symptom": "wrong normalized output",
        "rationale": "Exercises the reported behavior directly.",
    }


def _scheduled_runs(index: int) -> list[dict[str, Any]]:
    contract = v02_candidate_contract(case_id=f"rk-v0.2-{index:03d}", issue_number=index)
    schedule = ("base", "fixed", "fixed", "base", "base", "fixed")
    role_counts = {"base": 0, "fixed": 0}
    records: list[dict[str, Any]] = []
    for schedule_ordinal, source_role in enumerate(schedule, start=1):
        role_counts[source_role] += 1
        role_ordinal = role_counts[source_role]
        records.append(
            {
                "source_role": source_role,
                "role_ordinal": role_ordinal,
                "schedule_ordinal": schedule_ordinal,
                "phase": f"{source_role}_{role_ordinal}",
                "argv": contract.test_command.split(),
                "exit_code": 1 if source_role == "base" else 0,
                "duration_seconds": 0.1,
                "timed_out": False,
                "oom_killed": False,
                "output_truncated": False,
                "bounded_output": "bounded base failure" if source_role == "base" else None,
                "output_sha256": f"{index + schedule_ordinal + 1200:064x}",
                "junit_sha256": f"{index + schedule_ordinal + 1300:064x}",
                "evaluator_output_redacted": source_role == "fixed",
            }
        )
    return records


def _control_run(
    index: int,
    control_type: str,
    *,
    expected_outcome: str,
    observed_outcome: str,
    control_id: str | None = None,
) -> campaign.V02CausalControlRun:
    contract = v02_candidate_contract(case_id=f"rk-v0.2-{index:03d}", issue_number=index)
    return campaign.V02CausalControlRun(
        control_id=control_id or control_type,
        control_type=control_type,
        expected_outcome=expected_outcome,
        observed_outcome=observed_outcome,
        executed_at=CONTROL_EXECUTED_AT,
        test_command=contract.test_command,
        exit_code=0 if observed_outcome == "pass" else 1,
        duration_ms=100,
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        output_sha256=f"{index + len(control_type) + 1400:064x}",
        junit_sha256=f"{index + len(control_type) + 1500:064x}",
        sandbox_receipt_sha256=f"{index + len(control_type) + 1600:064x}",
        environment_sha256=f"{index + len(control_type) + 1700:064x}",
        reason=None,
    )


def _semantic_review(
    *,
    index: int,
    review_round: int,
    candidate_sha256: str,
    control_receipt_sha256: str,
    role_seal_sha256: str,
    fixed_pass_evidence_sha256: str,
    reviewer_id: str,
    valid: bool,
) -> campaign.V02SemanticReview:
    checklist_sha256 = campaign.v02_semantic_checklist_sha256(
        case_id=f"rk-v0.2-{index:03d}",
        candidate_sha256=candidate_sha256,
        causal_control_receipt_sha256=control_receipt_sha256,
        fixed_pass_evidence_sha256=fixed_pass_evidence_sha256,
    )
    return campaign.V02SemanticReview(
        case_id=f"rk-v0.2-{index:03d}",
        review_round=review_round,
        candidate_sha256=candidate_sha256,
        causal_control_receipt_sha256=control_receipt_sha256,
        reviewer_id=reviewer_id,
        reviewer_role_seal_sha256=role_seal_sha256,
        fixed_pass_evidence_sha256=fixed_pass_evidence_sha256,
        checklist_sha256=checklist_sha256,
        reviewed_at=REVIEWED_AT,
        trigger_faithful=valid,
        oracle_supported=True,
        failure_causal=True,
        implementation_independent=True,
        minimal_readable=True,
        confidence="high",
        rationale=(
            "The frozen issue, candidate, differential evidence, and declared controls "
            "support this bounded verdict."
        ),
        verdict="semantically_valid" if valid else "semantically_invalid",
    )


def _prepare(
    tmp_path: Path, *, no_candidate: set[int] | None = None, exact: bool = False
) -> _Artifacts:
    tmp_path.mkdir(parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    no_candidate = no_candidate or {20}
    cases = _cases()
    preregistration = tmp_path / "preregistration.json"
    _write(
        preregistration,
        _exact_preregistration(cases)
        if exact
        else build_v02_preregistration(
            cases,
            frozen_at=AT,
            tool_name="reproassert",
            tool_version="0.2-test",
            tool_git_sha="1" * 40,
        ),
    )
    freeze_path = tmp_path / "campaign-freeze.json"
    campaign.prepare_v02_campaign_freeze(
        preregistration,
        freeze_path,
        campaign_id="campaign_v02_final",
        prepared_at=AT,
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
    )
    freeze = campaign.verify_v02_campaign_freeze(freeze_path, preregistration)
    attempts_root = tmp_path / "attempts"
    attempts_root.mkdir(mode=0o700)
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    ledger_path = tmp_path / "events.jsonl"
    ledger_path.write_bytes(b"stub")
    ledger_path.chmod(0o600)
    events: list[dict[str, Any]] = []
    starts: dict[str, dict[str, Any]] = {}
    dispositions: dict[str, dict[str, Any]] = {}
    candidates: dict[str, dict[str, Any] | None] = {}
    configuration = _configuration(freeze.raw_sha256)

    for index, case in enumerate(cases, start=1):
        attempt_id = f"attempt_{index:03d}_{index:032x}"
        starts[case.id] = _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="attempt_started",
            payload={
                "started_at": AT,
                "preregistration_sha256": freeze.preregistration_sha256,
                "cohort_sha256": freeze.cohort_sha256,
                "case": asdict(case),
                "configuration": configuration,
                "source_context": {
                    "algorithm": "reproassert-source-context-v1",
                    "policy_sha256": "4" * 64,
                    "sha256": case.source_context_sha256,
                },
                "runner_input_sha256": f"{index + 500:064x}",
                "reserved_worst_case_microusd": 100,
            },
        )
        _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="phase_started",
            payload={"phase": "generation", "started_at": AT},
        )
        for category_index, category in enumerate(campaign._COST_CATEGORIES, start=1):
            attribution = "cold_prep_excluded" if category == "dependency_prep" else "scored"
            _event(
                events,
                case_id=case.id,
                attempt_id=attempt_id,
                event_type="cost_recorded",
                payload={
                    "entry_id": f"cost_{index:02x}{category_index:02x}{0:028x}",
                    "category": category,
                    "attribution": attribution,
                    "status": "measured",
                    "amount_microusd": 1,
                    "source_call_id": None,
                    "observed_at": AT,
                    "evidence_sha256": f"{index + category_index + 600:064x}",
                },
            )
        candidate = None if index in no_candidate else _candidate(index)
        candidates[case.id] = candidate
        if candidate is not None:
            _event(
                events,
                case_id=case.id,
                attempt_id=attempt_id,
                event_type="candidate_submitted",
                payload={
                    "candidate_index": 1,
                    "candidate_sha256": candidate["sha256"],
                    "candidate_bytes": candidate["bytes"],
                    "artifact_path": "generation-transaction.json",
                    "generation_artifact_sha256": f"{index + 700:064x}",
                    "generation_artifact_bytes": candidate["bytes"] + 100,
                    "test_function": v02_candidate_contract(
                        case_id=case.id, issue_number=index
                    ).test_function
                    if exact
                    else f"test_issue_{index}_reproduction",
                    "generation_call_id": f"call_{index:032x}",
                    "oracle_consulted": False,
                    "submitted_at": DISPOSITION_AT,
                },
            )
        _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="phase_finished",
            payload={
                "phase": "generation",
                "status": "failed" if candidate is None else "succeeded",
                "started_at": AT,
                "completed_at": DISPOSITION_AT,
                "duration_ms": 1_000,
                "classification_code": "no_output" if candidate is None else None,
                "evidence": {},
            },
        )
        dispositions[case.id] = _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="generation_disposition_frozen",
            payload={
                "status": "no_candidate" if candidate is None else "candidate_submitted",
                "candidate_sha256": None if candidate is None else candidate["sha256"],
                "classification_code": "no_output" if candidate is None else None,
                "frozen_at": DISPOSITION_AT,
            },
        )

    disposition_states = {
        case.id: {"start": starts[case.id], "disposition": dispositions[case.id]} for case in cases
    }
    disposition_set, barrier_sha256 = campaign._generation_barrier_hashes(
        freeze, disposition_states
    )
    last_case = cases[-1]
    _event(
        events,
        case_id=last_case.id,
        attempt_id=f"attempt_020_{20:032x}",
        event_type="campaign_generation_barrier_frozen",
        payload={
            "barrier_algorithm": campaign.GENERATION_BARRIER_ALGORITHM,
            **campaign._campaign_configuration_commitments(disposition_states),
            "disposition_set_sha256": disposition_set,
            "generation_barrier_sha256": barrier_sha256,
            "disposition_count": 20,
            "frozen_at": BARRIER_AT,
        },
    )

    private_records: dict[str, dict[str, Any]] = {}
    public_records: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases, start=1):
        attempt_id = f"attempt_{index:03d}_{index:032x}"
        candidate = candidates[case.id]
        if candidate is not None:
            _event(
                events,
                case_id=case.id,
                attempt_id=attempt_id,
                event_type="phase_started",
                payload={"phase": "differential", "started_at": BARRIER_AT},
            )
            _event(
                events,
                case_id=case.id,
                attempt_id=attempt_id,
                event_type="phase_finished",
                payload={
                    "phase": "differential",
                    "status": "succeeded",
                    "started_at": BARRIER_AT,
                    "completed_at": COMPLETED_AT,
                    "duration_ms": 2_000,
                    "classification_code": None,
                    "evidence": {},
                },
            )
        mechanical = index <= 6 and not exact
        outcome = (
            "no_output"
            if candidate is None
            else "benchmark_infrastructure_error"
            if exact and index == 14
            else "rejected_reproduction"
            if exact
            else "differential_reproduction"
            if mechanical
            else "fail_on_fix"
        )
        claim = (
            "rejected"
            if candidate is None
            else "rejected"
            if exact
            else "differential_reproduction"
            if mechanical
            else "repeatable_base_failure"
        )
        evaluation = (
            None
            if candidate is None
            else {
                "accepted_mechanical_differential": mechanical,
                "mechanical_claim_level": claim,
                "outcome": outcome,
                "fingerprint": "wrong normalized output",
                "base_run_count": 3,
                "fixed_run_count": 3,
                "scheduled_runs": _scheduled_runs(index),
                "evaluator_capability_sha256": f"{index + 800:064x}",
                "evaluator_package_sha256": f"{index + 900:064x}",
                "evaluator_commitment_sha256": case.evaluator_commitment_sha256,
                "dependency": {
                    "receipt_sha256": None,
                    "plan_sha256": None,
                    "tree_sha256": None,
                    "image_id": None,
                },
                "semantic_status": "not_reviewed_mechanical_result_only",
            }
        )
        exact_evaluation = (
            {
                "accepted": False,
                "classification": "no_output",
                "kind": "no_candidate",
                "reason": "generation_produced_no_candidate",
                "receipt_sha256": None,
            }
            if candidate is None
            else {
                "accepted": False,
                "classification": "network_dependency",
                "kind": "infrastructure_failure",
                "reason": "network_required_but_sandbox_network_is_disabled",
                "receipt_sha256": None,
            }
            if index == 14
            else {
                "accepted": False,
                "classification": "rejected_reproduction",
                "kind": "exact_image_receipt",
                "reason": None,
                "receipt_sha256": f"{index + 2500:064x}",
            }
        )
        costs = {name: 1 for name in campaign._COST_CATEGORIES}
        common = {
            "schema_version": "1.0.0",
            "benchmark_version": "0.2.0-draft",
            "algorithm": "reproassert-v02-scored-result-v1",
            "campaign_id": freeze.campaign_id,
            "attempt_id": attempt_id,
            "case": asdict(case),
            "preregistration_sha256": freeze.preregistration_sha256,
            "cohort_sha256": freeze.cohort_sha256,
            "runner_input_sha256": f"{index + 500:064x}",
            "configuration_sha256": campaign._json_sha256(configuration),
            "candidate": candidate,
            "cost": {
                "complete": True,
                "total_attributable_microusd": 4,
                "categories": costs,
                "pricing_snapshot_sha256": configuration["pricing_snapshot_sha256"],
            },
            "ledger_head_before_result_sha256": f"{index + 1000:064x}",
        }
        private = {
            **common,
            "visibility": "private_controller_only",
            "source_context": {
                "algorithm": "reproassert-source-context-v1",
                "policy_sha256": "4" * 64,
                "sha256": case.source_context_sha256,
            },
            "evaluation": evaluation,
            "terminal_projection": {
                "outcome": outcome,
                "claim_level": claim,
                "classification_code": "completed" if candidate is not None else "no_output",
                "issue_faithful_or_semantic_valid": False,
                "limitation": (
                    "Generated expected_symptom is mechanical only; issue fidelity requires "
                    "later blinded semantic review."
                ),
            },
        }
        public = {
            **common,
            "visibility": "public_safe_embargoed",
            "publication_status": ("embargoed_until_all_20_candidates_are_durably_frozen"),
            "evaluation": {
                "status": "sealed",
                "accepted": None,
                "outcome": None,
                "claim_level": None,
                "fixed_run_evidence": None,
                "evaluator_commitment_sha256": case.evaluator_commitment_sha256,
                "private_result_commitment": "withheld_until_campaign_terminal",
            },
        }
        if exact:
            assert candidate is None or isinstance(candidate, dict)
            exact_candidate = (
                None
                if candidate is None
                else {
                    "bytes": candidate["bytes"],
                    "path": candidate["path"],
                    "sha256": candidate["sha256"],
                    "test_function": v02_candidate_contract(
                        case_id=case.id, issue_number=index
                    ).test_function,
                }
            )
            exact_common = {
                "algorithm": campaign.EXACT_RESULT_ALGORITHM,
                "attempt_id": attempt_id,
                "benchmark_version": "0.2",
                "campaign_id": freeze.campaign_id,
                "candidate": exact_candidate,
                "case": asdict(case),
                "claims": {
                    "causal_controls_complete": False,
                    "hidden_bytes_emitted": False,
                    "network_enabled": False,
                    "provider_calls_during_evaluation": 0,
                    "semantic_review_complete": False,
                },
                "cost": {"complete": True, "total_attributable_microusd": 4},
                "evaluation": exact_evaluation,
                "exact_case_commitment_sha256": _exact_preregistration(cases)["cases"][index - 1][
                    "case_commitment_sha256"
                ],
                "exact_preregistration_sha256": freeze.preregistration_sha256,
                "ledger_head_before_result_sha256": f"{index + 1000:064x}",
                "runner_input_sha256": f"{index + 500:064x}",
                "schema_version": "1.0.0",
            }
            private = {**exact_common, "visibility": "private_controller_only"}
            public = {**exact_common, "visibility": "public_safe_embargoed"}
        directory = attempts_root / case.id
        directory.mkdir(mode=0o700)
        private_path = directory / (
            campaign.EXACT_PRIVATE_RESULT_FILENAME if exact else campaign.PRIVATE_RESULT_FILENAME
        )
        public_path = directory / (
            campaign.EXACT_EMBARGOED_RESULT_FILENAME
            if exact
            else campaign.EMBARGOED_RESULT_FILENAME
        )
        _write(private_path, private)
        _write(public_path, public)
        private_records[case.id] = private
        public_records[case.id] = public
        _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="phase_started",
            payload={"phase": "result_write", "started_at": COMPLETED_AT},
        )
        _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="phase_finished",
            payload={
                "phase": "result_write",
                "status": "succeeded",
                "started_at": COMPLETED_AT,
                "completed_at": COMPLETED_AT,
                "duration_ms": 500,
                "classification_code": None,
                "evidence": {},
            },
        )
        _event(
            events,
            case_id=case.id,
            attempt_id=attempt_id,
            event_type="attempt_finished",
            payload={
                "completed_at": COMPLETED_AT,
                "status": "complete",
                "outcome": outcome,
                "claim_level": claim,
                "cost_complete": True,
                "total_attributable_microusd": 4,
                "private_result_sha256": hashlib.sha256(private_path.read_bytes()).hexdigest(),
                "public_result_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
            },
        )

    control_cases: list[campaign.V02CausalControlCase] = []
    for index, case in enumerate(cases, start=1):
        candidate = candidates[case.id]
        if candidate is None:
            control_cases.append(
                campaign.V02CausalControlCase(
                    case_id=case.id,
                    candidate_sha256=None,
                    evaluator_commitment_sha256=case.evaluator_commitment_sha256,
                    issue_relevant_hunks_sha256=None,
                    fixed_pass_evidence_sha256=None,
                    status="not_applicable_no_candidate",
                    completed_at=None,
                    declared_decoy_control_ids=(),
                    controls=(),
                )
            )
            continue
        evaluation = private_records[case.id]["evaluation"]
        assert isinstance(evaluation, dict)
        fixed_evidence = (
            cast(str, private_records[case.id]["exact_case_commitment_sha256"])
            if exact and index == 14
            else campaign._fixed_pass_evidence_sha256(evaluation)
        )
        decoy_id = "decoy_alternative_fix"
        controls = (
            _control_run(
                index,
                "candidate_on_fixed",
                expected_outcome="pass",
                observed_outcome="pass" if index <= 6 else "fail",
            ),
            _control_run(
                index,
                "fix_minus_issue_relevant_hunks",
                expected_outcome="fail",
                observed_outcome="fail",
            ),
            _control_run(
                index,
                "base_plus_issue_relevant_hunks",
                expected_outcome="pass",
                observed_outcome="pass",
            ),
            _control_run(
                index,
                "declared_decoy",
                control_id=decoy_id,
                expected_outcome="pass",
                observed_outcome="pass",
            ),
        )
        control_cases.append(
            campaign.V02CausalControlCase(
                case_id=case.id,
                candidate_sha256=candidate["sha256"],
                evaluator_commitment_sha256=case.evaluator_commitment_sha256,
                issue_relevant_hunks_sha256=f"{index + 1800:064x}",
                fixed_pass_evidence_sha256=fixed_evidence,
                status="executed",
                completed_at=CONTROL_EXECUTED_AT,
                declared_decoy_control_ids=(decoy_id,),
                controls=controls,
            )
        )
    control_set = campaign.build_v02_causal_control_set(
        freeze_path,
        preregistration,
        control_cases,
        sealed_at=CONTROL_SEALED_AT,
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
    )
    control_path = tmp_path / "causal-controls.json"
    _write(control_path, control_set)
    control_records = {
        record["case_id"]: record
        for record in control_set["cases"]  # type: ignore[index]
    }

    review_cases: list[campaign.V02SemanticReviewCase] = []
    for index, case in enumerate(cases, start=1):
        candidate = candidates[case.id]
        control_receipt = control_records[case.id]["control_receipt_sha256"]
        if candidate is None:
            review_cases.append(
                campaign.V02SemanticReviewCase(
                    case_id=case.id,
                    candidate_sha256=None,
                    causal_control_receipt_sha256=control_receipt,
                    reviewer_role_seal_sha256=None,
                    mapping_reviewer_ids=(),
                    authorized_semantic_reviewer_ids=(),
                    reviews=(),
                )
            )
            continue
        if exact and index == 14:
            review_cases.append(
                campaign.V02SemanticReviewCase(
                    case_id=case.id,
                    candidate_sha256=None,
                    causal_control_receipt_sha256=control_receipt,
                    reviewer_role_seal_sha256=None,
                    mapping_reviewer_ids=(),
                    authorized_semantic_reviewer_ids=(),
                    reviews=(),
                )
            )
            continue
        evaluation = private_records[case.id]["evaluation"]
        assert isinstance(evaluation, dict)
        fixed_evidence = campaign._fixed_pass_evidence_sha256(evaluation)
        role_seal = f"{index + 1900:064x}"
        valid = index <= 6
        reviewer_ids = [f"semantic_{index:03d}_a", f"semantic_{index:03d}_b"]
        review_validities = [valid, valid]
        if index == 6:
            reviewer_ids.append(f"semantic_{index:03d}_c")
            review_validities = [True, False, True]
        reviews = tuple(
            _semantic_review(
                index=index,
                review_round=round_index,
                candidate_sha256=candidate["sha256"],
                control_receipt_sha256=control_receipt,
                role_seal_sha256=role_seal,
                fixed_pass_evidence_sha256=fixed_evidence,
                reviewer_id=reviewer_id,
                valid=review_validities[round_index - 1],
            )
            for round_index, reviewer_id in enumerate(reviewer_ids, start=1)
        )
        review_cases.append(
            campaign.V02SemanticReviewCase(
                case_id=case.id,
                candidate_sha256=candidate["sha256"],
                causal_control_receipt_sha256=control_receipt,
                reviewer_role_seal_sha256=role_seal,
                mapping_reviewer_ids=(f"mapping_{index:03d}_a", f"mapping_{index:03d}_b"),
                authorized_semantic_reviewer_ids=tuple(reviewer_ids),
                reviews=reviews,
            )
        )
    review_path = tmp_path / "semantic-reviews.json"
    review_set = campaign.build_v02_semantic_review_set(
        freeze_path,
        preregistration,
        review_cases,
        sealed_at=SEALED_AT,
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
    )
    if exact:
        infrastructure = review_set["cases"][13]
        infrastructure.update(
            {
                "candidate_sha256": candidates[cases[13].id]["sha256"],
                "status": "not_applicable_infrastructure_failure",
                "consensus_verdict": "inconclusive",
            }
        )
        infrastructure["review_case_sha256"] = campaign._self_hash(
            infrastructure, "review_case_sha256"
        )
        review_set["review_set_sha256"] = campaign._self_hash(review_set, "review_set_sha256")
    _write(review_path, review_set)
    return _Artifacts(
        preregistration=preregistration,
        freeze_path=freeze_path,
        freeze=freeze,
        attempts_root=attempts_root,
        control_path=control_path,
        review_path=review_path,
        ledger_path=ledger_path,
        output_root=output_root,
        events=events,
        private_records=private_records,
        public_records=public_records,
    )


def _finalize(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_exact_authority: bool = True,
) -> campaign.V02CampaignFinalization:
    monkeypatch.setattr(campaign, "read_v02_scored_ledger", lambda _path: artifacts.snapshot())
    loaded = load_v02_scored_preregistration(artifacts.preregistration)
    authority: object | None = None
    if loaded.format == "exact-image-v1" and include_exact_authority:
        authority = _issued_exact_authority(artifacts.preregistration)
    return campaign.finalize_v02_campaign(
        campaign_freeze_path=artifacts.freeze_path,
        preregistration_path=artifacts.preregistration,
        ledger_path=artifacts.ledger_path,
        attempts_root=artifacts.attempts_root,
        causal_control_set_path=artifacts.control_path,
        semantic_review_set_path=artifacts.review_path,
        output_root=artifacts.output_root,
        finalized_at=FINALIZED_AT,
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
        exact_preregistration=authority,
    )


def _issued_exact_authority(path: Path) -> object:
    loaded = load_v02_scored_preregistration(path)
    authority = object.__new__(exact_preregistration.VerifiedV02ExactPreregistration)
    for name, value in {
        "path": path,
        "sha256": loaded.raw_sha256,
        "cohort_sha256": loaded.cohort_sha256,
        "request_set_sha256": loaded.request_set_sha256,
        "case_count": len(loaded.cases),
        "evaluator_preflight_ready_count": 19,
        "infrastructure_failure_count": 1,
        "provider_calls": 0,
        "_issuer": exact_preregistration._ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def _rehash_control_document(document: dict[str, Any], case_index: int) -> str:
    control_case = document["cases"][case_index]
    for run in control_case["controls"]:
        run["control_run_sha256"] = campaign._self_hash(run, "control_run_sha256")
    required = [
        run
        for run in control_case["controls"]
        if run["control_type"] in campaign._REQUIRED_CONTROL_TYPES
    ]
    decoys = [run for run in control_case["controls"] if run["control_type"] == "declared_decoy"]
    control_case["required_controls_passed"] = all(
        campaign._control_run_passed(run) for run in required
    )
    control_case["declared_decoys_passed"] = all(
        campaign._control_run_passed(run) for run in decoys
    )
    control_case["l2_causal_controls_passed"] = (
        control_case["required_controls_passed"] and control_case["declared_decoys_passed"]
    )
    control_case["control_receipt_sha256"] = campaign._self_hash(
        control_case, "control_receipt_sha256"
    )
    document["control_set_sha256"] = campaign._self_hash(document, "control_set_sha256")
    return control_case["control_receipt_sha256"]


def _rebind_review_control(artifacts: _Artifacts, case_index: int, receipt: str) -> None:
    document = json.loads(artifacts.review_path.read_text())
    review_case = document["cases"][case_index]
    review_case["causal_control_receipt_sha256"] = receipt
    for review in review_case["reviews"]:
        review["causal_control_receipt_sha256"] = receipt
        review["checklist_sha256"] = campaign.v02_semantic_checklist_sha256(
            case_id=review["case_id"],
            candidate_sha256=review["candidate_sha256"],
            causal_control_receipt_sha256=receipt,
            fixed_pass_evidence_sha256=review["fixed_pass_evidence_sha256"],
        )
        review["review_sha256"] = campaign._self_hash(review, "review_sha256")
    review_case["review_case_sha256"] = campaign._self_hash(review_case, "review_case_sha256")
    document["review_set_sha256"] = campaign._self_hash(document, "review_set_sha256")
    _write(artifacts.review_path, document)


def test_campaign_finalizes_exact_20_with_abstention_and_rerunnable_public_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    result = _finalize(artifacts, monkeypatch)
    assert result.provisional_candidate_count == 6
    assert result.review_semantic_valid_count == 6
    assert result.total_attributable_microusd == 80
    public = json.loads(result.public_path.read_text())
    assert public["candidate_freeze_barrier"] == {
        "expected": 20,
        "verified": 20,
        "all_dispositions_preceded_first_evaluator_phase": True,
    }
    assert public["summary"]["candidate_count"] == 19
    assert public["summary"]["median_active_duration_ms"] == 3_500
    assert public["summary"]["blended_cost_per_provisional_candidate_microusd"] == 14
    assert public["summary"]["blended_cost_per_provisional_candidate_rounding"] == (
        "ceiling_integer_microusd"
    )
    assert public["summary"]["l2_semantic_valid_count"] == 6
    assert public["summary"]["blended_cost_per_l2_success_microusd"] == 14
    assert public["summary"]["l2_exact_binomial_95_interval"] == {
        "method": "clopper_pearson_two_sided_reference",
        "lower_millionths": 118_931,
        "upper_millionths": 542_790,
        "scope": "selected_cohort_only_not_population_generalization",
        "selection_bias_addressed": False,
    }
    assert public["claim_ceiling"] == (
        "l2_protocol_bounded_selected_cohort_no_maintainer_validation"
    )
    assert public["benchmark_provenance"]["corpus_visibility"] == (
        "historical_public_contamination_exposed"
    )
    assert public["run_configuration"]["requested_model"] == "gpt-test"
    assert public["run_configuration"]["campaign_freeze_sha256"] == (artifacts.freeze.raw_sha256)
    assert public["run_configuration"]["sandbox_verifier_identity_status"] == (
        "not_recorded_in_current_scored_result"
    )
    assert public["summary"]["mechanical_outcome_counts"] == {
        "differential_reproduction": 6,
        "fail_on_fix": 13,
        "no_output": 1,
    }
    assert public["summary"]["false_positive_rate_millionths"] == 0
    assert public["cases"][0]["candidate"]["test_content"].startswith("from demo")
    assert public["cases"][0]["provisional_mechanical_plus_review"] is True
    assert public["cases"][0]["l2_semantic_valid"] is True
    assert public["cases"][0]["validation_outcome"] == "semantic_valid"
    assert public["cases"][0]["causal_control_evidence"]["required_controls_passed"] is True
    assert public["cases"][5]["semantic_review_evidence"]["tiebreak_used"] is True
    assert public["cases"][0]["reproduction"]["test_command"].endswith(
        "::test_issue_1_reproduction"
    )
    assert public["cases"][0]["reproduction"]["command_scope"] == (
        "prepared_exact_source_and_dependencies_only_not_bootstrap"
    )
    assert public["cases"][-1]["candidate"] is None
    assert public["cases"][-1]["semantic_verdict"] == "not_applicable_no_candidate"
    public_text = result.public_path.read_text()
    assert '"private_result_sha256"' not in public_text
    assert '"fixed_run_count"' not in public_text
    assert '"authorization_ref"' not in public_text
    assert '"sandbox_receipt_sha256"' not in public_text
    assert '"environment_sha256"' not in public_text
    assert '"reviewer_id"' not in public_text
    assert "The frozen issue, candidate, differential evidence" not in public_text
    assert '"developer_tests"' not in public_text
    assert '"human_patch"' not in public_text
    verified = campaign.verify_v02_campaign_output_structure(
        campaign_freeze_path=artifacts.freeze_path,
        preregistration_path=artifacts.preregistration,
        private_finalization_path=result.private_path,
        public_aggregate_path=result.public_path,
    )
    assert verified.public_sha256 == result.public_sha256
    # Deterministic crash recovery: a private-only partial write can complete on rerun.
    public_bytes = result.public_path.read_bytes()
    result.public_path.unlink()
    partial_rerun = _finalize(artifacts, monkeypatch)
    assert partial_rerun.public_path.read_bytes() == public_bytes
    # Exact existing bytes are then accepted idempotently.
    rerun = _finalize(artifacts, monkeypatch)
    assert rerun == result


def test_exact_campaign_finalizes_20_mixed_profiles_and_rejects_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path / "exact", exact=True, no_candidate={20})
    with pytest.raises(PolicyRejection, match="Fresh verifier-issued"):
        _finalize(artifacts, monkeypatch, include_exact_authority=False)
    mismatched = _issued_exact_authority(artifacts.preregistration)
    object.__setattr__(mismatched, "sha256", "f" * 64)
    with pytest.raises(PolicyRejection, match="differs from the finalization campaign"):
        campaign._require_exact_finalization_preregistration(
            mismatched, load_v02_scored_preregistration(artifacts.preregistration)
        )
    result = _finalize(artifacts, monkeypatch)
    public = json.loads(result.public_path.read_text())

    assert len(public["cases"]) == 20
    assert public["summary"]["candidate_count"] == 19
    assert public["summary"]["mechanical_differential_count"] == 0
    assert public["cases"][13]["mechanical_outcome"] == "benchmark_infrastructure_error"
    assert public["cases"][13]["semantic_review_evidence"]["reviewer_count"] == 0
    assert public["cases"][19]["candidate_status"] == "no_candidate"
    sympy = public["cases"][15]["reproduction"]
    assert "bin/test " in sympy["test_command"]
    assert "junit" not in json.dumps(sympy).lower()
    review_schema = json.loads(
        (ROOT / "schemas" / "benchmark-v02-semantic-review-set.schema.json").read_text()
    )
    Draft202012Validator(review_schema).validate(json.loads(artifacts.review_path.read_text()))

    artifacts.output_root = tmp_path / "tampered-output"
    artifacts.output_root.mkdir(mode=0o700)
    record = artifacts.private_records["rk-v0.2-011"]
    record["exact_case_commitment_sha256"] = "f" * 64
    path = artifacts.attempts_root / "rk-v0.2-011" / campaign.EXACT_PRIVATE_RESULT_FILENAME
    _write(path, record)
    terminal = next(
        event
        for event in artifacts.events
        if event["case_id"] == "rk-v0.2-011" and event["event_type"] == "attempt_finished"
    )
    terminal["payload"]["private_result_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(PolicyRejection, match="exact result binding"):
        _finalize(artifacts, monkeypatch)


def test_exact_infrastructure_review_waiver_is_case014_only(tmp_path: Path) -> None:
    artifacts = _prepare(tmp_path / "exact-review", exact=True, no_candidate={20})
    review = json.loads(artifacts.review_path.read_text())
    row = review["cases"][12]
    row.update(
        {
            "status": "not_applicable_infrastructure_failure",
            "reviewer_role_seal_sha256": None,
            "mapping_reviewer_ids": [],
            "authorized_semantic_reviewer_ids": [],
            "reviews": [],
            "reviewer_count": 0,
            "consensus_verdict": "inconclusive",
            "tiebreak_used": False,
        }
    )
    row["review_case_sha256"] = campaign._self_hash(row, "review_case_sha256")
    review["review_set_sha256"] = campaign._self_hash(review, "review_set_sha256")
    path = tmp_path / "forged-infrastructure-review.json"
    _write(path, review)
    with pytest.raises(PolicyRejection, match="reviewer role seal"):
        campaign.verify_v02_semantic_review_set(
            path,
            campaign_freeze_path=artifacts.freeze_path,
            preregistration_path=artifacts.preregistration,
        )


def test_exact_finalize_cli_rederives_preregistration_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path / "exact-cli", exact=True, no_candidate={20})
    monkeypatch.setattr(campaign, "read_v02_scored_ledger", lambda _path: artifacts.snapshot())
    monkeypatch.setattr(
        cli,
        "verify_v02_exact_preregistration",
        lambda *_args, **_kwargs: _issued_exact_authority(artifacts.preregistration),
    )
    output = tmp_path / "exact-cli-output"
    args = [
        "benchmark",
        "finalize-v02-exact-campaign",
        "--campaign-freeze",
        str(artifacts.freeze_path),
        "--preregistration",
        str(artifacts.preregistration),
        "--ledger",
        str(artifacts.ledger_path),
        "--attempts-root",
        str(artifacts.attempts_root),
        "--causal-control-set",
        str(artifacts.control_path),
        "--semantic-review-set",
        str(artifacts.review_path),
        "--output-root",
        str(output),
        "--finalized-at",
        FINALIZED_AT,
        "--tool-version",
        "0.2-test",
        "--tool-git-sha",
        "1" * 40,
    ]
    evidence_files = {
        "--cases-preparation": artifacts.preregistration,
        "--cohort-plan": artifacts.preregistration,
        "--chronology": artifacts.preregistration,
        "--hidden-extraction-receipt": artifacts.preregistration,
        "--mapping-preparation": artifacts.preregistration,
        "--mapping-consensus": artifacts.preregistration,
        "--capability-index": artifacts.preregistration,
        "--instance-runtime-manifest": artifacts.preregistration,
        "--gold-smoke-receipt": artifacts.preregistration,
    }
    for option, path in evidence_files.items():
        args.extend((option, str(path)))
    args.extend(("--issue-responses-root", str(artifacts.attempts_root)))
    args.extend(("--expected-manifest-sha256", "a" * 64))
    invoked = CliRunner().invoke(cli.main, args)
    assert invoked.exit_code == 0, invoked.output
    payload = json.loads(invoked.output)
    assert payload["exact_preregistration_authority_rederived"] is True
    assert payload["l2_semantic_valid_count"] == 0


def test_legacy_aggregate_rejects_exact_candidate_shape_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path / "legacy")
    result = _finalize(artifacts, monkeypatch)
    public = json.loads(result.public_path.read_text())
    legacy_candidate = public["cases"][0]["candidate"]
    public["cases"][0]["candidate"] = {
        "bytes": legacy_candidate["bytes"],
        "path": legacy_candidate["path"],
        "sha256": legacy_candidate["sha256"],
        "test_function": "test_issue_1_reproduction",
    }
    public["public_aggregate_sha256"] = campaign._self_hash(public, "public_aggregate_sha256")
    public_path = tmp_path / "legacy-downgraded-public.json"
    _write(public_path, public)
    private = json.loads(result.private_path.read_text())
    private["public_aggregate_sha256"] = hashlib.sha256(public_path.read_bytes()).hexdigest()
    private_path = tmp_path / "legacy-downgraded-private.json"
    _write(private_path, private)
    with pytest.raises(PolicyRejection, match="candidate shape"):
        campaign.verify_v02_campaign_output_structure(
            campaign_freeze_path=artifacts.freeze_path,
            preregistration_path=artifacts.preregistration,
            private_finalization_path=private_path,
            public_aggregate_path=public_path,
        )


def test_emitted_campaign_artifacts_and_event_rows_match_strict_bundled_schemas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    result = _finalize(artifacts, monkeypatch)
    instances: dict[str, list[object]] = {
        "benchmark-v02-campaign-freeze": [json.loads(artifacts.freeze_path.read_text())],
        "benchmark-v02-causal-control-set": [json.loads(artifacts.control_path.read_text())],
        "benchmark-v02-semantic-review-set": [json.loads(artifacts.review_path.read_text())],
        "benchmark-v02-private-result": list(artifacts.private_records.values()),
        "benchmark-v02-embargoed-result": list(artifacts.public_records.values()),
        "benchmark-v02-private-event": artifacts.events,
        "benchmark-v02-campaign-finalization": [json.loads(result.private_path.read_text())],
        "benchmark-v02-public-aggregate": [json.loads(result.public_path.read_text())],
    }
    for name, values in instances.items():
        root = ROOT / "schemas" / f"{name}.schema.json"
        bundled = ROOT / "src" / "reproassert" / "schemas" / f"{name}.schema.json"
        assert root.read_bytes() == bundled.read_bytes()
        schema = json.loads(root.read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for value in values:
            validator.validate(value)


@pytest.mark.parametrize(
    "mutation,match",
    [
        ("missing_disposition", "dispositions"),
        ("duplicate_disposition", "dispositions"),
        ("evaluation_before_barrier", "precede evaluation"),
        ("tampered_barrier", "does not bind"),
        ("unknown_cost", "incomplete"),
        ("missing_terminal", "complete attempt"),
        ("unknown_case", "unbound campaign case"),
        ("duplicate_start", "complete attempt"),
        ("pre_freeze_start", "pre-inference campaign freeze"),
        ("wrong_freeze_binding", "pre-inference campaign freeze"),
    ],
)
def test_finalizer_rejects_incomplete_tampered_or_misordered_ledgers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    match: str,
) -> None:
    artifacts = _prepare(tmp_path)
    events = copy.deepcopy(artifacts.events)
    if mutation == "missing_disposition":
        events.remove(
            next(
                event for event in events if event["event_type"] == "generation_disposition_frozen"
            )
        )
    elif mutation == "duplicate_disposition":
        source = next(
            event for event in events if event["event_type"] == "generation_disposition_frozen"
        )
        events.insert(events.index(source) + 1, copy.deepcopy(source))
    elif mutation == "evaluation_before_barrier":
        differential = next(
            event
            for event in events
            if event["event_type"] == "phase_started"
            and event["payload"]["phase"] == "differential"
        )
        events.remove(differential)
        first_disposition = next(
            index
            for index, event in enumerate(events)
            if event["event_type"] == "generation_disposition_frozen"
        )
        events.insert(first_disposition, differential)
    elif mutation == "tampered_barrier":
        barrier = next(
            event for event in events if event["event_type"] == "campaign_generation_barrier_frozen"
        )
        barrier["payload"]["disposition_set_sha256"] = "f" * 64
    elif mutation == "unknown_cost":
        cost = next(event for event in events if event["event_type"] == "cost_recorded")
        cost["payload"]["status"] = "unknown"
        cost["payload"]["amount_microusd"] = None
    elif mutation == "missing_terminal":
        terminal = next(event for event in events if event["event_type"] == "attempt_finished")
        events.remove(terminal)
    elif mutation == "unknown_case":
        foreign = copy.deepcopy(events[0])
        foreign["case_id"] = "rk-v0.2-999"
        events.append(foreign)
    elif mutation == "duplicate_start":
        start = next(event for event in events if event["event_type"] == "attempt_started")
        events.insert(events.index(start) + 1, copy.deepcopy(start))
    elif mutation == "pre_freeze_start":
        start = next(event for event in events if event["event_type"] == "attempt_started")
        start["payload"]["started_at"] = "2026-07-09T23:59:59Z"
    else:
        start = next(event for event in events if event["event_type"] == "attempt_started")
        start["payload"]["configuration"]["campaign_freeze_sha256"] = "f" * 64
    artifacts.events = events
    with pytest.raises(PolicyRejection, match=match):
        _finalize(artifacts, monkeypatch)


def test_finalizer_rejects_unsealed_early_or_candidate_mismatched_reviews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    monkeypatch.setattr(campaign, "read_v02_scored_ledger", lambda _path: artifacts.snapshot())
    original = json.loads(artifacts.review_path.read_text())
    review = copy.deepcopy(original)
    first_case = review["cases"][0]
    first_case["reviews"][0]["reviewed_at"] = AT
    first_case["reviews"][0]["review_sha256"] = campaign._self_hash(
        first_case["reviews"][0], "review_sha256"
    )
    first_case["review_case_sha256"] = campaign._self_hash(first_case, "review_case_sha256")
    review["review_set_sha256"] = campaign._self_hash(review, "review_set_sha256")
    _write(artifacts.review_path, review)
    with pytest.raises(PolicyRejection, match="post-control"):
        _finalize(artifacts, monkeypatch)

    review = copy.deepcopy(original)
    first_case = review["cases"][0]
    first_case["candidate_sha256"] = "f" * 64
    for item in first_case["reviews"]:
        item["candidate_sha256"] = "f" * 64
        item["checklist_sha256"] = campaign.v02_semantic_checklist_sha256(
            case_id=first_case["case_id"],
            candidate_sha256="f" * 64,
            causal_control_receipt_sha256=first_case["causal_control_receipt_sha256"],
            fixed_pass_evidence_sha256=item["fixed_pass_evidence_sha256"],
        )
        item["review_sha256"] = campaign._self_hash(item, "review_sha256")
    first_case["review_case_sha256"] = campaign._self_hash(first_case, "review_case_sha256")
    review["review_set_sha256"] = campaign._self_hash(review, "review_set_sha256")
    _write(artifacts.review_path, review)
    with pytest.raises(PolicyRejection, match="evidence binding differs"):
        _finalize(artifacts, monkeypatch)


@pytest.mark.parametrize(
    "mutation,expected_outcome",
    [
        ("required_unavailable", "not_available"),
        ("declared_decoy_mismatch", "fail"),
    ],
)
def test_failed_or_unavailable_causal_controls_downgrade_l2_without_hiding_f2p(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_outcome: str,
) -> None:
    artifacts = _prepare(tmp_path)
    document = json.loads(artifacts.control_path.read_text())
    control_case = document["cases"][0]
    if mutation == "required_unavailable":
        run = next(
            item
            for item in control_case["controls"]
            if item["control_type"] == "fix_minus_issue_relevant_hunks"
        )
        run.update(
            {
                "observed_outcome": "not_available",
                "executed_at": None,
                "test_command": None,
                "exit_code": None,
                "duration_ms": None,
                "timed_out": False,
                "oom_killed": False,
                "output_truncated": False,
                "output_sha256": None,
                "junit_sha256": None,
                "sandbox_receipt_sha256": None,
                "environment_sha256": None,
                "reason": "Issue-relevant hunks could not be separated without changing setup.",
            }
        )
    else:
        run = next(
            item for item in control_case["controls"] if item["control_type"] == "declared_decoy"
        )
        run["observed_outcome"] = "fail"
        run["exit_code"] = 1
    receipt = _rehash_control_document(document, 0)
    _write(artifacts.control_path, document)
    _rebind_review_control(artifacts, 0, receipt)
    result = _finalize(artifacts, monkeypatch)
    public = json.loads(result.public_path.read_text())
    assert result.l2_semantic_valid_count == 5
    assert public["summary"]["l2_semantic_valid_count"] == 5
    assert public["summary"]["case_count"] == 20
    assert public["cases"][0]["mechanical_outcome"] == "differential_reproduction"
    assert public["cases"][0]["validation_outcome"] == ("plausible_f2p_semantic_invalid")
    assert (
        expected_outcome
        in public["cases"][0]["causal_control_evidence"]["required_control_outcomes"].values()
        or mutation == "declared_decoy_mismatch"
    )


@pytest.mark.parametrize("mutation", ["missing_required", "duplicate_control", "raw_tamper"])
def test_causal_control_receipts_fail_closed_on_missing_duplicate_or_tampered_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    artifacts = _prepare(tmp_path)
    document = json.loads(artifacts.control_path.read_text())
    if mutation == "raw_tamper":
        document["cases"][0]["controls"][0]["output_sha256"] = "f" * 64
        _write(artifacts.control_path, document)
        with pytest.raises(PolicyRejection, match="binding is invalid"):
            campaign.verify_v02_causal_control_set(
                artifacts.control_path,
                campaign_freeze_path=artifacts.freeze_path,
                preregistration_path=artifacts.preregistration,
            )
        return
    if mutation == "missing_required":
        document["cases"][0]["controls"].pop(0)
    else:
        document["cases"][0]["controls"].append(copy.deepcopy(document["cases"][0]["controls"][0]))
    _rehash_control_document(document, 0)
    _write(artifacts.control_path, document)
    with pytest.raises(PolicyRejection, match="control"):
        _finalize(artifacts, monkeypatch)


@pytest.mark.parametrize(
    "mutation,match",
    [
        ("one_reviewer", "two or three reviews"),
        ("disagreement_without_tiebreak", "third reviewer"),
        ("reviewer_role_overlap", "not independent"),
        ("gold_exposed", "seal is invalid"),
        ("checklist_mismatch", "checklist binding differs"),
    ],
)
def test_semantic_review_consensus_and_blinding_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    match: str,
) -> None:
    artifacts = _prepare(tmp_path)
    document = json.loads(artifacts.review_path.read_text())
    review_case = document["cases"][0]
    if mutation == "one_reviewer":
        review_case["reviews"] = review_case["reviews"][:1]
        review_case["reviewer_count"] = 1
    elif mutation == "disagreement_without_tiebreak":
        second = review_case["reviews"][1]
        second["trigger_faithful"] = False
        second["verdict"] = "semantically_invalid"
        second["review_sha256"] = campaign._self_hash(second, "review_sha256")
    elif mutation == "reviewer_role_overlap":
        review_case["mapping_reviewer_ids"] = sorted(
            [
                review_case["authorized_semantic_reviewer_ids"][0],
                review_case["mapping_reviewer_ids"][1],
            ]
        )
    elif mutation == "gold_exposed":
        first = review_case["reviews"][0]
        first["gold_hidden_until_verdict"] = False
        first["review_sha256"] = campaign._self_hash(first, "review_sha256")
    else:
        first = review_case["reviews"][0]
        first["checklist_sha256"] = "f" * 64
        first["review_sha256"] = campaign._self_hash(first, "review_sha256")
    review_case["review_case_sha256"] = campaign._self_hash(review_case, "review_case_sha256")
    document["review_set_sha256"] = campaign._self_hash(document, "review_set_sha256")
    _write(artifacts.review_path, document)
    with pytest.raises(PolicyRejection, match=match):
        _finalize(artifacts, monkeypatch)


def test_control_execution_must_follow_attempt_and_bind_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    document = json.loads(artifacts.control_path.read_text())
    document["cases"][0]["controls"][0]["executed_at"] = AT
    receipt = _rehash_control_document(document, 0)
    _write(artifacts.control_path, document)
    _rebind_review_control(artifacts, 0, receipt)
    with pytest.raises(PolicyRejection, match="execution or test-command binding"):
        _finalize(artifacts, monkeypatch)

    artifacts = _prepare(tmp_path / "candidate-mismatch")
    document = json.loads(artifacts.control_path.read_text())
    document["cases"][0]["candidate_sha256"] = "f" * 64
    _rehash_control_document(document, 0)
    _write(artifacts.control_path, document)
    with pytest.raises(PolicyRejection, match="control candidate differs"):
        _finalize(artifacts, monkeypatch)


def test_result_tampering_commitment_mismatch_and_existing_output_mismatch_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    monkeypatch.setattr(campaign, "read_v02_scored_ledger", lambda _path: artifacts.snapshot())
    first = artifacts.freeze.case_ids[0]
    public_path = artifacts.attempts_root / first / campaign.EMBARGOED_RESULT_FILENAME
    public = json.loads(public_path.read_text())
    public["evaluation"]["evaluator_commitment_sha256"] = "f" * 64
    _write(public_path, public)
    terminal = next(
        event
        for event in artifacts.events
        if event["case_id"] == first and event["event_type"] == "attempt_finished"
    )
    terminal["payload"]["public_result_sha256"] = hashlib.sha256(
        public_path.read_bytes()
    ).hexdigest()
    with pytest.raises(PolicyRejection, match="unsealed early"):
        _finalize(artifacts, monkeypatch)

    artifacts = _prepare(tmp_path / "second")
    result = _finalize(artifacts, monkeypatch)
    result.public_path.write_text("{}\n")
    with pytest.raises(PolicyRejection, match="differs"):
        _finalize(artifacts, monkeypatch)


def test_recovered_crash_chain_uses_latest_effective_terminal_and_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    first = artifacts.freeze.case_ids[0]
    disposition_index = next(
        index
        for index, event in enumerate(artifacts.events)
        if event["case_id"] == first and event["event_type"] == "generation_disposition_frozen"
    )
    start = next(
        event
        for event in artifacts.events
        if event["case_id"] == first and event["event_type"] == "attempt_started"
    )
    crash = {
        **{key: value for key, value in start.items() if key != "payload"},
        "event_type": "attempt_crashed",
        "event_sha256": "e" * 64,
        "payload": {
            "crashed_at": DISPOSITION_AT,
            "classification_code": "v02_runner_crash",
            "exception_type": "InjectedCrash",
            "cost_complete": False,
            "recovery_status": "manual_reconciliation_required_no_new_provider_call",
        },
    }
    recovery = {
        **{key: value for key, value in start.items() if key != "payload"},
        "event_type": "recovery_started",
        "event_sha256": "f" * 64,
        "payload": {
            "recovery_id": "recovery_0123456789abcdef",
            "started_at": DISPOSITION_AT,
            "mode": "exact_candidate_zero_provider_calls",
            "preregistration_sha256": artifacts.freeze.preregistration_sha256,
            "configuration_sha256": campaign._json_sha256(start["payload"]["configuration"]),
            "execution_authorization_sha256": start["payload"]["configuration"][
                "execution_authorization"
            ]["sha256"],
            "source_context_sha256": start["payload"]["source_context"]["sha256"],
            "runner_input_sha256": start["payload"]["runner_input_sha256"],
            "generation_call_id": "call_00000000000000000000000000000001",
            "generation_artifact_sha256": "a" * 64,
            "generation_artifact_bytes": 100,
            "candidate_sha256": artifacts.public_records[first]["candidate"]["sha256"],
            "provider_calls_permitted": 0,
            "oracle_feedback_permitted": False,
        },
    }
    artifacts.events[disposition_index:disposition_index] = [crash, recovery]
    result = _finalize(artifacts, monkeypatch)
    assert result.provisional_candidate_count == 6
    schema = json.loads((ROOT / "schemas" / "benchmark-v02-private-event.schema.json").read_text())
    Draft202012Validator(schema).validate(recovery)


def test_preparation_review_seal_and_verification_cli_never_expose_paid_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _prepare(tmp_path)
    runner = CliRunner()
    cli_freeze = tmp_path / "cli-freeze.json"
    prepared = runner.invoke(
        cli.main,
        [
            "benchmark",
            "prepare-v02-campaign",
            "--preregistration",
            str(artifacts.preregistration),
            "--campaign-id",
            "campaign_v02_cli",
            "--prepared-at",
            AT,
            "--tool-version",
            "0.2-test",
            "--tool-git-sha",
            "1" * 40,
            "--output",
            str(cli_freeze),
        ],
    )
    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.output)["provider_invoked_by_this_command"] is False
    verify = runner.invoke(
        cli.main,
        [
            "benchmark",
            "verify-v02-campaign",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
        ],
    )
    assert verify.exit_code == 0, verify.output
    assert json.loads(verify.output)["provider_authorized"] is False

    control_draft_path = tmp_path / "control-draft.json"
    sealed_controls = json.loads(artifacts.control_path.read_text())
    control_case_fields = (
        "case_id",
        "candidate_sha256",
        "evaluator_commitment_sha256",
        "issue_relevant_hunks_sha256",
        "fixed_pass_evidence_sha256",
        "status",
        "completed_at",
        "declared_decoy_control_ids",
        "controls",
    )
    control_run_fields = (
        "control_id",
        "control_type",
        "expected_outcome",
        "observed_outcome",
        "executed_at",
        "test_command",
        "exit_code",
        "duration_ms",
        "timed_out",
        "oom_killed",
        "output_truncated",
        "output_sha256",
        "junit_sha256",
        "sandbox_receipt_sha256",
        "environment_sha256",
        "reason",
    )
    control_draft = []
    for row in sealed_controls["cases"]:
        draft_case = {key: row[key] for key in control_case_fields if key != "controls"}
        draft_case["controls"] = [
            {key: control[key] for key in control_run_fields} for control in row["controls"]
        ]
        control_draft.append(draft_case)
    _write(control_draft_path, control_draft, canonical=False)
    sealed_control_path = tmp_path / "sealed-controls-from-cli.json"
    control_seal = runner.invoke(
        cli.main,
        [
            "benchmark",
            "seal-v02-causal-controls",
            "--campaign-freeze",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
            "--controls-draft",
            str(control_draft_path),
            "--sealed-at",
            CONTROL_SEALED_AT,
            "--tool-version",
            "0.2-test",
            "--tool-git-sha",
            "1" * 40,
            "--output",
            str(sealed_control_path),
        ],
    )
    assert control_seal.exit_code == 0, control_seal.output
    control_seal_payload = json.loads(control_seal.output)
    assert control_seal_payload["provider_invoked_by_this_command"] is False
    assert control_seal_payload["untrusted_code_executed_by_this_command"] is False
    control_verify = runner.invoke(
        cli.main,
        [
            "benchmark",
            "verify-v02-causal-controls",
            str(sealed_control_path),
            "--campaign-freeze",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
        ],
    )
    assert control_verify.exit_code == 0, control_verify.output
    assert json.loads(control_verify.output)["provider_invoked_by_this_command"] is False

    draft_path = tmp_path / "review-draft.json"
    sealed = json.loads(artifacts.review_path.read_text())
    review_fields = (
        "case_id",
        "review_round",
        "candidate_sha256",
        "causal_control_receipt_sha256",
        "reviewer_id",
        "reviewer_role_seal_sha256",
        "fixed_pass_evidence_sha256",
        "checklist_sha256",
        "reviewed_at",
        "trigger_faithful",
        "oracle_supported",
        "failure_causal",
        "implementation_independent",
        "minimal_readable",
        "confidence",
        "rationale",
        "verdict",
    )
    draft = []
    for row in sealed["cases"]:
        draft.append(
            {
                "case_id": row["case_id"],
                "candidate_sha256": row["candidate_sha256"],
                "causal_control_receipt_sha256": row["causal_control_receipt_sha256"],
                "reviewer_role_seal_sha256": row["reviewer_role_seal_sha256"],
                "mapping_reviewer_ids": row["mapping_reviewer_ids"],
                "authorized_semantic_reviewer_ids": row["authorized_semantic_reviewer_ids"],
                "reviews": [
                    {key: review[key] for key in review_fields} for review in row["reviews"]
                ],
            }
        )
    _write(draft_path, draft, canonical=False)
    sealed_path = tmp_path / "sealed-from-cli.json"
    seal = runner.invoke(
        cli.main,
        [
            "benchmark",
            "seal-v02-semantic-reviews",
            "--campaign-freeze",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
            "--reviews-draft",
            str(draft_path),
            "--sealed-at",
            SEALED_AT,
            "--tool-version",
            "0.2-test",
            "--tool-git-sha",
            "1" * 40,
            "--output",
            str(sealed_path),
        ],
    )
    assert seal.exit_code == 0, seal.output
    assert json.loads(seal.output)["provider_invoked_by_this_command"] is False

    monkeypatch.setattr(campaign, "read_v02_scored_ledger", lambda _path: artifacts.snapshot())
    cli_output = tmp_path / "cli-output"
    finalized = runner.invoke(
        cli.main,
        [
            "benchmark",
            "finalize-v02-campaign",
            "--campaign-freeze",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
            "--ledger",
            str(artifacts.ledger_path),
            "--attempts-root",
            str(artifacts.attempts_root),
            "--causal-control-set",
            str(artifacts.control_path),
            "--semantic-review-set",
            str(artifacts.review_path),
            "--output-root",
            str(cli_output),
            "--finalized-at",
            FINALIZED_AT,
            "--tool-version",
            "0.2-test",
            "--tool-git-sha",
            "1" * 40,
        ],
    )
    assert finalized.exit_code == 0, finalized.output
    finalized_payload = json.loads(finalized.output)
    assert finalized_payload["provider_invoked_by_this_command"] is False
    private_finalization = cli_output / campaign.PRIVATE_FINALIZATION_FILENAME
    public_aggregate = cli_output / campaign.PUBLIC_AGGREGATE_FILENAME
    verified = runner.invoke(
        cli.main,
        [
            "benchmark",
            "verify-v02-finalization",
            "--campaign-freeze",
            str(artifacts.freeze_path),
            "--preregistration",
            str(artifacts.preregistration),
            "--private-finalization",
            str(private_finalization),
            "--public-aggregate",
            str(public_aggregate),
            "--ledger",
            str(artifacts.ledger_path),
            "--attempts-root",
            str(artifacts.attempts_root),
            "--causal-control-set",
            str(artifacts.control_path),
            "--semantic-review-set",
            str(artifacts.review_path),
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["provider_invoked_by_this_command"] is False
    help_result = runner.invoke(cli.main, ["benchmark", "--help"])
    assert help_result.exit_code == 0
    assert "run-v02" not in help_result.output
    assert "seal-v02-causal-controls" in help_result.output
    assert "verify-v02-causal-controls" in help_result.output

    for name in (
        "benchmark-v02-private-event",
        "benchmark-v02-private-result",
        "benchmark-v02-embargoed-result",
        "benchmark-v02-campaign-freeze",
        "benchmark-v02-causal-control-set",
        "benchmark-v02-semantic-review-set",
        "benchmark-v02-campaign-finalization",
        "benchmark-v02-public-aggregate",
    ):
        schema = runner.invoke(cli.main, ["schema", "--name", name])
        assert schema.exit_code == 0
        assert schema.output == (ROOT / "schemas" / f"{name}.schema.json").read_text()
