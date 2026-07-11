from __future__ import annotations

import hashlib
import inspect
import json
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from reproassert import benchmark_v02_campaign as campaign
from reproassert import benchmark_v02_exact_preregistration as exact_preregistration_module
from reproassert import benchmark_v02_exact_scored as exact_scored
from reproassert import benchmark_v02_runner as runner
from reproassert import generator as generator_module
from reproassert import semantic_issuer as issuer
from reproassert.benchmark_snapshot import canonical_snapshot_content_bytes
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_package import (
    PreregisteredV02Case,
    V02CaseIdentity,
    build_v02_preregistration,
    canonical_preregistration_bytes,
    generator_projection_bytes,
    load_v02_preregistration,
)
from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.context import SourceContext
from reproassert.errors import PolicyRejection
from reproassert.generator import GenerationRequest
from reproassert.sandbox import DockerSandbox


def _pricing(**changes: object) -> runner.V02PricingSnapshot:
    values: dict[str, object] = {
        "provider": "openai",
        "requested_model": "gpt-test",
        "effective_at": "2026-07-10T00:00:00Z",
        "source": "frozen test pricing",
        "input_microusd_per_million_tokens": 0,
        "cached_input_microusd_per_million_tokens": 0,
        "output_microusd_per_million_tokens": 0,
        "sandbox_microusd_per_second": 0,
        "artifact_microusd_per_million_bytes": 0,
        "paid_storage_microusd": 0,
        "dependency_prep_microusd": 0,
    }
    values.update(changes)
    return runner.V02PricingSnapshot(**values)  # type: ignore[arg-type]


def _policy(**changes: object) -> runner.V02ScoredRunPolicy:
    values: dict[str, object] = {
        "campaign_id": "campaign_v02_test",
        "campaign_freeze_sha256": "9" * 64,
        "execution_authorization_sha256": "c" * 64,
        "authorization_text_sha256": "d" * 64,
        "authorized_at": "2026-07-10T00:00:00Z",
        "request_set_sha256": "e" * 64,
        "tool_git_sha": "1" * 40,
        "authorization_status": "explicit_user_approval",
        "authorization_ref": "test-only-no-provider-spend",
        "generator_mode": "trusted_builtin_provider_adapter",
        "provider": "openai",
        "requested_model": "gpt-test",
        "pricing": _pricing(),
        "reserved_worst_case_microusd": 100,
        "max_case_attributable_microusd": 100,
        "max_campaign_attributable_microusd": 2_000,
        "max_case_wall_ms": 60_000,
        "provider_timeout_seconds": 10.0,
    }
    values.update(changes)
    return runner.V02ScoredRunPolicy(**values)  # type: ignore[arg-type]


def _authorization_record() -> dict[str, Any]:
    requests = tuple((f"rk-v0.2-{index:03d}", f"{index:064x}") for index in range(1, 21))
    authorization_text = "Tom explicitly authorizes this exact test campaign."
    return {
        "schema_version": runner.SCHEMA_VERSION,
        "benchmark_version": runner.BENCHMARK_VERSION,
        "algorithm": runner.EXECUTION_AUTHORIZATION_ALGORITHM,
        "visibility": "private_controller_only",
        "authorization_kind": "explicit_user_approval",
        "authorized_at": "2026-07-10T00:00:00Z",
        "authorization_ref": "test-authorization-reference",
        "authorization_text": authorization_text,
        "authorization_text_sha256": hashlib.sha256(authorization_text.encode()).hexdigest(),
        "campaign": {
            "campaign_id": "campaign_v02_test",
            "campaign_freeze_sha256": "9" * 64,
            "preregistration_sha256": "a" * 64,
            "cohort_sha256": "b" * 64,
            "tool_git_sha": "1" * 40,
        },
        "provider": {
            "name": "openai",
            "endpoint_host": "api.openai.com",
            "requested_model": "gpt-test",
            "adapter_config_sha256": runner._openai_adapter_config_sha256("gpt-test"),
        },
        "request_set": {
            "algorithm": runner.EXECUTION_REQUEST_SET_ALGORITHM,
            "request_count": 20,
            "request_set_sha256": runner._execution_request_set_sha256(
                campaign_id="campaign_v02_test",
                preregistration_sha256="a" * 64,
                cohort_sha256="b" * 64,
                requests=requests,
            ),
            "requests": [
                {"case_id": case_id, "rendered_input_sha256": digest}
                for case_id, digest in requests
            ],
        },
        "pricing_snapshot": _pricing().record(),
        "pricing_snapshot_sha256": _pricing().sha256,
        "limits": {
            "reserved_worst_case_microusd": 100,
            "max_case_attributable_microusd": 100,
            "max_campaign_attributable_microusd": 2_000,
            "max_case_wall_ms": 60_000,
            "provider_timeout_ms": 10_000,
            "max_output_tokens": generator_module.OPENAI_MAX_OUTPUT_TOKENS,
        },
    }


def _case(index: int = 1) -> PreregisteredV02Case:
    return PreregisteredV02Case(
        id=f"rk-v0.2-{index:03d}",
        repo="owner/repo",
        issue_url=f"https://github.com/owner/repo/issues/{index}",
        base_sha=f"{index:040x}",
        difficulty="lt_15m",
        smoke=False,
        generator_projection_sha256="2" * 64,
        source_context_sha256="8" * 64,
        evaluator_commitment_sha256="3" * 64,
    )


def _candidate(issue_number: int = 1) -> ValidatedCandidate:
    return validate_candidate_payload(
        {
            "test_content": (
                "from demo import normalize\n\n"
                f"def test_issue_{issue_number}_reproduction():\n"
                "    actual = normalize('bug')\n"
                "    assert actual == 'fixed', 'wrong normalized output'\n"
            ),
            "expected_symptom": "wrong normalized output",
            "rationale": "Exercises the reported behavior directly.",
        },
        issue_number=issue_number,
    )


def _candidate_for_run(run: runner._RunContext) -> ValidatedCandidate:
    contract = runner._run_candidate_contract(run)
    if contract.profile == "pytest-v1":
        return _candidate(run.request.issue_number)
    return validate_candidate_payload(
        {
            "test_content": (
                "from sympy import Symbol\n\n"
                f"def {contract.test_function}():\n"
                "    actual = Symbol('x').is_commutative\n"
                "    assert actual is False, 'wrong normalized output'\n"
            ),
            "expected_symptom": "wrong normalized output",
            "rationale": "Exercises the reported SymPy behavior directly.",
        },
        issue_number=run.request.issue_number,
        required_test_function=contract.test_function,
    )


def test_generation_request_uses_native_sympy_profile_for_frozen_cases() -> None:
    case = _case(16)
    projection = runner._Projection(
        title="SymPy regression", body="Reported behavior is incorrect.", sha256="1" * 64
    )
    context = SimpleNamespace(source_context=SourceContext(("sympy/core/add.py",), (), 0))

    request = runner._generation_request(case, projection, cast(Any, context))

    assert request.candidate_profile == "sympy-native-v1"
    assert request.required_test_function == "test_reproassert_issue_016"
    assert request.to_dict()["candidate_contract"]["pytest_import_allowed"] is False


def test_adapter_config_binds_pytest_and_sympy_instruction_profiles() -> None:
    digest = runner._openai_adapter_config_sha256("gpt-test")
    pytest_payload = runner._openai_request_payload(
        GenerationRequest(
            issue_url="https://github.com/o/r/issues/1",
            issue_number=1,
            issue_title="x",
            issue_body="x",
            source_sha="0" * 40,
            source_context=SourceContext((), (), 0),
        ),
        "gpt-test",
    )
    sympy_payload = runner._openai_request_payload(
        GenerationRequest(
            issue_url="https://github.com/o/r/issues/1",
            issue_number=1,
            issue_title="x",
            issue_body="x",
            source_sha="0" * 40,
            source_context=SourceContext((), (), 0),
            candidate_profile="sympy-native-v1",
            required_test_function="test_reproassert_issue_016",
        ),
        "gpt-test",
    )

    assert len(digest) == 64
    assert pytest_payload["instructions"] != sympy_payload["instructions"]


def _run(tmp_path: Path, *, case: PreregisteredV02Case | None = None) -> runner._RunContext:
    frozen = case or _case()
    policy = _policy()
    attempt_directory = tmp_path / f"attempt-{frozen.id}"
    attempt_directory.mkdir(mode=0o700)
    context = SimpleNamespace(
        case=V02CaseIdentity(frozen.id, frozen.repo, frozen.issue_url, frozen.base_sha),
        source_evidence_sha256="4" * 64,
        source_tree_sha256="5" * 64,
        snapshot_sha256="6" * 64,
        algorithm="reproassert-source-context-v1",
        policy_sha256="7" * 64,
        context_sha256="8" * 64,
        source_context=SourceContext(("demo.py",), (), 0),
    )
    contract = v02_candidate_contract(case_id=frozen.id, issue_number=int(frozen.id[-3:]))
    request = GenerationRequest(
        issue_url=frozen.issue_url,
        issue_number=int(frozen.id[-3:]),
        issue_title="Normalizer returns the buggy value",
        issue_body="Calling normalize should return fixed output.",
        source_sha=frozen.base_sha,
        source_context=context.source_context,
        candidate_profile=contract.profile,
        required_test_function=(
            contract.test_function if contract.profile == "sympy-native-v1" else None
        ),
        attempt=1,
        feedback="",
    )
    rendered = runner._rendered_input_sha256(request)
    run = runner._RunContext(
        ledger_path=tmp_path / "events.jsonl",
        attempt_directory=attempt_directory,
        policy=policy,
        attempt_id=f"attempt_{frozen.id[-3:]}_{'a' * 16}",
        case=frozen,
        preregistration_sha256="9" * 64,
        cohort_sha256="a" * 64,
        source_context=cast(Any, context),
        request=request,
        rendered_input_sha256=rendered,
        runner_input_sha256="b" * 64,
    )
    runner._append_event(
        run,
        "attempt_started",
        {
            "started_at": runner._now(),
            "preregistration_sha256": run.preregistration_sha256,
            "cohort_sha256": run.cohort_sha256,
            "case": vars(frozen),
            "configuration": policy.configuration_record(),
            "source_context": {
                "algorithm": context.algorithm,
                "policy_sha256": context.policy_sha256,
                "sha256": context.context_sha256,
            },
            "runner_input_sha256": run.runner_input_sha256,
            "reserved_worst_case_microusd": policy.reserved_worst_case_microusd,
        },
        preflight=lambda snapshot: runner._preflight_attempt(snapshot, run),
    )
    return run


def _fake_response(issue_number: int = 1) -> bytes:
    candidate = _candidate(issue_number)
    return json.dumps(
        {
            "id": "resp_test_only",
            "model": "gpt-test-2026-07-10",
            "status": "completed",
            "usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14},
            "output_text": json.dumps(
                {
                    "test_content": candidate.test_content,
                    "expected_symptom": candidate.expected_symptom,
                    "rationale": candidate.rationale,
                }
            ),
        }
    ).encode()


def _seed_recoverable_generation(
    run: runner._RunContext,
    *,
    crash_point: str,
    usage_status: str = "reported",
    append_crash: bool = True,
) -> runner._GenerationTransaction:
    """Create an exact interrupted attempt without invoking any provider code."""

    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={"fixture": "recovery"},
    )
    generation_started_at = runner._start_phase(run, "generation")
    call_id = f"call_{run.request.issue_number:032x}"
    call_started_at = runner._now()
    runner._append_event(
        run,
        "model_call_started",
        {
            "call_id": call_id,
            "started_at": call_started_at,
            "execution_authorization_sha256": run.policy.execution_authorization_sha256,
            "provider": "openai",
            "endpoint_host": generator_module.OPENAI_API_HOST,
            "requested_model": run.policy.requested_model,
            "rendered_input_sha256": run.rendered_input_sha256,
            "config_sha256": runner._openai_adapter_config_sha256(run.policy.requested_model),
            "max_output_tokens": generator_module.OPENAI_MAX_OUTPUT_TOKENS,
            "pricing_snapshot_sha256": cast(runner.V02PricingSnapshot, run.policy.pricing).sha256,
            "reserved_worst_case_microusd": run.policy.reserved_worst_case_microusd,
            "runner_input_sha256": run.runner_input_sha256,
        },
    )
    usage: dict[str, object]
    if usage_status == "reported":
        usage = {
            "status": "reported",
            "input_tokens": 10,
            "cached_input_tokens": 0,
            "output_tokens": 4,
            "total_tokens": 14,
        }
    else:
        usage = {
            "status": "unknown",
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
        }
    finish: dict[str, object] = {
        "call_id": call_id,
        "status": "succeeded",
        "started_at": call_started_at,
        "completed_at": runner._now(),
        "duration_ms": 1,
        "response_model": "gpt-test-2026-07-10",
        "response_id_sha256": "d" * 64,
        "classification_code": "candidate_validated",
        "usage": usage,
    }
    path, _sha256, _bytes = runner._persist_generation_transaction(
        run,
        call_id=call_id,
        candidate=_candidate_for_run(run),
        model_finish=finish,
    )
    transaction = runner._load_generation_transaction(run)
    assert transaction.path == path
    ordered_points = (
        "after_candidate_fsync",
        "after_candidate_submitted",
        "after_model_finish",
        "after_model_cost",
        "before_differential",
    )
    point_index = ordered_points.index(crash_point)
    if point_index >= 1:
        runner._append_event(
            run,
            "candidate_submitted",
            {**runner._candidate_commit_payload(run, transaction), "submitted_at": runner._now()},
        )
    if point_index >= 2:
        runner._append_event(run, "model_call_finished", runner._model_finish_payload(transaction))
    if point_index >= 3:
        runner._record_model_cost(run, call_id=call_id, usage=usage)
    if point_index >= 4:
        runner._finish_phase(
            run,
            phase="generation",
            started_at=generation_started_at,
            started_monotonic=time.monotonic(),
            status="succeeded",
            classification_code=None,
            evidence={
                "candidate_sha256": transaction.candidate.sha256,
                "generation_artifact_sha256": transaction.sha256,
            },
        )
        runner._record_or_validate_recovery_artifact_cost(run, transaction.candidate)
    if append_crash:
        runner._append_event(
            run,
            "attempt_crashed",
            {
                "crashed_at": runner._now(),
                "classification_code": "injected_crash",
                "exception_type": "InjectedCrash",
                "cost_complete": False,
                "recovery_status": "manual_reconciliation_required_no_new_provider_call",
            },
        )
    return transaction


def _rewrite_event_chain(path: Path, events: list[dict[str, object]]) -> None:
    previous: str | None = None
    encoded = bytearray()
    for sequence, original in enumerate(events, start=1):
        event = dict(original)
        event["sequence"] = sequence
        event["previous_event_sha256"] = previous
        event["event_sha256"] = runner._event_sha256(cast(dict[str, Any], event))
        encoded.extend(runner._canonical_json(event) + b"\n")
        previous = cast(str, event["event_sha256"])
    path.write_bytes(bytes(encoded))


def _append_attempt_start(run: runner._RunContext) -> None:
    runner._append_event(
        run,
        "attempt_started",
        {
            "started_at": runner._now(),
            "preregistration_sha256": run.preregistration_sha256,
            "cohort_sha256": run.cohort_sha256,
            "case": vars(run.case),
            "configuration": run.policy.configuration_record(),
            "source_context": {
                "algorithm": run.source_context.algorithm,
                "policy_sha256": run.source_context.policy_sha256,
                "sha256": run.source_context.context_sha256,
            },
            "runner_input_sha256": run.runner_input_sha256,
            "reserved_worst_case_microusd": run.policy.reserved_worst_case_microusd,
        },
    )


def _campaign_case(index: int) -> PreregisteredV02Case:
    repository = f"owner/repo{(index + 1) // 2}"
    return PreregisteredV02Case(
        id=f"rk-v0.2-{index:03d}",
        repo=repository,
        issue_url=f"https://github.com/{repository}/issues/{index}",
        base_sha=f"{index:040x}",
        difficulty="lt_15m" if index <= 14 else "15m_to_1h",
        smoke=index in {4, 6, 10, 11, 18},
        generator_projection_sha256=f"{index + 100:064x}",
        evaluator_commitment_sha256=f"{index + 200:064x}",
        source_context_sha256=f"{index + 300:064x}",
    )


def _campaign_run(
    tmp_path: Path,
    *,
    case: PreregisteredV02Case,
    preregistration_sha256: str,
    cohort_sha256: str,
    ledger_path: Path,
    request_set_sha256: str | None = None,
) -> runner._RunContext:
    index = int(case.id[-3:])
    attempt_directory = tmp_path / f"campaign-attempt-{index:03d}"
    attempt_directory.mkdir(mode=0o700)
    source_context = SimpleNamespace(
        case=V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha),
        source_evidence_sha256=f"{index + 400:064x}",
        source_tree_sha256=f"{index + 500:064x}",
        snapshot_sha256=f"{index + 600:064x}",
        algorithm="reproassert-source-context-v1",
        policy_sha256=f"{index + 700:064x}",
        context_sha256=case.source_context_sha256,
        source_context=SourceContext(("demo.py",), (), 0),
    )
    contract = v02_candidate_contract(case_id=case.id, issue_number=index)
    request = GenerationRequest(
        issue_url=case.issue_url,
        issue_number=index,
        issue_title=f"Issue {index}",
        issue_body="Reported behavior should be reproduced.",
        source_sha=case.base_sha,
        source_context=source_context.source_context,
        candidate_profile=contract.profile,
        required_test_function=(
            contract.test_function if contract.profile == "sympy-native-v1" else None
        ),
        attempt=1,
        feedback="",
    )
    run = runner._RunContext(
        ledger_path=ledger_path,
        attempt_directory=attempt_directory,
        policy=_policy(),
        attempt_id=f"attempt_{index:03d}_{index:032x}",
        case=case,
        preregistration_sha256=preregistration_sha256,
        cohort_sha256=cohort_sha256,
        source_context=cast(Any, source_context),
        request=request,
        rendered_input_sha256=runner._rendered_input_sha256(request),
        runner_input_sha256=f"{index + 800:064x}",
        preregistration_request_set_sha256=request_set_sha256,
    )
    _append_attempt_start(run)
    return run


def _freeze_campaign_disposition(
    run: runner._RunContext,
    *,
    candidate_submitted: bool,
    recover_generation: bool = True,
) -> None:
    if candidate_submitted:
        transaction = _seed_recoverable_generation(
            run,
            crash_point="before_differential",
            append_crash=recover_generation,
        )
        if recover_generation:
            runner._recover_generation_without_provider(run)
        runner._append_event(
            run,
            "generation_disposition_frozen",
            {
                "status": "candidate_submitted",
                "candidate_sha256": transaction.candidate.sha256,
                "classification_code": None,
                "frozen_at": runner._now(),
            },
        )
        return
    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={"fixture": "no-candidate"},
    )
    started_at = runner._start_phase(run, "generation")
    runner._finish_phase(
        run,
        phase="generation",
        started_at=started_at,
        started_monotonic=time.monotonic(),
        status="failed",
        classification_code="generator_abstained",
        evidence={},
    )
    runner._ensure_generation_costs(run, candidate=None)
    runner._append_event(
        run,
        "generation_disposition_frozen",
        {
            "status": "no_candidate",
            "candidate_sha256": None,
            "classification_code": "generator_abstained",
            "frozen_at": runner._now(),
        },
    )


def _exact_scored_barrier_fixture(
    tmp_path: Path,
    *,
    selected_index: int,
    selected_candidate: bool = True,
    authentic_selected_recovery: bool = False,
) -> tuple[
    runner._RunContext,
    Path,
    runner.VerifiedV02CampaignGenerationBarrier,
    exact_preregistration_module.VerifiedV02ExactPreregistration,
]:
    rows: list[dict[str, object]] = []
    selected_context: issuer.VerifiedV02GeneratorSourceContext | None = None
    selected_request: GenerationRequest | None = None
    selected_projection_sha256: str | None = None
    for index in range(1, 21):
        case = _campaign_case(index)
        contract = v02_candidate_contract(case_id=case.id, issue_number=index)
        source_context = SourceContext(("demo.py",), (), 0)
        projection_sha256 = case.generator_projection_sha256
        if authentic_selected_recovery and index == selected_index:
            title = f"Issue {index}"
            body = "Reported behavior should be reproduced."
            snapshot = canonical_snapshot_content_bytes(title=title, body=body)
            projection = generator_projection_bytes(
                V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha),
                {
                    "title": title,
                    "body": body,
                    "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
                },
            )
            projection_path = tmp_path / "exact-selected-projection.json"
            projection_path.write_bytes(projection)
            projection_path.chmod(0o600)
            projection_sha256 = hashlib.sha256(projection).hexdigest()
            identity = V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha)
            context_record = {
                "algorithm": issuer.V02_SOURCE_CONTEXT_ALGORITHM,
                "policy_sha256": issuer.V02_SOURCE_CONTEXT_POLICY_SHA256,
                "case": vars(identity),
                "source_evidence_sha256": f"{index + 400:064x}",
                "source_tree_sha256": f"{index + 500:064x}",
                "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
                "context": source_context.to_dict(),
            }
            context = object.__new__(issuer.VerifiedV02GeneratorSourceContext)
            for name, value in {
                "case": identity,
                "source_evidence_sha256": f"{index + 400:064x}",
                "source_tree_sha256": f"{index + 500:064x}",
                "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
                "algorithm": issuer.V02_SOURCE_CONTEXT_ALGORITHM,
                "policy_sha256": issuer.V02_SOURCE_CONTEXT_POLICY_SHA256,
                "context_sha256": issuer._json_sha256(context_record),
                "source_context": source_context,
                "_issuer": issuer._CONTEXT_ISSUER,
            }.items():
                object.__setattr__(context, name, value)
            selected_context = issuer.require_v02_generator_source_context(context)
        request = GenerationRequest(
            issue_url=case.issue_url,
            issue_number=index,
            issue_title=f"Issue {index}",
            issue_body="Reported behavior should be reproduced.",
            source_sha=case.base_sha,
            source_context=source_context,
            candidate_profile=contract.profile,
            required_test_function=(
                contract.test_function if contract.profile == "sympy-native-v1" else None
            ),
            attempt=1,
            feedback="",
        )
        if authentic_selected_recovery and index == selected_index:
            selected_request = request
            selected_projection_sha256 = projection_sha256
        row: dict[str, object] = {
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
            "generator_projection_sha256": projection_sha256,
            "instance_id": f"instance-{index}",
            "issue_url": case.issue_url,
            "mapping_selected_hunks_sha256": f"{index + 900:064x}",
            "outbound_request_sha256": runner._outbound_request_sha256(request, "gpt-test"),
            "rendered_input_sha256": runner._rendered_input_sha256(request),
            "repo": case.repo,
            "request_envelope_sha256": f"{index + 1_000:064x}",
            "smoke": case.smoke,
            "source_projection_commitment_sha256": case.source_context_sha256,
            "test_command_profile": (
                "sympy-bin-test-v1" if contract.profile == "sympy-native-v1" else "pytest-v1"
            ),
        }
        row["case_commitment_sha256"] = runner._sha256_json(row)
        rows.append(row)
    record: dict[str, object] = {
        "algorithm": exact_preregistration_module.ALGORITHM,
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
        "frozen_at": "2026-07-10T00:00:00Z",
        "policy": {},
        "request_set_sha256": "e" * 64,
        "schema_version": "1.0.0",
        "status": "frozen_preinference_exact_image",
        "tool_git_sha": "1" * 40,
    }
    record["preregistration_sha256"] = exact_preregistration_module._self_hash(record)
    preregistration_path = tmp_path / "exact-scored-preregistration.json"
    preregistration_path.write_bytes(exact_preregistration_module._canonical(record) + b"\n")
    loaded = runner.load_v02_scored_preregistration(preregistration_path)
    ledger_path = tmp_path / "exact-scored-events.jsonl"
    selected: runner._RunContext | None = None
    for index, case in enumerate(loaded.cases, start=1):
        if authentic_selected_recovery and index == selected_index:
            assert selected_context is not None
            assert selected_request is not None
            assert selected_projection_sha256 is not None
            case = replace(case, source_context_sha256=selected_context.context_sha256)
            attempt_directory = tmp_path / f"campaign-attempt-{index:03d}"
            attempt_directory.mkdir(mode=0o700)
            context_record = runner._source_context_record(selected_context)
            rendered_input_sha256 = runner._rendered_input_sha256(selected_request)
            run = runner._RunContext(
                ledger_path=ledger_path,
                attempt_directory=attempt_directory,
                policy=_policy(),
                attempt_id=f"attempt_{index:03d}_{index:032x}",
                case=case,
                preregistration_sha256=loaded.raw_sha256,
                cohort_sha256=loaded.cohort_sha256,
                source_context=selected_context,
                request=selected_request,
                rendered_input_sha256=rendered_input_sha256,
                runner_input_sha256=runner._runner_input_digest(
                    preregistration_sha256=loaded.raw_sha256,
                    preregistration_request_set_sha256=loaded.request_set_sha256,
                    cohort_sha256=loaded.cohort_sha256,
                    case_record=vars(case),
                    generator_projection_sha256=selected_projection_sha256,
                    context_record=context_record,
                    rendered_input_sha256=rendered_input_sha256,
                    configuration_sha256=_policy().configuration_sha256,
                ),
                preregistration_request_set_sha256=loaded.request_set_sha256,
            )
            _append_attempt_start(run)
        else:
            run = _campaign_run(
                tmp_path,
                case=case,
                preregistration_sha256=loaded.raw_sha256,
                cohort_sha256=loaded.cohort_sha256,
                ledger_path=ledger_path,
                request_set_sha256=loaded.request_set_sha256,
            )
        _freeze_campaign_disposition(
            run,
            candidate_submitted=(selected_candidate if index == selected_index else True),
        )
        if index == selected_index:
            selected = run
    assert selected is not None
    barrier = runner.freeze_v02_campaign_generation_barrier(
        preregistration_path=preregistration_path,
        ledger_path=ledger_path,
        policy=_policy(),
    )
    authority = object.__new__(exact_preregistration_module.VerifiedV02ExactPreregistration)
    for name, value in {
        "path": preregistration_path,
        "sha256": loaded.raw_sha256,
        "cohort_sha256": loaded.cohort_sha256,
        "request_set_sha256": loaded.request_set_sha256,
        "case_count": 20,
        "evaluator_preflight_ready_count": 19,
        "infrastructure_failure_count": 1,
        "provider_calls": 0,
        "_issuer": exact_preregistration_module._ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return selected, preregistration_path, barrier, authority


def test_default_is_no_provider_and_public_api_accepts_no_generator_callback() -> None:
    with pytest.raises(PolicyRejection, match="defaults to no provider"):
        runner.V02ScoredRunPolicy().require_executable()
    parameters = inspect.signature(runner.run_v02_scored_case).parameters
    assert "generator" not in parameters
    assert "observer" not in parameters
    assert "command" not in parameters
    assert "callback" not in parameters
    for api in (
        runner.generate_v02_scored_case,
        runner.recover_v02_scored_case,
        runner.freeze_v02_campaign_generation_barrier,
    ):
        api_parameters = inspect.signature(api).parameters
        assert "evaluator_capability" not in api_parameters
        assert "fixed_source" not in api_parameters
        assert "feedback" not in api_parameters
    for api in (runner.generate_v02_scored_case, runner.recover_v02_scored_case):
        assert "execution_authorization_path" in inspect.signature(api).parameters

    with pytest.raises(PolicyRejection, match="campaign freeze"):
        _policy(campaign_freeze_sha256=None).require_executable()
    with pytest.raises(PolicyRejection, match="execution authorization"):
        _policy(execution_authorization_sha256=None).require_executable()
    with pytest.raises(PolicyRejection, match="application-issued"):
        runner.require_v02_execution_authorization(SimpleNamespace())
    assert _policy().configuration_record()["campaign_freeze_sha256"] == "9" * 64


@pytest.mark.parametrize("case_index", [1, 16, 17])
def test_exact_scored_entry_evaluates_pytest_and_sympy_after_exact_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_index: int,
) -> None:
    run, preregistration_path, barrier, authority = _exact_scored_barrier_fixture(
        tmp_path, selected_index=case_index
    )
    observed: list[Any] = []
    receipt = SimpleNamespace(
        path=run.attempt_directory / exact_scored.RECEIPT_FILENAME,
        sha256="a" * 64,
        case_id=run.case.id,
        classification="verified_reproduction",
        accepted=True,
    )
    capability = SimpleNamespace(
        case_id=run.case.id,
        evaluator_public_commitment_sha256=run.case.evaluator_commitment_sha256,
        gold_smoke_classification="semantic_valid",
        gold_smoke_reason="fails_on_base_passes_on_fixed",
    )

    def evaluate(**kwargs: object) -> Any:
        artifact = cast(Any, kwargs["candidate"])
        observed.append(artifact)
        candidate_sha = hashlib.sha256(artifact.content).hexdigest()
        cast(Path, kwargs["output_path"]).write_bytes(
            exact_scored._canonical({"candidate": {"sha256": candidate_sha}})
        )
        return receipt

    monkeypatch.setattr(exact_scored.runner, "_prepare_recovery_context", lambda **_kw: run)
    monkeypatch.setattr(
        exact_scored, "require_v02_exact_image_evaluator_capability", lambda value: value
    )
    monkeypatch.setattr(exact_scored, "hidden_case_artifacts", lambda _authority, _case: {})
    monkeypatch.setattr(exact_scored, "evaluate_instance_candidate", evaluate)
    monkeypatch.setattr(
        exact_scored, "_verify_reusable_receipt", lambda _path, _run, _artifact: receipt
    )

    kwargs = {
        "preregistration_path": preregistration_path,
        "exact_preregistration": authority,
        "case_id": run.case.id,
        "generator_projection_path": tmp_path / "unused-projection.json",
        "generator_source_context": run.source_context,
        "campaign_barrier": barrier,
        "evaluator_capability": cast(Any, capability),
        "verified_hidden": cast(Any, object()),
        "manifest_path": tmp_path / "unused-manifest.json",
        "expected_manifest_sha256": "b" * 64,
        "gold_smoke_receipt_path": tmp_path / "unused-gold.json",
        "gold_specs_path": tmp_path / "unused-specs.json",
        "ledger_path": run.ledger_path,
        "attempt_directory": run.attempt_directory,
        "attempt_id": run.attempt_id,
        "executed_at": "2026-07-11T00:00:00Z",
        "tool_git_sha": "1" * 40,
        "policy": run.policy,
    }
    result = exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    contract = runner._run_candidate_contract(run)
    assert result.evaluation_kind == "exact_image_receipt"
    assert observed[0].relative_path == contract.relative_path
    assert observed[0].test_function == contract.test_function
    before = len(runner.read_v02_scored_ledger(run.ledger_path).events)
    repeated = exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    assert repeated.terminal_event_sha256 == result.terminal_event_sha256
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == before
    assert len(observed) == 1


def test_exact_scored_no_candidate_never_requires_hidden_or_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, preregistration_path, barrier, authority = _exact_scored_barrier_fixture(
        tmp_path, selected_index=1, selected_candidate=False
    )
    monkeypatch.setattr(exact_scored.runner, "_prepare_recovery_context", lambda **_kw: run)
    result = exact_scored.evaluate_v02_exact_frozen_case(
        preregistration_path=preregistration_path,
        exact_preregistration=authority,
        case_id=run.case.id,
        generator_projection_path=tmp_path / "unused-projection.json",
        generator_source_context=run.source_context,
        campaign_barrier=barrier,
        evaluator_capability=None,
        verified_hidden=None,
        manifest_path=tmp_path / "unused-manifest.json",
        expected_manifest_sha256="b" * 64,
        gold_smoke_receipt_path=tmp_path / "unused-gold.json",
        gold_specs_path=tmp_path / "unused-specs.json",
        ledger_path=run.ledger_path,
        attempt_directory=run.attempt_directory,
        attempt_id=run.attempt_id,
        executed_at="2026-07-11T00:00:00Z",
        tool_git_sha="1" * 40,
        policy=run.policy,
    )
    assert result.evaluation_kind == "no_candidate"
    assert result.outcome == "no_output"


def test_exact_scored_recovery_reconstructs_exact_authorized_input_without_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, preregistration_path, barrier, authority = _exact_scored_barrier_fixture(
        tmp_path,
        selected_index=1,
        selected_candidate=False,
        authentic_selected_recovery=True,
    )
    projection_path = tmp_path / "exact-selected-projection.json"
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("exact recovery must never call the provider")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    reconstructed = runner._prepare_recovery_context(
        preregistration_path=preregistration_path,
        case_id=run.case.id,
        generator_projection_path=projection_path,
        generator_source_context=run.source_context,
        ledger_path=run.ledger_path,
        attempt_directory=run.attempt_directory,
        attempt_id=run.attempt_id,
        policy=run.policy,
    )
    assert reconstructed.runner_input_sha256 == run.runner_input_sha256
    assert reconstructed.preregistration_request_set_sha256 == authority.request_set_sha256
    assert barrier.execution_authorization_sha256 == run.policy.execution_authorization_sha256

    kwargs = {
        "preregistration_path": preregistration_path,
        "exact_preregistration": authority,
        "case_id": run.case.id,
        "generator_projection_path": projection_path,
        "generator_source_context": run.source_context,
        "campaign_barrier": barrier,
        "evaluator_capability": None,
        "verified_hidden": None,
        "manifest_path": tmp_path / "unused-manifest.json",
        "expected_manifest_sha256": "b" * 64,
        "gold_smoke_receipt_path": tmp_path / "unused-gold.json",
        "gold_specs_path": tmp_path / "unused-specs.json",
        "ledger_path": run.ledger_path,
        "attempt_directory": run.attempt_directory,
        "attempt_id": run.attempt_id,
        "executed_at": "2026-07-11T00:00:00Z",
        "tool_git_sha": "1" * 40,
        "policy": run.policy,
    }
    first = exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    event_count = len(runner.read_v02_scored_ledger(run.ledger_path).events)
    replay = exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    assert first.evaluation_kind == "no_candidate"
    assert replay.terminal_event_sha256 == first.terminal_event_sha256
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == event_count
    assert provider_calls == 0


def test_exact_scored_reuses_durable_receipt_after_pre_result_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, preregistration_path, barrier, authority = _exact_scored_barrier_fixture(
        tmp_path,
        selected_index=1,
        authentic_selected_recovery=True,
    )
    receipt = SimpleNamespace(
        path=run.attempt_directory / exact_scored.RECEIPT_FILENAME,
        sha256="a" * 64,
        case_id=run.case.id,
        classification="verified_reproduction",
        accepted=True,
    )
    capability = SimpleNamespace(
        case_id=run.case.id,
        evaluator_public_commitment_sha256=run.case.evaluator_commitment_sha256,
        gold_smoke_classification="semantic_valid",
        gold_smoke_reason="fails_on_base_passes_on_fixed",
    )
    evaluator_calls = 0
    provider_calls = 0

    def evaluate(**kwargs: object) -> Any:
        nonlocal evaluator_calls
        evaluator_calls += 1
        cast(Path, kwargs["output_path"]).write_text("{}")
        return receipt

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("receipt recovery must not call the provider")

    original_write_result = exact_scored._write_result
    write_attempts = 0

    def crash_once(*args: object, **kwargs: object) -> Any:
        nonlocal write_attempts
        write_attempts += 1
        if write_attempts == 1:
            raise RuntimeError("simulated crash after durable receipt")
        return original_write_result(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    monkeypatch.setattr(
        exact_scored, "require_v02_exact_image_evaluator_capability", lambda value: value
    )
    monkeypatch.setattr(exact_scored, "hidden_case_artifacts", lambda _authority, _case: {})
    monkeypatch.setattr(exact_scored, "evaluate_instance_candidate", evaluate)
    monkeypatch.setattr(
        exact_scored, "_verify_reusable_receipt", lambda _path, _run, _artifact: receipt
    )
    monkeypatch.setattr(exact_scored, "_write_result", crash_once)
    kwargs = {
        "preregistration_path": preregistration_path,
        "exact_preregistration": authority,
        "case_id": run.case.id,
        "generator_projection_path": tmp_path / "exact-selected-projection.json",
        "generator_source_context": run.source_context,
        "campaign_barrier": barrier,
        "evaluator_capability": cast(Any, capability),
        "verified_hidden": cast(Any, object()),
        "manifest_path": tmp_path / "unused-manifest.json",
        "expected_manifest_sha256": "b" * 64,
        "gold_smoke_receipt_path": tmp_path / "unused-gold.json",
        "gold_specs_path": tmp_path / "unused-specs.json",
        "ledger_path": run.ledger_path,
        "attempt_directory": run.attempt_directory,
        "attempt_id": run.attempt_id,
        "executed_at": "2026-07-11T00:00:00Z",
        "tool_git_sha": "1" * 40,
        "policy": run.policy,
    }
    with pytest.raises(RuntimeError, match="simulated crash"):
        exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    result = exact_scored.evaluate_v02_exact_frozen_case(**kwargs)
    assert result.evaluation_kind == "exact_image_receipt"
    assert evaluator_calls == 1
    assert provider_calls == 0


def test_exact_scored_case014_preserves_offline_network_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, preregistration_path, barrier, authority = _exact_scored_barrier_fixture(
        tmp_path, selected_index=14
    )
    capability = SimpleNamespace(
        case_id=run.case.id,
        evaluator_public_commitment_sha256=run.case.evaluator_commitment_sha256,
        gold_smoke_classification="infrastructure_failure",
        gold_smoke_reason="network_dependency",
    )
    evaluator_calls = 0

    def forbidden_evaluator(**_kwargs: object) -> Any:
        nonlocal evaluator_calls
        evaluator_calls += 1
        raise AssertionError("case 014 must remain offline")

    monkeypatch.setattr(exact_scored.runner, "_prepare_recovery_context", lambda **_kw: run)
    monkeypatch.setattr(
        exact_scored, "require_v02_exact_image_evaluator_capability", lambda value: value
    )
    monkeypatch.setattr(exact_scored, "hidden_case_artifacts", lambda _authority, _case: {})
    monkeypatch.setattr(exact_scored, "evaluate_instance_candidate", forbidden_evaluator)
    result = exact_scored.evaluate_v02_exact_frozen_case(
        preregistration_path=preregistration_path,
        exact_preregistration=authority,
        case_id=run.case.id,
        generator_projection_path=tmp_path / "unused-projection.json",
        generator_source_context=run.source_context,
        campaign_barrier=barrier,
        evaluator_capability=cast(Any, capability),
        verified_hidden=cast(Any, object()),
        manifest_path=tmp_path / "unused-manifest.json",
        expected_manifest_sha256="b" * 64,
        gold_smoke_receipt_path=tmp_path / "unused-gold.json",
        gold_specs_path=tmp_path / "unused-specs.json",
        ledger_path=run.ledger_path,
        attempt_directory=run.attempt_directory,
        attempt_id=run.attempt_id,
        executed_at="2026-07-11T00:00:00Z",
        tool_git_sha="1" * 40,
        policy=run.policy,
    )
    assert evaluator_calls == 0
    assert result.evaluation_kind == "infrastructure_failure"
    assert result.outcome == "benchmark_infrastructure_error"
    public = exact_scored.verify_v02_exact_scored_result(result.public_result_path).record
    assert public["evaluation"]["classification"] == "network_dependency"  # type: ignore[index]
    assert public["claims"]["network_enabled"] is False  # type: ignore[index]


def test_exact_preregistration_authority_is_not_directly_constructible() -> None:
    with pytest.raises(TypeError, match="verifier-issued"):
        exact_preregistration_module.VerifiedV02ExactPreregistration()
    with pytest.raises(PolicyRejection, match="Fresh verifier-issued"):
        exact_preregistration_module.require_v02_exact_preregistration(SimpleNamespace())


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_top_level",
        "wrong_version",
        "bad_reference",
        "text_digest",
        "campaign_fields",
        "tool_sha",
        "provider_fields",
        "provider_identity",
        "request_algorithm",
        "request_count",
        "request_length",
        "request_fields",
        "request_case",
        "pricing_fields",
        "limits_fields",
        "zero_limit",
        "output_cap",
    ],
)
def test_execution_authorization_record_rejects_noncanonical_or_unsafe_fields(
    mutation: str,
) -> None:
    record = _authorization_record()
    if mutation == "extra_top_level":
        record["unexpected"] = True
    elif mutation == "wrong_version":
        record["algorithm"] = "wrong"
    elif mutation == "bad_reference":
        record["authorization_ref"] = ""
    elif mutation == "text_digest":
        record["authorization_text_sha256"] = "f" * 64
    elif mutation == "campaign_fields":
        del record["campaign"]["cohort_sha256"]
    elif mutation == "tool_sha":
        record["campaign"]["tool_git_sha"] = "z" * 40
    elif mutation == "provider_fields":
        record["provider"]["unexpected"] = True
    elif mutation == "provider_identity":
        record["provider"]["name"] = "other"
    elif mutation == "request_algorithm":
        record["request_set"]["algorithm"] = "wrong"
    elif mutation == "request_count":
        record["request_set"]["request_count"] = 19
    elif mutation == "request_length":
        record["request_set"]["requests"].pop()
    elif mutation == "request_fields":
        record["request_set"]["requests"][0]["unexpected"] = True
    elif mutation == "request_case":
        record["request_set"]["requests"][0]["case_id"] = "bad"
    elif mutation == "pricing_fields":
        record["pricing_snapshot"]["unexpected"] = True
    elif mutation == "limits_fields":
        del record["limits"]["provider_timeout_ms"]
    elif mutation == "zero_limit":
        record["limits"]["max_case_wall_ms"] = 0
    elif mutation == "output_cap":
        record["limits"]["max_output_tokens"] += 1
    with pytest.raises(PolicyRejection):
        runner._validate_execution_authorization_record(record)


@pytest.mark.parametrize(
    "changes",
    [
        {"reserved_worst_case_microusd": True},
        {"reserved_worst_case_microusd": 101},
        {"provider_timeout_seconds": 0.5},
        {"provider_timeout_seconds": float("inf")},
    ],
)
def test_execution_authorization_limits_reject_invalid_caps_and_timeouts(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "reserved_worst_case_microusd": 100,
        "max_case_attributable_microusd": 100,
        "max_campaign_attributable_microusd": 2_000,
        "max_case_wall_ms": 60_000,
        "provider_timeout_seconds": 10,
    }
    values.update(changes)
    with pytest.raises(PolicyRejection):
        runner._validated_execution_limits(**values)  # type: ignore[arg-type]


def test_execution_request_normalization_rejects_wrong_cohort_and_bad_digest() -> None:
    expected = tuple(f"rk-v0.2-{index:03d}" for index in range(1, 21))
    with pytest.raises(PolicyRejection, match="differ from the frozen cohort"):
        runner._normalized_execution_requests({}, expected_case_ids=expected)
    bindings = {case_id: f"{index:064x}" for index, case_id in enumerate(expected, start=1)}
    bindings[expected[0]] = "not-a-digest"
    with pytest.raises(PolicyRejection):
        runner._normalized_execution_requests(bindings, expected_case_ids=expected)


@pytest.mark.parametrize("content", [b"", b"{}\n", b"[]", b"{not-json}"])
def test_public_pricing_loader_rejects_empty_noncanonical_or_nonobject_json(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "bad-pricing.json"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(PolicyRejection):
        runner.load_v02_pricing_snapshot(path)


def test_pricing_record_loader_rejects_wrong_shape_algorithm_and_types() -> None:
    extra = _pricing().record()
    extra["unexpected"] = 1
    wrong_algorithm = {**_pricing().record(), "algorithm": "wrong"}
    wrong_type = {**_pricing().record(), "provider": None}
    for value in (extra, wrong_algorithm, wrong_type):
        with pytest.raises(PolicyRejection):
            runner._pricing_from_record(value)


def test_generation_api_freezes_candidate_or_abstention_without_evaluator_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir(mode=0o700)
    candidate_run = _run(candidate_root)
    provider_calls = 0
    evaluator_accesses = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        assert api_key == "sk-test-only"
        assert timeout_seconds > 0
        return _fake_response()

    def forbidden_capability(_value: object) -> Any:
        nonlocal evaluator_accesses
        evaluator_accesses += 1
        raise AssertionError("generation touched evaluator authority")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)
    monkeypatch.setattr(runner, "require_v02_evaluator_capability", forbidden_capability)
    monkeypatch.setattr(runner, "_start_new_scored_attempt", lambda **_kwargs: candidate_run)
    call = {
        "preregistration_path": tmp_path / "unused-preregistration.json",
        "campaign_freeze_path": tmp_path / "unused-campaign-freeze.json",
        "execution_authorization_path": tmp_path / "unused-execution-authorization.json",
        "case_id": candidate_run.case.id,
        "generator_projection_path": tmp_path / "unused-projection.json",
        "generator_source_context": candidate_run.source_context,
        "ledger_path": candidate_run.ledger_path,
        "attempt_directory": candidate_run.attempt_directory,
        "policy": candidate_run.policy,
    }
    submitted = runner.generate_v02_scored_case(**call)  # type: ignore[arg-type]
    assert submitted.status == "candidate_submitted"
    assert submitted.candidate_sha256 == _candidate().sha256
    assert provider_calls == 1
    assert evaluator_accesses == 0

    abstention_root = tmp_path / "abstention"
    abstention_root.mkdir(mode=0o700)
    abstention_run = _run(abstention_root)
    monkeypatch.setattr(runner, "_start_new_scored_attempt", lambda **_kwargs: abstention_run)
    monkeypatch.setattr(
        runner,
        "_run_transactional_openai_generation",
        lambda _run: (_ for _ in ()).throw(
            runner._ControlledFailure("no_output", "generator_abstained")
        ),
    )
    abstained = runner.generate_v02_scored_case(
        **{
            **call,
            "case_id": abstention_run.case.id,
            "generator_source_context": abstention_run.source_context,
            "ledger_path": abstention_run.ledger_path,
            "attempt_directory": abstention_run.attempt_directory,
            "policy": abstention_run.policy,
        }  # type: ignore[arg-type]
    )
    assert abstained.status == "no_candidate"
    assert abstained.candidate_sha256 is None
    assert abstained.classification_code == "generator_abstained"
    assert provider_calls == 1
    assert evaluator_accesses == 0


@pytest.mark.parametrize("invalid_freeze", ["wrong_digest", "future_preparation"])
def test_generation_verifies_campaign_freeze_before_attempt_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_freeze: str,
) -> None:
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("invalid campaign freeze reached provider")

    frozen = SimpleNamespace(
        raw_sha256="a" * 64 if invalid_freeze == "wrong_digest" else "9" * 64,
        campaign_id="campaign_v02_test",
        case_ids=("rk-v0.2-001",),
        decoded={
            "prepared_at": (
                "2999-01-01T00:00:00Z"
                if invalid_freeze == "future_preparation"
                else "2026-07-09T00:00:00Z"
            ),
            "tool": {"git_sha": "1" * 40},
        },
    )
    monkeypatch.setattr(campaign, "verify_v02_campaign_freeze", lambda *_args: frozen)
    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    with pytest.raises(PolicyRejection, match=r"campaign freeze|Campaign preparation"):
        runner.generate_v02_scored_case(
            preregistration_path=tmp_path / "unused-preregistration.json",
            campaign_freeze_path=tmp_path / "unused-campaign-freeze.json",
            execution_authorization_path=tmp_path / "unused-execution-authorization.json",
            case_id="rk-v0.2-001",
            generator_projection_path=tmp_path / "unused-projection.json",
            generator_source_context=cast(Any, object()),
            ledger_path=tmp_path / "events.jsonl",
            attempt_directory=tmp_path / "attempt",
            policy=_policy(),
        )
    assert provider_calls == 0
    assert not (tmp_path / "events.jsonl").exists()


def test_real_attempt_start_binds_preregistration_projection_and_nominal_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = V02CaseIdentity(
        "rk-v0.2-001",
        "owner/repo1",
        "https://github.com/owner/repo1/issues/1",
        f"{1:040x}",
    )
    title = "Normalizer returns the buggy value"
    body = "Calling normalize should return fixed output."
    snapshot = canonical_snapshot_content_bytes(title=title, body=body)
    projection = generator_projection_bytes(
        identity,
        {
            "title": title,
            "body": body,
            "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        },
    )
    projection_path = tmp_path / "real-generator-projection.json"
    projection_path.write_bytes(projection)
    projection_path.chmod(0o600)

    source_context = SourceContext(("demo.py",), (), 0)
    context_record = {
        "algorithm": issuer.V02_SOURCE_CONTEXT_ALGORITHM,
        "policy_sha256": issuer.V02_SOURCE_CONTEXT_POLICY_SHA256,
        "case": vars(identity),
        "source_evidence_sha256": "4" * 64,
        "source_tree_sha256": "5" * 64,
        "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "context": source_context.to_dict(),
    }
    context = object.__new__(issuer.VerifiedV02GeneratorSourceContext)
    for name, value in {
        "case": identity,
        "source_evidence_sha256": "4" * 64,
        "source_tree_sha256": "5" * 64,
        "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "algorithm": issuer.V02_SOURCE_CONTEXT_ALGORITHM,
        "policy_sha256": issuer.V02_SOURCE_CONTEXT_POLICY_SHA256,
        "context_sha256": issuer._json_sha256(context_record),
        "source_context": source_context,
    }.items():
        object.__setattr__(context, name, value)
    object.__setattr__(context, "_issuer", issuer._CONTEXT_ISSUER)
    issuer.require_v02_generator_source_context(context)

    cases = [
        PreregisteredV02Case(
            id=f"rk-v0.2-{index:03d}",
            repo=f"owner/repo{(index + 1) // 2}",
            issue_url=f"https://github.com/owner/repo{(index + 1) // 2}/issues/{index}",
            base_sha=f"{index:040x}",
            difficulty="lt_15m" if index <= 14 else "15m_to_1h",
            smoke=index in {4, 6, 10, 11, 18},
            generator_projection_sha256=(
                hashlib.sha256(projection).hexdigest() if index == 1 else f"{index + 100:064x}"
            ),
            evaluator_commitment_sha256=f"{index + 200:064x}",
            source_context_sha256=(context.context_sha256 if index == 1 else f"{index + 300:064x}"),
        )
        for index in range(1, 21)
    ]
    preregistration_path = tmp_path / "real-preregistration.json"
    preregistration_path.write_bytes(
        canonical_preregistration_bytes(
            build_v02_preregistration(
                cases,
                frozen_at="2026-07-10T00:00:00Z",
                tool_name="reproassert",
                tool_version="0.2-test",
                tool_git_sha="1" * 40,
            )
        )
    )
    campaign_freeze_path = campaign.prepare_v02_campaign_freeze(
        preregistration_path,
        tmp_path / "real-campaign-freeze.json",
        campaign_id="campaign_v02_test",
        prepared_at="2026-07-09T00:00:00Z",
        tool_name="reproassert",
        tool_version="0.2-test",
        tool_git_sha="1" * 40,
    )
    verified_freeze = campaign.verify_v02_campaign_freeze(
        campaign_freeze_path, preregistration_path
    )
    request = GenerationRequest(
        issue_url=identity.issue_url,
        issue_number=1,
        issue_title=title,
        issue_body=body,
        source_sha=identity.base_sha,
        source_context=source_context,
        attempt=1,
        feedback="",
    )
    request_bindings = {
        case.id: (
            runner._rendered_input_sha256(request) if case.id == identity.id else f"{500 + i:064x}"
        )
        for i, case in enumerate(cases, start=1)
    }
    pricing_path = tmp_path / "pricing-snapshot.json"
    pricing_path.write_bytes(runner._canonical_json(_pricing().record()))
    pricing_path.chmod(0o600)
    assert runner.load_v02_pricing_snapshot(pricing_path) == _pricing()
    request_bindings_path = tmp_path / "request-bindings.json"
    request_bindings_path.write_bytes(
        runner._canonical_json(
            {
                "schema_version": runner.SCHEMA_VERSION,
                "benchmark_version": runner.BENCHMARK_VERSION,
                "algorithm": runner.EXECUTION_REQUEST_BINDINGS_ALGORITHM,
                "preregistration_sha256": verified_freeze.preregistration_sha256,
                "cohort_sha256": verified_freeze.cohort_sha256,
                "requests": [
                    {"case_id": case_id, "rendered_input_sha256": digest}
                    for case_id, digest in sorted(request_bindings.items())
                ],
            }
        )
    )
    request_bindings_path.chmod(0o600)
    assert dict(
        runner.load_v02_request_bindings(request_bindings_path, preregistration_path)
    ) == dict(sorted(request_bindings.items()))
    root = Path(__file__).parents[1]
    request_bindings_record = json.loads(request_bindings_path.read_text())
    for request_bindings_schema_path in (
        root / "schemas" / "benchmark-v02-execution-request-bindings.schema.json",
        root
        / "src"
        / "reproassert"
        / "schemas"
        / "benchmark-v02-execution-request-bindings.schema.json",
    ):
        request_bindings_schema = json.loads(request_bindings_schema_path.read_text())
        Draft202012Validator.check_schema(request_bindings_schema)
        Draft202012Validator(request_bindings_schema).validate(request_bindings_record)
    unsorted_bindings = json.loads(request_bindings_path.read_text())
    unsorted_bindings["requests"].reverse()
    unsorted_bindings_path = tmp_path / "unsorted-request-bindings.json"
    unsorted_bindings_path.write_bytes(runner._canonical_json(unsorted_bindings))
    unsorted_bindings_path.chmod(0o600)
    with pytest.raises(PolicyRejection, match="sorted canonical"):
        runner.load_v02_request_bindings(unsorted_bindings_path, preregistration_path)
    with pytest.raises(PolicyRejection, match="pricing that was not yet effective"):
        runner.write_v02_execution_authorization(
            output_path=tmp_path / "future-pricing-execution-authorization.json",
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
            request_bindings=request_bindings,
            tool_git_sha="1" * 40,
            requested_model="gpt-test",
            pricing=_pricing(effective_at="2026-07-10T00:00:01Z"),
            reserved_worst_case_microusd=100,
            max_case_attributable_microusd=100,
            max_campaign_attributable_microusd=2_000,
            max_case_wall_ms=60_000,
            provider_timeout_seconds=10,
            authorization_ref="test-only-no-provider-spend",
            authorization_text="Tom explicitly authorizes this exact test-only campaign fixture.",
            authorized_at="2026-07-10T00:00:00Z",
        )
    execution_authorization_path = runner.write_v02_execution_authorization(
        output_path=tmp_path / "real-execution-authorization.json",
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        request_bindings=request_bindings,
        tool_git_sha="1" * 40,
        requested_model="gpt-test",
        pricing=_pricing(),
        reserved_worst_case_microusd=100,
        max_case_attributable_microusd=100,
        max_campaign_attributable_microusd=2_000,
        max_case_wall_ms=60_000,
        provider_timeout_seconds=10,
        authorization_ref="test-only-no-provider-spend",
        authorization_text="Tom explicitly authorizes this exact test-only campaign fixture.",
        authorized_at="2026-07-10T00:00:00Z",
    )
    verified_authorization = runner.verify_v02_execution_authorization(
        execution_authorization_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    authorization_record = json.loads(execution_authorization_path.read_text())
    assert verified_authorization.authorization_text == (
        "Tom explicitly authorizes this exact test-only campaign fixture."
    )
    with pytest.raises(PolicyRejection, match="does not contain"):
        verified_authorization.request_sha256("rk-v0.2-999")
    predated_record = json.loads(execution_authorization_path.read_text())
    predated_record["authorized_at"] = "2026-07-08T00:00:00Z"
    predated_path = tmp_path / "predated-execution-authorization.json"
    predated_path.write_bytes(runner._canonical_json(predated_record))
    predated_path.chmod(0o600)
    with pytest.raises(PolicyRejection, match="chronology"):
        runner.verify_v02_execution_authorization(
            predated_path,
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
        )
    future_pricing_record = json.loads(execution_authorization_path.read_text())
    future_pricing = _pricing(effective_at="2026-07-10T00:00:01Z")
    future_pricing_record["pricing_snapshot"] = future_pricing.record()
    future_pricing_record["pricing_snapshot_sha256"] = future_pricing.sha256
    future_pricing_path = tmp_path / "future-pricing-execution-authorization.json"
    future_pricing_path.write_bytes(runner._canonical_json(future_pricing_record))
    future_pricing_path.chmod(0o600)
    with pytest.raises(PolicyRejection, match="chronology"):
        runner.verify_v02_execution_authorization(
            future_pricing_path,
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
        )
    pricing_tampered_record = json.loads(execution_authorization_path.read_text())
    pricing_tampered_record["pricing_snapshot"]["input_microusd_per_million_tokens"] = 1
    pricing_tampered_path = tmp_path / "pricing-tampered-execution-authorization.json"
    pricing_tampered_path.write_bytes(runner._canonical_json(pricing_tampered_record))
    pricing_tampered_path.chmod(0o600)
    with pytest.raises(PolicyRejection, match="pricing snapshot"):
        runner.verify_v02_execution_authorization(
            pricing_tampered_path,
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
        )
    text_tampered_record = json.loads(execution_authorization_path.read_text())
    text_tampered_record["authorization_text"] = "Tampered authorization evidence text."
    text_tampered_path = tmp_path / "text-tampered-execution-authorization.json"
    text_tampered_path.write_bytes(runner._canonical_json(text_tampered_record))
    text_tampered_path.chmod(0o600)
    with pytest.raises(PolicyRejection, match="text or its digest"):
        runner.verify_v02_execution_authorization(
            text_tampered_path,
            campaign_freeze_path=campaign_freeze_path,
            preregistration_path=preregistration_path,
        )
    for authorization_schema_path in (
        root / "schemas" / "benchmark-v02-execution-authorization.schema.json",
        root
        / "src"
        / "reproassert"
        / "schemas"
        / "benchmark-v02-execution-authorization.schema.json",
    ):
        authorization_schema = json.loads(authorization_schema_path.read_text())
        Draft202012Validator.check_schema(authorization_schema)
        Draft202012Validator(authorization_schema).validate(authorization_record)
    policy = verified_authorization.policy()
    assert policy.campaign_freeze_sha256 == verified_freeze.raw_sha256
    configuration = policy.configuration_record()
    assert configuration["pricing_snapshot"] == _pricing().record()
    assert cast(dict[str, object], configuration["execution_authorization"])["sha256"] == (
        verified_authorization.raw_sha256
    )
    assert (
        cast(dict[str, object], configuration["run_provenance"])["authorization_text_sha256"]
        == verified_authorization.authorization_text_sha256
    )
    assert "Tom explicitly authorizes" not in runner._canonical_json(configuration).decode()
    tampered_record = json.loads(execution_authorization_path.read_text())
    tampered_record["limits"]["max_case_attributable_microusd"] = 101
    tampered_authorization_path = tmp_path / "tampered-execution-authorization.json"
    tampered_authorization_path.write_bytes(runner._canonical_json(tampered_record))
    tampered_authorization_path.chmod(0o600)
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("tampered authorization reached provider")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    request_drift_record = json.loads(execution_authorization_path.read_text())
    request_drift_record["request_set"]["requests"][0]["rendered_input_sha256"] = "f" * 64
    request_pairs = tuple(
        (row["case_id"], row["rendered_input_sha256"])
        for row in request_drift_record["request_set"]["requests"]
    )
    request_drift_record["request_set"]["request_set_sha256"] = (
        runner._execution_request_set_sha256(
            campaign_id="campaign_v02_test",
            preregistration_sha256=verified_freeze.preregistration_sha256,
            cohort_sha256=verified_freeze.cohort_sha256,
            requests=request_pairs,
        )
    )
    request_drift_path = tmp_path / "request-drift-execution-authorization.json"
    request_drift_path.write_bytes(runner._canonical_json(request_drift_record))
    request_drift_path.chmod(0o600)
    request_drift_authorization = runner.verify_v02_execution_authorization(
        request_drift_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    with pytest.raises(PolicyRejection, match="rendered request"):
        runner.generate_v02_scored_case(
            preregistration_path=preregistration_path,
            campaign_freeze_path=campaign_freeze_path,
            execution_authorization_path=request_drift_path,
            case_id=identity.id,
            generator_projection_path=projection_path,
            generator_source_context=context,
            ledger_path=tmp_path / "request-drift-events.jsonl",
            attempt_directory=tmp_path / "request-drift-attempt",
            policy=request_drift_authorization.policy(),
        )
    with pytest.raises(PolicyRejection, match="execution authorization"):
        runner.generate_v02_scored_case(
            preregistration_path=preregistration_path,
            campaign_freeze_path=campaign_freeze_path,
            execution_authorization_path=tampered_authorization_path,
            case_id=identity.id,
            generator_projection_path=projection_path,
            generator_source_context=context,
            ledger_path=tmp_path / "tampered-auth-events.jsonl",
            attempt_directory=tmp_path / "tampered-auth-attempt",
            policy=policy,
        )
    assert provider_calls == 0
    assert not (tmp_path / "tampered-auth-attempt").exists()
    with pytest.raises(PolicyRejection, match="execution authorization"):
        runner._start_new_scored_attempt(
            preregistration_path=preregistration_path,
            campaign_freeze_path=campaign_freeze_path,
            execution_authorization_path=execution_authorization_path,
            case_id=identity.id,
            generator_projection_path=projection_path,
            generator_source_context=context,
            ledger_path=tmp_path / "cap-drift-events.jsonl",
            attempt_directory=tmp_path / "cap-drift-attempt",
            policy=replace(policy, max_case_attributable_microusd=101),
        )
    assert not (tmp_path / "cap-drift-attempt").exists()
    run = runner._start_new_scored_attempt(
        preregistration_path=preregistration_path,
        campaign_freeze_path=campaign_freeze_path,
        execution_authorization_path=execution_authorization_path,
        case_id=identity.id,
        generator_projection_path=projection_path,
        generator_source_context=context,
        ledger_path=tmp_path / "real-events.jsonl",
        attempt_directory=tmp_path / "real-attempt",
        policy=policy,
    )
    assert run.case.id == identity.id
    assert run.source_context is context
    assert run.request.attempt == 1
    assert run.request.feedback == ""
    claim_path = execution_authorization_path.with_name(
        f"{execution_authorization_path.name}.claim.json"
    )
    assert claim_path.exists()
    assert claim_path.stat().st_mode & 0o777 == 0o600
    claim_record = json.loads(claim_path.read_text())
    assert claim_record["execution_authorization_sha256"] == verified_authorization.raw_sha256
    assert str(run.ledger_path) not in claim_path.read_text()
    assert runner._claim_execution_authorization(verified_authorization, run.ledger_path) == (
        claim_path
    )
    replay_attempt = tmp_path / "authorization-replay-attempt"
    with pytest.raises(PolicyRejection, match="already claimed"):
        runner.generate_v02_scored_case(
            preregistration_path=preregistration_path,
            campaign_freeze_path=campaign_freeze_path,
            execution_authorization_path=execution_authorization_path,
            case_id=identity.id,
            generator_projection_path=projection_path,
            generator_source_context=context,
            ledger_path=tmp_path / "authorization-replay-events.jsonl",
            attempt_directory=replay_attempt,
            policy=policy,
        )
    assert provider_calls == 0
    assert not replay_attempt.exists()
    ledger = runner.read_v02_scored_ledger(run.ledger_path)
    assert [event["event_type"] for event in ledger.events] == ["attempt_started"]
    assert ledger.events[0]["payload"]["runner_input_sha256"] == run.runner_input_sha256
    transaction = _seed_recoverable_generation(run, crash_point="after_candidate_fsync")
    with pytest.raises(PolicyRejection, match="execution authorization"):
        runner.recover_v02_scored_case(
            preregistration_path=preregistration_path,
            campaign_freeze_path=campaign_freeze_path,
            execution_authorization_path=tampered_authorization_path,
            case_id=identity.id,
            generator_projection_path=projection_path,
            generator_source_context=context,
            ledger_path=run.ledger_path,
            attempt_directory=run.attempt_directory,
            attempt_id=run.attempt_id,
            policy=policy,
        )
    recovered = runner.recover_v02_scored_case(
        preregistration_path=preregistration_path,
        campaign_freeze_path=campaign_freeze_path,
        execution_authorization_path=execution_authorization_path,
        case_id=identity.id,
        generator_projection_path=projection_path,
        generator_source_context=context,
        ledger_path=run.ledger_path,
        attempt_directory=run.attempt_directory,
        attempt_id=run.attempt_id,
        policy=policy,
    )
    assert recovered.status == "candidate_submitted"
    assert recovered.candidate_sha256 == transaction.candidate.sha256


def test_arbitrary_or_sandbox_claim_cannot_bypass_exact_builtin_allowlist() -> None:
    policy = _policy(
        authorization_status="offline_zero_cost",
        authorization_ref=None,
        generator_mode="sandboxed_generator_process",
        provider="local-model",
        pricing=None,
        reserved_worst_case_microusd=0,
    )
    with pytest.raises(PolicyRejection, match=r"positive integer|unavailable"):
        policy.require_executable()


def test_transaction_fsyncs_candidate_before_model_finish_and_never_calls_provider_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={"test": True},
    )
    runner._start_phase(run, "generation")
    calls = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal calls
        calls += 1
        assert api_key == "sk-test-only"
        assert timeout_seconds > 0
        return _fake_response()

    original_append = runner._append_event

    def assert_candidate_exists_before_finish(
        current: runner._RunContext,
        event_type: str,
        payload: dict[str, Any],
        **kwargs: object,
    ) -> dict[str, Any]:
        if event_type == "model_call_finished" and payload["status"] == "succeeded":
            artifact = current.attempt_directory / "generation-transaction.json"
            assert artifact.is_file()
            assert artifact.stat().st_size == payload["generation_artifact_bytes"]
            assert (
                runner._sha256_file(artifact, runner.MAX_RESULT_BYTES)
                == payload["generation_artifact_sha256"]
            )
        return original_append(current, event_type, payload, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)
    monkeypatch.setattr(runner, "_append_event", assert_candidate_exists_before_finish)
    candidate, artifact = runner._run_transactional_openai_generation(run)
    assert calls == 1
    runner._revalidate_candidate_file(run, artifact, candidate)
    events = runner.read_v02_scored_ledger(run.ledger_path).events
    lifecycle = [
        event["event_type"]
        for event in events
        if event["event_type"]
        in {"model_call_started", "model_call_finished", "cost_recorded", "candidate_submitted"}
    ]
    assert lifecycle[-3:] == ["candidate_submitted", "model_call_finished", "cost_recorded"]
    candidate_event = next(
        event for event in events if event["event_type"] == "candidate_submitted"
    )
    assert candidate_event["payload"]["oracle_consulted"] is False


def test_crash_after_candidate_fsync_leaves_unmatched_call_and_halts_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={},
    )
    runner._start_phase(run, "generation")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(
        generator_module,
        "_post_openai_response",
        lambda *_args, **_kwargs: _fake_response(),
    )
    original_append = runner._append_event

    def crash_on_finish(
        current: runner._RunContext,
        event_type: str,
        payload: dict[str, Any],
        **kwargs: object,
    ) -> dict[str, Any]:
        if event_type == "model_call_finished":
            raise PolicyRejection("test_crash", "injected after artifact fsync")
        return original_append(current, event_type, payload, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner, "_append_event", crash_on_finish)
    with pytest.raises(runner._PostExternalDurabilityCrash):
        runner._run_transactional_openai_generation(run)
    assert (run.attempt_directory / "generation-transaction.json").is_file()
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    assert sum(event["event_type"] == "model_call_started" for event in snapshot.events) == 1
    assert not any(event["event_type"] == "model_call_finished" for event in snapshot.events)
    assert sum(event["event_type"] == "candidate_submitted" for event in snapshot.events) == 1

    next_run = replace(
        run,
        attempt_id=f"attempt_002_{'b' * 16}",
        case=_case(2),
        attempt_directory=tmp_path / "attempt-rk-v0.2-002",
    )
    with pytest.raises(PolicyRejection, match="unmatched"):
        runner._preflight_model_call(snapshot, next_run)


@pytest.mark.parametrize(
    "crash_point",
    [
        "after_candidate_fsync",
        "after_candidate_submitted",
        "after_model_finish",
        "after_model_cost",
        "before_differential",
    ],
)
def test_recovery_reconciles_each_pre_differential_crash_with_zero_provider_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    run = _run(tmp_path)
    transaction = _seed_recoverable_generation(run, crash_point=crash_point)
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("recovery must never contact the provider")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    candidate, artifact = runner._recover_generation_without_provider(run)
    assert provider_calls == 0
    assert candidate == transaction.candidate
    assert artifact == transaction.path

    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    assert sum(event["event_type"] == "recovery_started" for event in events) == 1
    assert sum(event["event_type"] == "candidate_submitted" for event in events) == 1
    assert sum(event["event_type"] == "model_call_started" for event in events) == 1
    assert sum(event["event_type"] == "model_call_finished" for event in events) == 1
    assert (
        sum(
            event["event_type"] == "cost_recorded"
            and event["payload"]["category"] == "model_inference"
            for event in events
        )
        == 1
    )
    assert (
        sum(
            event["event_type"] == "phase_finished" and event["payload"]["phase"] == "generation"
            for event in events
        )
        == 1
    )
    recovery = next(event for event in events if event["event_type"] == "recovery_started")
    assert recovery["payload"]["execution_authorization_sha256"] == (
        run.policy.execution_authorization_sha256
    )
    assert recovery["payload"]["provider_calls_permitted"] == 0
    assert recovery["payload"]["oracle_feedback_permitted"] is False
    assert recovery["payload"]["candidate_sha256"] == transaction.candidate.sha256
    root = Path(__file__).parents[1]
    for event_schema_path in (
        root / "schemas" / "benchmark-v02-private-event.schema.json",
        root / "src" / "reproassert" / "schemas" / "benchmark-v02-private-event.schema.json",
    ):
        event_schema = json.loads(event_schema_path.read_text())
        Draft202012Validator.check_schema(event_schema)
        Draft202012Validator(event_schema).validate(recovery)
    assert transaction.candidate.test_content not in snapshot.encoded.decode()
    assert transaction.candidate.expected_symptom not in snapshot.encoded.decode()

    event_count = len(snapshot.events)
    assert runner._recover_generation_without_provider(run) == (candidate, artifact)
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == event_count
    assert provider_calls == 0


@pytest.mark.parametrize("case_index", [16, 17])
def test_sympy_recovery_reuses_one_durable_candidate_without_second_provider_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_index: int,
) -> None:
    run = _run(tmp_path, case=_case(case_index))
    transaction = _seed_recoverable_generation(run, crash_point="after_candidate_fsync")
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("SymPy recovery must not issue another provider request")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    candidate, artifact = runner._recover_generation_without_provider(run)
    contract = runner._run_candidate_contract(run)

    assert provider_calls == 0
    assert candidate == transaction.candidate
    assert artifact == transaction.path
    assert candidate.test_function == contract.test_function
    private = runner._private_result_record(
        run,
        candidate=candidate,
        differential=None,
        outcome="no_output",
        claim_level="rejected",
        costs={},
        cost_complete=True,
        total_cost=0,
        ledger_head="f" * 64,
        classification_code="v02_test_only",
    )
    embargoed = runner._public_embargoed_result_record(
        run,
        candidate=candidate,
        costs={},
        cost_complete=True,
        total_cost=0,
        ledger_head="f" * 64,
    )
    assert private["candidate"]["path"] == contract.relative_path  # type: ignore[index]
    assert embargoed["candidate"]["path"] == contract.relative_path  # type: ignore[index]

    event_count = len(runner.read_v02_scored_ledger(run.ledger_path).events)
    assert runner._recover_generation_without_provider(run) == (candidate, artifact)
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == event_count
    assert provider_calls == 0
    assert candidate == transaction.candidate
    assert artifact == transaction.path

    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    assert sum(event["event_type"] == "recovery_started" for event in events) == 1
    assert sum(event["event_type"] == "candidate_submitted" for event in events) == 1
    assert sum(event["event_type"] == "model_call_started" for event in events) == 1
    assert sum(event["event_type"] == "model_call_finished" for event in events) == 1
    assert (
        sum(
            event["event_type"] == "cost_recorded"
            and event["payload"]["category"] == "model_inference"
            for event in events
        )
        == 1
    )
    assert (
        sum(
            event["event_type"] == "phase_finished" and event["payload"]["phase"] == "generation"
            for event in events
        )
        == 1
    )
    recovery = next(event for event in events if event["event_type"] == "recovery_started")
    assert recovery["payload"]["execution_authorization_sha256"] == (
        run.policy.execution_authorization_sha256
    )
    assert recovery["payload"]["provider_calls_permitted"] == 0
    assert recovery["payload"]["oracle_feedback_permitted"] is False
    assert recovery["payload"]["candidate_sha256"] == transaction.candidate.sha256
    root = Path(__file__).parents[1]
    for event_schema_path in (
        root / "schemas" / "benchmark-v02-private-event.schema.json",
        root / "src" / "reproassert" / "schemas" / "benchmark-v02-private-event.schema.json",
    ):
        event_schema = json.loads(event_schema_path.read_text())
        Draft202012Validator.check_schema(event_schema)
        Draft202012Validator(event_schema).validate(recovery)
    assert transaction.candidate.test_content not in snapshot.encoded.decode()
    assert transaction.candidate.expected_symptom not in snapshot.encoded.decode()

    # Reconciliation is idempotent: an identical second invocation adds no events and still cannot
    # reach provider code.
    event_count = len(snapshot.events)
    assert runner._recover_generation_without_provider(run) == (candidate, artifact)
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == event_count
    assert provider_calls == 0


@pytest.mark.parametrize("crash_boundary", ["artifact_cost", "disposition_fsync"])
def test_recovery_baseexception_is_durably_halted_without_provider_or_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_boundary: str,
) -> None:
    run = _run(tmp_path)
    _seed_recoverable_generation(run, crash_point="after_candidate_fsync")
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("recovery contacted provider")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    monkeypatch.setattr(runner, "_prepare_recovery_context", lambda **_kwargs: run)
    if crash_boundary == "artifact_cost":
        monkeypatch.setattr(
            runner,
            "_record_or_validate_recovery_artifact_cost",
            lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
    else:
        original_append = runner._append_event

        def crash_disposition(
            current: runner._EventContext,
            event_type: str,
            payload: dict[str, Any],
            **kwargs: object,
        ) -> dict[str, Any]:
            if event_type == "generation_disposition_frozen":
                raise KeyboardInterrupt
            return original_append(current, event_type, payload, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(runner, "_append_event", crash_disposition)
    call = {
        "preregistration_path": tmp_path / "preregistration.json",
        "campaign_freeze_path": tmp_path / "unused-campaign-freeze.json",
        "execution_authorization_path": tmp_path / "unused-execution-authorization.json",
        "case_id": run.case.id,
        "generator_projection_path": tmp_path / "projection.json",
        "generator_source_context": run.source_context,
        "ledger_path": run.ledger_path,
        "attempt_directory": run.attempt_directory,
        "attempt_id": run.attempt_id,
        "policy": run.policy,
    }
    with pytest.raises(KeyboardInterrupt):
        runner.recover_v02_scored_case(**call)  # type: ignore[arg-type]
    assert provider_calls == 0
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    assert snapshot.events[-1]["event_type"] == "attempt_crashed"
    assert snapshot.events[-1]["payload"]["exception_type"] == "KeyboardInterrupt"
    assert (
        "evaluator_capability" not in inspect.signature(runner.recover_v02_scored_case).parameters
    )


def test_recovery_unknown_usage_hard_halts_without_evaluator_or_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    _seed_recoverable_generation(
        run,
        crash_point="after_candidate_fsync",
        usage_status="unknown",
    )
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    with pytest.raises(PolicyRejection, match="cannot be reconciled"):
        runner._recover_generation_without_provider(run)
    assert provider_calls == 0
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    assert snapshot.events[-1]["event_type"] == "attempt_crashed"
    assert snapshot.events[-1]["payload"]["classification_code"] == ("v02_recovery_spend_unknown")
    model_cost = next(
        event
        for event in snapshot.events
        if event["event_type"] == "cost_recorded"
        and event["payload"]["category"] == "model_inference"
    )
    assert model_cost["payload"]["status"] == "unknown"
    assert model_cost["payload"]["amount_microusd"] is None
    with pytest.raises(PolicyRejection, match="hard-halted"):
        runner._recover_generation_without_provider(run)
    assert provider_calls == 0


def test_recovery_rejects_other_finished_call_without_model_cost(tmp_path: Path) -> None:
    run = _run(tmp_path)
    _seed_recoverable_generation(run, crash_point="after_candidate_fsync")
    other_directory = tmp_path / "attempt-rk-v0.2-002"
    other_directory.mkdir(mode=0o700)
    other = replace(
        run,
        attempt_id=f"attempt_002_{'b' * 16}",
        case=_case(2),
        attempt_directory=other_directory,
    )
    _append_attempt_start(other)
    _seed_recoverable_generation(other, crash_point="after_model_finish")

    with pytest.raises(PolicyRejection, match="lacks reconciled model spend"):
        runner._recover_generation_without_provider(run)
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    assert not any(
        event["attempt_id"] == run.attempt_id and event["event_type"] == "recovery_started"
        for event in snapshot.events
    )


def test_provider_response_then_transaction_write_failure_records_unknown_cost_and_halts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={},
    )
    runner._start_phase(run, "generation")
    provider_calls = 0

    def fake_post(_body: bytes, *, api_key: str, timeout_seconds: float) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        assert api_key == "sk-test-only"
        assert timeout_seconds > 0
        return _fake_response()

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(generator_module, "_post_openai_response", fake_post)
    monkeypatch.setattr(
        runner,
        "_persist_generation_transaction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PolicyRejection("injected_transaction_fsync", "injected transaction fsync failure")
        ),
    )
    with pytest.raises(PolicyRejection, match="transaction fsync failure"):
        runner._run_transactional_openai_generation(run)
    assert provider_calls == 1

    runner._finish_open_phase(
        run, status="failed", classification_code="injected_transaction_fsync"
    )
    runner._fill_missing_costs(run, candidate=None)
    result = runner._write_terminal_result(
        run,
        candidate=None,
        differential=None,
        outcome="benchmark_infrastructure_error",
        claim_level="rejected",
        classification_code="injected_transaction_fsync",
    )
    assert result.status == "incomplete_unknown_cost"
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    model_cost = next(
        event
        for event in snapshot.events
        if event["event_type"] == "cost_recorded"
        and event["payload"]["category"] == "model_inference"
    )
    model_start = next(
        event for event in snapshot.events if event["event_type"] == "model_call_started"
    )
    assert model_cost["payload"]["status"] == "unknown"
    assert model_cost["payload"]["amount_microusd"] is None
    assert model_cost["payload"]["source_call_id"] == model_start["payload"]["call_id"]
    assert model_start["payload"]["execution_authorization_sha256"] == (
        run.policy.execution_authorization_sha256
    )
    assert snapshot.events[-1]["event_type"] == "attempt_finished"
    assert provider_calls == 1


@pytest.mark.parametrize(
    "tamper",
    [
        "artifact_bytes",
        "runner_identity",
        "call_identity",
        "candidate_commit",
    ],
)
def test_recovery_rejects_tampered_artifact_and_mismatched_frozen_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    run = _run(tmp_path)
    transaction = _seed_recoverable_generation(
        run,
        crash_point=(
            "after_candidate_submitted" if tamper == "candidate_commit" else "after_candidate_fsync"
        ),
    )
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("provider called")

    monkeypatch.setattr(
        generator_module,
        "_post_openai_response",
        forbidden_provider,
    )
    if tamper == "artifact_bytes":
        encoded = transaction.path.read_bytes()
        transaction.path.write_bytes(
            encoded.replace(b"candidate_validated", b"candidate_tampered", 1)
        )
    elif tamper == "runner_identity":
        run = replace(run, runner_input_sha256="f" * 64)
    elif tamper == "call_identity":
        decoded = json.loads(transaction.path.read_text())
        decoded["call_id"] = f"call_{'e' * 32}"
        decoded["model_finish"]["call_id"] = decoded["call_id"]
        transaction.path.write_bytes(runner._canonical_json(decoded) + b"\n")
    else:
        lines = run.ledger_path.read_text().splitlines()
        changed: list[dict[str, object]] = [json.loads(line) for line in lines]
        for event in changed:
            if event["event_type"] == "candidate_submitted":
                cast(dict[str, object], event["payload"])["candidate_sha256"] = "f" * 64
        _rewrite_event_chain(run.ledger_path, changed)
    with pytest.raises(PolicyRejection, match=r"transaction|identity|artifact|freeze"):
        runner._recover_generation_without_provider(run)
    assert provider_calls == 0


def test_recovery_lock_is_nonblocking_race_safe_and_reusable(tmp_path: Path) -> None:
    run = _run(tmp_path)
    first = runner._acquire_recovery_lock(run.attempt_directory)
    try:
        with pytest.raises(PolicyRejection, match="Another recovery"):
            runner._acquire_recovery_lock(run.attempt_directory)
    finally:
        runner._release_recovery_lock(first)
    second = runner._acquire_recovery_lock(run.attempt_directory)
    runner._release_recovery_lock(second)


def test_public_recovery_freezes_exact_candidate_disposition_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    transaction = _seed_recoverable_generation(run, crash_point="after_candidate_fsync")
    provider_calls = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("recovery contacted provider")

    def prepared_context(**_kwargs: object) -> runner._RunContext:
        return run

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    monkeypatch.setattr(runner, "_prepare_recovery_context", prepared_context)
    call = {
        "preregistration_path": tmp_path / "preregistration.json",
        "campaign_freeze_path": tmp_path / "unused-campaign-freeze.json",
        "execution_authorization_path": tmp_path / "unused-execution-authorization.json",
        "case_id": run.case.id,
        "generator_projection_path": tmp_path / "projection.json",
        "generator_source_context": run.source_context,
        "ledger_path": run.ledger_path,
        "attempt_directory": run.attempt_directory,
        "attempt_id": run.attempt_id,
        "policy": run.policy,
    }
    disposition = runner.recover_v02_scored_case(**call)  # type: ignore[arg-type]
    assert disposition.status == "candidate_submitted"
    assert disposition.candidate_sha256 == transaction.candidate.sha256
    assert provider_calls == 0
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    event_count = len(snapshot.events)
    assert snapshot.events[-1]["event_type"] == "generation_disposition_frozen"
    assert not any(
        event["event_type"] == "phase_started" and event["payload"]["phase"] == "differential"
        for event in snapshot.events
    )
    assert (
        "evaluator_capability" not in inspect.signature(runner.recover_v02_scored_case).parameters
    )

    repeated = runner.recover_v02_scored_case(**call)  # type: ignore[arg-type]
    assert repeated == disposition
    assert len(runner.read_v02_scored_ledger(run.ledger_path).events) == event_count
    assert provider_calls == 0


def test_all_case_generation_barrier_precedes_first_capability_and_keeps_abstention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = [_campaign_case(index) for index in range(1, 21)]
    preregistration_path = tmp_path / "campaign-preregistration.json"
    preregistration_path.write_bytes(
        canonical_preregistration_bytes(
            build_v02_preregistration(
                cases,
                frozen_at="2026-07-10T00:00:00Z",
                tool_name="reproassert",
                tool_version="0.2-test",
                tool_git_sha="1" * 40,
            )
        )
    )
    preregistration = load_v02_preregistration(preregistration_path)
    cohort_sha256 = cast(str, preregistration.decoded["cohort_sha256"])
    ledger_path = tmp_path / "two-phase-events.jsonl"
    runs: list[runner._RunContext] = []
    provider_calls = 0
    capability_accesses = 0

    def forbidden_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("two-phase fixture contacted provider")

    monkeypatch.setattr(generator_module, "_post_openai_response", forbidden_provider)
    for case in preregistration.cases[:18]:
        current = _campaign_run(
            tmp_path,
            case=case,
            preregistration_sha256=preregistration.raw_sha256,
            cohort_sha256=cohort_sha256,
            ledger_path=ledger_path,
        )
        _freeze_campaign_disposition(current, candidate_submitted=True)
        runs.append(current)
    abstention = _campaign_run(
        tmp_path,
        case=preregistration.cases[18],
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        ledger_path=ledger_path,
    )
    _freeze_campaign_disposition(abstention, candidate_submitted=False)
    runs.append(abstention)
    with pytest.raises(PolicyRejection, match="Every preregistered case"):
        runner.freeze_v02_campaign_generation_barrier(
            preregistration_path=preregistration_path,
            ledger_path=ledger_path,
            policy=_policy(),
        )
    assert capability_accesses == 0
    assert provider_calls == 0

    final_candidate = _campaign_run(
        tmp_path,
        case=preregistration.cases[19],
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        ledger_path=ledger_path,
    )
    _freeze_campaign_disposition(
        final_candidate,
        candidate_submitted=True,
        recover_generation=False,
    )
    runs.append(final_candidate)
    runner._append_event(
        final_candidate,
        "attempt_crashed",
        {
            "crashed_at": runner._now(),
            "classification_code": "injected_post_disposition_crash",
            "exception_type": "InjectedControllerCrash",
            "cost_complete": False,
            "recovery_status": "manual_reconciliation_required_no_new_provider_call",
        },
    )
    monkeypatch.setattr(
        runner,
        "_prepare_recovery_context",
        lambda **_kwargs: final_candidate,
    )
    recovered = runner.recover_v02_scored_case(
        preregistration_path=preregistration_path,
        campaign_freeze_path=tmp_path / "unused-campaign-freeze.json",
        execution_authorization_path=tmp_path / "unused-execution-authorization.json",
        case_id=final_candidate.case.id,
        generator_projection_path=tmp_path / "unused-projection.json",
        generator_source_context=final_candidate.source_context,
        ledger_path=ledger_path,
        attempt_directory=final_candidate.attempt_directory,
        attempt_id=final_candidate.attempt_id,
        policy=_policy(),
    )
    assert recovered.status == "candidate_submitted"
    assert provider_calls == 0
    before_barrier = runner.read_v02_scored_ledger(ledger_path)
    final_events = [
        event
        for event in before_barrier.events
        if event["attempt_id"] == final_candidate.attempt_id
    ]
    assert [event["event_type"] for event in final_events[-3:]] == [
        "generation_disposition_frozen",
        "attempt_crashed",
        "recovery_started",
    ]
    assert not any(
        event["event_type"] == "phase_started" and event["payload"]["phase"] == "differential"
        for event in before_barrier.events
    )

    barrier = runner.freeze_v02_campaign_generation_barrier(
        preregistration_path=preregistration_path,
        ledger_path=ledger_path,
        policy=_policy(),
    )
    assert barrier.algorithm == runner.GENERATION_BARRIER_ALGORITHM
    assert barrier.disposition_count == 20
    assert len(barrier.disposition_set_sha256) == 64
    assert len(barrier.sha256) == 64
    assert barrier.execution_authorization_sha256 == _policy().execution_authorization_sha256
    assert barrier.request_set_sha256 == _policy().request_set_sha256
    assert (
        barrier.pricing_snapshot_sha256 == cast(runner.V02PricingSnapshot, _policy().pricing).sha256
    )
    assert barrier.run_provenance_sha256 == runner._sha256_json(
        _policy().configuration_record()["run_provenance"]
    )
    barrier_event = next(
        event
        for event in runner.read_v02_scored_ledger(ledger_path).events
        if event["event_type"] == "campaign_generation_barrier_frozen"
    )
    assert barrier_event["payload"]["configuration_sha256"] == _policy().configuration_sha256
    assert barrier_event["payload"]["execution_authorization_sha256"] == (
        _policy().execution_authorization_sha256
    )
    assert barrier_event["payload"]["pricing_snapshot_sha256"] == (barrier.pricing_snapshot_sha256)
    assert capability_accesses == 0
    assert provider_calls == 0
    event_count = len(runner.read_v02_scored_ledger(ledger_path).events)
    assert (
        runner.freeze_v02_campaign_generation_barrier(
            preregistration_path=preregistration_path,
            ledger_path=ledger_path,
            policy=_policy(),
        )
        == barrier
    )
    assert len(runner.read_v02_scored_ledger(ledger_path).events) == event_count

    tampered = replace(barrier, disposition_set_sha256="f" * 64)
    with pytest.raises(PolicyRejection, match="durable event chain"):
        runner.require_v02_campaign_generation_barrier(
            tampered,
            preregistration_path=preregistration_path,
            ledger_path=ledger_path,
            policy=_policy(),
        )

    run_by_case = {current.case.id: current for current in runs}
    monkeypatch.setattr(
        runner,
        "_prepare_recovery_context",
        lambda **kwargs: run_by_case[cast(str, kwargs["case_id"])],
    )
    capability = SimpleNamespace(
        capability_sha256="1" * 64,
        package_identity_sha256="2" * 64,
        public_commitment_sha256=runs[0].case.evaluator_commitment_sha256,
    )

    def guarded_capability(_value: object) -> Any:
        nonlocal capability_accesses
        capability_accesses += 1
        snapshot = runner.read_v02_scored_ledger(ledger_path)
        assert any(
            event["event_type"] == "campaign_generation_barrier_frozen" for event in snapshot.events
        )
        return capability

    def fake_differential(current: runner._RunContext, **_kwargs: object) -> tuple[Any, int]:
        started_at = runner._start_phase(current, "differential")
        runner._finish_phase(
            current,
            phase="differential",
            started_at=started_at,
            started_monotonic=time.monotonic(),
            status="succeeded",
            classification_code=None,
            evidence={"stubbed_docker_boundary": True},
        )
        return (
            SimpleNamespace(
                accepted=False,
                claim_level="rejected",
                outcome="false_reproduction",
                fingerprint="private-only",
                evaluator_capability_sha256=capability.capability_sha256,
                evaluator_package_sha256=capability.package_identity_sha256,
                evaluator_public_commitment_sha256=capability.public_commitment_sha256,
                dependency_receipt_sha256=None,
                dependency_plan_sha256=None,
                dependency_tree_sha256=None,
                dependency_image_id=None,
                scheduled_runs=(),
            ),
            1,
        )

    monkeypatch.setattr(runner, "require_v02_evaluator_capability", guarded_capability)
    monkeypatch.setattr(runner, "_bind_capability", lambda *_args: None)
    monkeypatch.setattr(runner, "acquire_v02_evaluation_session", lambda value, **_kw: value)
    monkeypatch.setattr(runner, "consume_v02_evaluation_session", lambda value, **_kw: value)
    monkeypatch.setattr(runner, "_differential_phase", fake_differential)
    candidate_run = runs[0]
    evaluation_call = {
        "preregistration_path": preregistration_path,
        "case_id": candidate_run.case.id,
        "generator_projection_path": tmp_path / "unused-projection.json",
        "generator_source_context": candidate_run.source_context,
        "campaign_barrier": barrier,
        "evaluator_capability": cast(Any, capability),
        "sandbox": DockerSandbox(),
        "base_source": tmp_path,
        "fixed_source": tmp_path,
        "ledger_path": ledger_path,
        "attempt_directory": candidate_run.attempt_directory,
        "attempt_id": candidate_run.attempt_id,
        "policy": _policy(),
    }
    with pytest.raises(PolicyRejection, match="durable event chain"):
        runner.evaluate_v02_frozen_case(
            **{**evaluation_call, "campaign_barrier": tampered}  # type: ignore[arg-type]
        )
    assert capability_accesses == 0

    result = runner.evaluate_v02_frozen_case(**evaluation_call)  # type: ignore[arg-type]
    assert result.status == "complete"
    assert capability_accesses == 1
    assert provider_calls == 0

    no_candidate_call = {
        **evaluation_call,
        "case_id": abstention.case.id,
        "generator_source_context": abstention.source_context,
        "evaluator_capability": cast(Any, object()),
        "attempt_directory": abstention.attempt_directory,
        "attempt_id": abstention.attempt_id,
    }
    no_candidate = runner.evaluate_v02_frozen_case(  # type: ignore[arg-type]
        **no_candidate_call
    )
    assert no_candidate.outcome == "no_output"
    assert no_candidate.candidate_sha256 is None
    assert capability_accesses == 1
    assert provider_calls == 0

    for boundary, boundary_run in zip(
        ("capability", "differential", "result_write"),
        runs[1:4],
        strict=True,
    ):
        boundary_accesses = 0

        def boundary_capability(_value: object, _boundary: str = boundary) -> Any:
            nonlocal boundary_accesses
            boundary_accesses += 1
            if _boundary == "capability":
                raise KeyboardInterrupt
            return capability

        def boundary_differential(
            current: runner._RunContext,
            _boundary: str = boundary,
            **kwargs: object,
        ) -> tuple[Any, int]:
            if _boundary == "differential":
                runner._start_phase(current, "differential")
                raise KeyboardInterrupt
            return fake_differential(current, **kwargs)

        def boundary_result(current: runner._RunContext, **_kwargs: object) -> Any:
            runner._start_phase(current, "result_write")
            raise KeyboardInterrupt

        boundary_call = {
            **evaluation_call,
            "case_id": boundary_run.case.id,
            "generator_source_context": boundary_run.source_context,
            "attempt_directory": boundary_run.attempt_directory,
            "attempt_id": boundary_run.attempt_id,
        }
        with monkeypatch.context() as boundary_patch:
            boundary_patch.setattr(runner, "require_v02_evaluator_capability", boundary_capability)
            boundary_patch.setattr(runner, "_differential_phase", boundary_differential)
            if boundary == "result_write":
                boundary_patch.setattr(runner, "_write_terminal_result", boundary_result)
            with pytest.raises(KeyboardInterrupt):
                runner.evaluate_v02_frozen_case(  # type: ignore[arg-type]
                    **boundary_call
                )
        assert boundary_accesses == 1
        attempt_events = [
            event
            for event in runner.read_v02_scored_ledger(ledger_path).events
            if event["attempt_id"] == boundary_run.attempt_id
        ]
        assert attempt_events[-1]["event_type"] == "attempt_crashed"
        accesses_before_retry = capability_accesses
        with pytest.raises(PolicyRejection, match=r"terminal|already began"):
            runner.evaluate_v02_frozen_case(**boundary_call)  # type: ignore[arg-type]
        assert capability_accesses == accesses_before_retry
        assert provider_calls == 0


@pytest.mark.parametrize("mutation", ["truncate", "hash", "reorder"])
def test_v02_chain_rejects_truncation_mutation_and_reorder(tmp_path: Path, mutation: str) -> None:
    run = _run(tmp_path)
    runner._record_cost(
        run,
        category="dependency_prep",
        attribution="cold_prep_excluded",
        status="zero_verified",
        amount=0,
        source_call_id=None,
        evidence={},
    )
    raw = run.ledger_path.read_bytes()
    lines = raw.splitlines(keepends=True)
    if mutation == "truncate":
        changed = raw[:-1]
    elif mutation == "hash":
        changed = raw.replace(b'"amount_microusd":0', b'"amount_microusd":1', 1)
    else:
        changed = lines[1] + lines[0]
    path = tmp_path / f"mutated-{mutation}.jsonl"
    path.write_bytes(changed)
    with pytest.raises(PolicyRejection):
        runner.read_v02_scored_ledger(path)


def test_attempt_rejects_post_hoc_authorization_even_with_rehashed_chain(tmp_path: Path) -> None:
    run = _run(tmp_path)
    events = [json.loads(line) for line in run.ledger_path.read_bytes().splitlines()]
    configuration = cast(dict[str, Any], events[0]["payload"]["configuration"])
    execution_authorization = cast(dict[str, Any], configuration["execution_authorization"])
    execution_authorization["authorized_at"] = "2999-01-01T00:00:00Z"
    cast(dict[str, Any], configuration["run_provenance"])["authorized_at"] = "2999-01-01T00:00:00Z"
    path = tmp_path / "post-hoc-authorization.jsonl"
    _rewrite_event_chain(path, events)
    with pytest.raises(PolicyRejection, match="predates its execution authorization"):
        runner.read_v02_scored_ledger(path)


def test_public_projection_is_embargoed_and_contains_no_fixed_or_private_digest_or_verdict(
    tmp_path: Path,
) -> None:
    run = _run(tmp_path)
    record = runner._public_embargoed_result_record(
        run,
        candidate=_candidate(),
        costs={category: 0 for category in runner._COST_CATEGORIES},
        cost_complete=True,
        total_cost=0,
        ledger_head="c" * 64,
    )
    encoded = runner._canonical_json(record).decode()
    assert record["publication_status"] == "embargoed_until_all_20_candidates_are_durably_frozen"
    evaluation = cast(dict[str, object], record["evaluation"])
    assert evaluation["status"] == "sealed"
    assert evaluation["accepted"] is None
    assert evaluation["outcome"] is None
    assert evaluation["claim_level"] is None
    assert "private_result_sha256" not in encoded
    assert "fixed_root_tree_oid" not in encoded
    assert "junit_sha256" not in encoded
    assert "duration_seconds" not in encoded


def test_private_result_preserves_bounded_base_run_evidence_and_redacts_fixed_output(
    tmp_path: Path,
) -> None:
    run = _run(tmp_path)

    def scheduled_run(
        source_role: str,
        schedule_ordinal: int,
        *,
        output: str,
        redacted: bool,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            source_role=source_role,
            role_ordinal=1,
            schedule_ordinal=schedule_ordinal,
            result=SimpleNamespace(
                phase=f"{source_role}_1",
                argv=("python", "-m", "pytest", "candidate.py::test_repro"),
                exit_code=1 if source_role == "base" else 0,
                duration_seconds=0.125,
                timed_out=False,
                oom_killed=False,
                output_truncated=False,
                output=output,
            ),
            output_sha256=hashlib.sha256(output.encode()).hexdigest(),
            junit_sha256="a" * 64,
            evaluator_output_redacted=redacted,
        )

    base_output = "FAILED: wrong normalized output"
    fixed_output = "HIDDEN_FIXED_SENTINEL"
    differential = SimpleNamespace(
        accepted=True,
        claim_level="differential_reproduction",
        outcome="differential_reproduction",
        fingerprint="wrong normalized output",
        scheduled_runs=(
            scheduled_run("base", 1, output=base_output, redacted=False),
            scheduled_run("fixed", 2, output=fixed_output, redacted=True),
        ),
        evaluator_capability_sha256="b" * 64,
        evaluator_package_sha256="c" * 64,
        evaluator_public_commitment_sha256="d" * 64,
        dependency_receipt_sha256=None,
        dependency_plan_sha256=None,
        dependency_tree_sha256=None,
        dependency_image_id=None,
    )
    record = runner._private_result_record(
        run,
        candidate=_candidate(),
        differential=cast(Any, differential),
        outcome="differential_reproduction",
        claim_level="differential_reproduction",
        costs={category: 0 for category in runner._COST_CATEGORIES},
        cost_complete=True,
        total_cost=0,
        ledger_head="e" * 64,
        classification_code="differential_reproduction",
    )
    evaluation = cast(dict[str, Any], record["evaluation"])
    scheduled = cast(list[dict[str, Any]], evaluation["scheduled_runs"])
    assert scheduled[0] == {
        "source_role": "base",
        "role_ordinal": 1,
        "schedule_ordinal": 1,
        "phase": "base_1",
        "argv": ["python", "-m", "pytest", "candidate.py::test_repro"],
        "exit_code": 1,
        "duration_seconds": 0.125,
        "timed_out": False,
        "oom_killed": False,
        "output_truncated": False,
        "bounded_output": base_output,
        "output_sha256": hashlib.sha256(base_output.encode()).hexdigest(),
        "junit_sha256": "a" * 64,
        "evaluator_output_redacted": False,
    }
    assert scheduled[1]["bounded_output"] is None
    assert scheduled[1]["evaluator_output_redacted"] is True
    assert fixed_output not in runner._canonical_json(record).decode()
    root = Path(__file__).parents[1]
    for result_schema_path in (
        root / "schemas" / "benchmark-v02-private-result.schema.json",
        root / "src" / "reproassert" / "schemas" / "benchmark-v02-private-result.schema.json",
    ):
        result_schema = json.loads(result_schema_path.read_text())
        Draft202012Validator.check_schema(result_schema)
        Draft202012Validator(result_schema).validate(record)


def test_reservation_is_deterministic_and_under_reservation_is_rejected() -> None:
    with pytest.raises(PolicyRejection, match="Cached-input pricing"):
        _pricing(
            input_microusd_per_million_tokens=1,
            cached_input_microusd_per_million_tokens=2,
        )
    assert (
        _pricing(
            input_microusd_per_million_tokens=2,
            cached_input_microusd_per_million_tokens=2,
        ).cached_input_microusd_per_million_tokens
        == 2
    )
    pricing = _pricing(
        input_microusd_per_million_tokens=1_000_000,
        output_microusd_per_million_tokens=2_000_000,
        sandbox_microusd_per_second=3,
        artifact_microusd_per_million_bytes=1_000_000,
        paid_storage_microusd=7,
    )
    policy = _policy(pricing=pricing, reserved_worst_case_microusd=1_000_000)
    request = GenerationRequest(
        issue_url="https://github.com/owner/repo/issues/1",
        issue_number=1,
        issue_title="title",
        issue_body="body",
        source_sha="1" * 40,
        source_context=SourceContext((), (), 0),
    )
    required = runner._required_reservation(policy, request)
    rendered_bytes = len(runner._rendered_input_text(request).encode())
    input_only_reservation = (
        rendered_bytes
        + runner.OPENAI_MAX_OUTPUT_TOKENS * 2
        + policy.max_case_wall_ms * 3 // 1_000
        + runner.MAX_TEST_BYTES
        + 7
    )
    assert required > 0
    assert required > input_only_reservation
    assert (
        len(runner._canonical_openai_request_bytes(request, policy.requested_model))
        > rendered_bytes
    )
    assert required == runner._required_reservation(policy, request)
    under_reserved = replace(policy, reserved_worst_case_microusd=required - 1)
    assert required > under_reserved.reserved_worst_case_microusd


def test_generator_context_and_capability_are_cross_bound_to_preregistration() -> None:
    frozen = _case()
    identity = V02CaseIdentity(frozen.id, frozen.repo, frozen.issue_url, frozen.base_sha)
    context = SimpleNamespace(
        case=identity,
        algorithm="context-v1",
        policy_sha256="4" * 64,
        context_sha256=frozen.source_context_sha256,
    )
    capability = SimpleNamespace(
        case=identity,
        public_commitment_sha256=frozen.evaluator_commitment_sha256,
        source_context_algorithm=context.algorithm,
        source_context_policy_sha256=context.policy_sha256,
        source_context_sha256=context.context_sha256,
    )
    runner._validate_generator_context(cast(Any, context), frozen)
    runner._bind_capability(cast(Any, capability), frozen, cast(Any, context))
    with pytest.raises(PolicyRejection, match="contexts differ"):
        runner._bind_capability(
            cast(Any, SimpleNamespace(**{**vars(capability), "source_context_sha256": "f" * 64})),
            frozen,
            cast(Any, context),
        )
    with pytest.raises(PolicyRejection, match="case differs"):
        runner._validate_generator_context(
            cast(Any, SimpleNamespace(**{**vars(context), "case": _case(2)})), frozen
        )


def test_crashed_attempt_with_missing_costs_blocks_new_campaign_reservation(tmp_path: Path) -> None:
    run = _run(tmp_path)
    runner._append_event(
        run,
        "attempt_crashed",
        {
            "crashed_at": runner._now(),
            "classification_code": "injected_crash",
            "exception_type": "KeyboardInterrupt",
            "cost_complete": False,
            "recovery_status": "manual_reconciliation_required_no_new_provider_call",
        },
    )
    next_run = replace(
        run,
        attempt_id=f"attempt_002_{'c' * 16}",
        case=_case(2),
        attempt_directory=tmp_path / "attempt-rk-v0.2-002",
    )
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    crash = snapshot.events[-1]
    assert crash["payload"]["recovery_status"] == (
        "manual_reconciliation_required_no_new_provider_call"
    )
    with pytest.raises(PolicyRejection, match="unknown attributable cost"):
        runner._preflight_attempt(snapshot, next_run)


def test_generation_request_is_one_shot_with_no_feedback(tmp_path: Path) -> None:
    run = _run(tmp_path)
    assert run.request.attempt == 1
    assert run.request.feedback == ""
    assert run.request.source_sha == run.case.base_sha
    serialized = run.request.to_dict()
    assert serialized["bounded_verifier_feedback"] == ""
    assert "evaluator" not in json.dumps(serialized).lower()


def test_top_level_composition_commits_once_before_capability_and_embargoes_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(PolicyRejection, match="generation barrier"):
        runner.run_v02_scored_case(
            preregistration_path=tmp_path / "unused-preregistration.json",
            case_id="rk-v0.2-001",
            generator_projection_path=tmp_path / "unused-projection.json",
            generator_source_context=cast(Any, object()),
            evaluator_capability=cast(Any, object()),
            sandbox=DockerSandbox(),
            base_source=tmp_path,
            fixed_source=tmp_path,
            ledger_path=tmp_path / "unused-ledger.jsonl",
            attempt_directory=tmp_path / "unused-attempt",
            policy=_policy(),
        )
