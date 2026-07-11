"""Separate exact-image evaluation entry for frozen v0.2 generation dispositions."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import cast

from reproassert import benchmark_v02_runner as runner
from reproassert.benchmark_v02_candidate_evaluator import (
    CandidateArtifact,
    CandidateEvaluationReceipt,
    ExecutorFactory,
    evaluate_instance_candidate,
    verify_instance_candidate_receipt,
)
from reproassert.benchmark_v02_exact_capability import (
    VerifiedV02ExactImageEvaluatorCapability,
    require_v02_exact_image_evaluator_capability,
)
from reproassert.benchmark_v02_exact_preregistration import (
    VerifiedV02ExactPreregistration,
    require_v02_exact_preregistration,
)
from reproassert.benchmark_v02_hidden import (
    VerifiedV02HiddenExtraction,
    hidden_case_artifacts,
)
from reproassert.benchmark_v02_scored_preregistration import load_v02_scored_preregistration
from reproassert.candidate import ValidatedCandidate
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file
from reproassert.semantic_issuer import VerifiedV02GeneratorSourceContext

ALGORITHM = "reproassert-v02-exact-image-scored-result-v1"
SCHEMA_VERSION = "1.0.0"
PRIVATE_FILENAME = "reproassert-v02-exact-private-result.json"
PUBLIC_FILENAME = "reproassert-v02-exact-public-embargoed-result.json"
RECEIPT_FILENAME = "reproassert-v02-exact-candidate-evaluation.json"
MAX_BYTES = 2 * 1024 * 1024
_EXECUTION_ISSUER = object()


@dataclass(frozen=True, init=False)
class V02ExactScoredResult:
    """Nominal live result issued only by the exact scored execution path."""

    campaign_id: str
    attempt_id: str
    case_id: str
    status: str
    outcome: str
    claim_level: str
    evaluation_kind: str
    candidate_sha256: str | None
    evaluation_receipt_sha256: str | None
    private_result_path: Path
    public_result_path: Path
    terminal_event_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("V02ExactScoredResult is exact-executor-issued only")


@dataclass(frozen=True)
class StructuralV02ExactScoredResult:
    path: Path
    sha256: str
    record: Mapping[str, object] = field(repr=False)
    verification_scope: str = "structural_only_no_trusted_verdict"


def evaluate_v02_exact_frozen_case(
    *,
    preregistration_path: Path,
    exact_preregistration: VerifiedV02ExactPreregistration,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    campaign_barrier: runner.VerifiedV02CampaignGenerationBarrier,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability | None,
    verified_hidden: VerifiedV02HiddenExtraction | None,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    ledger_path: Path,
    attempt_directory: Path,
    attempt_id: str,
    executed_at: str,
    tool_git_sha: str,
    policy: runner.V02ScoredRunPolicy,
) -> V02ExactScoredResult:
    """Evaluate with the production exact-image executor only."""

    return _evaluate_v02_exact_frozen_case_with_factory(
        preregistration_path=preregistration_path,
        exact_preregistration=exact_preregistration,
        case_id=case_id,
        generator_projection_path=generator_projection_path,
        generator_source_context=generator_source_context,
        campaign_barrier=campaign_barrier,
        evaluator_capability=evaluator_capability,
        verified_hidden=verified_hidden,
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        gold_specs_path=gold_specs_path,
        ledger_path=ledger_path,
        attempt_directory=attempt_directory,
        attempt_id=attempt_id,
        executed_at=executed_at,
        tool_git_sha=tool_git_sha,
        policy=policy,
        executor_factory=None,
    )


def _evaluate_v02_exact_frozen_case_with_factory(
    *,
    preregistration_path: Path,
    exact_preregistration: VerifiedV02ExactPreregistration,
    case_id: str,
    generator_projection_path: Path,
    generator_source_context: VerifiedV02GeneratorSourceContext,
    campaign_barrier: runner.VerifiedV02CampaignGenerationBarrier,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability | None,
    verified_hidden: VerifiedV02HiddenExtraction | None,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    ledger_path: Path,
    attempt_directory: Path,
    attempt_id: str,
    executed_at: str,
    tool_git_sha: str,
    policy: runner.V02ScoredRunPolicy,
    executor_factory: ExecutorFactory | None,
) -> V02ExactScoredResult:
    """Evaluate one frozen candidate in its exact image; never invokes a provider."""

    policy.require_executable()
    run = runner._prepare_recovery_context(
        preregistration_path=Path(preregistration_path),
        case_id=case_id,
        generator_projection_path=Path(generator_projection_path),
        generator_source_context=generator_source_context,
        ledger_path=Path(ledger_path),
        attempt_directory=Path(attempt_directory),
        attempt_id=attempt_id,
        policy=policy,
    )
    lock = runner._acquire_recovery_lock(run.attempt_directory)
    mutated = False
    receipt_recoverable = False
    try:
        exact_sha, exact_case_commitment = _bind_exact_preregistration_view(
            preregistration_path=Path(preregistration_path),
            exact_preregistration=exact_preregistration,
            run=run,
        )
        completed = _completed_result(run, exact_sha, exact_case_commitment)
        if completed is not None:
            return completed
        runner.require_v02_campaign_generation_barrier(
            campaign_barrier,
            preregistration_path=Path(preregistration_path),
            ledger_path=run.ledger_path,
            policy=policy,
        )
        snapshot = runner.read_v02_scored_ledger(run.ledger_path)
        disposition = runner._attempt_generation_disposition(snapshot, run)
        receipt_path = run.attempt_directory / RECEIPT_FILENAME
        receipt_recovery = receipt_path.exists()
        if receipt_recovery:
            _preflight_receipt_recovery(snapshot, run)
        else:
            runner._preflight_frozen_evaluation(snapshot, run)
        if disposition["status"] == "no_candidate":
            mutated = True
            return _write_result(
                run,
                candidate=None,
                evaluation={
                    "kind": "no_candidate",
                    "accepted": False,
                    "classification": disposition["classification_code"],
                    "receipt_sha256": None,
                    "reason": "generation_produced_no_candidate",
                },
                outcome="no_output",
                claim_level="rejected",
                exact_preregistration_sha256=exact_sha,
                exact_case_commitment_sha256=exact_case_commitment,
            )

        transaction = runner._load_generation_transaction(run)
        candidate = transaction.candidate
        if disposition["candidate_sha256"] != candidate.sha256:
            raise _reject("Frozen disposition differs from its durable candidate transaction.")
        runner._revalidate_candidate_file(run, transaction.path, candidate)
        runner._assert_known_model_cost(run)
        runner._assert_total_within_reservation(run)

        # This is deliberately the first exact evaluator/hidden authority access.
        mutated = True
        capability = require_v02_exact_image_evaluator_capability(evaluator_capability)
        if capability.case_id != run.case.id:
            raise _reject("Exact evaluator capability is for a different scored case.")
        if capability.evaluator_public_commitment_sha256 != run.case.evaluator_commitment_sha256:
            raise _reject("Exact evaluator commitment differs from the campaign view.")
        if verified_hidden is None:
            raise _reject("Freshly verified hidden extraction authority is required.")
        hidden_case_artifacts(verified_hidden, run.case.id)

        phase_at = (
            _existing_differential_started_at(snapshot, run)
            if receipt_recovery
            else runner._start_phase(run, "differential")
        )
        phase_started = time.monotonic()
        if run.case.id == "rk-v0.2-014":
            if (
                capability.gold_smoke_classification != "infrastructure_failure"
                or capability.gold_smoke_reason != "network_dependency"
            ):
                raise _reject("Case 014 must preserve its frozen network infrastructure failure.")
            runner._finish_phase(
                run,
                phase="differential",
                started_at=phase_at,
                started_monotonic=phase_started,
                status="failed",
                classification_code="v02_exact_network_dependency",
                evidence={"network_mode": "none", "reason": "network_dependency"},
            )
            return _write_result(
                run,
                candidate=candidate,
                evaluation={
                    "kind": "infrastructure_failure",
                    "accepted": False,
                    "classification": "network_dependency",
                    "receipt_sha256": None,
                    "reason": "network_required_but_sandbox_network_is_disabled",
                },
                outcome="benchmark_infrastructure_error",
                claim_level="rejected",
                exact_preregistration_sha256=exact_sha,
                exact_case_commitment_sha256=exact_case_commitment,
            )

        artifact = CandidateArtifact(
            relative_path=runner._run_candidate_contract(run).relative_path,
            content=candidate.test_content.encode("utf-8"),
            test_function=candidate.test_function,
        )
        receipt = None
        if not receipt_recovery:
            receipt = evaluate_instance_candidate(
                evaluator_capability=capability,
                verified_hidden=verified_hidden,
                gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
                gold_specs_path=Path(gold_specs_path),
                manifest_path=Path(manifest_path),
                expected_manifest_sha256=expected_manifest_sha256,
                case_id=run.case.id,
                candidate=artifact,
                output_path=receipt_path,
                executed_at=executed_at,
                tool_git_sha=tool_git_sha,
                executor_factory=executor_factory,
            )
        verified = _verify_reusable_receipt(
            receipt_path,
            run,
            artifact,
            capability=capability,
            manifest_path=Path(manifest_path),
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
            gold_specs_path=Path(gold_specs_path),
            executed_at=executed_at,
            tool_git_sha=tool_git_sha,
        )
        if receipt is not None and verified != receipt:
            raise _reject("Exact candidate receipt changed after evaluation.")
        receipt_recoverable = True
        duration_ms = verified.evaluator_wall_ms
        if not _differential_finished(snapshot, run):
            runner._finish_phase(
                run,
                phase="differential",
                started_at=phase_at,
                started_monotonic=phase_started,
                status="succeeded",
                classification_code=None,
                evidence={
                    "accepted": verified.accepted,
                    "classification": verified.classification,
                    "exact_receipt_sha256": verified.sha256,
                    "network_mode": "none",
                },
            )
        pricing = runner._require_pricing(run.policy)
        if not _has_sandbox_cost(snapshot, run):
            runner._record_cost(
                run,
                category="sandbox_compute",
                attribution="scored",
                status="measured" if pricing.sandbox_microusd_per_second else "zero_verified",
                amount=runner._sandbox_cost(pricing, duration_ms),
                source_call_id=None,
                evidence={"duration_ms": duration_ms, "exact_receipt_sha256": verified.sha256},
            )
        runner._assert_total_within_reservation(run)
        sealed = _verify_reusable_receipt(
            receipt_path,
            run,
            artifact,
            capability=capability,
            manifest_path=Path(manifest_path),
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
            gold_specs_path=Path(gold_specs_path),
            executed_at=executed_at,
            tool_git_sha=tool_git_sha,
        )
        if sealed.sha256 != verified.sha256:
            raise _reject("Exact receipt changed immediately before result sealing.")
        return _write_result(
            run,
            candidate=candidate,
            evaluation={
                "kind": "exact_image_receipt",
                "accepted": verified.accepted,
                "classification": verified.classification,
                "receipt_sha256": verified.sha256,
                "reason": None,
            },
            outcome=("verified_reproduction" if verified.accepted else "rejected_reproduction"),
            claim_level=("differential_reproduction" if verified.accepted else "rejected"),
            exact_preregistration_sha256=exact_sha,
            exact_case_commitment_sha256=exact_case_commitment,
        )
    except BaseException as exc:
        if mutated and not receipt_recoverable:
            runner._append_evaluation_crash_if_open(run, exc)
        raise
    finally:
        runner._release_recovery_lock(lock)


def verify_v02_exact_scored_result(path: Path) -> StructuralV02ExactScoredResult:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise _reject("Exact scored result exceeds its size limit.")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Exact scored result is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject("Exact scored result is not canonical JSON.")
    if (
        set(value)
        != {
            "algorithm",
            "attempt_id",
            "benchmark_version",
            "campaign_id",
            "candidate",
            "case",
            "claims",
            "cost",
            "evaluation",
            "exact_case_commitment_sha256",
            "exact_preregistration_sha256",
            "ledger_head_before_result_sha256",
            "outcome",
            "claim_level",
            "result_sha256",
            "runner_input_sha256",
            "schema_version",
            "visibility",
        }
        or value.get("algorithm") != ALGORITHM
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("benchmark_version") != "0.2"
        or value.get("result_sha256") != _result_self_hash(value)
    ):
        raise _reject("Exact scored result fields or identity are invalid.")
    for name in (
        "exact_case_commitment_sha256",
        "exact_preregistration_sha256",
        "ledger_head_before_result_sha256",
        "runner_input_sha256",
        "result_sha256",
    ):
        digest = value.get(name)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise _reject("Exact scored result preregistration binding is invalid.")
    evaluation = value.get("evaluation")
    if not isinstance(evaluation, dict) or set(evaluation) != {
        "accepted",
        "classification",
        "kind",
        "reason",
        "receipt_sha256",
    }:
        raise _reject("Exact evaluation result union is invalid.")
    kind = evaluation.get("kind")
    receipt = evaluation.get("receipt_sha256")
    if kind == "exact_image_receipt":
        if (
            not isinstance(receipt, str)
            or len(receipt) != 64
            or evaluation.get("reason") is not None
        ):
            raise _reject("Exact receipt result is incomplete.")
        receipt_path = Path(path).parent / RECEIPT_FILENAME
        verified_receipt = verify_instance_candidate_receipt(receipt_path)
        receipt_record = cast(
            dict[str, object], json.loads(_read_regular_bytes(receipt_path, MAX_BYTES))
        )
        receipt_candidate = receipt_record.get("candidate")
        scored_case = value.get("case")
        scored_candidate = value.get("candidate")
        if (
            verified_receipt.sha256 != receipt
            or verified_receipt.accepted != evaluation.get("accepted")
            or verified_receipt.classification != evaluation.get("classification")
            or not isinstance(scored_case, dict)
            or verified_receipt.case_id != scored_case.get("id")
            or not isinstance(receipt_candidate, dict)
            or not isinstance(scored_candidate, dict)
            or receipt_candidate.get("sha256") != scored_candidate.get("sha256")
        ):
            raise _reject("Exact candidate receipt bytes disagree with the scored result.")
        if (evaluation.get("accepted") is True) != (
            evaluation.get("classification") == "verified_reproduction"
        ):
            raise _reject("Exact acceptance and classification disagree.")
    elif kind == "infrastructure_failure":
        if (
            receipt is not None
            or evaluation.get("accepted") is not False
            or not evaluation.get("reason")
        ):
            raise _reject("Infrastructure result is inconsistent.")
    elif kind == "no_candidate":
        if receipt is not None or value.get("candidate") is not None:
            raise _reject("No-candidate result is inconsistent.")
    else:
        raise _reject("Exact evaluation result kind is unsupported.")
    claims = value.get("claims")
    if claims != {
        "causal_controls_complete": False,
        "hidden_bytes_emitted": False,
        "network_enabled": False,
        "provider_calls_during_evaluation": 0,
        "semantic_review_complete": False,
    }:
        raise _reject("Exact scored result trust claims are invalid.")
    candidate = value.get("candidate")
    if candidate is not None:
        if not isinstance(candidate, dict) or set(candidate) != {
            "bytes",
            "path",
            "sha256",
            "test_function",
        }:
            raise _reject("Exact scored candidate binding is invalid.")
        size = candidate.get("bytes")
        if (
            type(size) is not int
            or not 1 <= size <= 32_768
            or not isinstance(candidate.get("path"), str)
            or not isinstance(candidate.get("test_function"), str)
            or not isinstance(candidate.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", cast(str, candidate["sha256"])) is None
        ):
            raise _reject("Exact scored candidate values are invalid.")
    if kind == "no_candidate" and candidate is not None:
        raise _reject("No-candidate result cannot bind candidate bytes.")
    if kind != "no_candidate" and candidate is None:
        raise _reject("Evaluated exact result must bind one candidate.")
    cost = value.get("cost")
    if not isinstance(cost, dict) or set(cost) != {"complete", "total_attributable_microusd"}:
        raise _reject("Exact scored cost binding is invalid.")
    complete = cost.get("complete")
    total = cost.get("total_attributable_microusd")
    if type(complete) is not bool or (
        (complete is True and (type(total) is not int or total < 0))
        or (complete is False and total is not None)
    ):
        raise _reject("Exact scored cost completeness is inconsistent.")
    expected_relations = {
        "exact_image_receipt": (
            "verified_reproduction"
            if evaluation.get("accepted") is True
            else "rejected_reproduction",
            "differential_reproduction" if evaluation.get("accepted") is True else "rejected",
        ),
        "infrastructure_failure": ("benchmark_infrastructure_error", "rejected"),
        "no_candidate": ("no_output", "rejected"),
    }
    if (value.get("outcome"), value.get("claim_level")) != expected_relations[cast(str, kind)]:
        raise _reject("Exact scored outcome and claim level disagree with evaluation evidence.")
    case = value.get("case")
    if not isinstance(case, dict) or set(case) != {
        "base_sha",
        "difficulty",
        "evaluator_commitment_sha256",
        "generator_projection_sha256",
        "id",
        "issue_url",
        "repo",
        "smoke",
        "source_context_sha256",
    }:
        raise _reject("Exact scored case binding is invalid.")
    if (
        not isinstance(case.get("id"), str)
        or re.fullmatch(r"rk-v0\.2-[0-9]{3}", cast(str, case["id"])) is None
        or not isinstance(case.get("repo"), str)
        or not isinstance(case.get("issue_url"), str)
        or not isinstance(case.get("difficulty"), str)
        or type(case.get("smoke")) is not bool
    ):
        raise _reject("Exact scored case values are invalid.")
    for name in (
        "base_sha",
        "evaluator_commitment_sha256",
        "generator_projection_sha256",
        "source_context_sha256",
    ):
        expected_length = 40 if name == "base_sha" else 64
        if (
            not isinstance(case.get(name), str)
            or re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", cast(str, case[name])) is None
        ):
            raise _reject("Exact scored case digest binding is invalid.")
    for name in ("attempt_id", "campaign_id"):
        if (
            not isinstance(value.get(name), str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}", cast(str, value[name])) is None
        ):
            raise _reject("Exact scored execution identity is invalid.")
    return StructuralV02ExactScoredResult(Path(path), hashlib.sha256(raw).hexdigest(), value)


def _preflight_receipt_recovery(
    snapshot: runner.V02LedgerSnapshot, run: runner._RunContext
) -> None:
    events = [event for event in snapshot.events if event["attempt_id"] == run.attempt_id]
    terminal = False
    for event in events:
        if event["event_type"] in {"attempt_finished", "attempt_crashed"}:
            terminal = True
        elif event["event_type"] == "recovery_started":
            terminal = False
    if terminal:
        raise _reject("Receipt recovery cannot continue from a terminal attempt.")
    differential = [
        event
        for event in events
        if event["event_type"] in {"phase_started", "phase_finished"}
        and cast(Mapping[str, object], event["payload"])["phase"] == "differential"
    ]
    starts = [event for event in differential if event["event_type"] == "phase_started"]
    finishes = [event for event in differential if event["event_type"] == "phase_finished"]
    if len(starts) != 1 or len(finishes) > 1:
        raise _reject("Receipt recovery requires one unambiguous differential phase.")
    if any(
        event["event_type"] in {"phase_started", "phase_finished"}
        and cast(Mapping[str, object], event["payload"])["phase"] == "result_write"
        for event in events
    ):
        raise _reject("Receipt recovery cannot cross an incomplete result-write boundary.")


def _existing_differential_started_at(
    snapshot: runner.V02LedgerSnapshot, run: runner._RunContext
) -> str:
    event = next(
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id
        and event["event_type"] == "phase_started"
        and cast(Mapping[str, object], event["payload"])["phase"] == "differential"
    )
    return cast(str, cast(Mapping[str, object], event["payload"])["started_at"])


def _differential_finished(snapshot: runner.V02LedgerSnapshot, run: runner._RunContext) -> bool:
    return any(
        event["attempt_id"] == run.attempt_id
        and event["event_type"] == "phase_finished"
        and cast(Mapping[str, object], event["payload"])["phase"] == "differential"
        for event in snapshot.events
    )


def _has_sandbox_cost(snapshot: runner.V02LedgerSnapshot, run: runner._RunContext) -> bool:
    return any(
        event["attempt_id"] == run.attempt_id
        and event["event_type"] == "cost_recorded"
        and cast(Mapping[str, object], event["payload"])["category"] == "sandbox_compute"
        for event in snapshot.events
    )


def _verify_reusable_receipt(
    path: Path,
    run: runner._RunContext,
    artifact: CandidateArtifact,
    *,
    capability: VerifiedV02ExactImageEvaluatorCapability,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    executed_at: str,
    tool_git_sha: str,
) -> CandidateEvaluationReceipt:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_BYTES + 1)
    verified = verify_instance_candidate_receipt(path, raw=raw)
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Reusable exact receipt is invalid JSON.") from exc
    candidate = value.get("candidate") if isinstance(value, dict) else None
    inputs = value.get("inputs") if isinstance(value, dict) else None
    expected_target = f"{artifact.relative_path}::{artifact.test_function}"
    expected_inputs = {
        **capability.public_record(),
        "evaluator_public_commitment_sha256": capability.evaluator_public_commitment_sha256,
    }
    manifest_sha256 = _regular_file_sha256(manifest_path, "runtime manifest")
    gold_raw = _regular_file_bytes(gold_smoke_receipt_path, "gold-smoke receipt")
    try:
        gold = json.loads(gold_raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Fresh gold-smoke receipt is invalid JSON.") from exc
    gold_inputs = gold.get("inputs") if isinstance(gold, dict) else None
    expected_specs_sha256 = (
        gold_inputs.get("gold_specs_sha256") if isinstance(gold_inputs, Mapping) else None
    )
    if (
        verified.case_id != run.case.id
        or not isinstance(candidate, Mapping)
        or candidate.get("sha256") != hashlib.sha256(artifact.content).hexdigest()
        or candidate.get("bytes") != len(artifact.content)
        or candidate.get("relative_path") != artifact.relative_path
        or candidate.get("target") != expected_target
        or inputs != expected_inputs
        or value.get("executed_at") != executed_at
        or value.get("tool_git_sha") != tool_git_sha
        or manifest_sha256 != expected_manifest_sha256
        or manifest_sha256 != capability.runtime_manifest_sha256
        or hashlib.sha256(gold_raw).hexdigest() != capability.gold_smoke_receipt_sha256
        or not isinstance(expected_specs_sha256, str)
        or _regular_file_sha256(gold_specs_path, "gold specs") != expected_specs_sha256
    ):
        raise _reject("Reusable exact receipt differs from the durable candidate.")
    return verified


def _regular_file_bytes(path: Path, label: str) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise _reject(f"Fresh {label} exceeds its byte limit.")
    return raw


def _regular_file_sha256(path: Path, label: str) -> str:
    return hashlib.sha256(_regular_file_bytes(path, label)).hexdigest()


def _write_result(
    run: runner._RunContext,
    *,
    candidate: ValidatedCandidate | None,
    evaluation: dict[str, object],
    outcome: str,
    claim_level: str,
    exact_preregistration_sha256: str,
    exact_case_commitment_sha256: str,
) -> V02ExactScoredResult:
    runner._fill_missing_costs(run, candidate=candidate)
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    costs = runner._attempt_costs(snapshot, run.attempt_id)
    cost_complete = all(costs.get(category) is not None for category in runner._COST_CATEGORIES)
    total = (
        sum(cast(int, costs[name]) for name in runner._ATTRIBUTABLE_COST_CATEGORIES)
        if cost_complete
        else None
    )
    contract = runner._run_candidate_contract(run)
    candidate_record = (
        None
        if candidate is None
        else {
            "bytes": len(candidate.test_content.encode("utf-8")),
            "path": contract.relative_path,
            "sha256": candidate.sha256,
            "test_function": candidate.test_function,
        }
    )
    common = {
        "algorithm": ALGORITHM,
        "attempt_id": run.attempt_id,
        "benchmark_version": "0.2",
        "campaign_id": run.policy.campaign_id,
        "candidate": candidate_record,
        "case": asdict(run.case),
        "claims": {
            "causal_controls_complete": False,
            "hidden_bytes_emitted": False,
            "network_enabled": False,
            "provider_calls_during_evaluation": 0,
            "semantic_review_complete": False,
        },
        "cost": {"complete": cost_complete, "total_attributable_microusd": total},
        "evaluation": evaluation,
        "exact_case_commitment_sha256": exact_case_commitment_sha256,
        "exact_preregistration_sha256": exact_preregistration_sha256,
        "ledger_head_before_result_sha256": snapshot.head_event_sha256,
        "outcome": outcome,
        "claim_level": claim_level,
        "runner_input_sha256": run.runner_input_sha256,
        "schema_version": SCHEMA_VERSION,
    }
    private = {**common, "result_sha256": "0" * 64, "visibility": "private_controller_only"}
    public = {**common, "result_sha256": "0" * 64, "visibility": "public_safe_embargoed"}
    private["result_sha256"] = _result_self_hash(private)
    public["result_sha256"] = _result_self_hash(public)
    private_bytes = _canonical(private) + b"\n"
    public_bytes = _canonical(public) + b"\n"
    private_sha = hashlib.sha256(private_bytes).hexdigest()
    public_sha = hashlib.sha256(public_bytes).hexdigest()
    phase_at = runner._start_phase(run, "result_write")
    phase_started = time.monotonic()
    private_path = run.attempt_directory / PRIVATE_FILENAME
    public_path = run.attempt_directory / PUBLIC_FILENAME
    runner._write_exclusive_fsync(private_path, private_bytes)
    runner._write_exclusive_fsync(public_path, public_bytes)
    verify_v02_exact_scored_result(private_path)
    verify_v02_exact_scored_result(public_path)
    runner._finish_phase(
        run,
        phase="result_write",
        started_at=phase_at,
        started_monotonic=phase_started,
        status="succeeded",
        classification_code=None,
        evidence={"private_result_sha256": private_sha, "public_result_sha256": public_sha},
    )
    terminal = runner._append_event(
        run,
        "attempt_finished",
        {
            "completed_at": runner._now(),
            "status": "complete" if cost_complete else "incomplete_unknown_cost",
            "outcome": outcome,
            "claim_level": claim_level,
            "cost_complete": cost_complete,
            "total_attributable_microusd": total,
            "private_result_sha256": private_sha,
            "public_result_sha256": public_sha,
        },
    )
    return _issue_exact_result(
        campaign_id=cast(str, run.policy.campaign_id),
        attempt_id=run.attempt_id,
        case_id=run.case.id,
        status="complete" if cost_complete else "incomplete_unknown_cost",
        outcome=outcome,
        claim_level=claim_level,
        evaluation_kind=cast(str, evaluation["kind"]),
        candidate_sha256=candidate.sha256 if candidate else None,
        evaluation_receipt_sha256=cast(str | None, evaluation["receipt_sha256"]),
        private_result_path=private_path,
        public_result_path=public_path,
        terminal_event_sha256=cast(str, terminal["event_sha256"]),
    )


def _completed_result(
    run: runner._RunContext,
    exact_preregistration_sha256: str,
    exact_case_commitment_sha256: str,
) -> V02ExactScoredResult | None:
    snapshot = runner.read_v02_scored_ledger(run.ledger_path)
    terminals = [
        event
        for event in snapshot.events
        if event["attempt_id"] == run.attempt_id and event["event_type"] == "attempt_finished"
    ]
    if not terminals:
        return None
    if len(terminals) != 1:
        raise _reject("Exact scored terminal state is ambiguous.")
    terminal = terminals[0]
    payload = cast(Mapping[str, object], terminal["payload"])
    private_path = run.attempt_directory / PRIVATE_FILENAME
    public_path = run.attempt_directory / PUBLIC_FILENAME
    private = verify_v02_exact_scored_result(private_path).record
    verify_v02_exact_scored_result(public_path)
    private_sha = runner._sha256_file(private_path, MAX_BYTES)
    public_sha = runner._sha256_file(public_path, MAX_BYTES)
    if (
        private_sha != payload["private_result_sha256"]
        or public_sha != payload["public_result_sha256"]
    ):
        raise _reject("Exact scored result changed after terminalization.")
    if (
        private["exact_preregistration_sha256"] != exact_preregistration_sha256
        or private["exact_case_commitment_sha256"] != exact_case_commitment_sha256
    ):
        raise _reject("Completed result differs from the exact preregistration bridge.")
    evaluation = cast(Mapping[str, object], private["evaluation"])
    candidate = private["candidate"]
    return _issue_exact_result(
        campaign_id=cast(str, run.policy.campaign_id),
        attempt_id=run.attempt_id,
        case_id=run.case.id,
        status=cast(str, payload["status"]),
        outcome=cast(str, payload["outcome"]),
        claim_level=cast(str, payload["claim_level"]),
        evaluation_kind=cast(str, evaluation["kind"]),
        candidate_sha256=(
            cast(str, cast(Mapping[str, object], candidate)["sha256"])
            if isinstance(candidate, Mapping)
            else None
        ),
        evaluation_receipt_sha256=cast(str | None, evaluation["receipt_sha256"]),
        private_result_path=private_path,
        public_result_path=public_path,
        terminal_event_sha256=cast(str, terminal["event_sha256"]),
    )


def _bind_exact_preregistration_view(
    *,
    preregistration_path: Path,
    exact_preregistration: VerifiedV02ExactPreregistration,
    run: runner._RunContext,
) -> tuple[str, str]:
    """Bind the live exact bytes, verifier-issued token, runner, and selected case."""

    authority = require_v02_exact_preregistration(exact_preregistration)
    loaded = load_v02_scored_preregistration(preregistration_path)
    if loaded.format != "exact-image-v1" or len(loaded.cases) != 20:
        raise _reject("Scored evaluation requires the complete exact preregistration.")
    if (
        loaded.raw_sha256 != authority.sha256
        or loaded.cohort_sha256 != authority.cohort_sha256
        or loaded.request_set_sha256 != authority.request_set_sha256
        or len(loaded.cases) != authority.case_count
        or run.preregistration_sha256 != loaded.raw_sha256
        or run.preregistration_request_set_sha256 != loaded.request_set_sha256
        or run.cohort_sha256 != loaded.cohort_sha256
    ):
        raise _reject("Exact preregistration authority differs from the runner input.")
    selected = loaded.exact_row(run.case.id)
    if (
        selected is None
        or selected.get("candidate_profile") != runner._run_candidate_contract(run).profile
    ):
        raise _reject("Scored case profile is absent from the exact preregistration bridge.")
    commitment = selected.get("case_commitment_sha256")
    if not isinstance(commitment, str) or len(commitment) != 64:
        raise _reject("Exact preregistered case commitment is invalid.")
    return loaded.raw_sha256, commitment


def _issue_exact_result(**values: object) -> V02ExactScoredResult:
    issued = object.__new__(V02ExactScoredResult)
    for name, value in {**values, "_issuer": _EXECUTION_ISSUER}.items():
        object.__setattr__(issued, name, value)
    return issued


def require_v02_exact_scored_execution(value: object) -> V02ExactScoredResult:
    if type(value) is not V02ExactScoredResult or value._issuer is not _EXECUTION_ISSUER:
        raise _reject("Fresh exact scored execution authority is required.")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _result_self_hash(value: Mapping[str, object]) -> str:
    unsigned = dict(value)
    unsigned["result_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _read_regular_bytes(path: Path, limit: int) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _reject("Exact scored bound receipt exceeds its size limit.")
    return raw


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("v02_exact_scored", message)
