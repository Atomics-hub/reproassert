"""All-20 automated-oracle bridge from durable generation to sandbox evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_amendment import VerifiedV02BenchmarkAmendment
from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_candidate_evaluator import (
    CandidateArtifact,
    CandidateEvaluationReceipt,
    evaluate_instance_candidate,
    verify_instance_candidate_receipt,
)
from reproassert.benchmark_v02_exact_capability import VerifiedV02ExactImageEvaluatorCapability
from reproassert.benchmark_v02_hidden import VerifiedV02HiddenExtraction
from reproassert.benchmark_v021_automated_evidence import (
    VerifiedV021AutomatedEvidence,
    require_v021_automated_evidence,
)
from reproassert.benchmark_v021_campaign_controller import (
    VerifiedV021GenerationBarrier,
    require_v021_generation_barrier,
)
from reproassert.benchmark_v021_openai_adapter import parse_v021_candidate_output
from reproassert.benchmark_v021_runtime import (
    RESPONSE_ALGORITHM,
    V021GenerationResult,
    VerifiedV021RuntimePlan,
    require_v021_generation_result,
    require_v021_runtime_plan,
)
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v021-automated-evaluation-v1"
AGGREGATE_ALGORITHM = "reproassert-v021-automated-evaluation-aggregate-v1"
SCHEMA_VERSION = "1.0.0"
CASE_COUNT = 20
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_EVALUATION_RECEIPT_BYTES = 512 * 1024
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class V021EvaluationCaseInputs:
    """Private evaluator authorities and paths; never serialized into public receipts."""

    issue_number: int
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability = field(repr=False)
    verified_hidden: VerifiedV02HiddenExtraction = field(repr=False)
    gold_smoke_receipt_path: Path = field(repr=False)
    gold_specs_path: Path = field(repr=False)
    manifest_path: Path = field(repr=False)
    expected_manifest_sha256: str
    amendment_authority: VerifiedV02BenchmarkAmendment | None = field(default=None, repr=False)


@dataclass(frozen=True)
class V021AutomatedEvaluationReceipt:
    path: Path
    sha256: str
    case_id: str
    classification: str
    accepted: bool


@dataclass(frozen=True, init=False)
class VerifiedV021AutomatedEvaluationSet:
    """Process-local authority issued only after all 20 evaluations are verified."""

    path: Path
    sha256: str
    accepted_count: int
    rejected_count: int
    receipt_sha256_by_case: Mapping[str, str] = field(repr=False)
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021AutomatedEvaluationSet is verifier-issued only")


@dataclass(frozen=True)
class StructuralV021AutomatedEvaluationSet:
    path: Path
    sha256: str
    accepted_count: int
    rejected_count: int
    verification_scope: str = "structural_only_no_live_authority"


Evaluator = Callable[..., CandidateEvaluationReceipt]
ReceiptVerifier = Callable[[Path], CandidateEvaluationReceipt]
_ISSUER = object()
_LIVE_ISSUANCE = object()


def evaluate_v021_automated_campaign(
    *,
    plan: VerifiedV021RuntimePlan,
    barrier: VerifiedV021GenerationBarrier,
    generation_results: Sequence[V021GenerationResult],
    automated_evidence_authority: VerifiedV021AutomatedEvidence,
    response_directory: Path,
    case_inputs: Mapping[str, V021EvaluationCaseInputs],
    receipt_directory: Path,
    aggregate_path: Path,
    executed_at: str,
    tool_git_sha: str,
) -> VerifiedV021AutomatedEvaluationSet:
    """Production all-20 evaluation using only the built-in sandbox evaluator."""

    def verify_live_receipt(path: Path) -> CandidateEvaluationReceipt:
        case_id = path.name.removesuffix(".evaluator.json")
        inputs = case_inputs.get(case_id)
        if inputs is None:
            raise _reject("Evaluator receipt is for an unknown case.")
        return verify_instance_candidate_receipt(
            path,
            automated_evidence_authority=automated_evidence_authority,
            expected_capability=inputs.evaluator_capability,
        )

    issued = _evaluate_v021_automated_campaign_with_ports(
        plan=plan,
        barrier=barrier,
        generation_results=generation_results,
        automated_evidence_authority=automated_evidence_authority,
        response_directory=response_directory,
        case_inputs=case_inputs,
        receipt_directory=receipt_directory,
        aggregate_path=aggregate_path,
        executed_at=executed_at,
        tool_git_sha=tool_git_sha,
        evaluator=evaluate_instance_candidate,
        receipt_verifier=verify_live_receipt,
        issuance=_LIVE_ISSUANCE,
    )
    if type(issued) is not VerifiedV021AutomatedEvaluationSet:
        raise _reject("Production evaluation did not issue live authority.")
    return issued


def _evaluate_v021_automated_campaign_with_ports(
    *,
    plan: VerifiedV021RuntimePlan,
    barrier: VerifiedV021GenerationBarrier,
    generation_results: Sequence[V021GenerationResult],
    automated_evidence_authority: VerifiedV021AutomatedEvidence,
    response_directory: Path,
    case_inputs: Mapping[str, V021EvaluationCaseInputs],
    receipt_directory: Path,
    aggregate_path: Path,
    executed_at: str,
    tool_git_sha: str,
    evaluator: Evaluator,
    receipt_verifier: ReceiptVerifier,
    issuance: object | None = None,
) -> VerifiedV021AutomatedEvaluationSet | StructuralV021AutomatedEvaluationSet:
    """Parse and evaluate exactly 20 durable outputs, or publish no aggregate authority."""

    verified_plan = require_v021_runtime_plan(plan)
    verified_barrier = require_v021_generation_barrier(barrier)
    evidence = require_v021_automated_evidence(automated_evidence_authority)
    expected_ids = tuple(f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1))
    if tuple(case_inputs) != expected_ids:
        raise _reject("Automated evaluation requires exact sorted inputs for all 20 cases.")
    if (
        verified_barrier.authorization_sha256 != verified_plan.authorization_sha256
        or verified_barrier.request_set_sha256 != verified_plan.request_set_sha256
        or evidence.request_set_sha256 != verified_plan.preregistration_request_set_sha256
    ):
        raise _reject("Generation, plan, and automated evidence lineages differ.")
    if tuple(result.case_id for result in generation_results) != expected_ids:
        raise _reject("Generation results are missing, reordered, or cross-case mixed.")
    response_root, receipt_root, aggregate = (
        Path(response_directory),
        Path(receipt_directory),
        Path(aggregate_path),
    )
    require_private_directory(response_root)
    require_private_directory(receipt_root)
    require_private_directory(aggregate.parent)
    if aggregate.is_symlink():
        raise _reject("Automated evaluation aggregate path is unsafe.")

    rows: list[dict[str, object]] = []
    for result_value in generation_results:
        result = require_v021_generation_result(result_value)
        case_id = result.case_id
        expected_result_sha = verified_barrier.result_sha256_by_case.get(case_id)
        if (
            result.outcome != "provider_response_durable_unparsed"
            or result.sha256 != expected_result_sha
            or result.response_sha256 is None
        ):
            raise _reject("Every barrier result must be a durable unparsed provider response.")
        result_raw = _read_bounded(result.path, MAX_RESULT_BYTES, "generation result")
        if hashlib.sha256(result_raw).hexdigest() != result.sha256:
            raise _reject("Generation result changed after nominal verification.")
        result_record = _decode_canonical(result_raw, "generation result")
        if (
            result_record.get("case_id") != case_id
            or result_record.get("response_sha256") != result.response_sha256
            or result_record.get("request_sha256")
            != _plan_row(verified_plan, case_id)["request_sha256"]
        ):
            raise _reject("Generation result durable bindings are invalid.")

        response_raw = _read_bounded(
            response_root / f"{case_id}.json", MAX_RESPONSE_BYTES, "provider response"
        )
        if hashlib.sha256(response_raw).hexdigest() != result.response_sha256:
            raise _reject("Provider response differs from the generation result commitment.")
        response = _decode_canonical(response_raw, "provider response")
        plan_row = _plan_row(verified_plan, case_id)
        if (
            response.get("algorithm") != RESPONSE_ALGORITHM
            or response.get("case_id") != case_id
            or response.get("authorization_sha256") != verified_plan.authorization_sha256
            or response.get("preregistration_sha256") != verified_plan.preregistration_sha256
            or response.get("lineage_commitment_sha256") != verified_plan.lineage_commitment_sha256
            or response.get("request_sha256") != plan_row["request_sha256"]
            or response.get("input_sha256") != plan_row["input_sha256"]
        ):
            raise _reject("Provider response has stale or cross-case bindings.")
        output = response.get("output")
        if not isinstance(output, str):
            raise _reject("Provider response output is not a string.")
        inputs = case_inputs[case_id]
        contract = v02_candidate_contract(case_id=case_id, issue_number=inputs.issue_number)
        evaluator_path = receipt_root / f"{case_id}.evaluator.json"
        public_path = receipt_root / f"{case_id}.json"
        try:
            candidate = parse_v021_candidate_output(
                output,
                issue_number=inputs.issue_number,
                required_test_function=contract.test_function,
            )
        except (PolicyRejection, ReproAssertError):
            if evaluator_path.exists() or evaluator_path.is_symlink():
                raise _reject("Contract rejection conflicts with an evaluator receipt.") from None
            candidate_record: dict[str, object] = {
                "bytes": len(output.encode("utf-8")),
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                "status": "rejected_before_sandbox",
            }
            evaluator_receipt_sha256: str | None = None
            accepted = False
            classification = "candidate_contract_rejected"
            remaining_controls = ["candidate_contract"]
        else:
            artifact = CandidateArtifact(
                relative_path=contract.relative_path,
                content=candidate.test_content.encode("utf-8"),
                test_function=contract.test_function,
            )
            if evaluator_path.exists() and not evaluator_path.is_symlink():
                verified_evaluation = receipt_verifier(evaluator_path)
                if public_path.is_symlink():
                    raise _reject("Case evaluation receipt path is unsafe.")
            elif evaluator_path.is_symlink() or public_path.exists() or public_path.is_symlink():
                raise _reject("Partial evaluation receipt requires reconciliation.")
            else:
                evaluated = evaluator(
                    evaluator_capability=inputs.evaluator_capability,
                    verified_hidden=inputs.verified_hidden,
                    gold_smoke_receipt_path=inputs.gold_smoke_receipt_path,
                    gold_specs_path=inputs.gold_specs_path,
                    manifest_path=inputs.manifest_path,
                    expected_manifest_sha256=inputs.expected_manifest_sha256,
                    case_id=case_id,
                    candidate=artifact,
                    output_path=evaluator_path,
                    executed_at=executed_at,
                    tool_git_sha=tool_git_sha,
                    automated_evidence_authority=evidence,
                )
                verified_evaluation = receipt_verifier(evaluated.path)
            evaluator_raw = _read_bounded(
                verified_evaluation.path, MAX_EVALUATION_RECEIPT_BYTES, "candidate evaluation"
            )
            if (
                hashlib.sha256(evaluator_raw).hexdigest() != verified_evaluation.sha256
                or verified_evaluation.case_id != case_id
            ):
                raise _reject("Candidate evaluator receipt changed or crossed case boundaries.")
            candidate_record = {
                "bytes": len(artifact.content),
                "expected_symptom_sha256": hashlib.sha256(
                    candidate.expected_symptom.encode()
                ).hexdigest(),
                "relative_path": contract.relative_path,
                "sha256": candidate.sha256,
                "test_function": contract.test_function,
            }
            evaluator_receipt_sha256 = verified_evaluation.sha256
            expected_candidate_sha256 = hashlib.sha256(artifact.content).hexdigest()
            expected_target = f"{artifact.relative_path}::{artifact.test_function}"
            if (
                verified_evaluation.candidate_sha256 != expected_candidate_sha256
                or verified_evaluation.candidate_target != expected_target
                or verified_evaluation.tool_git_sha != tool_git_sha
            ):
                raise _reject(
                    "Evaluator receipt differs from the current candidate or evaluator runtime."
                )
            accepted = verified_evaluation.accepted
            classification = verified_evaluation.classification
            remaining_controls = [
                "fix_minus_issue_relevant_hunks",
                "base_plus_issue_relevant_hunks",
            ]
        record = {
            "algorithm": ALGORITHM,
            "benchmark_version": "0.2.1",
            "candidate": candidate_record,
            "case_id": case_id,
            "claims": {
                "automated_disposition_validated": True,
                "automated_oracle_executed": evaluator_receipt_sha256 is not None,
                "human_reviewed": False,
                "l2_causal_claim": False,
                "maintainer_validated": False,
            },
            "evaluator_receipt_sha256": evaluator_receipt_sha256,
            "generation": {
                "barrier_sha256": verified_barrier.sha256,
                "response_sha256": result.response_sha256,
                "result_sha256": result.sha256,
            },
            "outcome": {
                "accepted": accepted,
                "classification": classification,
                "claim_level": "l1_deterministic" if accepted else "rejected",
                "remaining_required_controls": remaining_controls,
            },
            "schema_version": SCHEMA_VERSION,
            "tool_git_sha": _git_sha(tool_git_sha),
        }
        record["receipt_sha256"] = _self_hash(record)
        public_raw = _canonical(record) + b"\n"
        if public_path.exists():
            if (
                _read_bounded(public_path, MAX_RESULT_BYTES, "case evaluation receipt")
                != public_raw
            ):
                raise _reject("Existing case evaluation receipt differs from live evidence.")
        elif public_path.is_symlink():
            raise _reject("Case evaluation receipt path is unsafe.")
        else:
            write_bytes_exclusive(public_path, public_raw)
        rows.append(
            {
                "accepted": accepted,
                "case_id": case_id,
                "classification": classification,
                "receipt_sha256": hashlib.sha256(public_raw).hexdigest(),
            }
        )

    aggregate_record = _aggregate_record(
        plan=verified_plan,
        barrier=verified_barrier,
        evidence=evidence,
        rows=rows,
        tool_git_sha=tool_git_sha,
    )
    aggregate_record["receipt_sha256"] = _self_hash(aggregate_record)
    aggregate_raw = _canonical(aggregate_record) + b"\n"
    if aggregate.exists():
        existing_aggregate = _read_bounded(
            aggregate, MAX_RESULT_BYTES, "automated evaluation aggregate"
        )
        if existing_aggregate != aggregate_raw:
            raise _reject("Existing automated evaluation aggregate differs from live evidence.")
    else:
        write_bytes_exclusive(aggregate, aggregate_raw)
    issued = _verify_v021_automated_evaluation_set(
        aggregate,
        receipt_directory=receipt_root,
        issuance=issuance,
        receipt_verifier=receipt_verifier,
    )
    if issuance is _LIVE_ISSUANCE and type(issued) is not VerifiedV021AutomatedEvaluationSet:
        raise _reject("Live evaluation did not issue nominal aggregate authority.")
    return issued


def inspect_v021_automated_evaluation_set(
    path: Path, *, receipt_directory: Path
) -> StructuralV021AutomatedEvaluationSet:
    """Structurally inspect public receipts without minting execution authority."""

    inspected = _verify_v021_automated_evaluation_set(
        path,
        receipt_directory=receipt_directory,
        issuance=None,
        receipt_verifier=lambda receipt_path: verify_instance_candidate_receipt(
            receipt_path, structural_pending=True
        ),
    )
    if type(inspected) is not StructuralV021AutomatedEvaluationSet:
        raise _reject("Structural inspection returned live authority.")
    return inspected


def _verify_v021_automated_evaluation_set(
    path: Path,
    *,
    receipt_directory: Path,
    issuance: object | None,
    receipt_verifier: ReceiptVerifier,
) -> VerifiedV021AutomatedEvaluationSet | StructuralV021AutomatedEvaluationSet:
    raw = _read_bounded(Path(path), MAX_RESULT_BYTES, "automated evaluation aggregate")
    record = _decode_canonical(raw, "automated evaluation aggregate")
    rows = record.get("results")
    expected_ids = tuple(f"rk-v0.2-{index:03d}" for index in range(1, CASE_COUNT + 1))
    if (
        set(record)
        != {
            "algorithm",
            "automated_evidence_sha256",
            "benchmark_version",
            "case_count",
            "claims",
            "counts",
            "generation_barrier_sha256",
            "lineage_commitment_sha256",
            "receipt_sha256",
            "request_set_sha256",
            "results",
            "schema_version",
            "tool_git_sha",
        }
        or not _is_sha(record.get("automated_evidence_sha256"))
        or not _is_sha(record.get("generation_barrier_sha256"))
        or not _is_sha(record.get("lineage_commitment_sha256"))
        or not _is_sha(record.get("request_set_sha256"))
        or record.get("algorithm") != AGGREGATE_ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2.1"
        or record.get("case_count") != CASE_COUNT
        or record.get("receipt_sha256") != _self_hash(record)
        or not isinstance(rows, list)
        or tuple(row.get("case_id") for row in rows if isinstance(row, dict)) != expected_ids
        or record.get("claims")
        != {
            "automated_evidence_validated": True,
            "full_denominator_reported": True,
            "human_reviewed": False,
            "l2_causal_claim": False,
            "maintainer_validated": False,
        }
    ):
        raise _reject("Automated evaluation aggregate identity or claim ceiling is invalid.")
    receipt_root = Path(receipt_directory)
    require_private_directory(receipt_root)
    bindings: dict[str, str] = {}
    accepted = 0
    for value in rows:
        if not isinstance(value, dict) or set(value) != {
            "accepted",
            "case_id",
            "classification",
            "receipt_sha256",
        }:
            raise _reject("Automated evaluation aggregate row is invalid.")
        case_id = cast(str, value["case_id"])
        receipt_raw = _read_bounded(
            receipt_root / f"{case_id}.json", MAX_RESULT_BYTES, "case evaluation receipt"
        )
        digest = hashlib.sha256(receipt_raw).hexdigest()
        if digest != value["receipt_sha256"]:
            raise _reject("Case evaluation receipt changed after aggregation.")
        case_record = _decode_canonical(receipt_raw, "case evaluation receipt")
        outcome = case_record.get("outcome")
        evaluator_sha = case_record.get("evaluator_receipt_sha256")
        if (
            set(case_record)
            != {
                "algorithm",
                "benchmark_version",
                "candidate",
                "case_id",
                "claims",
                "evaluator_receipt_sha256",
                "generation",
                "outcome",
                "receipt_sha256",
                "schema_version",
                "tool_git_sha",
            }
            or case_record.get("algorithm") != ALGORITHM
            or case_record.get("schema_version") != SCHEMA_VERSION
            or case_record.get("benchmark_version") != "0.2.1"
            or case_record.get("case_id") != case_id
            or case_record.get("receipt_sha256") != _self_hash(case_record)
            or case_record.get("claims")
            != {
                "automated_disposition_validated": True,
                "automated_oracle_executed": case_record.get("evaluator_receipt_sha256")
                is not None,
                "human_reviewed": False,
                "l2_causal_claim": False,
                "maintainer_validated": False,
            }
            or not isinstance(outcome, dict)
            or outcome.get("accepted") is not value["accepted"]
            or outcome.get("classification") != value["classification"]
            or outcome.get("claim_level")
            != ("l1_deterministic" if value["accepted"] is True else "rejected")
            or outcome.get("remaining_required_controls")
            != (
                ["candidate_contract"]
                if value["classification"] == "candidate_contract_rejected"
                else ["fix_minus_issue_relevant_hunks", "base_plus_issue_relevant_hunks"]
            )
        ):
            raise _reject("Case evaluation receipt binding is invalid.")
        if evaluator_sha is None:
            candidate = case_record.get("candidate")
            if (
                value["classification"] != "candidate_contract_rejected"
                or not isinstance(candidate, dict)
                or candidate.get("status") != "rejected_before_sandbox"
            ):
                raise _reject("Missing evaluator receipt is not a contract rejection.")
        else:
            if not _is_sha(evaluator_sha):
                raise _reject("Evaluator receipt commitment is invalid.")
            verified_evaluator = receipt_verifier(receipt_root / f"{case_id}.evaluator.json")
            if (
                verified_evaluator.sha256 != evaluator_sha
                or verified_evaluator.case_id != case_id
                or verified_evaluator.accepted is not value["accepted"]
                or verified_evaluator.classification != value["classification"]
                or verified_evaluator.candidate_sha256
                != cast(dict[str, object], case_record["candidate"]).get("sha256")
                or verified_evaluator.candidate_target
                != (
                    f"{cast(dict[str, object], case_record['candidate']).get('relative_path')}::"
                    f"{cast(dict[str, object], case_record['candidate']).get('test_function')}"
                )
                or verified_evaluator.tool_git_sha != case_record.get("tool_git_sha")
                or verified_evaluator.tool_git_sha != record.get("tool_git_sha")
            ):
                raise _reject("Evaluator receipt differs from the live aggregate row.")
        bindings[case_id] = digest
        accepted += int(value["accepted"] is True)
    counts = record.get("counts")
    oracle_executed = sum(
        isinstance(value, dict) and value.get("classification") != "candidate_contract_rejected"
        for value in rows
    )
    if counts != {
        "accepted": accepted,
        "oracle_executed": oracle_executed,
        "rejected": CASE_COUNT - accepted,
        "total": CASE_COUNT,
    }:
        raise _reject("Automated evaluation full-denominator counts are invalid.")
    if issuance is not _LIVE_ISSUANCE:
        return StructuralV021AutomatedEvaluationSet(
            path=Path(path),
            sha256=hashlib.sha256(raw).hexdigest(),
            accepted_count=accepted,
            rejected_count=CASE_COUNT - accepted,
        )
    authority = object.__new__(VerifiedV021AutomatedEvaluationSet)
    for name, value in {
        "path": Path(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "accepted_count": accepted,
        "rejected_count": CASE_COUNT - accepted,
        "receipt_sha256_by_case": bindings,
        "_issuer": _ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v021_automated_evaluation_set(value: object) -> VerifiedV021AutomatedEvaluationSet:
    if type(value) is not VerifiedV021AutomatedEvaluationSet or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued automated evaluation set is required.")
    if value.accepted_count + value.rejected_count != CASE_COUNT:
        raise _reject("Automated evaluation authority lost its full denominator.")
    return value


def _aggregate_record(
    *,
    plan: VerifiedV021RuntimePlan,
    barrier: VerifiedV021GenerationBarrier,
    evidence: VerifiedV021AutomatedEvidence,
    rows: list[dict[str, object]],
    tool_git_sha: str,
) -> dict[str, object]:
    accepted = sum(row["accepted"] is True for row in rows)
    oracle_executed = sum(row["classification"] != "candidate_contract_rejected" for row in rows)
    return {
        "algorithm": AGGREGATE_ALGORITHM,
        "automated_evidence_sha256": evidence.sha256,
        "benchmark_version": "0.2.1",
        "case_count": CASE_COUNT,
        "claims": {
            "automated_evidence_validated": True,
            "full_denominator_reported": True,
            "human_reviewed": False,
            "l2_causal_claim": False,
            "maintainer_validated": False,
        },
        "counts": {
            "accepted": accepted,
            "oracle_executed": oracle_executed,
            "rejected": CASE_COUNT - accepted,
            "total": CASE_COUNT,
        },
        "generation_barrier_sha256": barrier.sha256,
        "lineage_commitment_sha256": plan.lineage_commitment_sha256,
        "request_set_sha256": plan.request_set_sha256,
        "results": rows,
        "schema_version": SCHEMA_VERSION,
        "tool_git_sha": _git_sha(tool_git_sha),
    }


def _plan_row(plan: VerifiedV021RuntimePlan, case_id: str) -> Mapping[str, object]:
    row = next((value for value in plan.cases if value.get("case_id") == case_id), None)
    if row is None:
        raise _reject("Case is outside the verified runtime plan.")
    return row


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"Cannot safely read {label}.") from exc
    if not raw or len(raw) > limit:
        raise _reject(f"{label.capitalize()} is empty or exceeds its byte limit.")
    return raw


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _self_hash(record: Mapping[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("receipt_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_automated_evaluation", message)
