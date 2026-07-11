from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from reproassert.benchmark_v02_candidate_contract import v02_candidate_contract
from reproassert.benchmark_v02_package import (
    BENCHMARK_VERSION,
    EXPECTED_CASE_COUNT,
    PreregisteredV02Case,
)
from reproassert.benchmark_v02_runner import V02LedgerSnapshot, read_v02_scored_ledger
from reproassert.benchmark_v02_scored_preregistration import load_v02_scored_preregistration
from reproassert.errors import PolicyRejection
from reproassert.intake import parse_issue_url
from reproassert.safeio import require_private_directory

SCHEMA_VERSION = "1.0.0"
CAMPAIGN_FREEZE_ALGORITHM = "reproassert-v02-campaign-freeze-v1"
SEMANTIC_REVIEW_ALGORITHM = "reproassert-v02-blinded-semantic-review-v1"
CAUSAL_CONTROL_ALGORITHM = "reproassert-v02-causal-control-set-v1"
CAUSAL_CONTROL_RECEIPT_ALGORITHM = "reproassert-v02-causal-control-receipt-v1"
CAUSAL_CONTROL_RUN_ALGORITHM = "reproassert-v02-causal-control-run-v1"
SEMANTIC_CHECKLIST_ALGORITHM = "reproassert-v02-semantic-checklist-v1"
FINALIZATION_ALGORITHM = "reproassert-v02-campaign-finalization-v1"
PUBLIC_AGGREGATE_ALGORITHM = "reproassert-v02-public-aggregate-v1"
GENERATION_BARRIER_ALGORITHM = "reproassert-v02-campaign-generation-barrier-v1"
DISPOSITION_SET_ALGORITHM = "reproassert-v02-generation-disposition-set-v1"
PRIVATE_RESULT_FILENAME = "reproassert-v02-private-result.json"
EMBARGOED_RESULT_FILENAME = "reproassert-v02-public-embargoed-result.json"
EXACT_PRIVATE_RESULT_FILENAME = "reproassert-v02-exact-private-result.json"
EXACT_EMBARGOED_RESULT_FILENAME = "reproassert-v02-exact-public-embargoed-result.json"
EXACT_RESULT_ALGORITHM = "reproassert-v02-exact-image-scored-result-v1"
PRIVATE_FINALIZATION_FILENAME = "reproassert-v02-private-finalization.json"
PUBLIC_AGGREGATE_FILENAME = "reproassert-v02-public-aggregate.json"

_MAX_JSON_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
_COST_CATEGORIES = (
    "model_inference",
    "sandbox_compute",
    "artifact_transfer",
    "paid_storage",
    "dependency_prep",
)
_ATTRIBUTABLE_COST_CATEGORIES = _COST_CATEGORIES[:-1]
_REVIEW_VERDICTS = {
    "semantically_valid",
    "semantically_invalid",
    "inconclusive",
    "not_applicable_no_candidate",
}
_CANDIDATE_REVIEW_VERDICTS = {"semantically_valid", "semantically_invalid"}
_REQUIRED_CONTROL_TYPES = (
    "candidate_on_fixed",
    "fix_minus_issue_relevant_hunks",
    "base_plus_issue_relevant_hunks",
)
_CONTROL_EXPECTED_OUTCOMES = {
    "candidate_on_fixed": "pass",
    "fix_minus_issue_relevant_hunks": "fail",
    "base_plus_issue_relevant_hunks": "pass",
}
_CONTROL_OBSERVED_OUTCOMES = {
    "pass",
    "fail",
    "infra_error",
    "timeout",
    "not_available",
    "inconclusive",
}
_SEMANTIC_RUBRIC_FIELDS = (
    "trigger_faithful",
    "oracle_supported",
    "failure_causal",
    "implementation_independent",
    "minimal_readable",
)
_SEMANTIC_RUBRIC_QUESTIONS = (
    "Does the candidate trigger the behavior described by the frozen issue?",
    "Is the candidate oracle supported by the issue and observed symptom?",
    "Does the failure causally track the issue-relevant production change?",
    "Is the test independent of the human implementation and developer tests?",
    "Is the reproduction minimal, readable, and maintainable?",
)


@dataclass(frozen=True)
class VerifiedV02CampaignFreeze:
    path: Path
    raw_sha256: str
    campaign_id: str
    preregistration_sha256: str
    cohort_sha256: str
    case_ids: tuple[str, ...]
    decoded: dict[str, Any]


@dataclass(frozen=True)
class V02SemanticReview:
    case_id: str
    review_round: int
    candidate_sha256: str
    causal_control_receipt_sha256: str
    reviewer_id: str
    reviewer_role_seal_sha256: str
    fixed_pass_evidence_sha256: str
    checklist_sha256: str
    reviewed_at: str
    trigger_faithful: bool
    oracle_supported: bool
    failure_causal: bool
    implementation_independent: bool
    minimal_readable: bool
    confidence: str
    rationale: str
    verdict: str


@dataclass(frozen=True)
class V02SemanticReviewCase:
    case_id: str
    candidate_sha256: str | None
    causal_control_receipt_sha256: str
    reviewer_role_seal_sha256: str | None
    mapping_reviewer_ids: tuple[str, ...]
    authorized_semantic_reviewer_ids: tuple[str, ...]
    reviews: tuple[V02SemanticReview, ...]


@dataclass(frozen=True)
class V02CausalControlRun:
    control_id: str
    control_type: str
    expected_outcome: str
    observed_outcome: str
    executed_at: str | None
    test_command: str | None
    exit_code: int | None
    duration_ms: int | None
    timed_out: bool
    oom_killed: bool
    output_truncated: bool
    output_sha256: str | None
    junit_sha256: str | None
    sandbox_receipt_sha256: str | None
    environment_sha256: str | None
    reason: str | None


@dataclass(frozen=True)
class V02CausalControlCase:
    case_id: str
    candidate_sha256: str | None
    evaluator_commitment_sha256: str
    issue_relevant_hunks_sha256: str | None
    fixed_pass_evidence_sha256: str | None
    status: str
    completed_at: str | None
    declared_decoy_control_ids: tuple[str, ...]
    controls: tuple[V02CausalControlRun, ...]


@dataclass(frozen=True)
class V02CampaignFinalization:
    private_path: Path
    private_sha256: str
    public_path: Path
    public_sha256: str
    review_semantic_valid_count: int
    provisional_candidate_count: int
    l2_semantic_valid_count: int
    total_attributable_microusd: int


def seal_v02_semantic_review_set(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    reviews_draft_path: Path,
    output_path: Path,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> Path:
    """Turn 20 bounded case-review bundles into a canonical self-hashed seal."""

    value = _load_json_value(Path(reviews_draft_path), "semantic review draft")
    if not isinstance(value, list) or len(value) != EXPECTED_CASE_COUNT:
        raise _reject("v02_semantic_review", "Review draft must contain exactly 20 case bundles.")
    review_cases: list[V02SemanticReviewCase] = []
    for item in value:
        row = _mapping(item, "semantic review draft case")
        _exact_keys(
            row,
            {
                "case_id",
                "candidate_sha256",
                "causal_control_receipt_sha256",
                "reviewer_role_seal_sha256",
                "mapping_reviewer_ids",
                "authorized_semantic_reviewer_ids",
                "reviews",
            },
            "semantic review draft case",
        )
        raw_reviews = row["reviews"]
        if not isinstance(raw_reviews, list):
            raise _reject("v02_semantic_review", "Draft case reviews must be an array.")
        parsed_reviews: list[V02SemanticReview] = []
        for raw_review in raw_reviews:
            review = _mapping(raw_review, "semantic review draft record")
            _exact_keys(
                review,
                {
                    "case_id",
                    "review_round",
                    "candidate_sha256",
                    "causal_control_receipt_sha256",
                    "reviewer_id",
                    "reviewer_role_seal_sha256",
                    "fixed_pass_evidence_sha256",
                    "checklist_sha256",
                    "reviewed_at",
                    *_SEMANTIC_RUBRIC_FIELDS,
                    "confidence",
                    "rationale",
                    "verdict",
                },
                "semantic review draft record",
            )
            parsed_reviews.append(
                V02SemanticReview(
                    case_id=cast(str, review["case_id"]),
                    review_round=cast(int, review["review_round"]),
                    candidate_sha256=cast(str, review["candidate_sha256"]),
                    causal_control_receipt_sha256=cast(
                        str, review["causal_control_receipt_sha256"]
                    ),
                    reviewer_id=cast(str, review["reviewer_id"]),
                    reviewer_role_seal_sha256=cast(str, review["reviewer_role_seal_sha256"]),
                    fixed_pass_evidence_sha256=cast(str, review["fixed_pass_evidence_sha256"]),
                    checklist_sha256=cast(str, review["checklist_sha256"]),
                    reviewed_at=cast(str, review["reviewed_at"]),
                    trigger_faithful=cast(bool, review["trigger_faithful"]),
                    oracle_supported=cast(bool, review["oracle_supported"]),
                    failure_causal=cast(bool, review["failure_causal"]),
                    implementation_independent=cast(bool, review["implementation_independent"]),
                    minimal_readable=cast(bool, review["minimal_readable"]),
                    confidence=cast(str, review["confidence"]),
                    rationale=cast(str, review["rationale"]),
                    verdict=cast(str, review["verdict"]),
                )
            )
        mapping_ids = row["mapping_reviewer_ids"]
        authorized_ids = row["authorized_semantic_reviewer_ids"]
        if not isinstance(mapping_ids, list) or not isinstance(authorized_ids, list):
            raise _reject("v02_semantic_review", "Reviewer role IDs must be arrays.")
        review_cases.append(
            V02SemanticReviewCase(
                case_id=cast(str, row["case_id"]),
                candidate_sha256=cast(str | None, row["candidate_sha256"]),
                causal_control_receipt_sha256=cast(str, row["causal_control_receipt_sha256"]),
                reviewer_role_seal_sha256=cast(str | None, row["reviewer_role_seal_sha256"]),
                mapping_reviewer_ids=tuple(cast(list[str], mapping_ids)),
                authorized_semantic_reviewer_ids=tuple(cast(list[str], authorized_ids)),
                reviews=tuple(parsed_reviews),
            )
        )
    record = build_v02_semantic_review_set(
        campaign_freeze_path,
        preregistration_path,
        review_cases,
        sealed_at=sealed_at,
        tool_name=tool_name,
        tool_version=tool_version,
        tool_git_sha=tool_git_sha,
    )
    destination = Path(output_path)
    require_private_directory(destination.parent)
    _write_exclusive_fsync(destination, _canonical_bytes(record))
    verify_v02_semantic_review_set(
        destination,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    return destination


def verify_v02_semantic_review_set(
    semantic_review_set_path: Path,
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
) -> str:
    """Verify review bundles and seals; evidence/timing binding occurs at finalization."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    scored = load_v02_scored_preregistration(Path(preregistration_path))
    raw, record = _load_canonical_json(Path(semantic_review_set_path), "semantic review set")
    _, values = _verify_review_set_envelope(record, freeze)
    case_ids: list[str] = []
    for value in values:
        review_case = _mapping(value, "semantic review case")
        _verify_semantic_review_case_record(
            review_case, allow_exact_infrastructure=scored.format == "exact-image-v1"
        )
        case_ids.append(cast(str, review_case["case_id"]))
    if tuple(case_ids) != freeze.case_ids:
        raise _reject("v02_semantic_review", "Semantic reviews are not the ordered cohort.")
    return hashlib.sha256(raw).hexdigest()


def build_v02_causal_control_set(
    campaign_freeze_path: Path,
    preregistration_path: Path,
    cases: Sequence[V02CausalControlCase],
    *,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> dict[str, object]:
    """Build canonical receipts for executed causal controls over the frozen cohort."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    _timestamp(sealed_at, "causal-control seal time")
    _identifier(tool_name, "tool name")
    _bounded_text(tool_version, "tool version", 1, 64)
    _git_sha(tool_git_sha, "tool Git SHA")
    by_case = {case.case_id: case for case in cases}
    if len(cases) != EXPECTED_CASE_COUNT or tuple(by_case) != freeze.case_ids:
        raise _reject(
            "v02_causal_control", "Causal-control cases must cover the ordered cohort once."
        )
    records = [_causal_control_case_record(by_case[case_id]) for case_id in freeze.case_ids]
    result: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": CAUSAL_CONTROL_ALGORITHM,
        "status": "sealed_complete",
        "campaign_id": freeze.campaign_id,
        "campaign_freeze_sha256": freeze.raw_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
        "cohort_sha256": freeze.cohort_sha256,
        "sealed_at": sealed_at,
        "execution_contract": {
            "required_control_types": list(_REQUIRED_CONTROL_TYPES),
            "real_sandbox_boundary_required": True,
            "host_secrets_exposed": False,
            "network_after_dependency_prep": "disabled",
            "resource_limits_required": True,
            "declared_decoys_frozen_before_gold_unblinding": True,
            "unavailable_or_inconclusive_controls_cannot_pass_l2": True,
        },
        "cases": records,
        "tool": {"name": tool_name, "version": tool_version, "git_sha": tool_git_sha},
    }
    result["control_set_sha256"] = _self_hash(result, "control_set_sha256")
    return result


def seal_v02_causal_control_set(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    controls_draft_path: Path,
    output_path: Path,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> Path:
    """Seal 20 bounded causal-control drafts without executing code or invoking a provider."""

    value = _load_json_value(Path(controls_draft_path), "causal-control draft")
    if not isinstance(value, list) or len(value) != EXPECTED_CASE_COUNT:
        raise _reject("v02_causal_control", "Causal-control draft must contain exactly 20 cases.")
    cases: list[V02CausalControlCase] = []
    case_fields = {field.name for field in fields(V02CausalControlCase)}
    run_fields = {field.name for field in fields(V02CausalControlRun)}
    for item in value:
        row = _mapping(item, "causal-control draft case")
        _exact_keys(row, case_fields, "causal-control draft case")
        raw_controls = row["controls"]
        raw_decoys = row["declared_decoy_control_ids"]
        if not isinstance(raw_controls, list) or not isinstance(raw_decoys, list):
            raise _reject("v02_causal_control", "Causal-control draft arrays are invalid.")
        controls: list[V02CausalControlRun] = []
        for raw_control in raw_controls:
            control = _mapping(raw_control, "causal-control draft run")
            _exact_keys(control, run_fields, "causal-control draft run")
            controls.append(
                V02CausalControlRun(
                    control_id=cast(str, control["control_id"]),
                    control_type=cast(str, control["control_type"]),
                    expected_outcome=cast(str, control["expected_outcome"]),
                    observed_outcome=cast(str, control["observed_outcome"]),
                    executed_at=cast(str | None, control["executed_at"]),
                    test_command=cast(str | None, control["test_command"]),
                    exit_code=cast(int | None, control["exit_code"]),
                    duration_ms=cast(int | None, control["duration_ms"]),
                    timed_out=cast(bool, control["timed_out"]),
                    oom_killed=cast(bool, control["oom_killed"]),
                    output_truncated=cast(bool, control["output_truncated"]),
                    output_sha256=cast(str | None, control["output_sha256"]),
                    junit_sha256=cast(str | None, control["junit_sha256"]),
                    sandbox_receipt_sha256=cast(str | None, control["sandbox_receipt_sha256"]),
                    environment_sha256=cast(str | None, control["environment_sha256"]),
                    reason=cast(str | None, control["reason"]),
                )
            )
        cases.append(
            V02CausalControlCase(
                case_id=cast(str, row["case_id"]),
                candidate_sha256=cast(str | None, row["candidate_sha256"]),
                evaluator_commitment_sha256=cast(str, row["evaluator_commitment_sha256"]),
                issue_relevant_hunks_sha256=cast(str | None, row["issue_relevant_hunks_sha256"]),
                fixed_pass_evidence_sha256=cast(str | None, row["fixed_pass_evidence_sha256"]),
                status=cast(str, row["status"]),
                completed_at=cast(str | None, row["completed_at"]),
                declared_decoy_control_ids=tuple(cast(list[str], raw_decoys)),
                controls=tuple(controls),
            )
        )
    record = build_v02_causal_control_set(
        campaign_freeze_path,
        preregistration_path,
        cases,
        sealed_at=sealed_at,
        tool_name=tool_name,
        tool_version=tool_version,
        tool_git_sha=tool_git_sha,
    )
    destination = Path(output_path)
    require_private_directory(destination.parent)
    _write_exclusive_fsync(destination, _canonical_bytes(record))
    verify_v02_causal_control_set(
        destination,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
    )
    return destination


def verify_v02_causal_control_set(
    causal_control_set_path: Path,
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
) -> str:
    """Verify canonical causal-control receipts before opening final campaign evidence."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    raw, record = _load_canonical_json(Path(causal_control_set_path), "causal-control set")
    _, values = _verify_causal_control_set_envelope(record, freeze)
    case_ids: list[str] = []
    for value in values:
        case = _mapping(value, "causal-control case")
        _verify_causal_control_case_record(case)
        case_ids.append(cast(str, case["case_id"]))
    if tuple(case_ids) != freeze.case_ids:
        raise _reject("v02_causal_control", "Causal-control cases are not the ordered cohort.")
    return hashlib.sha256(raw).hexdigest()


def verify_v02_campaign_output_structure(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    private_finalization_path: Path,
    public_aggregate_path: Path,
) -> V02CampaignFinalization:
    """Structurally verify two outputs; this does not re-open their source evidence bundle."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    preregistration = load_v02_scored_preregistration(Path(preregistration_path))
    private_raw, private = _load_canonical_json(
        Path(private_finalization_path), "private campaign finalization"
    )
    public_raw, public = _load_canonical_json(Path(public_aggregate_path), "public aggregate")
    _exact_keys(
        private,
        {
            "schema_version",
            "benchmark_version",
            "algorithm",
            "visibility",
            "status",
            "campaign_id",
            "finalized_at",
            "campaign_freeze_sha256",
            "preregistration_sha256",
            "cohort_sha256",
            "generation_barrier_sha256",
            "ledger_sha256",
            "ledger_head_event_sha256",
            "causal_control_set_sha256",
            "semantic_review_set_sha256",
            "candidate_freeze_barrier_verified",
            "attempt_count",
            "cases",
            "tool",
            "public_aggregate_sha256",
        },
        "private campaign finalization",
    )
    _exact_keys(
        public,
        {
            "schema_version",
            "benchmark_version",
            "algorithm",
            "publication_status",
            "claim_ceiling",
            "campaign_id",
            "finalized_at",
            "campaign_freeze_sha256",
            "preregistration_sha256",
            "cohort_sha256",
            "generation_barrier_sha256",
            "candidate_freeze_barrier",
            "benchmark_provenance",
            "run_configuration",
            "summary",
            "cases",
            "limitations",
            "tool",
            "public_aggregate_sha256",
        },
        "public aggregate",
    )
    public_sha256 = hashlib.sha256(public_raw).hexdigest()
    if (
        private["schema_version"] != SCHEMA_VERSION
        or private["benchmark_version"] != BENCHMARK_VERSION
        or private["algorithm"] != FINALIZATION_ALGORITHM
        or private["visibility"] != "private_controller_only"
        or private["status"] != "complete"
        or public["schema_version"] != SCHEMA_VERSION
        or public["benchmark_version"] != BENCHMARK_VERSION
        or public["algorithm"] != PUBLIC_AGGREGATE_ALGORITHM
        or public["publication_status"] != "campaign_complete_unsealed"
        or public["claim_ceiling"] != "l2_protocol_bounded_selected_cohort_no_maintainer_validation"
        or private["campaign_id"] != freeze.campaign_id
        or public["campaign_id"] != freeze.campaign_id
        or private["campaign_freeze_sha256"] != freeze.raw_sha256
        or public["campaign_freeze_sha256"] != freeze.raw_sha256
        or private["preregistration_sha256"] != freeze.preregistration_sha256
        or public["preregistration_sha256"] != freeze.preregistration_sha256
        or private["cohort_sha256"] != freeze.cohort_sha256
        or public["cohort_sha256"] != freeze.cohort_sha256
        or private["generation_barrier_sha256"] != public["generation_barrier_sha256"]
        or private["finalized_at"] != public["finalized_at"]
        or private["public_aggregate_sha256"] != public_sha256
        or public["public_aggregate_sha256"] != _self_hash(public, "public_aggregate_sha256")
    ):
        raise _reject("v02_campaign_finalization", "Final campaign artifact binding is invalid.")
    _timestamp(public["finalized_at"], "campaign finalization time")
    _digest(public["generation_barrier_sha256"], "generation barrier")
    for name in (
        "ledger_sha256",
        "ledger_head_event_sha256",
        "causal_control_set_sha256",
        "semantic_review_set_sha256",
    ):
        _digest(private[name], name)
    _verify_tool(private["tool"], "private finalization tool")
    if private["tool"] != public["tool"]:
        raise _reject("v02_campaign_finalization", "Final campaign tool identities differ.")
    _verify_tool(public["tool"], "public aggregate tool")
    barrier = _mapping(public["candidate_freeze_barrier"], "candidate freeze barrier")
    if (
        barrier
        != {
            "expected": EXPECTED_CASE_COUNT,
            "verified": EXPECTED_CASE_COUNT,
            "all_dispositions_preceded_first_evaluator_phase": True,
        }
        or private["candidate_freeze_barrier_verified"] is not True
    ):
        raise _reject("v02_phase_separation_required", "Final campaign barrier is not verified.")
    _verify_public_disclosure(public["benchmark_provenance"], public["run_configuration"])
    public_configuration = _mapping(public["run_configuration"], "public run configuration")
    if public_configuration["campaign_freeze_sha256"] != freeze.raw_sha256:
        raise _reject("v02_campaign_chronology", "Public run lacks its exact pre-run freeze.")
    private_cases = private["cases"]
    public_cases = public["cases"]
    if (
        private["attempt_count"] != EXPECTED_CASE_COUNT
        or not isinstance(private_cases, list)
        or not isinstance(public_cases, list)
        or len(private_cases) != EXPECTED_CASE_COUNT
        or len(public_cases) != EXPECTED_CASE_COUNT
    ):
        raise _reject("v02_campaign_finalization", "Final campaign case set is incomplete.")
    expected_cases = {case.id: case for case in preregistration.cases}
    private_ids: list[str] = []
    for value in private_cases:
        row = _mapping(value, "private finalization case")
        _exact_keys(
            row,
            {
                "case_id",
                "attempt_id",
                "private_result_sha256",
                "embargoed_result_sha256",
                "causal_control_receipt_sha256",
                "semantic_review_case_sha256",
                "terminal_event_sha256",
            },
            "private finalization case",
        )
        case_id = _case_id(row["case_id"])
        private_ids.append(case_id)
        _identifier(row["attempt_id"], "attempt ID")
        for name in (
            "private_result_sha256",
            "embargoed_result_sha256",
            "causal_control_receipt_sha256",
            "semantic_review_case_sha256",
            "terminal_event_sha256",
        ):
            _digest(row[name], name)
    if tuple(private_ids) != freeze.case_ids:
        raise _reject("v02_campaign_finalization", "Private finalization case order changed.")
    verified_public_cases: list[Mapping[str, Any]] = []
    for value in public_cases:
        row = _mapping(value, "public aggregate case")
        _verify_public_aggregate_case(
            row,
            expected_cases,
            exact_mode=preregistration.format == "exact-image-v1",
        )
        verified_public_cases.append(row)
    if tuple(cast(str, row["case_id"]) for row in verified_public_cases) != freeze.case_ids:
        raise _reject("v02_campaign_finalization", "Public aggregate case order changed.")
    expected_summary = _aggregate_summary(verified_public_cases)
    if public["summary"] != expected_summary:
        raise _reject("v02_campaign_finalization", "Public aggregate summary does not reconcile.")
    public_text = public_raw.decode("utf-8")
    forbidden_public_keys = (
        '"private_result_sha256"',
        '"fixed_run_count"',
        '"fixed_run_evidence_sha256"',
        '"hidden_fixed_root_tree_oid"',
        '"ledger_head_event_sha256"',
    )
    if any(key in public_text for key in forbidden_public_keys):
        raise _reject("v02_campaign_publication", "Public aggregate contains private evidence.")
    summary = cast(Mapping[str, Any], public["summary"])
    return V02CampaignFinalization(
        private_path=Path(private_finalization_path),
        private_sha256=hashlib.sha256(private_raw).hexdigest(),
        public_path=Path(public_aggregate_path),
        public_sha256=public_sha256,
        review_semantic_valid_count=cast(int, summary["review_semantic_valid_count"]),
        provisional_candidate_count=cast(int, summary["provisional_candidate_count"]),
        l2_semantic_valid_count=cast(int, summary["l2_semantic_valid_count"]),
        total_attributable_microusd=cast(int, summary["total_attributable_microusd"]),
    )


def verify_v02_campaign_bundle(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    ledger_path: Path,
    attempts_root: Path,
    semantic_review_set_path: Path,
    causal_control_set_path: Path,
    private_finalization_path: Path,
    public_aggregate_path: Path,
) -> V02CampaignFinalization:
    """Rederive a finalization from its ledger, attempts, reviews, and frozen inputs."""

    structural = verify_v02_campaign_output_structure(
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        private_finalization_path=private_finalization_path,
        public_aggregate_path=public_aggregate_path,
    )
    private_path = Path(private_finalization_path)
    public_path = Path(public_aggregate_path)
    if (
        private_path.name != PRIVATE_FINALIZATION_FILENAME
        or public_path.name != PUBLIC_AGGREGATE_FILENAME
        or private_path.parent != public_path.parent
    ):
        raise _reject(
            "v02_campaign_finalization",
            "Full-bundle verification requires the canonical final artifact layout.",
        )
    _, private = _load_canonical_json(private_path, "private campaign finalization")
    tool = _mapping(private["tool"], "private finalization tool")
    rederived = finalize_v02_campaign(
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        ledger_path=ledger_path,
        attempts_root=attempts_root,
        causal_control_set_path=causal_control_set_path,
        semantic_review_set_path=semantic_review_set_path,
        output_root=private_path.parent,
        finalized_at=cast(str, private["finalized_at"]),
        tool_name=cast(str, tool["name"]),
        tool_version=cast(str, tool["version"]),
        tool_git_sha=cast(str, tool["git_sha"]),
    )
    if rederived != structural:
        raise _reject("v02_campaign_finalization", "Full bundle rederivation changed outputs.")
    return rederived


def prepare_v02_campaign_freeze(
    preregistration_path: Path,
    output_path: Path,
    *,
    campaign_id: str,
    prepared_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> Path:
    """Write a public preparation-only campaign freeze with no provider authorization."""

    preregistration = load_v02_scored_preregistration(Path(preregistration_path))
    _identifier(campaign_id, "campaign ID")
    _timestamp(prepared_at, "campaign preparation time")
    _identifier(tool_name, "tool name")
    _bounded_text(tool_version, "tool version", 1, 64)
    _git_sha(tool_git_sha, "tool Git SHA")
    case_ids = [case.id for case in preregistration.cases]
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": CAMPAIGN_FREEZE_ALGORITHM,
        "status": "prepared_no_provider_authorized",
        "campaign_id": campaign_id,
        "prepared_at": prepared_at,
        "preregistration_sha256": preregistration.raw_sha256,
        "cohort_sha256": _digest_value(preregistration.decoded.get("cohort_sha256"), "cohort"),
        "case_count": EXPECTED_CASE_COUNT,
        "case_ids": case_ids,
        "execution_contract": {
            "expected_attempt_count": EXPECTED_CASE_COUNT,
            "candidate_budget_per_case": 1,
            "all_20_generation_dispositions_before_first_evaluator_phase": True,
            "generation_barrier_algorithm": GENERATION_BARRIER_ALGORITHM,
            "durable_barrier_seal_event_required": True,
            "per_case_publication": "embargoed_until_campaign_finalization",
            "paid_execution_exposed_by_cli": False,
            "provider_authorization": "not_included",
        },
        "tool": {"name": tool_name, "version": tool_version, "git_sha": tool_git_sha},
    }
    record["campaign_freeze_sha256"] = _self_hash(record, "campaign_freeze_sha256")
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write_exclusive_fsync(destination, _canonical_bytes(record))
    return destination


def verify_v02_campaign_freeze(
    campaign_freeze_path: Path, preregistration_path: Path
) -> VerifiedV02CampaignFreeze:
    """Independently rederive a preparation-only freeze from the exact preregistration."""

    raw, record = _load_canonical_json(Path(campaign_freeze_path), "campaign freeze")
    _exact_keys(
        record,
        {
            "schema_version",
            "benchmark_version",
            "algorithm",
            "status",
            "campaign_id",
            "prepared_at",
            "preregistration_sha256",
            "cohort_sha256",
            "case_count",
            "case_ids",
            "execution_contract",
            "tool",
            "campaign_freeze_sha256",
        },
        "campaign freeze",
    )
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["benchmark_version"] != BENCHMARK_VERSION
        or record["algorithm"] != CAMPAIGN_FREEZE_ALGORITHM
        or record["status"] != "prepared_no_provider_authorized"
    ):
        raise _reject("v02_campaign_freeze", "Campaign freeze version or status is invalid.")
    campaign_id = _identifier(record["campaign_id"], "campaign ID")
    _timestamp(record["prepared_at"], "campaign preparation time")
    preregistration = load_v02_scored_preregistration(Path(preregistration_path))
    cohort_sha256 = _digest_value(preregistration.decoded.get("cohort_sha256"), "cohort")
    if (
        record["preregistration_sha256"] != preregistration.raw_sha256
        or record["cohort_sha256"] != cohort_sha256
    ):
        raise _reject("v02_campaign_freeze", "Campaign freeze does not bind this preregistration.")
    expected_ids = tuple(case.id for case in preregistration.cases)
    if record["case_count"] != EXPECTED_CASE_COUNT or tuple(record["case_ids"]) != expected_ids:
        raise _reject("v02_campaign_freeze", "Campaign freeze does not contain the exact cohort.")
    contract = _mapping(record["execution_contract"], "execution contract")
    _exact_keys(
        contract,
        {
            "expected_attempt_count",
            "candidate_budget_per_case",
            "all_20_generation_dispositions_before_first_evaluator_phase",
            "generation_barrier_algorithm",
            "durable_barrier_seal_event_required",
            "per_case_publication",
            "paid_execution_exposed_by_cli",
            "provider_authorization",
        },
        "execution contract",
    )
    if contract != {
        "expected_attempt_count": EXPECTED_CASE_COUNT,
        "candidate_budget_per_case": 1,
        "all_20_generation_dispositions_before_first_evaluator_phase": True,
        "generation_barrier_algorithm": GENERATION_BARRIER_ALGORITHM,
        "durable_barrier_seal_event_required": True,
        "per_case_publication": "embargoed_until_campaign_finalization",
        "paid_execution_exposed_by_cli": False,
        "provider_authorization": "not_included",
    }:
        raise _reject("v02_campaign_freeze", "Campaign execution contract is not deny-by-default.")
    tool = _mapping(record["tool"], "campaign tool")
    _exact_keys(tool, {"name", "version", "git_sha"}, "campaign tool")
    _identifier(tool["name"], "tool name")
    _bounded_text(tool["version"], "tool version", 1, 64)
    _git_sha(tool["git_sha"], "tool Git SHA")
    if record["campaign_freeze_sha256"] != _self_hash(record, "campaign_freeze_sha256"):
        raise _reject("v02_campaign_freeze", "Campaign freeze self-hash is invalid.")
    return VerifiedV02CampaignFreeze(
        path=Path(campaign_freeze_path),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        campaign_id=campaign_id,
        preregistration_sha256=preregistration.raw_sha256,
        cohort_sha256=cohort_sha256,
        case_ids=expected_ids,
        decoded=record,
    )


def build_v02_semantic_review_set(
    campaign_freeze_path: Path,
    preregistration_path: Path,
    review_cases: Sequence[V02SemanticReviewCase],
    *,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> dict[str, object]:
    """Build private, role-bound, verdict-blinded multi-reviewer evidence."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    _timestamp(sealed_at, "semantic review seal time")
    _identifier(tool_name, "tool name")
    _bounded_text(tool_version, "tool version", 1, 64)
    _git_sha(tool_git_sha, "tool Git SHA")
    by_case = {review_case.case_id: review_case for review_case in review_cases}
    if len(review_cases) != EXPECTED_CASE_COUNT or tuple(by_case) != freeze.case_ids:
        raise _reject(
            "v02_semantic_review",
            "Semantic review cases must cover the ordered cohort once.",
        )
    records = [_semantic_review_case_record(by_case[case_id]) for case_id in freeze.case_ids]
    result: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": SEMANTIC_REVIEW_ALGORITHM,
        "status": "sealed_complete",
        "campaign_id": freeze.campaign_id,
        "campaign_freeze_sha256": freeze.raw_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
        "cohort_sha256": freeze.cohort_sha256,
        "sealed_at": sealed_at,
        "review_contract": {
            "reviewer_role": "declared_blinded_semantic_reviewer",
            "role_evidence": "opaque_package_role_seal_commitment_not_reopened",
            "two_reviewers_required_per_candidate": True,
            "third_reviewer_only_breaks_disagreement": True,
            "mapping_and_semantic_reviewer_ids_disjoint": True,
            "issue_snapshot_accessed": True,
            "candidate_accessed": True,
            "normalized_base_failure_accessed": True,
            "fixed_pass_evidence_accessed": True,
            "declared_causal_controls_accessed": True,
            "developer_tests_accessed": False,
            "human_patch_accessed": False,
            "mechanical_verdict_label_accessed": False,
            "gold_hidden_until_verdict": True,
        },
        "cases": records,
        "tool": {"name": tool_name, "version": tool_version, "git_sha": tool_git_sha},
    }
    result["review_set_sha256"] = _self_hash(result, "review_set_sha256")
    return result


def canonical_v02_campaign_bytes(value: Mapping[str, object]) -> bytes:
    return _canonical_bytes(value)


def finalize_v02_campaign(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    ledger_path: Path,
    attempts_root: Path,
    causal_control_set_path: Path,
    semantic_review_set_path: Path,
    output_root: Path,
    finalized_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    exact_preregistration: object | None = None,
    exact_causal_control_authorities: Mapping[str, object] | None = None,
) -> V02CampaignFinalization:
    """Fail closed, cross-check 20 private attempts, then unseal one bounded aggregate."""

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    preregistration = load_v02_scored_preregistration(Path(preregistration_path))
    exact_mode = preregistration.format == "exact-image-v1"
    exact_authority_sha256: str | None = None
    if exact_mode:
        exact_authority_sha256 = _require_exact_finalization_preregistration(
            exact_preregistration, preregistration
        )
    elif exact_preregistration is not None or exact_causal_control_authorities is not None:
        raise _reject(
            "v02_campaign_finalization",
            "Legacy finalization rejects exact-only nominal authorities.",
        )
    exact_rows = {cast(str, row["case_id"]): row for row in preregistration.exact_rows}
    _timestamp(finalized_at, "campaign finalization time")
    _identifier(tool_name, "tool name")
    _bounded_text(tool_version, "tool version", 1, 64)
    _git_sha(tool_git_sha, "tool Git SHA")
    private_directories = (
        Path(attempts_root),
        Path(causal_control_set_path).parent,
        Path(semantic_review_set_path).parent,
        Path(output_root),
    )
    for directory in private_directories:
        require_private_directory(directory)
    ledger = read_v02_scored_ledger(Path(ledger_path))
    attempts = _account_attempts(ledger, freeze)
    frozen_public = _freeze_all_public_dispositions(
        attempts_root=Path(attempts_root),
        attempts=attempts,
        cases=preregistration.cases,
        freeze=freeze,
        exact_mode=exact_mode,
        exact_rows=exact_rows,
    )
    # This is the intentional barrier: no private verdict file is opened until every public
    # candidate disposition has been validated as sealed and immutable.
    private_results = _open_private_results_after_barrier(
        attempts_root=Path(attempts_root),
        attempts=attempts,
        cases=preregistration.cases,
        freeze=freeze,
        public_results=frozen_public,
        exact_mode=exact_mode,
        exact_rows=exact_rows,
    )
    controls_raw, controls = _load_canonical_json(
        Path(causal_control_set_path), "causal-control set"
    )
    control_by_case = _verify_causal_control_set(
        controls,
        freeze,
        preregistration.cases,
        frozen_public,
        private_results,
        attempts,
        finalized_at=finalized_at,
        exact_mode=exact_mode,
        exact_causal_control_authorities=exact_causal_control_authorities,
        exact_preregistration_sha256=exact_authority_sha256,
        exact_rows=exact_rows,
    )
    reviews_raw, reviews = _load_canonical_json(
        Path(semantic_review_set_path), "semantic review set"
    )
    review_by_case = _verify_review_set(
        reviews,
        freeze,
        frozen_public,
        private_results,
        control_by_case,
        attempts,
        finalized_at=finalized_at,
    )
    public_record, private_record = _final_records(
        freeze=freeze,
        finalized_at=finalized_at,
        tool={"name": tool_name, "version": tool_version, "git_sha": tool_git_sha},
        ledger=ledger,
        attempts=attempts,
        public_results=frozen_public,
        private_results=private_results,
        controls=control_by_case,
        reviews=review_by_case,
        control_set_sha256=hashlib.sha256(controls_raw).hexdigest(),
        review_set_sha256=hashlib.sha256(reviews_raw).hexdigest(),
        exact_mode=exact_mode,
    )
    public_bytes = _canonical_bytes(public_record)
    private_record["public_aggregate_sha256"] = hashlib.sha256(public_bytes).hexdigest()
    private_bytes = _canonical_bytes(private_record)
    private_path = Path(output_root) / PRIVATE_FINALIZATION_FILENAME
    public_path = Path(output_root) / PUBLIC_AGGREGATE_FILENAME
    _write_or_match_fsync(private_path, private_bytes)
    _write_or_match_fsync(public_path, public_bytes)
    return verify_v02_campaign_output_structure(
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        private_finalization_path=private_path,
        public_aggregate_path=public_path,
    )


def _require_exact_finalization_preregistration(
    value: object,
    loaded: object,
) -> str:
    """Bind exact finalization to the same fresh evidence authority used by scoring."""

    from reproassert.benchmark_v02_exact_preregistration import (
        require_v02_exact_preregistration,
    )

    authority = require_v02_exact_preregistration(value)
    scored = cast(Any, loaded)
    if (
        authority.sha256 != scored.raw_sha256
        or authority.cohort_sha256 != scored.cohort_sha256
        or authority.request_set_sha256 != scored.request_set_sha256
        or authority.case_count != len(scored.cases)
    ):
        raise _reject(
            "v02_campaign_finalization",
            "Exact preregistration authority differs from the finalization campaign.",
        )
    return authority.sha256


def _account_attempts(
    ledger: V02LedgerSnapshot, freeze: VerifiedV02CampaignFreeze
) -> dict[str, dict[str, Any]]:
    prepared_at = _parse_timestamp(freeze.decoded["prepared_at"], "campaign preparation time")
    grouped: dict[str, dict[str, Any]] = {
        case_id: {"events": [], "costs": {}} for case_id in freeze.case_ids
    }
    first_differential_position: int | None = None
    disposition_positions: list[int] = []
    barrier_events: list[tuple[int, dict[str, Any]]] = []
    for position, event in enumerate(ledger.events):
        if event["campaign_id"] != freeze.campaign_id or event["case_id"] not in grouped:
            raise _reject("v02_campaign_finalization", "Ledger contains an unbound campaign case.")
        grouped[cast(str, event["case_id"])]["events"].append(event)
        payload = cast(Mapping[str, Any], event["payload"])
        if event["event_type"] == "generation_disposition_frozen":
            disposition_positions.append(position)
        if event["event_type"] == "campaign_generation_barrier_frozen":
            barrier_events.append((position, event))
        if (
            event["event_type"] == "phase_started"
            and payload.get("phase") == "differential"
            and first_differential_position is None
        ):
            first_differential_position = position
    barrier_position = barrier_events[0][0] if len(barrier_events) == 1 else -1
    if (
        len(disposition_positions) != EXPECTED_CASE_COUNT
        or len(barrier_events) != 1
        or max(disposition_positions, default=-1) >= barrier_position
        or (
            first_differential_position is not None
            and barrier_position >= first_differential_position
        )
    ):
        raise _reject(
            "v02_phase_separation_required",
            "All 20 dispositions and one durable barrier seal must precede evaluation.",
        )
    for case_id, state in grouped.items():
        events = cast(list[dict[str, Any]], state["events"])
        starts = [event for event in events if event["event_type"] == "attempt_started"]
        effective_terminal: dict[str, Any] | None = None
        for event in events:
            if event["event_type"] in {"attempt_finished", "attempt_crashed"}:
                effective_terminal = event
            elif event["event_type"] == "recovery_started":
                effective_terminal = None
        if (
            len(starts) != 1
            or effective_terminal is None
            or effective_terminal["event_type"] != "attempt_finished"
        ):
            raise _reject(
                "v02_campaign_finalization", f"Case {case_id} lacks one complete attempt."
            )
        terminal = cast(Mapping[str, Any], effective_terminal["payload"])
        start_payload = cast(Mapping[str, Any], starts[0]["payload"])
        start_configuration = _mapping(start_payload["configuration"], "attempt configuration")
        if (
            start_configuration.get("campaign_freeze_sha256") != freeze.raw_sha256
            or _parse_timestamp(start_payload["started_at"], "attempt start") < prepared_at
        ):
            raise _reject(
                "v02_campaign_chronology",
                f"Case {case_id} is not bound to a pre-inference campaign freeze.",
            )
        if terminal["status"] != "complete" or terminal["cost_complete"] is not True:
            raise _reject("v02_campaign_cost", f"Case {case_id} has incomplete or unknown cost.")
        cost_events = [event for event in events if event["event_type"] == "cost_recorded"]
        costs: dict[str, int] = {}
        for event in cost_events:
            payload = cast(Mapping[str, Any], event["payload"])
            category = cast(str, payload["category"])
            if (
                category in costs
                or category not in _COST_CATEGORIES
                or payload["status"] == "unknown"
                or not isinstance(payload["amount_microusd"], int)
            ):
                raise _reject("v02_campaign_cost", f"Case {case_id} cost ledger is incomplete.")
            costs[category] = payload["amount_microusd"]
        if set(costs) != set(_COST_CATEGORIES):
            raise _reject("v02_campaign_cost", f"Case {case_id} lacks exact cost categories.")
        total = sum(costs[name] for name in _ATTRIBUTABLE_COST_CATEGORIES)
        if terminal["total_attributable_microusd"] != total:
            raise _reject("v02_campaign_cost", f"Case {case_id} cost total does not reconcile.")
        model_starts = [event for event in events if event["event_type"] == "model_call_started"]
        model_finishes = [event for event in events if event["event_type"] == "model_call_finished"]
        if len(model_starts) > 1 or len(model_starts) != len(model_finishes):
            raise _reject("v02_campaign_cost", f"Case {case_id} provider attempt is incomplete.")
        disposition_events = [
            event for event in events if event["event_type"] == "generation_disposition_frozen"
        ]
        candidate_events = [
            event for event in events if event["event_type"] == "candidate_submitted"
        ]
        if len(disposition_events) != 1:
            raise _reject(
                "v02_phase_separation_required",
                f"Case {case_id} lacks one durable generation disposition.",
            )
        disposition = cast(Mapping[str, Any], disposition_events[0]["payload"])
        _exact_keys(
            disposition,
            {"status", "candidate_sha256", "classification_code", "frozen_at"},
            "generation disposition",
        )
        _timestamp(disposition["frozen_at"], "generation disposition time")
        if disposition["status"] == "candidate_submitted":
            if (
                len(candidate_events) != 1
                or disposition["candidate_sha256"]
                != candidate_events[0]["payload"]["candidate_sha256"]
            ):
                raise _reject(
                    "v02_phase_separation_required",
                    f"Case {case_id} submitted disposition lacks its durable candidate.",
                )
        elif disposition["status"] == "no_candidate":
            if candidate_events or disposition["candidate_sha256"] is not None:
                raise _reject(
                    "v02_phase_separation_required",
                    f"Case {case_id} no-candidate disposition is inconsistent.",
                )
        else:
            raise _reject(
                "v02_phase_separation_required",
                f"Case {case_id} generation disposition is invalid.",
            )
        state.update(
            {
                "start": starts[0],
                "terminal": effective_terminal,
                "costs": costs,
                "candidate_events": candidate_events,
                "disposition": disposition_events[0],
            }
        )
    if len(grouped) != EXPECTED_CASE_COUNT:
        raise _reject("v02_campaign_finalization", "Campaign does not contain exactly 20 cases.")
    disposition_set_sha256, generation_barrier_sha256 = _generation_barrier_hashes(freeze, grouped)
    barrier_payload = _mapping(barrier_events[0][1]["payload"], "generation barrier seal")
    barrier_commitments = _campaign_configuration_commitments(grouped)
    expected_barrier = {
        "barrier_algorithm": GENERATION_BARRIER_ALGORITHM,
        **barrier_commitments,
        "disposition_set_sha256": disposition_set_sha256,
        "generation_barrier_sha256": generation_barrier_sha256,
        "disposition_count": EXPECTED_CASE_COUNT,
        "frozen_at": barrier_payload.get("frozen_at"),
    }
    _timestamp(expected_barrier["frozen_at"], "generation barrier seal time")
    if barrier_payload != expected_barrier:
        raise _reject(
            "v02_phase_separation_required",
            "Generation barrier seal does not bind the exact disposition set.",
        )
    for state in grouped.values():
        state["generation_barrier_sha256"] = generation_barrier_sha256
        state["generation_barrier_frozen_at"] = barrier_payload["frozen_at"]
    return grouped


def _freeze_all_public_dispositions(
    *,
    attempts_root: Path,
    attempts: Mapping[str, Mapping[str, Any]],
    cases: Sequence[PreregisteredV02Case],
    freeze: VerifiedV02CampaignFreeze,
    exact_mode: bool = False,
    exact_rows: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, dict[str, Any]]:
    frozen: dict[str, dict[str, Any]] = {}
    for case in cases:
        directory = attempts_root / case.id
        require_private_directory(directory)
        raw, record = _load_canonical_json(
            directory
            / (EXACT_EMBARGOED_RESULT_FILENAME if exact_mode else EMBARGOED_RESULT_FILENAME),
            "embargoed result",
        )
        state = attempts[case.id]
        terminal = cast(Mapping[str, Any], cast(Mapping[str, Any], state["terminal"])["payload"])
        _verify_common_result(
            record,
            case,
            freeze,
            state,
            visibility="public_safe_embargoed",
            exact_mode=exact_mode,
            exact_row=None if exact_rows is None else exact_rows.get(case.id),
        )
        if hashlib.sha256(raw).hexdigest() != terminal["public_result_sha256"]:
            raise _reject("v02_campaign_result", f"Case {case.id} public result was tampered.")
        evaluation = _mapping(record["evaluation"], "embargoed evaluation")
        if exact_mode:
            _verify_exact_evaluation(evaluation, candidate=record["candidate"], case_id=case.id)
            _verify_result_candidate(record["candidate"], case)
            frozen[case.id] = record
            continue
        _exact_keys(
            evaluation,
            {
                "status",
                "accepted",
                "outcome",
                "claim_level",
                "fixed_run_evidence",
                "evaluator_commitment_sha256",
                "private_result_commitment",
            },
            "embargoed evaluation",
        )
        if (
            evaluation
            != {
                "status": "sealed",
                "accepted": None,
                "outcome": None,
                "claim_level": None,
                "fixed_run_evidence": None,
                "evaluator_commitment_sha256": case.evaluator_commitment_sha256,
                "private_result_commitment": "withheld_until_campaign_terminal",
            }
            or record["publication_status"]
            != "embargoed_until_all_20_candidates_are_durably_frozen"
        ):
            raise _reject("v02_campaign_embargo", f"Case {case.id} verdict was unsealed early.")
        candidate_events = cast(list[dict[str, Any]], state["candidate_events"])
        candidate = record["candidate"]
        if candidate is None:
            if candidate_events:
                raise _reject("v02_campaign_candidate", f"Case {case.id} candidate is missing.")
        else:
            candidate_record = _verify_candidate(candidate, case.id)
            if (
                len(candidate_events) != 1
                or candidate_events[0]["payload"]["candidate_sha256"] != candidate_record["sha256"]
            ):
                raise _reject("v02_campaign_candidate", f"Case {case.id} candidate is not frozen.")
        frozen[case.id] = record
    if tuple(frozen) != freeze.case_ids:
        raise _reject("v02_campaign_embargo", "All 20 dispositions were not frozen before unseal.")
    return frozen


def _generation_barrier_hashes(
    freeze: VerifiedV02CampaignFreeze,
    attempts: Mapping[str, Mapping[str, Any]],
) -> tuple[str, str]:
    dispositions: list[dict[str, object]] = []
    for case_id in freeze.case_ids:
        event = cast(Mapping[str, Any], attempts[case_id]["disposition"])
        payload = cast(Mapping[str, Any], event["payload"])
        dispositions.append(
            {
                "case_id": case_id,
                "attempt_id": event["attempt_id"],
                "event_sha256": event["event_sha256"],
                "status": payload["status"],
                "candidate_sha256": payload["candidate_sha256"],
            }
        )
    disposition_set_sha256 = _json_sha256(
        {
            "algorithm": DISPOSITION_SET_ALGORITHM,
            "campaign_id": freeze.campaign_id,
            "preregistration_sha256": freeze.preregistration_sha256,
            "cohort_sha256": freeze.cohort_sha256,
            "dispositions": dispositions,
        }
    )
    commitments = _campaign_configuration_commitments(attempts)
    generation_barrier_sha256 = _json_sha256(
        {
            "algorithm": GENERATION_BARRIER_ALGORITHM,
            "campaign_id": freeze.campaign_id,
            "preregistration_sha256": freeze.preregistration_sha256,
            "cohort_sha256": freeze.cohort_sha256,
            "disposition_count": EXPECTED_CASE_COUNT,
            "disposition_set_sha256": disposition_set_sha256,
            **commitments,
        }
    )
    return disposition_set_sha256, generation_barrier_sha256


def _campaign_configuration_commitments(
    attempts: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    configurations = [
        _mapping(
            _mapping(_mapping(state["start"], "attempt start")["payload"], "attempt payload")[
                "configuration"
            ],
            "attempt configuration",
        )
        for state in attempts.values()
    ]
    configuration_hashes = {_json_sha256(configuration) for configuration in configurations}
    if len(configurations) != EXPECTED_CASE_COUNT or len(configuration_hashes) != 1:
        raise _reject("v02_campaign_configuration", "Campaign run configuration changed.")
    configuration = configurations[0]
    execution_authorization = _mapping(
        configuration.get("execution_authorization"), "execution authorization"
    )
    for name in ("sha256", "request_set_sha256"):
        _digest(execution_authorization.get(name), name)
    _digest(configuration.get("pricing_snapshot_sha256"), "pricing snapshot")
    run_provenance = _mapping(configuration.get("run_provenance"), "run provenance")
    return {
        "configuration_sha256": next(iter(configuration_hashes)),
        "execution_authorization_sha256": cast(str, execution_authorization["sha256"]),
        "request_set_sha256": cast(str, execution_authorization["request_set_sha256"]),
        "pricing_snapshot_sha256": cast(str, configuration["pricing_snapshot_sha256"]),
        "run_provenance_sha256": _json_sha256(run_provenance),
    }


def _open_private_results_after_barrier(
    *,
    attempts_root: Path,
    attempts: Mapping[str, Mapping[str, Any]],
    cases: Sequence[PreregisteredV02Case],
    freeze: VerifiedV02CampaignFreeze,
    public_results: Mapping[str, Mapping[str, Any]],
    exact_mode: bool = False,
    exact_rows: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, dict[str, Any]]:
    private: dict[str, dict[str, Any]] = {}
    for case in cases:
        raw, record = _load_canonical_json(
            attempts_root
            / case.id
            / (EXACT_PRIVATE_RESULT_FILENAME if exact_mode else PRIVATE_RESULT_FILENAME),
            "private result",
        )
        state = attempts[case.id]
        terminal = cast(Mapping[str, Any], cast(Mapping[str, Any], state["terminal"])["payload"])
        _verify_common_result(
            record,
            case,
            freeze,
            state,
            visibility="private_controller_only",
            exact_mode=exact_mode,
            exact_row=None if exact_rows is None else exact_rows.get(case.id),
        )
        if hashlib.sha256(raw).hexdigest() != terminal["private_result_sha256"]:
            raise _reject("v02_campaign_result", f"Case {case.id} private result was tampered.")
        public_candidate = public_results[case.id]["candidate"]
        if record["candidate"] != public_candidate:
            raise _reject("v02_campaign_candidate", f"Case {case.id} candidate projections differ.")
        if exact_mode:
            public_projection = dict(public_results[case.id])
            public_projection["visibility"] = "private_controller_only"
            if record != public_projection:
                raise _reject(
                    "v02_campaign_result",
                    f"Case {case.id} exact public/private projections differ.",
                )
            private[case.id] = record
            continue
        terminal_projection = _mapping(record["terminal_projection"], "terminal projection")
        _exact_keys(
            terminal_projection,
            {
                "outcome",
                "claim_level",
                "classification_code",
                "issue_faithful_or_semantic_valid",
                "limitation",
            },
            "terminal projection",
        )
        if (
            terminal_projection["outcome"] != terminal["outcome"]
            or terminal_projection["claim_level"] != terminal["claim_level"]
            or terminal_projection["issue_faithful_or_semantic_valid"] is not False
        ):
            raise _reject("v02_campaign_result", f"Case {case.id} terminal result differs.")
        evaluation = record["evaluation"]
        if evaluation is not None:
            evaluation_record = _mapping(evaluation, "private evaluation")
            if evaluation_record.get("evaluator_commitment_sha256") != (
                case.evaluator_commitment_sha256
            ):
                raise _reject(
                    "v02_campaign_evaluator", f"Case {case.id} evaluator commitment differs."
                )
        private[case.id] = record
    return private


def _verify_common_result(
    record: Mapping[str, Any],
    case: PreregisteredV02Case,
    freeze: VerifiedV02CampaignFreeze,
    state: Mapping[str, Any],
    *,
    visibility: str,
    exact_mode: bool = False,
    exact_row: Mapping[str, object] | None = None,
) -> None:
    if exact_mode:
        _verify_exact_common_result(
            record, case, freeze, state, visibility=visibility, exact_row=exact_row
        )
        return
    common = {
        "schema_version",
        "benchmark_version",
        "algorithm",
        "visibility",
        "campaign_id",
        "attempt_id",
        "case",
        "preregistration_sha256",
        "cohort_sha256",
        "runner_input_sha256",
        "configuration_sha256",
        "candidate",
        "evaluation",
        "cost",
        "ledger_head_before_result_sha256",
    }
    extras = (
        {"publication_status"}
        if visibility == "public_safe_embargoed"
        else {
            "source_context",
            "terminal_projection",
        }
    )
    _exact_keys(record, common | extras, f"{visibility} result")
    start = cast(Mapping[str, Any], cast(Mapping[str, Any], state["start"])["payload"])
    start_event = cast(Mapping[str, Any], state["start"])
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["benchmark_version"] != BENCHMARK_VERSION
        or record["algorithm"] != "reproassert-v02-scored-result-v1"
        or record["visibility"] != visibility
        or record["campaign_id"] != freeze.campaign_id
        or record["attempt_id"] != start_event["attempt_id"]
        or record["case"] != asdict(case)
        or record["preregistration_sha256"] != freeze.preregistration_sha256
        or record["cohort_sha256"] != freeze.cohort_sha256
        or record["runner_input_sha256"] != start["runner_input_sha256"]
        or record["configuration_sha256"] != _json_sha256(start["configuration"])
    ):
        raise _reject("v02_campaign_result", f"Case {case.id} result binding is invalid.")
    cost = _mapping(record["cost"], "result cost")
    _exact_keys(
        cost,
        {"complete", "total_attributable_microusd", "categories", "pricing_snapshot_sha256"},
        "result cost",
    )
    categories = _mapping(cost["categories"], "result cost categories")
    if (
        cost["complete"] is not True
        or categories != state["costs"]
        or cost["total_attributable_microusd"]
        != sum(
            cast(Mapping[str, int], state["costs"])[name] for name in _ATTRIBUTABLE_COST_CATEGORIES
        )
        or cost["pricing_snapshot_sha256"] != start["configuration"]["pricing_snapshot_sha256"]
    ):
        raise _reject("v02_campaign_cost", f"Case {case.id} result cost is not reconciled.")


def _verify_exact_common_result(
    record: Mapping[str, Any],
    case: PreregisteredV02Case,
    freeze: VerifiedV02CampaignFreeze,
    state: Mapping[str, Any],
    *,
    visibility: str,
    exact_row: Mapping[str, object] | None,
) -> None:
    _exact_keys(
        record,
        {
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
            "runner_input_sha256",
            "schema_version",
            "visibility",
        },
        f"exact {visibility} result",
    )
    start = cast(Mapping[str, Any], cast(Mapping[str, Any], state["start"])["payload"])
    start_event = cast(Mapping[str, Any], state["start"])
    terminal = cast(Mapping[str, Any], cast(Mapping[str, Any], state["terminal"])["payload"])
    if exact_row is None:
        raise _reject("v02_campaign_result", f"Case {case.id} lacks its exact preregistration row.")
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["benchmark_version"] != "0.2"
        or record["algorithm"] != EXACT_RESULT_ALGORITHM
        or record["visibility"] != visibility
        or record["campaign_id"] != freeze.campaign_id
        or record["attempt_id"] != start_event["attempt_id"]
        or record["case"] != asdict(case)
        or record["exact_preregistration_sha256"] != freeze.preregistration_sha256
        or record["exact_case_commitment_sha256"] != exact_row.get("case_commitment_sha256")
        or record["runner_input_sha256"] != start["runner_input_sha256"]
    ):
        raise _reject("v02_campaign_result", f"Case {case.id} exact result binding is invalid.")
    _digest(record["ledger_head_before_result_sha256"], "exact result ledger head")
    if record["claims"] != {
        "causal_controls_complete": False,
        "hidden_bytes_emitted": False,
        "network_enabled": False,
        "provider_calls_during_evaluation": 0,
        "semantic_review_complete": False,
    }:
        raise _reject("v02_campaign_result", f"Case {case.id} exact trust claims are invalid.")
    candidate = _verify_result_candidate(record["candidate"], case)
    candidate_events = cast(list[dict[str, Any]], state["candidate_events"])
    if candidate is None:
        if candidate_events:
            raise _reject("v02_campaign_candidate", f"Case {case.id} candidate event differs.")
    elif (
        len(candidate_events) != 1
        or candidate_events[0]["payload"]["candidate_sha256"] != candidate["sha256"]
        or candidate_events[0]["payload"]["candidate_bytes"] != candidate["bytes"]
        or candidate_events[0]["payload"]["test_function"] != candidate["test_function"]
    ):
        raise _reject("v02_campaign_candidate", f"Case {case.id} exact candidate is not frozen.")
    evaluation = _mapping(record["evaluation"], "exact evaluation")
    _verify_exact_evaluation(evaluation, candidate=candidate, case_id=case.id)
    kind = evaluation["kind"]
    if kind == "no_candidate":
        expected_terminal = ("no_output", "rejected")
    elif kind == "infrastructure_failure":
        expected_terminal = ("benchmark_infrastructure_error", "rejected")
    elif evaluation["accepted"] is True:
        expected_terminal = ("verified_reproduction", "differential_reproduction")
    else:
        expected_terminal = ("rejected_reproduction", "rejected")
    if (terminal["outcome"], terminal["claim_level"]) != expected_terminal:
        raise _reject("v02_campaign_result", f"Case {case.id} exact terminal verdict differs.")
    cost = _mapping(record["cost"], "exact result cost")
    _exact_keys(cost, {"complete", "total_attributable_microusd"}, "exact result cost")
    expected_total = sum(
        cast(Mapping[str, int], state["costs"])[name]
        for name in _ATTRIBUTABLE_COST_CATEGORIES
    )
    if (
        cost["complete"] is not True
        or cost["total_attributable_microusd"] != expected_total
        or terminal["cost_complete"] is not True
        or terminal["total_attributable_microusd"] != expected_total
    ):
        raise _reject("v02_campaign_cost", f"Case {case.id} exact result cost is not reconciled.")


def _verify_result_candidate(
    value: object, case: PreregisteredV02Case
) -> Mapping[str, Any] | None:
    if value is None:
        return None
    candidate = _mapping(value, "exact candidate")
    _exact_keys(candidate, {"bytes", "path", "sha256", "test_function"}, "exact candidate")
    issue_number = parse_issue_url(case.issue_url).number
    contract = v02_candidate_contract(case_id=case.id, issue_number=issue_number)
    if (
        candidate["path"] != contract.relative_path
        or candidate["test_function"] != contract.test_function
        or isinstance(candidate["bytes"], bool)
        or not isinstance(candidate["bytes"], int)
        or not 1 <= candidate["bytes"] <= 65_536
    ):
        raise _reject("v02_campaign_candidate", f"Case {case.id} exact candidate contract differs.")
    _digest(candidate["sha256"], "exact candidate")
    return candidate


def _verify_exact_evaluation(
    evaluation: Mapping[str, Any], *, candidate: object, case_id: str
) -> None:
    _exact_keys(
        evaluation,
        {"accepted", "classification", "kind", "reason", "receipt_sha256"},
        "exact evaluation",
    )
    kind = evaluation["kind"]
    accepted = evaluation["accepted"]
    classification = evaluation["classification"]
    if type(accepted) is not bool or not isinstance(classification, str) or not classification:
        raise _reject("v02_campaign_result", f"Case {case_id} exact evaluation verdict is invalid.")
    if kind == "exact_image_receipt":
        if candidate is None or evaluation["reason"] is not None:
            raise _reject("v02_campaign_result", f"Case {case_id} exact receipt is inconsistent.")
        _digest(evaluation["receipt_sha256"], "exact evaluation receipt")
    elif kind == "infrastructure_failure":
        if (
            case_id != "rk-v0.2-014"
            or candidate is None
            or accepted is not False
            or classification != "network_dependency"
            or evaluation["receipt_sha256"] is not None
            or not isinstance(evaluation["reason"], str)
            or not evaluation["reason"]
        ):
            raise _reject("v02_campaign_result", "Case 014 infrastructure result is invalid.")
    elif kind == "no_candidate":
        if (
            candidate is not None
            or accepted is not False
            or evaluation["receipt_sha256"] is not None
            or not isinstance(evaluation["reason"], str)
            or not evaluation["reason"]
        ):
            raise _reject("v02_campaign_result", f"Case {case_id} no-candidate result is invalid.")
    else:
        raise _reject("v02_campaign_result", f"Case {case_id} exact evaluation kind is invalid.")


def _verify_causal_control_set(
    record: Mapping[str, Any],
    freeze: VerifiedV02CampaignFreeze,
    preregistered_cases: Sequence[PreregisteredV02Case],
    public_results: Mapping[str, Mapping[str, Any]],
    private_results: Mapping[str, Mapping[str, Any]],
    attempts: Mapping[str, Mapping[str, Any]],
    *,
    finalized_at: str,
    exact_mode: bool = False,
    exact_causal_control_authorities: Mapping[str, object] | None = None,
    exact_preregistration_sha256: str | None = None,
    exact_rows: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, dict[str, Any]]:
    sealed_at, values = _verify_causal_control_set_envelope(record, freeze)
    if sealed_at > _parse_timestamp(finalized_at, "campaign finalization time"):
        raise _reject("v02_causal_control", "Causal controls were sealed after finalization.")
    expected_cases = {case.id: case for case in preregistered_cases}
    by_case: dict[str, dict[str, Any]] = {}
    for value in values:
        control_case = _mapping(value, "causal-control case")
        _verify_causal_control_case_record(control_case)
        case_id = cast(str, control_case["case_id"])
        if case_id in by_case or case_id not in public_results or case_id not in expected_cases:
            raise _reject("v02_causal_control", "Causal-control case is duplicate or unknown.")
        candidate = public_results[case_id]["candidate"]
        candidate_sha256 = None if candidate is None else candidate["sha256"]
        if control_case["candidate_sha256"] != candidate_sha256:
            raise _reject("v02_causal_control", f"Case {case_id} control candidate differs.")
        expected_commitment = expected_cases[case_id].evaluator_commitment_sha256
        if control_case["evaluator_commitment_sha256"] != expected_commitment:
            raise _reject("v02_causal_control", f"Case {case_id} evaluator commitment differs.")
        if candidate is None:
            by_case[case_id] = dict(control_case)
            continue
        private_result = private_results[case_id]
        evaluation = _mapping(private_result["evaluation"], "private differential evaluation")
        if exact_mode:
            exact_row = None if exact_rows is None else exact_rows.get(case_id)
            if (
                exact_preregistration_sha256 is None
                or exact_row is None
                or private_result.get("exact_preregistration_sha256")
                != exact_preregistration_sha256
                or private_result.get("exact_case_commitment_sha256")
                != exact_row.get("case_commitment_sha256")
            ):
                raise _reject(
                    "v02_causal_control",
                    f"Case {case_id} exact control authority lacks its campaign identity chain.",
                )
            normalized = _exact_control_case(
                control_case,
                evaluation=evaluation,
                candidate_sha256=cast(str, candidate_sha256),
                evaluator_commitment_sha256=expected_commitment,
                authority=(
                    None
                    if exact_causal_control_authorities is None
                    else exact_causal_control_authorities.get(case_id)
                ),
            )
            terminal = _mapping(attempts[case_id]["terminal"], "terminal event")
            terminal_payload = _mapping(terminal["payload"], "terminal payload")
            attempt_completed = _parse_timestamp(
                terminal_payload["completed_at"], "attempt completion time"
            )
            completed_at = normalized.get("completed_at")
            if completed_at is not None:
                control_completed = _parse_timestamp(
                    completed_at, "exact causal-control completion time"
                )
                if control_completed < attempt_completed or control_completed > sealed_at:
                    raise _reject(
                        "v02_causal_control",
                        f"Case {case_id} exact controls fall outside the sealed window.",
                    )
            by_case[case_id] = normalized
            continue
        if evaluation["evaluator_commitment_sha256"] != expected_commitment:
            raise _reject(
                "v02_causal_control", f"Case {case_id} private evaluator commitment differs."
            )
        fixed_evidence = _fixed_pass_evidence_sha256(evaluation)
        if control_case["fixed_pass_evidence_sha256"] != fixed_evidence:
            raise _reject(
                "v02_causal_control", f"Case {case_id} fixed-pass evidence binding differs."
            )
        terminal = _mapping(attempts[case_id]["terminal"], "terminal event")
        terminal_payload = _mapping(terminal["payload"], "terminal payload")
        attempt_completed = _parse_timestamp(
            terminal_payload["completed_at"], "attempt completion time"
        )
        control_completed = _parse_timestamp(
            control_case["completed_at"], "causal-control completion time"
        )
        if control_completed < attempt_completed or control_completed > sealed_at:
            raise _reject(
                "v02_causal_control",
                f"Case {case_id} controls fall outside the post-attempt sealed window.",
            )
        candidate_path = cast(str, _mapping(candidate, "candidate")["path"])
        issue_number = parse_issue_url(expected_cases[case_id].issue_url).number
        contract = v02_candidate_contract(case_id=case_id, issue_number=issue_number)
        if candidate_path != contract.relative_path:
            raise _reject("v02_causal_control", f"Case {case_id} candidate path differs.")
        expected_command = contract.test_command
        for control_value in cast(Sequence[object], control_case["controls"]):
            control = _mapping(control_value, "causal-control run")
            if control["observed_outcome"] in {"not_available", "inconclusive"}:
                continue
            executed_at = _parse_timestamp(control["executed_at"], "control execution time")
            if (
                executed_at < attempt_completed
                or executed_at > control_completed
                or control["test_command"] != expected_command
            ):
                raise _reject(
                    "v02_causal_control",
                    f"Case {case_id} control execution or test-command binding is invalid.",
                )
        by_case[case_id] = dict(control_case)
    if tuple(by_case) != freeze.case_ids:
        raise _reject("v02_causal_control", "Causal controls are not in frozen cohort order.")
    return by_case


def _exact_control_case(
    structural: Mapping[str, Any],
    *,
    evaluation: Mapping[str, Any],
    candidate_sha256: str,
    evaluator_commitment_sha256: str,
    authority: object | None,
) -> dict[str, Any]:
    """Project exact control authority; serialized receipts alone never carry L2 trust."""

    case_id = cast(str, structural["case_id"])
    if evaluation.get("kind") != "exact_image_receipt" or evaluation.get("accepted") is not True:
        result = dict(structural)
        result.update(
            {
                "candidate_sha256": candidate_sha256,
                "evaluator_commitment_sha256": evaluator_commitment_sha256,
                "required_controls_passed": False,
                "declared_decoys_passed": False,
                "l2_causal_controls_passed": False,
            }
        )
        return result
    if authority is None:
        result = dict(structural)
        result.update(
            {
                "candidate_sha256": candidate_sha256,
                "evaluator_commitment_sha256": evaluator_commitment_sha256,
                "required_controls_passed": False,
                "declared_decoys_passed": False,
                "l2_causal_controls_passed": False,
            }
        )
        return result
    from reproassert.benchmark_v02_exact_controls import (
        require_exact_causal_control_execution,
        verify_exact_image_causal_control_receipt,
    )

    issued = require_exact_causal_control_execution(authority)
    structural_receipt = verify_exact_image_causal_control_receipt(issued.path)
    if (
        issued.case_id != case_id
        or structural_receipt.case_id != case_id
        or structural_receipt.sha256 != issued.sha256
    ):
        raise _reject("v02_causal_control", f"Case {case_id} exact control authority changed.")
    raw, receipt = _load_canonical_json(issued.path, "exact causal-control receipt")
    candidate = _mapping(receipt["candidate"], "exact control candidate")
    if (
        hashlib.sha256(raw).hexdigest() != issued.sha256
        or candidate.get("sha256") != candidate_sha256
        or receipt.get("evaluator_public_commitment_sha256") != evaluator_commitment_sha256
        or candidate.get("evaluation_receipt_sha256") != evaluation.get("receipt_sha256")
        or receipt.get("claims", {}).get("l2_causal_controls_passed")
        is not issued.l2_causal_controls_passed
    ):
        raise _reject("v02_causal_control", f"Case {case_id} exact control evidence differs.")
    receipt_controls = cast(Sequence[Mapping[str, Any]], receipt["controls"])
    outcomes = {
        "full_fix": "candidate_on_fixed",
        "fix_minus_selected": "fix_minus_issue_relevant_hunks",
        "base_plus_selected": "base_plus_issue_relevant_hunks",
    }
    projected: list[dict[str, object]] = []
    for control in receipt_controls:
        name = cast(str, control["name"])
        expected = _CONTROL_EXPECTED_OUTCOMES[outcomes[name]]
        projected.append(
            {
                "control_type": outcomes[name],
                "observed_outcome": (
                    expected if control["status"] == "conclusive_pass" else "inconclusive"
                ),
            }
        )
    return {
        **dict(structural),
        "candidate_sha256": candidate_sha256,
        "evaluator_commitment_sha256": evaluator_commitment_sha256,
        "fixed_pass_evidence_sha256": evaluation["receipt_sha256"],
        "completed_at": receipt["executed_at"],
        "controls": projected,
        "control_receipt_sha256": issued.sha256,
        "required_controls_passed": issued.l2_causal_controls_passed,
        "declared_decoy_control_ids": [],
        "declared_decoys_passed": True,
        "l2_causal_controls_passed": issued.l2_causal_controls_passed,
    }


def _verify_review_set(
    record: Mapping[str, Any],
    freeze: VerifiedV02CampaignFreeze,
    public_results: Mapping[str, Mapping[str, Any]],
    private_results: Mapping[str, Mapping[str, Any]],
    controls: Mapping[str, Mapping[str, Any]],
    attempts: Mapping[str, Mapping[str, Any]],
    *,
    finalized_at: str,
) -> dict[str, dict[str, Any]]:
    sealed_at, values = _verify_review_set_envelope(record, freeze)
    if sealed_at > _parse_timestamp(finalized_at, "campaign finalization time"):
        raise _reject("v02_semantic_review", "Semantic reviews were sealed after finalization.")
    by_case: dict[str, dict[str, Any]] = {}
    for value in values:
        review_case = _mapping(value, "semantic review case")
        candidate_case_id = cast(str, review_case.get("case_id"))
        raw_candidate_evaluation = private_results.get(candidate_case_id, {}).get("evaluation")
        infrastructure = (
            isinstance(raw_candidate_evaluation, Mapping)
            and raw_candidate_evaluation.get("kind") == "infrastructure_failure"
        )
        _verify_semantic_review_case_record(
            review_case, allow_exact_infrastructure=infrastructure
        )
        case_id = cast(str, review_case["case_id"])
        if case_id in by_case or case_id not in public_results:
            raise _reject("v02_semantic_review", "Semantic review case is duplicate or unknown.")
        candidate = public_results[case_id]["candidate"]
        candidate_sha256 = None if candidate is None else candidate["sha256"]
        control = controls[case_id]
        if (
            review_case["candidate_sha256"] != candidate_sha256
            or review_case["causal_control_receipt_sha256"] != control["control_receipt_sha256"]
        ):
            raise _reject("v02_semantic_review", f"Case {case_id} review evidence binding differs.")
        if candidate is None:
            by_case[case_id] = dict(review_case)
            continue
        evaluation = _mapping(
            private_results[case_id]["evaluation"], "private differential evaluation"
        )
        if evaluation.get("kind") == "infrastructure_failure":
            if (
                review_case["status"] != "not_applicable_infrastructure_failure"
                or review_case["reviewer_count"] != 0
                or review_case["consensus_verdict"] != "inconclusive"
                or review_case["reviews"] != []
            ):
                raise _reject(
                    "v02_semantic_review", f"Case {case_id} infrastructure review is invalid."
                )
            by_case[case_id] = dict(review_case)
            continue
        fixed_evidence = _fixed_pass_evidence_sha256(evaluation)
        control_completed = _parse_timestamp(
            control["completed_at"], "causal-control completion time"
        )
        barrier_at = _parse_timestamp(
            attempts[case_id]["generation_barrier_frozen_at"], "generation barrier seal time"
        )
        for review_value in cast(Sequence[object], review_case["reviews"]):
            review = _mapping(review_value, "semantic review")
            if review["fixed_pass_evidence_sha256"] != fixed_evidence:
                raise _reject(
                    "v02_semantic_review", f"Case {case_id} review fixed evidence differs."
                )
            expected_checklist = v02_semantic_checklist_sha256(
                case_id=case_id,
                candidate_sha256=cast(str, candidate_sha256),
                causal_control_receipt_sha256=cast(str, control["control_receipt_sha256"]),
                fixed_pass_evidence_sha256=fixed_evidence,
            )
            if review["checklist_sha256"] != expected_checklist:
                raise _reject(
                    "v02_semantic_review", f"Case {case_id} review checklist binding differs."
                )
            reviewed_at = _parse_timestamp(review["reviewed_at"], "semantic review time")
            if reviewed_at < max(barrier_at, control_completed) or reviewed_at > sealed_at:
                raise _reject(
                    "v02_semantic_review",
                    f"Case {case_id} review falls outside the post-control sealed window.",
                )
        by_case[case_id] = dict(review_case)
    if tuple(by_case) != freeze.case_ids:
        raise _reject("v02_semantic_review", "Semantic reviews are not in frozen cohort order.")
    return by_case


def _verify_review_set_envelope(
    record: Mapping[str, Any], freeze: VerifiedV02CampaignFreeze
) -> tuple[datetime, list[object]]:
    _exact_keys(
        record,
        {
            "schema_version",
            "benchmark_version",
            "algorithm",
            "status",
            "campaign_id",
            "campaign_freeze_sha256",
            "preregistration_sha256",
            "cohort_sha256",
            "sealed_at",
            "review_contract",
            "cases",
            "tool",
            "review_set_sha256",
        },
        "semantic review set",
    )
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["benchmark_version"] != BENCHMARK_VERSION
        or record["algorithm"] != SEMANTIC_REVIEW_ALGORITHM
        or record["status"] != "sealed_complete"
        or record["campaign_id"] != freeze.campaign_id
        or record["campaign_freeze_sha256"] != freeze.raw_sha256
        or record["preregistration_sha256"] != freeze.preregistration_sha256
        or record["cohort_sha256"] != freeze.cohort_sha256
        or record["review_set_sha256"] != _self_hash(record, "review_set_sha256")
    ):
        raise _reject("v02_semantic_review", "Semantic review set binding is invalid.")
    sealed_at = _parse_timestamp(record["sealed_at"], "semantic review seal time")
    contract = _mapping(record["review_contract"], "semantic review contract")
    expected_contract = {
        "reviewer_role": "declared_blinded_semantic_reviewer",
        "role_evidence": "opaque_package_role_seal_commitment_not_reopened",
        "two_reviewers_required_per_candidate": True,
        "third_reviewer_only_breaks_disagreement": True,
        "mapping_and_semantic_reviewer_ids_disjoint": True,
        "issue_snapshot_accessed": True,
        "candidate_accessed": True,
        "normalized_base_failure_accessed": True,
        "fixed_pass_evidence_accessed": True,
        "declared_causal_controls_accessed": True,
        "developer_tests_accessed": False,
        "human_patch_accessed": False,
        "mechanical_verdict_label_accessed": False,
        "gold_hidden_until_verdict": True,
    }
    if contract != expected_contract:
        raise _reject("v02_semantic_review", "Semantic review was not sealed and blinded.")
    _verify_tool(record["tool"], "semantic review tool")
    values = record["cases"]
    if not isinstance(values, list) or len(values) != EXPECTED_CASE_COUNT:
        raise _reject("v02_semantic_review", "Semantic review set is incomplete.")
    return sealed_at, cast(list[object], values)


def _final_records(
    *,
    freeze: VerifiedV02CampaignFreeze,
    finalized_at: str,
    tool: Mapping[str, str],
    ledger: V02LedgerSnapshot,
    attempts: Mapping[str, Mapping[str, Any]],
    public_results: Mapping[str, Mapping[str, Any]],
    private_results: Mapping[str, Mapping[str, Any]],
    controls: Mapping[str, Mapping[str, Any]],
    reviews: Mapping[str, Mapping[str, Any]],
    control_set_sha256: str,
    review_set_sha256: str,
    exact_mode: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    public_cases: list[dict[str, object]] = []
    private_cases: list[dict[str, object]] = []
    generation_barrier_sha256 = cast(str, attempts[freeze.case_ids[0]]["generation_barrier_sha256"])
    for case_id in freeze.case_ids:
        state = attempts[case_id]
        public_result = public_results[case_id]
        private_result = private_results[case_id]
        control = controls[case_id]
        review_case = reviews[case_id]
        terminal = cast(Mapping[str, Any], cast(Mapping[str, Any], state["terminal"])["payload"])
        active_duration_ms = _active_duration_ms(state)
        cost = cast(int, terminal["total_attributable_microusd"])
        evaluation = private_result["evaluation"]
        mechanical = bool(
            isinstance(evaluation, Mapping)
            and (
                evaluation.get("accepted_mechanical_differential") is True
                or (
                    exact_mode
                    and evaluation.get("kind") == "exact_image_receipt"
                    and evaluation.get("accepted") is True
                )
            )
        )
        review_consensus = cast(str, review_case["consensus_verdict"])
        review_semantic_valid = review_consensus == "semantically_valid"
        controls_passed = control["l2_causal_controls_passed"] is True
        provisional = mechanical and review_semantic_valid
        l2_semantic_valid = mechanical and controls_passed and review_semantic_valid
        candidate = public_result["candidate"]
        case_record = cast(Mapping[str, Any], public_result["case"])
        reproduction: dict[str, object] | None = None
        if candidate is not None:
            candidate_record = cast(Mapping[str, Any], candidate)
            candidate_path_value = cast(str, candidate_record["path"])
            issue_number = parse_issue_url(cast(str, case_record["issue_url"])).number
            contract = v02_candidate_contract(case_id=case_id, issue_number=issue_number)
            if candidate_path_value != contract.relative_path:
                raise _reject(
                    "v02_campaign_publication", "Candidate path differs from its case profile."
                )
            evaluation_record = _mapping(evaluation, "private differential evaluation")
            dependency = (
                {"receipt_sha256": None, "plan_sha256": None, "tree_sha256": None, "image_id": None}
                if exact_mode
                else _mapping(evaluation_record["dependency"], "dependency evidence")
            )
            reproduction = {
                "repository": case_record["repo"],
                "base_sha": case_record["base_sha"],
                "candidate_path": candidate_path_value,
                "candidate_sha256": candidate_record["sha256"],
                "source_context_sha256": (
                    case_record["source_context_sha256"]
                    if exact_mode
                    else cast(Mapping[str, Any], private_result["source_context"])["sha256"]
                ),
                "evaluator_commitment_sha256": (
                    case_record["evaluator_commitment_sha256"]
                    if exact_mode
                    else evaluation_record["evaluator_commitment_sha256"]
                ),
                "dependency_receipt_sha256": dependency["receipt_sha256"],
                "dependency_plan_sha256": dependency["plan_sha256"],
                "dependency_tree_sha256": dependency["tree_sha256"],
                "dependency_runner_image_id": dependency["image_id"],
                "test_command": contract.test_command,
                "command_scope": "prepared_exact_source_and_dependencies_only_not_bootstrap",
            }
        if candidate is None:
            validation_outcome = "no_candidate"
            semantic_verdict = "not_applicable_no_candidate"
        elif l2_semantic_valid:
            validation_outcome = "semantic_valid"
            semantic_verdict = "semantically_valid"
        elif mechanical:
            validation_outcome = "plausible_f2p_semantic_invalid"
            semantic_verdict = "semantically_invalid"
        else:
            validation_outcome = "mechanical_gate_not_met"
            semantic_verdict = "semantically_invalid"
        control_values = [
            _mapping(value, "causal-control run")
            for value in cast(Sequence[object], control["controls"])
        ]
        required_outcomes = {
            cast(str, value["control_type"]): value["observed_outcome"]
            for value in control_values
            if value["control_type"] in _REQUIRED_CONTROL_TYPES
        }
        review_values = cast(Sequence[Mapping[str, Any]], review_case["reviews"])
        public_cases.append(
            {
                "case_id": case_id,
                "issue_url": case_record["issue_url"],
                "runner_input_sha256": private_result["runner_input_sha256"],
                "candidate_status": "submitted" if candidate is not None else "no_candidate",
                "candidate": candidate,
                "reproduction": reproduction,
                "mechanical_outcome": terminal["outcome"],
                "claim_level": terminal["claim_level"],
                "causal_control_evidence": {
                    "control_receipt_sha256": control["control_receipt_sha256"],
                    "required_control_outcomes": required_outcomes,
                    "required_controls_passed": control["required_controls_passed"],
                    "declared_decoy_count": len(control["declared_decoy_control_ids"]),
                    "declared_decoys_passed": control["declared_decoys_passed"],
                },
                "semantic_review_evidence": {
                    "review_case_sha256": review_case["review_case_sha256"],
                    "reviewer_role_seal_sha256": review_case["reviewer_role_seal_sha256"],
                    "reviewer_count": review_case["reviewer_count"],
                    "consensus_verdict": review_consensus,
                    "tiebreak_used": review_case["tiebreak_used"],
                    "checklist_sha256": (
                        review_values[0]["checklist_sha256"] if review_values else None
                    ),
                },
                "semantic_verdict": semantic_verdict,
                "validation_outcome": validation_outcome,
                "provisional_mechanical_plus_review": provisional,
                "l2_semantic_valid": l2_semantic_valid,
                "total_attributable_microusd": cost,
                "active_duration_ms": active_duration_ms,
            }
        )
        private_cases.append(
            {
                "case_id": case_id,
                "attempt_id": cast(Mapping[str, Any], state["start"])["attempt_id"],
                "private_result_sha256": terminal["private_result_sha256"],
                "embargoed_result_sha256": terminal["public_result_sha256"],
                "causal_control_receipt_sha256": control["control_receipt_sha256"],
                "semantic_review_case_sha256": review_case["review_case_sha256"],
                "terminal_event_sha256": cast(Mapping[str, Any], state["terminal"])["event_sha256"],
            }
        )
    summary = _aggregate_summary(public_cases)
    public: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": PUBLIC_AGGREGATE_ALGORITHM,
        "publication_status": "campaign_complete_unsealed",
        "claim_ceiling": "l2_protocol_bounded_selected_cohort_no_maintainer_validation",
        "campaign_id": freeze.campaign_id,
        "finalized_at": finalized_at,
        "campaign_freeze_sha256": freeze.raw_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
        "cohort_sha256": freeze.cohort_sha256,
        "generation_barrier_sha256": generation_barrier_sha256,
        "candidate_freeze_barrier": {
            "expected": EXPECTED_CASE_COUNT,
            "verified": EXPECTED_CASE_COUNT,
            "all_dispositions_preceded_first_evaluator_phase": True,
        },
        "benchmark_provenance": {
            "corpus_visibility": "historical_public_contamination_exposed",
            "cohort_scope": "selected_feasibility_cohort_not_population_sample",
            "generalization_claim": "none",
        },
        "run_configuration": _public_run_configuration(attempts, private_results),
        "summary": summary,
        "cases": public_cases,
        "limitations": [
            (
                "L2 requires mechanical F-to-P, every required and declared control, "
                "and review consensus."
            ),
            (
                "Reviewer independence is bounded to disjoint declared IDs and an opaque "
                "role-seal commitment; case packages are not reopened."
            ),
            (
                "No maintainer acceptance or willingness-to-reuse evidence is included "
                "in this aggregate."
            ),
            (
                "The selected historical cohort is not a population sample; no "
                "generalization claim is made."
            ),
            (
                "Active duration sums generation, differential, and result-write phases; "
                "dependency prep, causal controls, review, and barrier wait are excluded."
            ),
        ],
        "tool": dict(tool),
    }
    public["public_aggregate_sha256"] = _self_hash(public, "public_aggregate_sha256")
    private: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "algorithm": FINALIZATION_ALGORITHM,
        "visibility": "private_controller_only",
        "status": "complete",
        "campaign_id": freeze.campaign_id,
        "finalized_at": finalized_at,
        "campaign_freeze_sha256": freeze.raw_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
        "cohort_sha256": freeze.cohort_sha256,
        "generation_barrier_sha256": generation_barrier_sha256,
        "ledger_sha256": ledger.sha256,
        "ledger_head_event_sha256": ledger.head_event_sha256,
        "causal_control_set_sha256": control_set_sha256,
        "semantic_review_set_sha256": review_set_sha256,
        "candidate_freeze_barrier_verified": True,
        "attempt_count": EXPECTED_CASE_COUNT,
        "cases": private_cases,
        "tool": dict(tool),
    }
    return public, private


def _public_run_configuration(
    attempts: Mapping[str, Mapping[str, Any]],
    private_results: Mapping[str, Mapping[str, Any]],
) -> dict[str, object]:
    starts = [
        cast(Mapping[str, Any], cast(Mapping[str, Any], state["start"])["payload"])
        for state in attempts.values()
    ]
    configurations = [cast(Mapping[str, Any], start["configuration"]) for start in starts]
    configuration_hashes = {_json_sha256(configuration) for configuration in configurations}
    if len(configuration_hashes) != 1:
        raise _reject("v02_campaign_configuration", "Campaign run configuration changed.")
    configuration = configurations[0]
    generator = _mapping(configuration["generator"], "generator configuration")
    authorization = _mapping(configuration["authorization"], "authorization configuration")
    response_models = sorted(
        {
            cast(str, payload["response_model"])
            for state in attempts.values()
            for event in cast(Sequence[Mapping[str, Any]], state["events"])
            if event["event_type"] == "model_call_finished"
            for payload in [cast(Mapping[str, Any], event["payload"])]
            if isinstance(payload.get("response_model"), str)
        }
    )
    dependency_runner_image_ids = sorted(
        {
            cast(str, dependency["image_id"])
            for result in private_results.values()
            if isinstance(result.get("evaluation"), Mapping)
            for evaluation in [cast(Mapping[str, Any], result["evaluation"])]
            if isinstance(evaluation.get("dependency"), Mapping)
            for dependency in [cast(Mapping[str, Any], evaluation["dependency"])]
            if isinstance(dependency.get("image_id"), str)
        }
    )
    terminal_payloads = [
        cast(Mapping[str, Any], cast(Mapping[str, Any], state["terminal"])["payload"])
        for state in attempts.values()
    ]
    provider_call_count = sum(
        event["event_type"] == "model_call_started"
        for state in attempts.values()
        for event in cast(Sequence[Mapping[str, Any]], state["events"])
    )
    model_terminal_count = sum(
        event["event_type"] == "model_call_finished"
        for state in attempts.values()
        for event in cast(Sequence[Mapping[str, Any]], state["events"])
    )
    return {
        "configuration_sha256": next(iter(configuration_hashes)),
        "campaign_freeze_sha256": configuration["campaign_freeze_sha256"],
        "runner_tool_git_sha": configuration["tool_git_sha"],
        "authorization_status": authorization["status"],
        "provider": generator["provider"],
        "requested_model": generator["requested_model"],
        "response_models": response_models,
        "adapter_config_sha256": generator["adapter_config_sha256"],
        "pricing_snapshot_sha256": configuration["pricing_snapshot_sha256"],
        "feedback_policy": generator["feedback_policy"],
        "candidate_budget_per_case": generator["submitted_candidate_budget"],
        "reserved_worst_case_microusd": configuration["reserved_worst_case_microusd"],
        "max_case_attributable_microusd": configuration["max_case_attributable_microusd"],
        "max_campaign_attributable_microusd": configuration["max_campaign_attributable_microusd"],
        "max_case_wall_ms": configuration["max_case_wall_ms"],
        "provider_timeout_ms": configuration["provider_timeout_ms"],
        "provider_call_count": provider_call_count,
        "model_terminal_count": model_terminal_count,
        "run_started_at": min(cast(str, start["started_at"]) for start in starts),
        "run_completed_at": max(
            cast(str, terminal["completed_at"]) for terminal in terminal_payloads
        ),
        "sandbox_verifier_identity_status": "not_recorded_in_current_scored_result",
        "dependency_runner_image_ids": dependency_runner_image_ids,
    }


def _verify_public_disclosure(provenance_value: object, configuration_value: object) -> None:
    provenance = _mapping(provenance_value, "benchmark provenance")
    if provenance != {
        "corpus_visibility": "historical_public_contamination_exposed",
        "cohort_scope": "selected_feasibility_cohort_not_population_sample",
        "generalization_claim": "none",
    }:
        raise _reject("v02_campaign_publication", "Benchmark provenance disclosure is invalid.")
    configuration = _mapping(configuration_value, "public run configuration")
    _exact_keys(
        configuration,
        {
            "configuration_sha256",
            "campaign_freeze_sha256",
            "runner_tool_git_sha",
            "authorization_status",
            "provider",
            "requested_model",
            "response_models",
            "adapter_config_sha256",
            "pricing_snapshot_sha256",
            "feedback_policy",
            "candidate_budget_per_case",
            "reserved_worst_case_microusd",
            "max_case_attributable_microusd",
            "max_campaign_attributable_microusd",
            "max_case_wall_ms",
            "provider_timeout_ms",
            "provider_call_count",
            "model_terminal_count",
            "run_started_at",
            "run_completed_at",
            "sandbox_verifier_identity_status",
            "dependency_runner_image_ids",
        },
        "public run configuration",
    )
    for name in (
        "configuration_sha256",
        "campaign_freeze_sha256",
        "adapter_config_sha256",
        "pricing_snapshot_sha256",
    ):
        _digest(configuration[name], name)
    _git_sha(configuration["runner_tool_git_sha"], "runner tool Git SHA")
    if (
        configuration["authorization_status"] != "explicit_user_approval"
        or configuration["provider"] != "openai"
        or configuration["feedback_policy"] != "none_one_shot"
        or configuration["candidate_budget_per_case"] != 1
        or configuration["sandbox_verifier_identity_status"]
        != "not_recorded_in_current_scored_result"
    ):
        raise _reject("v02_campaign_publication", "Public run policy disclosure is invalid.")
    _bounded_text(configuration["requested_model"], "requested model", 1, 128)
    for name in (
        "reserved_worst_case_microusd",
        "max_case_attributable_microusd",
        "max_campaign_attributable_microusd",
        "max_case_wall_ms",
        "provider_timeout_ms",
        "provider_call_count",
        "model_terminal_count",
    ):
        value = configuration[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise _reject("v02_campaign_publication", f"Public run {name} is invalid.")
    started = _parse_timestamp(configuration["run_started_at"], "public run start")
    completed = _parse_timestamp(configuration["run_completed_at"], "public run completion")
    if completed < started:
        raise _reject("v02_campaign_publication", "Public run chronology is invalid.")
    for name in ("response_models", "dependency_runner_image_ids"):
        values = configuration[name]
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or not all(isinstance(value, str) and 1 <= len(value) <= 200 for value in values)
        ):
            raise _reject("v02_campaign_publication", f"Public run {name} is invalid.")


def _verify_public_aggregate_case(
    row: Mapping[str, Any],
    expected_cases: Mapping[str, PreregisteredV02Case],
    *,
    exact_mode: bool = False,
) -> None:
    _exact_keys(
        row,
        {
            "case_id",
            "issue_url",
            "runner_input_sha256",
            "candidate_status",
            "candidate",
            "reproduction",
            "mechanical_outcome",
            "claim_level",
            "causal_control_evidence",
            "semantic_review_evidence",
            "semantic_verdict",
            "validation_outcome",
            "provisional_mechanical_plus_review",
            "l2_semantic_valid",
            "total_attributable_microusd",
            "active_duration_ms",
        },
        "public aggregate case",
    )
    case_id = _case_id(row["case_id"])
    case = expected_cases.get(case_id)
    if case is None or row["issue_url"] != case.issue_url:
        raise _reject("v02_campaign_publication", "Public case identity is invalid.")
    _digest(row["runner_input_sha256"], "public runner input")
    candidate = row["candidate"]
    if candidate is None:
        if row["candidate_status"] != "no_candidate" or row["reproduction"] is not None:
            raise _reject("v02_campaign_publication", "No-candidate public case is inconsistent.")
    else:
        exact_shape = isinstance(candidate, Mapping) and set(candidate) == {
                "bytes",
                "path",
                "sha256",
                "test_function",
            }
        if exact_mode is not exact_shape:
            raise _reject(
                "v02_campaign_candidate",
                "Aggregate candidate shape differs from its preregistration protocol.",
            )
        candidate_record = (
            _verify_result_candidate(candidate, case)
            if exact_mode
            else _verify_candidate(candidate, case_id)
        )
        if candidate_record is None:
            raise _reject("v02_campaign_candidate", "Submitted aggregate candidate is missing.")
        path = cast(str, candidate_record["path"])
        issue_number = parse_issue_url(case.issue_url).number
        contract = v02_candidate_contract(case_id=case_id, issue_number=issue_number)
        reproduction = _mapping(row["reproduction"], "public reproduction requirements")
        _exact_keys(
            reproduction,
            {
                "repository",
                "base_sha",
                "candidate_path",
                "candidate_sha256",
                "source_context_sha256",
                "evaluator_commitment_sha256",
                "dependency_receipt_sha256",
                "dependency_plan_sha256",
                "dependency_tree_sha256",
                "dependency_runner_image_id",
                "test_command",
                "command_scope",
            },
            "public reproduction requirements",
        )
        if (
            row["candidate_status"] != "submitted"
            or reproduction["repository"] != case.repo
            or reproduction["base_sha"] != case.base_sha
            or reproduction["candidate_path"] != path
            or reproduction["candidate_sha256"] != candidate_record["sha256"]
            or reproduction["source_context_sha256"] != case.source_context_sha256
            or reproduction["evaluator_commitment_sha256"] != case.evaluator_commitment_sha256
            or path != contract.relative_path
            or reproduction["test_command"] != contract.test_command
            or reproduction["command_scope"]
            != "prepared_exact_source_and_dependencies_only_not_bootstrap"
        ):
            raise _reject("v02_campaign_publication", "Public reproduction command is invalid.")
        for name in (
            "dependency_receipt_sha256",
            "dependency_plan_sha256",
            "dependency_tree_sha256",
        ):
            if reproduction[name] is not None:
                _digest(reproduction[name], f"public reproduction {name}")
        image_id = reproduction["dependency_runner_image_id"]
        if image_id is not None and (
            not isinstance(image_id, str) or not 1 <= len(image_id) <= 200
        ):
            raise _reject("v02_campaign_publication", "Public dependency image ID is invalid.")
    outcome = row["mechanical_outcome"]
    claim = row["claim_level"]
    verdict = row["semantic_verdict"]
    if not isinstance(outcome, str) or re.fullmatch(r"[a-z][a-z0-9_]{1,99}", outcome) is None:
        raise _reject("v02_campaign_publication", "Public mechanical outcome is invalid.")
    if (
        claim
        not in {
            "rejected",
            "collected",
            "repeatable_base_failure",
            "differential_reproduction",
        }
        or verdict not in _REVIEW_VERDICTS
    ):
        raise _reject("v02_campaign_publication", "Public verdict is invalid.")
    control_evidence = _mapping(row["causal_control_evidence"], "public causal evidence")
    _exact_keys(
        control_evidence,
        {
            "control_receipt_sha256",
            "required_control_outcomes",
            "required_controls_passed",
            "declared_decoy_count",
            "declared_decoys_passed",
        },
        "public causal evidence",
    )
    _digest(control_evidence["control_receipt_sha256"], "public causal-control receipt")
    outcomes = _mapping(
        control_evidence["required_control_outcomes"], "public required control outcomes"
    )
    if (
        not all(key in _REQUIRED_CONTROL_TYPES for key in outcomes)
        or not all(value in _CONTROL_OBSERVED_OUTCOMES for value in outcomes.values())
        or not isinstance(control_evidence["required_controls_passed"], bool)
        or isinstance(control_evidence["declared_decoy_count"], bool)
        or not isinstance(control_evidence["declared_decoy_count"], int)
        or not 0 <= control_evidence["declared_decoy_count"] <= 32
        or not isinstance(control_evidence["declared_decoys_passed"], bool)
    ):
        raise _reject("v02_campaign_publication", "Public causal evidence is invalid.")
    review_evidence = _mapping(row["semantic_review_evidence"], "public review evidence")
    _exact_keys(
        review_evidence,
        {
            "review_case_sha256",
            "reviewer_role_seal_sha256",
            "reviewer_count",
            "consensus_verdict",
            "tiebreak_used",
            "checklist_sha256",
        },
        "public review evidence",
    )
    _digest(review_evidence["review_case_sha256"], "public review case")
    reviewer_count = review_evidence["reviewer_count"]
    if (
        isinstance(reviewer_count, bool)
        or reviewer_count not in {0, 2, 3}
        or review_evidence["consensus_verdict"] not in _REVIEW_VERDICTS
        or not isinstance(review_evidence["tiebreak_used"], bool)
    ):
        raise _reject("v02_campaign_publication", "Public review evidence is invalid.")
    infrastructure_without_review = (
        candidate is not None
        and outcome == "benchmark_infrastructure_error"
        and review_evidence["consensus_verdict"] == "inconclusive"
    )
    if reviewer_count == 0:
        if (
            review_evidence["reviewer_role_seal_sha256"] is not None
            or review_evidence["checklist_sha256"] is not None
            or (
                review_evidence["consensus_verdict"] != "not_applicable_no_candidate"
                and not infrastructure_without_review
            )
            or review_evidence["tiebreak_used"] is not False
        ):
            raise _reject("v02_campaign_publication", "No-candidate review evidence is invalid.")
    else:
        _digest(review_evidence["reviewer_role_seal_sha256"], "public reviewer role seal")
        _digest(review_evidence["checklist_sha256"], "public semantic checklist")
        if review_evidence[
            "consensus_verdict"
        ] not in _CANDIDATE_REVIEW_VERDICTS or review_evidence["tiebreak_used"] is not (
            reviewer_count == 3
        ):
            raise _reject("v02_campaign_publication", "Candidate review consensus is invalid.")
    mechanical = claim == "differential_reproduction" and outcome in {
        "differential_reproduction",
        "verified_reproduction",
    }
    review_valid = review_evidence["consensus_verdict"] == "semantically_valid"
    controls_passed = (
        control_evidence["required_controls_passed"] is True
        and control_evidence["declared_decoys_passed"] is True
    )
    expected_l2 = mechanical and controls_passed and review_valid
    if candidate is None:
        expected_verdict = "not_applicable_no_candidate"
        expected_validation = "no_candidate"
        if outcomes or reviewer_count != 0:
            raise _reject("v02_campaign_publication", "No-candidate evidence is inconsistent.")
    elif expected_l2:
        expected_verdict = "semantically_valid"
        expected_validation = "semantic_valid"
    elif mechanical:
        expected_verdict = "semantically_invalid"
        expected_validation = "plausible_f2p_semantic_invalid"
    else:
        expected_verdict = "semantically_invalid"
        expected_validation = "mechanical_gate_not_met"
    if (
        row["provisional_mechanical_plus_review"] is not (mechanical and review_valid)
        or row["l2_semantic_valid"] is not expected_l2
        or verdict != expected_verdict
        or row["validation_outcome"] != expected_validation
    ):
        raise _reject("v02_campaign_publication", "Public L2 verdict does not reconcile.")
    for name in ("total_attributable_microusd", "active_duration_ms"):
        if isinstance(row[name], bool) or not isinstance(row[name], int) or row[name] < 0:
            raise _reject("v02_campaign_publication", f"Public {name} is invalid.")


def _aggregate_summary(cases: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    costs = [cast(int, case["total_attributable_microusd"]) for case in cases]
    durations = [cast(int, case["active_duration_ms"]) for case in cases]
    provisional = [case for case in cases if case["provisional_mechanical_plus_review"] is True]
    l2_valid = [case for case in cases if case["l2_semantic_valid"] is True]
    mechanical = [
        case
        for case in cases
        if case["claim_level"] == "differential_reproduction"
        and case["mechanical_outcome"] in {"differential_reproduction", "verified_reproduction"}
    ]
    provisional_count = len(provisional)
    false_positive_count = sum(case["l2_semantic_valid"] is False for case in mechanical)
    outcome_counts: dict[str, int] = {}
    for case in cases:
        outcome = cast(str, case["mechanical_outcome"])
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
    mechanical_count = len(mechanical)
    l2_count = len(l2_valid)
    total_cost = sum(costs)
    return {
        "case_count": EXPECTED_CASE_COUNT,
        "candidate_count": sum(case["candidate_status"] == "submitted" for case in cases),
        "mechanical_differential_count": mechanical_count,
        "mechanical_outcome_counts": dict(sorted(outcome_counts.items())),
        "review_semantic_valid_count": sum(
            _mapping(case["semantic_review_evidence"], "review evidence")["consensus_verdict"]
            == "semantically_valid"
            for case in cases
        ),
        "provisional_candidate_count": provisional_count,
        "l2_semantic_valid_count": l2_count,
        "false_positive_count": false_positive_count,
        "false_positive_rate_millionths": (
            (false_positive_count * 1_000_000 + mechanical_count - 1) // mechanical_count
            if mechanical_count
            else None
        ),
        "provisional_rate_millionths": (provisional_count * 1_000_000 // EXPECTED_CASE_COUNT),
        "l2_success_rate_millionths": l2_count * 1_000_000 // EXPECTED_CASE_COUNT,
        "l2_exact_binomial_95_interval": _clopper_pearson_95_interval(
            l2_count, EXPECTED_CASE_COUNT
        ),
        "total_attributable_microusd": total_cost,
        "median_active_duration_ms": _integer_median(durations),
        "median_provisional_candidate_cost_microusd": _integer_median(
            [cast(int, case["total_attributable_microusd"]) for case in provisional]
        ),
        "blended_cost_per_provisional_candidate_microusd": (
            (total_cost + provisional_count - 1) // provisional_count if provisional_count else None
        ),
        "blended_cost_per_provisional_candidate_rounding": "ceiling_integer_microusd",
        "blended_cost_per_l2_success_microusd": (
            (total_cost + l2_count - 1) // l2_count if l2_count else None
        ),
        "l2_cost_per_success_status": (
            "ceiling_integer_microusd_all_campaign_attributable_cost"
            if l2_count
            else "undefined_no_l2_verdicts"
        ),
    }


def v02_semantic_checklist_sha256(
    *,
    case_id: str,
    candidate_sha256: str,
    causal_control_receipt_sha256: str,
    fixed_pass_evidence_sha256: str,
) -> str:
    """Derive the exact five-question checklist commitment reviewed for one candidate."""

    record = {
        "algorithm": SEMANTIC_CHECKLIST_ALGORITHM,
        "case_id": _case_id(case_id),
        "candidate_sha256": _digest_value(candidate_sha256, "checklist candidate"),
        "causal_control_receipt_sha256": _digest_value(
            causal_control_receipt_sha256, "checklist causal-control receipt"
        ),
        "fixed_pass_evidence_sha256": _digest_value(
            fixed_pass_evidence_sha256, "checklist fixed-pass evidence"
        ),
        "questions": list(_SEMANTIC_RUBRIC_QUESTIONS),
    }
    return _json_sha256(record)


def _semantic_review_record(review: V02SemanticReview) -> dict[str, object]:
    _case_id(review.case_id)
    if isinstance(review.review_round, bool) or review.review_round not in {1, 2, 3}:
        raise _reject("v02_semantic_review", "Semantic review round is invalid.")
    _digest(review.candidate_sha256, "review candidate")
    _digest(review.causal_control_receipt_sha256, "review causal-control receipt")
    _identifier(review.reviewer_id, "semantic reviewer ID")
    _digest(review.reviewer_role_seal_sha256, "reviewer role seal")
    _digest(review.fixed_pass_evidence_sha256, "review fixed-pass evidence")
    _digest(review.checklist_sha256, "semantic review checklist")
    _timestamp(review.reviewed_at, "semantic review time")
    rubric = tuple(getattr(review, field) for field in _SEMANTIC_RUBRIC_FIELDS)
    if not all(isinstance(value, bool) for value in rubric):
        raise _reject("v02_semantic_review", "Semantic rubric answers must be booleans.")
    expected_verdict = "semantically_valid" if all(rubric) else "semantically_invalid"
    if review.verdict != expected_verdict:
        raise _reject("v02_semantic_review", "Semantic verdict does not match rubric answers.")
    if review.confidence not in {"low", "medium", "high"}:
        raise _reject("v02_semantic_review", "Semantic review confidence is invalid.")
    _bounded_text(review.rationale, "semantic review rationale", 20, 2_000)
    record: dict[str, object] = {
        **asdict(review),
        "status": "sealed",
        "reviewer_role": "declared_blinded_semantic_reviewer",
        "issue_snapshot_accessed": True,
        "candidate_accessed": True,
        "normalized_base_failure_accessed": True,
        "fixed_pass_evidence_accessed": True,
        "declared_causal_controls_accessed": True,
        "developer_tests_accessed": False,
        "human_patch_accessed": False,
        "mechanical_verdict_label_accessed": False,
        "gold_hidden_until_verdict": True,
    }
    record["review_sha256"] = _self_hash(record, "review_sha256")
    return record


def _semantic_review_case_record(review_case: V02SemanticReviewCase) -> dict[str, object]:
    _case_id(review_case.case_id)
    _digest(review_case.causal_control_receipt_sha256, "case causal-control receipt")
    if review_case.candidate_sha256 is None:
        if (
            review_case.reviewer_role_seal_sha256 is not None
            or review_case.mapping_reviewer_ids
            or review_case.authorized_semantic_reviewer_ids
            or review_case.reviews
        ):
            raise _reject(
                "v02_semantic_review", "No-candidate review case must contain no reviewer data."
            )
        record: dict[str, object] = {
            "case_id": review_case.case_id,
            "candidate_sha256": None,
            "causal_control_receipt_sha256": review_case.causal_control_receipt_sha256,
            "status": "not_applicable_no_candidate",
            "reviewer_role_seal_sha256": None,
            "mapping_reviewer_ids": [],
            "authorized_semantic_reviewer_ids": [],
            "reviews": [],
            "reviewer_count": 0,
            "consensus_verdict": "not_applicable_no_candidate",
            "tiebreak_used": False,
        }
        record["review_case_sha256"] = _self_hash(record, "review_case_sha256")
        return record
    _digest(review_case.candidate_sha256, "review case candidate")
    if review_case.reviewer_role_seal_sha256 is None:
        raise _reject("v02_semantic_review", "Candidate review lacks a reviewer role seal.")
    _digest(review_case.reviewer_role_seal_sha256, "review case role seal")
    mapping_ids = tuple(
        _identifier(value, "mapping reviewer ID") for value in review_case.mapping_reviewer_ids
    )
    semantic_ids = tuple(
        _identifier(value, "authorized semantic reviewer ID")
        for value in review_case.authorized_semantic_reviewer_ids
    )
    if (
        not 1 <= len(mapping_ids) <= 4
        or mapping_ids != tuple(sorted(set(mapping_ids)))
        or not 2 <= len(semantic_ids) <= 3
        or semantic_ids != tuple(sorted(set(semantic_ids)))
        or set(mapping_ids) & set(semantic_ids)
    ):
        raise _reject(
            "v02_semantic_review", "Mapping and semantic reviewer roles are not independent."
        )
    reviews = tuple(_semantic_review_record(review) for review in review_case.reviews)
    if len(reviews) not in {2, 3}:
        raise _reject("v02_semantic_review", "Each candidate requires two or three reviews.")
    reviewer_ids = tuple(cast(str, review["reviewer_id"]) for review in reviews)
    rounds = tuple(cast(int, review["review_round"]) for review in reviews)
    if (
        rounds != tuple(range(1, len(reviews) + 1))
        or len(set(reviewer_ids)) != len(reviewer_ids)
        or tuple(sorted(reviewer_ids)) != semantic_ids
    ):
        raise _reject("v02_semantic_review", "Review rounds or authorized reviewers differ.")
    for review in reviews:
        if (
            review["case_id"] != review_case.case_id
            or review["candidate_sha256"] != review_case.candidate_sha256
            or review["causal_control_receipt_sha256"] != review_case.causal_control_receipt_sha256
            or review["reviewer_role_seal_sha256"] != review_case.reviewer_role_seal_sha256
        ):
            raise _reject("v02_semantic_review", "Review does not bind its case evidence.")
    first_verdict = cast(str, reviews[0]["verdict"])
    second_verdict = cast(str, reviews[1]["verdict"])
    disagreement = first_verdict != second_verdict
    if disagreement != (len(reviews) == 3):
        raise _reject(
            "v02_semantic_review",
            "A third reviewer is required only and always when the first two disagree.",
        )
    consensus = cast(str, reviews[2]["verdict"]) if disagreement else first_verdict
    record = {
        "case_id": review_case.case_id,
        "candidate_sha256": review_case.candidate_sha256,
        "causal_control_receipt_sha256": review_case.causal_control_receipt_sha256,
        "status": "sealed_consensus",
        "reviewer_role_seal_sha256": review_case.reviewer_role_seal_sha256,
        "mapping_reviewer_ids": list(mapping_ids),
        "authorized_semantic_reviewer_ids": list(semantic_ids),
        "reviews": list(reviews),
        "reviewer_count": len(reviews),
        "consensus_verdict": consensus,
        "tiebreak_used": disagreement,
    }
    record["review_case_sha256"] = _self_hash(record, "review_case_sha256")
    return record


def _verify_semantic_review_record(review: Mapping[str, Any]) -> None:
    _exact_keys(
        review,
        {
            *{field.name for field in fields(V02SemanticReview)},
            "status",
            "reviewer_role",
            "issue_snapshot_accessed",
            "candidate_accessed",
            "normalized_base_failure_accessed",
            "fixed_pass_evidence_accessed",
            "declared_causal_controls_accessed",
            "developer_tests_accessed",
            "human_patch_accessed",
            "mechanical_verdict_label_accessed",
            "gold_hidden_until_verdict",
            "review_sha256",
        },
        "semantic review",
    )
    expected = _semantic_review_record(
        V02SemanticReview(
            case_id=cast(str, review["case_id"]),
            review_round=cast(int, review["review_round"]),
            candidate_sha256=cast(str, review["candidate_sha256"]),
            causal_control_receipt_sha256=cast(str, review["causal_control_receipt_sha256"]),
            reviewer_id=cast(str, review["reviewer_id"]),
            reviewer_role_seal_sha256=cast(str, review["reviewer_role_seal_sha256"]),
            fixed_pass_evidence_sha256=cast(str, review["fixed_pass_evidence_sha256"]),
            checklist_sha256=cast(str, review["checklist_sha256"]),
            reviewed_at=cast(str, review["reviewed_at"]),
            trigger_faithful=cast(bool, review["trigger_faithful"]),
            oracle_supported=cast(bool, review["oracle_supported"]),
            failure_causal=cast(bool, review["failure_causal"]),
            implementation_independent=cast(bool, review["implementation_independent"]),
            minimal_readable=cast(bool, review["minimal_readable"]),
            confidence=cast(str, review["confidence"]),
            rationale=cast(str, review["rationale"]),
            verdict=cast(str, review["verdict"]),
        )
    )
    if review != expected:
        raise _reject("v02_semantic_review", "Semantic review seal is invalid.")


def _verify_semantic_review_case_record(
    review_case: Mapping[str, Any], *, allow_exact_infrastructure: bool = False
) -> None:
    _exact_keys(
        review_case,
        {
            "case_id",
            "candidate_sha256",
            "causal_control_receipt_sha256",
            "status",
            "reviewer_role_seal_sha256",
            "mapping_reviewer_ids",
            "authorized_semantic_reviewer_ids",
            "reviews",
            "reviewer_count",
            "consensus_verdict",
            "tiebreak_used",
            "review_case_sha256",
        },
        "semantic review case",
    )
    reviews_value = review_case["reviews"]
    mapping_value = review_case["mapping_reviewer_ids"]
    authorized_value = review_case["authorized_semantic_reviewer_ids"]
    if not all(
        isinstance(value, list) for value in (reviews_value, mapping_value, authorized_value)
    ):
        raise _reject("v02_semantic_review", "Semantic review case arrays are invalid.")
    if (
        allow_exact_infrastructure
        and review_case.get("case_id") == "rk-v0.2-014"
        and review_case.get("status") == "not_applicable_infrastructure_failure"
    ):
        expected: dict[str, object] = {
            "case_id": _case_id(review_case.get("case_id")),
            "candidate_sha256": _digest_value(
                review_case.get("candidate_sha256"), "infrastructure review candidate"
            ),
            "causal_control_receipt_sha256": _digest_value(
                review_case.get("causal_control_receipt_sha256"),
                "infrastructure control receipt",
            ),
            "status": "not_applicable_infrastructure_failure",
            "reviewer_role_seal_sha256": None,
            "mapping_reviewer_ids": [],
            "authorized_semantic_reviewer_ids": [],
            "reviews": [],
            "reviewer_count": 0,
            "consensus_verdict": "inconclusive",
            "tiebreak_used": False,
        }
        expected["review_case_sha256"] = _self_hash(expected, "review_case_sha256")
        if review_case != expected:
            raise _reject("v02_semantic_review", "Infrastructure review seal is invalid.")
        return
    parsed_reviews: list[V02SemanticReview] = []
    for value in cast(list[object], reviews_value):
        review = _mapping(value, "semantic review")
        _verify_semantic_review_record(review)
        parsed_reviews.append(
            V02SemanticReview(
                case_id=cast(str, review["case_id"]),
                review_round=cast(int, review["review_round"]),
                candidate_sha256=cast(str, review["candidate_sha256"]),
                causal_control_receipt_sha256=cast(str, review["causal_control_receipt_sha256"]),
                reviewer_id=cast(str, review["reviewer_id"]),
                reviewer_role_seal_sha256=cast(str, review["reviewer_role_seal_sha256"]),
                fixed_pass_evidence_sha256=cast(str, review["fixed_pass_evidence_sha256"]),
                checklist_sha256=cast(str, review["checklist_sha256"]),
                reviewed_at=cast(str, review["reviewed_at"]),
                trigger_faithful=cast(bool, review["trigger_faithful"]),
                oracle_supported=cast(bool, review["oracle_supported"]),
                failure_causal=cast(bool, review["failure_causal"]),
                implementation_independent=cast(bool, review["implementation_independent"]),
                minimal_readable=cast(bool, review["minimal_readable"]),
                confidence=cast(str, review["confidence"]),
                rationale=cast(str, review["rationale"]),
                verdict=cast(str, review["verdict"]),
            )
        )
    expected = _semantic_review_case_record(
        V02SemanticReviewCase(
            case_id=cast(str, review_case["case_id"]),
            candidate_sha256=cast(str | None, review_case["candidate_sha256"]),
            causal_control_receipt_sha256=cast(str, review_case["causal_control_receipt_sha256"]),
            reviewer_role_seal_sha256=cast(str | None, review_case["reviewer_role_seal_sha256"]),
            mapping_reviewer_ids=tuple(cast(list[str], mapping_value)),
            authorized_semantic_reviewer_ids=tuple(cast(list[str], authorized_value)),
            reviews=tuple(parsed_reviews),
        )
    )
    if review_case != expected:
        raise _reject("v02_semantic_review", "Semantic review case seal is invalid.")


def _causal_control_run_record(run: V02CausalControlRun) -> dict[str, object]:
    _identifier(run.control_id, "causal-control ID")
    if run.control_type not in {*_REQUIRED_CONTROL_TYPES, "declared_decoy"}:
        raise _reject("v02_causal_control", "Causal-control type is invalid.")
    if run.control_type in _REQUIRED_CONTROL_TYPES:
        if (
            run.control_id != run.control_type
            or run.expected_outcome != _CONTROL_EXPECTED_OUTCOMES[run.control_type]
        ):
            raise _reject("v02_causal_control", "Required control identity is invalid.")
    elif run.expected_outcome not in {"pass", "fail"}:
        raise _reject("v02_causal_control", "Declared decoy expectation is invalid.")
    if run.observed_outcome not in _CONTROL_OBSERVED_OUTCOMES:
        raise _reject("v02_causal_control", "Observed control outcome is invalid.")
    if not all(
        isinstance(value, bool) for value in (run.timed_out, run.oom_killed, run.output_truncated)
    ):
        raise _reject("v02_causal_control", "Control execution flags are invalid.")
    nonexecution_outcome = run.observed_outcome in {"not_available", "inconclusive"}
    execution_values = (
        run.executed_at,
        run.test_command,
        run.exit_code,
        run.duration_ms,
        run.output_sha256,
        run.junit_sha256,
        run.sandbox_receipt_sha256,
        run.environment_sha256,
    )
    if nonexecution_outcome:
        if (
            any(value is not None for value in execution_values)
            or run.timed_out
            or run.oom_killed
            or run.output_truncated
            or run.reason is None
        ):
            raise _reject("v02_causal_control", "Unavailable control evidence is inconsistent.")
        _bounded_text(run.reason, "unavailable control reason", 10, 500)
    else:
        if run.reason is not None:
            raise _reject("v02_causal_control", "Executed control must not contain a reason.")
        _timestamp(run.executed_at, "control execution time")
        _bounded_text(run.test_command, "control test command", 1, 500)
        if (
            isinstance(run.duration_ms, bool)
            or not isinstance(run.duration_ms, int)
            or not 0 <= run.duration_ms <= 3_600_000
        ):
            raise _reject("v02_causal_control", "Control duration is invalid.")
        for value, label in (
            (run.output_sha256, "control output"),
            (run.junit_sha256, "control JUnit"),
            (run.sandbox_receipt_sha256, "control sandbox receipt"),
            (run.environment_sha256, "control environment"),
        ):
            _digest(value, label)
        if run.observed_outcome == "pass":
            valid_exit = run.exit_code == 0 and not run.timed_out and not run.oom_killed
        elif run.observed_outcome == "fail":
            valid_exit = (
                isinstance(run.exit_code, int)
                and not isinstance(run.exit_code, bool)
                and 1 <= run.exit_code <= 255
                and not run.timed_out
                and not run.oom_killed
            )
        elif run.observed_outcome == "timeout":
            valid_exit = run.exit_code is None and run.timed_out and not run.oom_killed
        else:
            valid_exit = (
                run.exit_code is None or isinstance(run.exit_code, int)
            ) and not run.timed_out
        if not valid_exit:
            raise _reject("v02_causal_control", "Control outcome and process result disagree.")
    record: dict[str, object] = {
        "algorithm": CAUSAL_CONTROL_RUN_ALGORITHM,
        **asdict(run),
    }
    record["control_run_sha256"] = _self_hash(record, "control_run_sha256")
    return record


def _causal_control_case_record(control_case: V02CausalControlCase) -> dict[str, object]:
    _case_id(control_case.case_id)
    _digest(control_case.evaluator_commitment_sha256, "control evaluator commitment")
    if control_case.candidate_sha256 is None:
        if (
            control_case.status != "not_applicable_no_candidate"
            or control_case.issue_relevant_hunks_sha256 is not None
            or control_case.fixed_pass_evidence_sha256 is not None
            or control_case.completed_at is not None
            or control_case.declared_decoy_control_ids
            or control_case.controls
        ):
            raise _reject("v02_causal_control", "No-candidate control case is inconsistent.")
        record: dict[str, object] = {
            "algorithm": CAUSAL_CONTROL_RECEIPT_ALGORITHM,
            "case_id": control_case.case_id,
            "candidate_sha256": None,
            "evaluator_commitment_sha256": control_case.evaluator_commitment_sha256,
            "issue_relevant_hunks_sha256": None,
            "fixed_pass_evidence_sha256": None,
            "status": "not_applicable_no_candidate",
            "completed_at": None,
            "declared_decoy_control_ids": [],
            "controls": [],
            "required_controls_passed": False,
            "declared_decoys_passed": False,
            "l2_causal_controls_passed": False,
        }
        record["control_receipt_sha256"] = _self_hash(record, "control_receipt_sha256")
        return record
    if control_case.status != "executed":
        raise _reject("v02_causal_control", "Candidate control case must be executed.")
    _digest(control_case.candidate_sha256, "control candidate")
    _digest(control_case.issue_relevant_hunks_sha256, "issue-relevant hunks")
    _digest(control_case.fixed_pass_evidence_sha256, "fixed-pass evidence")
    _timestamp(control_case.completed_at, "control completion time")
    decoy_ids = tuple(
        _identifier(value, "declared decoy control ID")
        for value in control_case.declared_decoy_control_ids
    )
    if len(decoy_ids) > 32 or decoy_ids != tuple(sorted(set(decoy_ids))):
        raise _reject("v02_causal_control", "Declared decoy controls are not canonical.")
    controls = tuple(_causal_control_run_record(run) for run in control_case.controls)
    control_ids = tuple(cast(str, run["control_id"]) for run in controls)
    if len(set(control_ids)) != len(control_ids):
        raise _reject("v02_causal_control", "Causal-control IDs are duplicated.")
    required_types = tuple(
        run["control_type"] for run in controls if run["control_type"] in _REQUIRED_CONTROL_TYPES
    )
    observed_decoys = tuple(
        cast(str, run["control_id"]) for run in controls if run["control_type"] == "declared_decoy"
    )
    if required_types != _REQUIRED_CONTROL_TYPES or observed_decoys != decoy_ids:
        raise _reject(
            "v02_causal_control",
            "Required and declared controls must appear exactly once in canonical order.",
        )
    required_controls_passed = all(
        _control_run_passed(run)
        for run in controls
        if run["control_type"] in _REQUIRED_CONTROL_TYPES
    )
    declared_decoys_passed = all(
        _control_run_passed(run) for run in controls if run["control_type"] == "declared_decoy"
    )
    record = {
        "algorithm": CAUSAL_CONTROL_RECEIPT_ALGORITHM,
        "case_id": control_case.case_id,
        "candidate_sha256": control_case.candidate_sha256,
        "evaluator_commitment_sha256": control_case.evaluator_commitment_sha256,
        "issue_relevant_hunks_sha256": control_case.issue_relevant_hunks_sha256,
        "fixed_pass_evidence_sha256": control_case.fixed_pass_evidence_sha256,
        "status": control_case.status,
        "completed_at": control_case.completed_at,
        "declared_decoy_control_ids": list(decoy_ids),
        "controls": list(controls),
        "required_controls_passed": required_controls_passed,
        "declared_decoys_passed": declared_decoys_passed,
        "l2_causal_controls_passed": (required_controls_passed and declared_decoys_passed),
    }
    record["control_receipt_sha256"] = _self_hash(record, "control_receipt_sha256")
    return record


def _control_run_passed(run: Mapping[str, object]) -> bool:
    return bool(
        run["observed_outcome"] == run["expected_outcome"]
        and run["timed_out"] is False
        and run["oom_killed"] is False
        and run["output_truncated"] is False
    )


def _verify_causal_control_case_record(control_case: Mapping[str, Any]) -> None:
    _exact_keys(
        control_case,
        {
            "algorithm",
            "case_id",
            "candidate_sha256",
            "evaluator_commitment_sha256",
            "issue_relevant_hunks_sha256",
            "fixed_pass_evidence_sha256",
            "status",
            "completed_at",
            "declared_decoy_control_ids",
            "controls",
            "required_controls_passed",
            "declared_decoys_passed",
            "l2_causal_controls_passed",
            "control_receipt_sha256",
        },
        "causal-control case",
    )
    controls_value = control_case["controls"]
    decoys_value = control_case["declared_decoy_control_ids"]
    if not isinstance(controls_value, list) or not isinstance(decoys_value, list):
        raise _reject("v02_causal_control", "Causal-control case arrays are invalid.")
    parsed_runs: list[V02CausalControlRun] = []
    for value in controls_value:
        run = _mapping(value, "causal-control run")
        _exact_keys(
            run,
            {
                "algorithm",
                *{field.name for field in fields(V02CausalControlRun)},
                "control_run_sha256",
            },
            "causal-control run",
        )
        parsed = V02CausalControlRun(
            control_id=cast(str, run["control_id"]),
            control_type=cast(str, run["control_type"]),
            expected_outcome=cast(str, run["expected_outcome"]),
            observed_outcome=cast(str, run["observed_outcome"]),
            executed_at=cast(str | None, run["executed_at"]),
            test_command=cast(str | None, run["test_command"]),
            exit_code=cast(int | None, run["exit_code"]),
            duration_ms=cast(int | None, run["duration_ms"]),
            timed_out=cast(bool, run["timed_out"]),
            oom_killed=cast(bool, run["oom_killed"]),
            output_truncated=cast(bool, run["output_truncated"]),
            output_sha256=cast(str | None, run["output_sha256"]),
            junit_sha256=cast(str | None, run["junit_sha256"]),
            sandbox_receipt_sha256=cast(str | None, run["sandbox_receipt_sha256"]),
            environment_sha256=cast(str | None, run["environment_sha256"]),
            reason=cast(str | None, run["reason"]),
        )
        if run != _causal_control_run_record(parsed):
            raise _reject("v02_causal_control", "Causal-control run seal is invalid.")
        parsed_runs.append(parsed)
    expected = _causal_control_case_record(
        V02CausalControlCase(
            case_id=cast(str, control_case["case_id"]),
            candidate_sha256=cast(str | None, control_case["candidate_sha256"]),
            evaluator_commitment_sha256=cast(str, control_case["evaluator_commitment_sha256"]),
            issue_relevant_hunks_sha256=cast(
                str | None, control_case["issue_relevant_hunks_sha256"]
            ),
            fixed_pass_evidence_sha256=cast(str | None, control_case["fixed_pass_evidence_sha256"]),
            status=cast(str, control_case["status"]),
            completed_at=cast(str | None, control_case["completed_at"]),
            declared_decoy_control_ids=tuple(cast(list[str], decoys_value)),
            controls=tuple(parsed_runs),
        )
    )
    if control_case != expected:
        raise _reject("v02_causal_control", "Causal-control case seal is invalid.")


def _verify_causal_control_set_envelope(
    record: Mapping[str, Any], freeze: VerifiedV02CampaignFreeze
) -> tuple[datetime, list[object]]:
    _exact_keys(
        record,
        {
            "schema_version",
            "benchmark_version",
            "algorithm",
            "status",
            "campaign_id",
            "campaign_freeze_sha256",
            "preregistration_sha256",
            "cohort_sha256",
            "sealed_at",
            "execution_contract",
            "cases",
            "tool",
            "control_set_sha256",
        },
        "causal-control set",
    )
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["benchmark_version"] != BENCHMARK_VERSION
        or record["algorithm"] != CAUSAL_CONTROL_ALGORITHM
        or record["status"] != "sealed_complete"
        or record["campaign_id"] != freeze.campaign_id
        or record["campaign_freeze_sha256"] != freeze.raw_sha256
        or record["preregistration_sha256"] != freeze.preregistration_sha256
        or record["cohort_sha256"] != freeze.cohort_sha256
        or record["control_set_sha256"] != _self_hash(record, "control_set_sha256")
    ):
        raise _reject("v02_causal_control", "Causal-control set binding is invalid.")
    expected_contract = {
        "required_control_types": list(_REQUIRED_CONTROL_TYPES),
        "real_sandbox_boundary_required": True,
        "host_secrets_exposed": False,
        "network_after_dependency_prep": "disabled",
        "resource_limits_required": True,
        "declared_decoys_frozen_before_gold_unblinding": True,
        "unavailable_or_inconclusive_controls_cannot_pass_l2": True,
    }
    if record["execution_contract"] != expected_contract:
        raise _reject("v02_causal_control", "Causal-control execution contract is invalid.")
    _verify_tool(record["tool"], "causal-control tool")
    values = record["cases"]
    if not isinstance(values, list) or len(values) != EXPECTED_CASE_COUNT:
        raise _reject("v02_causal_control", "Causal-control set is incomplete.")
    return (
        _parse_timestamp(record["sealed_at"], "causal-control seal time"),
        cast(list[object], values),
    )


def _fixed_pass_evidence_sha256(evaluation: Mapping[str, Any]) -> str:
    if evaluation.get("kind") == "exact_image_receipt":
        receipt = evaluation.get("receipt_sha256")
        return _digest_value(receipt, "exact fixed-pass receipt")
    runs = evaluation.get("scheduled_runs")
    if not isinstance(runs, list):
        raise _reject("v02_causal_control", "Differential evaluation lacks scheduled runs.")
    fixed_runs = [
        run for run in runs if isinstance(run, Mapping) and run.get("source_role") == "fixed"
    ]
    if not fixed_runs:
        raise _reject("v02_causal_control", "Differential evaluation lacks fixed-run evidence.")
    return _json_sha256(
        {
            "algorithm": "reproassert-v02-fixed-run-evidence-v1",
            "scheduled_fixed_runs": fixed_runs,
        }
    )


def _clopper_pearson_95_interval(successes: int, trials: int) -> dict[str, object]:
    if not 0 <= successes <= trials or trials <= 0:
        raise ValueError("invalid binomial counts")
    lower = 0.0 if successes == 0 else _beta_quantile(0.025, successes, trials - successes + 1)
    upper = 1.0 if successes == trials else _beta_quantile(0.975, successes + 1, trials - successes)
    return {
        "method": "clopper_pearson_two_sided_reference",
        "lower_millionths": math.floor(lower * 1_000_000),
        "upper_millionths": math.ceil(upper * 1_000_000),
        "scope": "selected_cohort_only_not_population_generalization",
        "selection_bias_addressed": False,
    }


def _beta_quantile(probability: float, alpha: int, beta: int) -> float:
    low = 0.0
    high = 1.0
    for _ in range(80):
        midpoint = (low + high) / 2
        if _integer_beta_cdf(midpoint, alpha, beta) < probability:
            low = midpoint
        else:
            high = midpoint
    return (low + high) / 2


def _integer_beta_cdf(value: float, alpha: int, beta: int) -> float:
    order = alpha + beta - 1
    return sum(
        math.comb(order, index) * value**index * (1 - value) ** (order - index)
        for index in range(alpha, order + 1)
    )


def _verify_candidate(value: object, case_id: str) -> Mapping[str, Any]:
    candidate = _mapping(value, "candidate")
    _exact_keys(
        candidate,
        {"path", "sha256", "bytes", "test_content", "expected_symptom", "rationale"},
        "candidate",
    )
    content = candidate["test_content"]
    if (
        not isinstance(content, str)
        or hashlib.sha256(content.encode()).hexdigest() != candidate["sha256"]
    ):
        raise _reject("v02_campaign_candidate", f"Case {case_id} candidate hash is invalid.")
    if candidate["bytes"] != len(content.encode()) or not isinstance(candidate["path"], str):
        raise _reject("v02_campaign_candidate", f"Case {case_id} candidate size is invalid.")
    return candidate


def _active_duration_ms(state: Mapping[str, Any]) -> int:
    phases: dict[str, int] = {}
    events = cast(Sequence[Mapping[str, Any]], state["events"])
    for event in events:
        if event["event_type"] != "phase_finished":
            continue
        payload = _mapping(event["payload"], "phase finish")
        phase = payload.get("phase")
        duration = payload.get("duration_ms")
        if (
            phase not in {"generation", "differential", "result_write"}
            or phase in phases
            or isinstance(duration, bool)
            or not isinstance(duration, int)
            or duration < 0
        ):
            raise _reject("v02_campaign_time", "Active phase accounting is invalid.")
        phases[cast(str, phase)] = duration
    if "generation" not in phases or "result_write" not in phases:
        raise _reject("v02_campaign_time", "Active phase accounting is incomplete.")
    return sum(phases.values())


def _integer_median(values: Sequence[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def _load_canonical_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bounded_regular(path, label)
    decoded = _decode_json(raw, label)
    if not isinstance(decoded, dict) or _canonical_bytes(decoded) != raw:
        raise _reject("v02_campaign_artifact", f"{label} is not canonical JSON.")
    return raw, cast(dict[str, Any], decoded)


def _load_json_value(path: Path, label: str) -> object:
    return _decode_json(_read_bounded_regular(path, label), label)


def _read_bounded_regular(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _reject("v02_campaign_artifact", f"Cannot safely open {label}.") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject("v02_campaign_artifact", f"{label} is not one regular file.")
        chunks: list[bytes] = []
        remaining = _MAX_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_JSON_BYTES:
        raise _reject("v02_campaign_artifact", f"{label} exceeds its byte limit.")
    return raw


def _decode_json(raw: bytes, label: str) -> object:
    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("v02_campaign_artifact", f"{label} is invalid JSON.") from exc
    return decoded


def _write_exclusive_fsync(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise _reject("v02_campaign_output_exists", "Campaign output already exists.") from exc
    except OSError as exc:
        raise _reject("v02_campaign_output", "Campaign output must be a new regular file.") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _reject("v02_campaign_output", "Campaign output is not a regular file.")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short campaign artifact write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_or_match_fsync(path: Path, content: bytes) -> None:
    try:
        _write_exclusive_fsync(path, content)
        return
    except PolicyRejection as exc:
        if exc.code != "v02_campaign_output_exists":
            raise
    existing = _read_bounded_regular(path, "existing final campaign output")
    if existing != content:
        raise _reject(
            "v02_campaign_output_mismatch",
            "Existing final campaign output differs from deterministic rerun bytes.",
        )


def _canonical_bytes(value: object) -> bytes:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return encoded.encode() + b"\n"


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)[:-1]).hexdigest()


def _self_hash(value: Mapping[str, Any], field: str) -> str:
    return _json_sha256({key: item for key, item in value.items() if key != field})


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _reject("v02_campaign_schema", f"{label} must be an object.")
    return cast(Mapping[str, Any], value)


def _verify_tool(value: object, label: str) -> None:
    tool = _mapping(value, label)
    _exact_keys(tool, {"name", "version", "git_sha"}, label)
    _identifier(tool["name"], "tool name")
    _bounded_text(tool["version"], "tool version", 1, 64)
    _git_sha(tool["git_sha"], "tool Git SHA")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise _reject("v02_campaign_schema", f"{label} fields are not exact.")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise _reject("v02_campaign_identity", f"{label} is invalid.")
    return value


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("v02_campaign_identity", "Case ID is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject("v02_campaign_identity", f"{label} SHA-256 is invalid.")
    return value


def _digest_value(value: object, label: str) -> str:
    return _digest(value, label)


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("v02_campaign_identity", f"{label} is invalid.")
    return value


def _bounded_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.isprintable()
    ):
        raise _reject("v02_campaign_identity", f"{label} is invalid.")
    return value


def _parse_timestamp(value: object, label: str) -> datetime:
    _timestamp(value, label)
    return datetime.fromisoformat(cast(str, value)[:-1] + "+00:00").astimezone(timezone.utc)


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("v02_campaign_time", f"{label} is invalid.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject("v02_campaign_time", f"{label} is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _reject("v02_campaign_time", f"{label} is not UTC.")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _reject(code: str, message: str) -> PolicyRejection:
    return PolicyRejection(code, message)
