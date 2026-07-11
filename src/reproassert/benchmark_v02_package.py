from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, TypeVar, cast

from reproassert.benchmark_snapshot import (
    MAX_BODY_BYTES,
    MAX_CANONICAL_BYTES,
    MAX_TITLE_BYTES,
    canonical_snapshot_content_bytes,
    load_snapshot_receipt,
)
from reproassert.benchmark_snapshot_producer import (
    GRAPHQL_CAPTURE_FORMAT,
    ISSUE_HISTORY_QUERY_SHA256,
    REDACTION_POLICY_SHA256,
    SOLUTION_CUTOFF_QUERY_SHA256,
)
from reproassert.context import V02_SOURCE_CONTEXT_ALGORITHM, V02_SOURCE_CONTEXT_POLICY_SHA256
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file, require_private_directory
from reproassert.source_attestation import (
    ExpectedGitSpecialEntry,
    validate_expected_git_special_entries,
)

SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.2.0-draft"
FIX_MAPPING_FILENAME = "benchmark-v02-fix-mapping.json"
CASE_PACKAGE_FILENAME = "benchmark-v02-case-package.json"
PREREGISTRATION_FILENAME = "benchmark-v02-preregistration.json"
GENERATOR_PROJECTION_ALGORITHM = "reproassert-generator-case-v1"
EVALUATOR_PACKAGE_ALGORITHM = "reproassert-hidden-evaluator-package-v1"
EVALUATOR_COMMITMENT_ALGORITHM = "reproassert-salted-evaluator-commitment-v1"
SEMANTIC_VERIFICATION_ALGORITHM = "reproassert-v02-semantic-verification-v1"
SOURCE_DATASET_TRANSFORM = "drop_PASS_TO_PASS_and_FAIL_TO_PASS_v1"
FIXING_PR_IDENTITY_QUERY = """query ReproAssertFixingPullRequestIdentity(
  $owner: String!
  $repo: String!
  $number: Int!
  $baseOid: GitObjectID!
) {
  repository(owner: $owner, name: $repo) {
    nameWithOwner
    baseCommit: object(oid: $baseOid) {
      ... on Commit { oid tree { oid } }
    }
    pullRequest(number: $number) {
      number
      url
      createdAt
      publishedAt
      mergedAt
      isDraft
      headRefOid
      baseRepository { nameWithOwner }
      commits(last: 1) {
        totalCount
        nodes { commit { oid tree { oid } } }
      }
    }
  }
}
"""
FIXING_PR_IDENTITY_QUERY_SHA256 = hashlib.sha256(FIXING_PR_IDENTITY_QUERY.encode()).hexdigest()
EXPECTED_CASE_COUNT = 20
EXPECTED_SMOKE_COUNT = 5
EXPECTED_SMOKE_CASE_IDS = (
    "rk-v0.2-004",
    "rk-v0.2-006",
    "rk-v0.2-010",
    "rk-v0.2-011",
    "rk-v0.2-018",
)
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_PACKAGE_BYTES = 128 * 1024 * 1024

_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)

_CASE_KEYS = {"id", "repo", "issue_url", "base_sha"}
_ARTIFACT_KEYS = {"path", "sha256", "bytes"}
_TOOL_KEYS = {"name", "version", "git_sha"}
_FIX_ROOT_KEYS = {
    "schema_version",
    "benchmark_version",
    "case",
    "provenance",
    "fixing_pull_request",
    "evaluator_artifacts",
    "review",
    "tool",
}
_PROVENANCE_KEYS = {
    "tdd_bench_repository_url",
    "tdd_bench_git_sha",
    "tdd_bench_root_tree_oid",
    "tdd_id_list_path",
    "tdd_id_list_blob_oid",
    "tdd_id_list",
    "tdd_membership_ordinal",
    "source_dataset_repository_url",
    "source_dataset_git_sha",
    "source_dataset_root_tree_oid",
    "source_dataset_split",
    "source_dataset_artifact_path",
    "source_dataset_artifact_git_blob_oid",
    "source_dataset_lfs_pointer",
    "source_dataset_artifact_lfs_sha256",
    "source_dataset_artifact_lfs_bytes",
    "source_dataset_artifact_xet_sha256",
    "source_dataset_artifact",
    "source_dataset_row_ordinal",
    "instance_id",
    "upstream_record",
    "fixing_pr_evidence",
    "mapping_method",
}
_FIX_PR_KEYS = {
    "number",
    "url",
    "created_at",
    "published_at",
    "target_sha256",
    "fixed_commit_sha",
    "base_root_tree_oid",
    "head_root_tree_oid",
    "production_patch_sha256",
    "developer_tests_sha256",
}
_EVALUATOR_ARTIFACT_KEYS = {
    "production_patch",
    "developer_tests",
    "oracle_rubric",
    "causal_controls",
    "reviewer_packet",
}
_REVIEW_KEYS = {
    "status",
    "reviewed_at",
    "reviewer_ids",
    "checklist",
    "mapping_correct",
    "upstream_license_reviewed",
    "generator_access",
}
_PACKAGE_ROOT_KEYS = {
    "schema_version",
    "benchmark_version",
    "case",
    "snapshot",
    "fix_mapping",
    "supporting_inputs",
    "isolation",
    "evaluator_package",
    "tool",
}
_SNAPSHOT_KEYS = {
    "receipt",
    "raw_history",
    "cutoff_basis",
    "privacy_review",
    "generator_projection",
}
_FIX_MAPPING_KEYS = {"receipt"}
_SUPPORTING_KEYS = {
    "source_receipt",
    "dependency_receipt",
    "isolation_canary_receipt",
    "reviewer_role_seal",
    "semantic_verification_receipt",
}
_ISOLATION_KEYS = {
    "policy_sha256",
    "generator_visible_artifacts",
    "evaluator_artifacts_mounted_in_generator",
    "network_after_dependency_prep",
}
_EVALUATOR_PACKAGE_KEYS = {
    "algorithm",
    "commitment_algorithm",
    "commitment_nonce",
    "nonce_generation",
    "identity_sha256",
    "public_commitment_sha256",
}
_PREREG_ROOT_KEYS = {
    "schema_version",
    "benchmark_version",
    "status",
    "frozen_at",
    "cohort",
    "protocol",
    "artifact_contract",
    "cases",
    "cohort_sha256",
    "tool",
}
_COHORT_KEYS = {"case_count", "selection_method", "preinference_freeze"}
_PROTOCOL_KEYS = {
    "cutoff",
    "comments_included",
    "generator_visible_fields",
    "evaluator_only_fields",
    "submitted_candidates_per_case",
    "candidate_selection_uses_oracle",
    "semantic_valid_minimum",
    "semantic_valid_denominator",
}
_CONTRACT_KEYS = {
    "issue_history_query_sha256",
    "solution_cutoff_query_sha256",
    "fixing_pr_identity_query_sha256",
    "redaction_policy_sha256",
    "generator_projection_algorithm",
    "evaluator_package_algorithm",
    "evaluator_commitment_algorithm",
    "semantic_verification_algorithm",
    "source_dataset_transform",
    "source_context_algorithm",
    "source_context_policy_sha256",
}
_UPSTREAM_RECORD_KEYS = {
    "repo",
    "instance_id",
    "base_commit",
    "patch",
    "test_patch",
    "problem_statement",
    "hints_text",
    "created_at",
    "version",
    "environment_setup_commit",
    "difficulty",
}
_FIXING_GRAPHQL_ARTIFACT_KEYS = {"format", "query_sha256", "captured_at", "response"}
_GRAPHQL_RESPONSE_KEYS = {"data"}
_GRAPHQL_DATA_KEYS = {"repository"}
_PR_EVIDENCE_REPOSITORY_KEYS = {"nameWithOwner", "baseCommit", "pullRequest"}
_PR_EVIDENCE_KEYS = {
    "number",
    "url",
    "createdAt",
    "publishedAt",
    "mergedAt",
    "isDraft",
    "headRefOid",
    "baseRepository",
    "commits",
}
_BASE_REPOSITORY_KEYS = {"nameWithOwner"}
_COMMIT_KEYS = {"oid", "tree"}
_TREE_KEYS = {"oid"}
_COMMITS_KEYS = {"totalCount", "nodes"}
_COMMIT_NODE_KEYS = {"commit"}
_UPSTREAM_DIFFICULTIES = {
    "<15 min fix": "lt_15m",
    "15 min - 1 hour": "15m_to_1h",
}
_UniqueKey = TypeVar("_UniqueKey")
_CAPABILITY_ISSUER = object()
_PREREG_CASE_KEYS = {
    "id",
    "repo",
    "issue_url",
    "base_sha",
    "difficulty",
    "smoke",
    "generator_projection_sha256",
    "evaluator_commitment_sha256",
    "source_context_sha256",
}


@dataclass(frozen=True)
class V02CaseIdentity:
    id: str
    repo: str
    issue_url: str
    base_sha: str


@dataclass(frozen=True)
class ArtifactReference:
    path: str
    sha256: str
    bytes: int


@dataclass(frozen=True)
class FixMappingReceipt:
    case: V02CaseIdentity
    instance_id: str
    tdd_bench_git_sha: str
    tdd_bench_root_tree_oid: str
    tdd_id_list_path: str
    tdd_id_list_blob_oid: str
    tdd_id_list_sha256: str
    tdd_membership_ordinal: int
    source_dataset_git_sha: str
    source_dataset_root_tree_oid: str
    source_dataset_split: str
    source_dataset_artifact_path: str
    source_dataset_artifact_git_blob_oid: str
    source_dataset_lfs_pointer_sha256: str
    source_dataset_artifact_lfs_sha256: str
    source_dataset_artifact_lfs_bytes: int
    source_dataset_artifact_xet_sha256: str
    source_dataset_artifact_sha256: str
    source_dataset_row_ordinal: int
    upstream_record_sha256: str
    target_sha256: str
    created_at: str
    published_at: str
    merged_at: str
    evidence_captured_at: str
    reviewed_at: str
    mapping_reviewer_ids: tuple[str, ...]
    fixing_pr_number: int
    fixing_pr_url: str
    fixed_commit_sha: str
    base_root_tree_oid: str
    head_root_tree_oid: str
    production_patch_sha256: str
    developer_tests_sha256: str
    environment_setup_commit: str
    difficulty: str
    receipt_sha256: str
    artifacts: tuple[ArtifactReference, ...]
    tdd_id_list: ArtifactReference
    source_dataset_artifact: ArtifactReference
    source_dataset_lfs_pointer: ArtifactReference
    upstream_record: ArtifactReference
    fixing_pr_evidence: ArtifactReference
    production_patch: ArtifactReference
    developer_tests: ArtifactReference


@dataclass(frozen=True)
class VerifiedV02CasePackage:
    case: V02CaseIdentity
    generator_projection_sha256: str
    evaluator_package_sha256: str
    evaluator_commitment_sha256: str
    snapshot_sha256: str
    difficulty: str
    upstream_instance_id: str
    fixing_pr_number: int
    fixed_commit_sha: str
    hidden_fixed_root_tree_oid: str
    evaluator_commitment_nonce: str
    verification_completed_at: str
    evaluator_capability: VerifiedV02EvaluatorCapability | None


@dataclass(frozen=True, init=False)
class VerifiedV02EvaluatorCapability:
    """Nominal live authority for a causally verified private base/fixed pair.

    The capability carries identities, not caller-supplied filesystem paths. Consumers must attest
    freshly staged trees against these OIDs before executing a differential claim.
    """

    case: V02CaseIdentity
    preregistration_sha256: str
    cohort_sha256: str
    preregistered_case_sha256: str
    package_identity_sha256: str
    public_commitment_sha256: str
    generator_projection_sha256: str
    dataset_evidence_sha256: str
    difficulty: str
    upstream_instance_id: str
    fixing_pr_number: int
    evaluator_commitment_nonce: str
    verification_completed_at: str
    base_commit_sha: str
    base_root_tree_oid: str
    source_receipt_sha256: str
    source_tree_sha256: str
    source_context_algorithm: str
    source_context_policy_sha256: str
    source_context_sha256: str
    source_special_entries: tuple[ExpectedGitSpecialEntry, ...]
    hidden_fixed_root_tree_oid: str
    fixing_head_commit_sha: str
    fixing_head_root_tree_oid: str
    production_patch_sha256: str
    developer_tests_sha256: str
    dependencies_required: bool
    dependency_receipt_sha256: str | None
    dependency_plan_sha256: str | None
    dependency_tree_sha256: str | None
    dependency_runner_image_id: str | None
    isolation_receipt_sha256: str
    isolation_policy_sha256: str
    reviewer_role_seal_sha256: str
    semantic_verification_receipt_sha256: str
    capability_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(
        self,
        issuer: object,
        *,
        case: V02CaseIdentity,
        preregistration_sha256: str,
        cohort_sha256: str,
        preregistered_case_sha256: str,
        package_identity_sha256: str,
        public_commitment_sha256: str,
        generator_projection_sha256: str,
        dataset_evidence_sha256: str,
        difficulty: str,
        upstream_instance_id: str,
        fixing_pr_number: int,
        evaluator_commitment_nonce: str,
        verification_completed_at: str,
        base_commit_sha: str,
        base_root_tree_oid: str,
        source_receipt_sha256: str,
        source_tree_sha256: str,
        source_context_algorithm: str,
        source_context_policy_sha256: str,
        source_context_sha256: str,
        source_special_entries: tuple[ExpectedGitSpecialEntry, ...],
        hidden_fixed_root_tree_oid: str,
        fixing_head_commit_sha: str,
        fixing_head_root_tree_oid: str,
        production_patch_sha256: str,
        developer_tests_sha256: str,
        dependencies_required: bool,
        dependency_receipt_sha256: str | None,
        dependency_plan_sha256: str | None,
        dependency_tree_sha256: str | None,
        dependency_runner_image_id: str | None,
        isolation_receipt_sha256: str,
        isolation_policy_sha256: str,
        reviewer_role_seal_sha256: str,
        semantic_verification_receipt_sha256: str,
    ) -> None:
        if issuer is not _CAPABILITY_ISSUER:
            raise _rejection("Evaluator capability may only be issued by verified package loading.")
        validated_special_entries = validate_expected_git_special_entries(source_special_entries)
        record = {
            "algorithm": "reproassert-v02-evaluator-capability-v1",
            "case": asdict(case),
            "preregistration_sha256": preregistration_sha256,
            "cohort_sha256": cohort_sha256,
            "preregistered_case_sha256": preregistered_case_sha256,
            "package_identity_sha256": package_identity_sha256,
            "public_commitment_sha256": public_commitment_sha256,
            "generator_projection_sha256": generator_projection_sha256,
            "dataset_evidence_sha256": dataset_evidence_sha256,
            "difficulty": difficulty,
            "upstream_instance_id": upstream_instance_id,
            "fixing_pr_number": fixing_pr_number,
            "evaluator_commitment_nonce": evaluator_commitment_nonce,
            "verification_completed_at": verification_completed_at,
            "base_commit_sha": base_commit_sha,
            "base_root_tree_oid": base_root_tree_oid,
            "source_receipt_sha256": source_receipt_sha256,
            "source_tree_sha256": source_tree_sha256,
            "source_context_algorithm": source_context_algorithm,
            "source_context_policy_sha256": source_context_policy_sha256,
            "source_context_sha256": source_context_sha256,
            "source_special_entries": [asdict(entry) for entry in validated_special_entries],
            "hidden_fixed_root_tree_oid": hidden_fixed_root_tree_oid,
            "fixing_head_commit_sha": fixing_head_commit_sha,
            "fixing_head_root_tree_oid": fixing_head_root_tree_oid,
            "production_patch_sha256": production_patch_sha256,
            "developer_tests_sha256": developer_tests_sha256,
            "dependencies_required": dependencies_required,
            "dependency_receipt_sha256": dependency_receipt_sha256,
            "dependency_plan_sha256": dependency_plan_sha256,
            "dependency_tree_sha256": dependency_tree_sha256,
            "dependency_runner_image_id": dependency_runner_image_id,
            "isolation_receipt_sha256": isolation_receipt_sha256,
            "isolation_policy_sha256": isolation_policy_sha256,
            "reviewer_role_seal_sha256": reviewer_role_seal_sha256,
            "semantic_verification_receipt_sha256": semantic_verification_receipt_sha256,
        }
        for name, value in record.items():
            if name in {
                "algorithm",
                "case",
                "dependencies_required",
                "dependency_receipt_sha256",
                "dependency_plan_sha256",
                "dependency_tree_sha256",
                "dependency_runner_image_id",
                "difficulty",
                "upstream_instance_id",
                "fixing_pr_number",
                "verification_completed_at",
                "source_special_entries",
            }:
                continue
            if name == "source_context_algorithm":
                _require_equal(
                    value,
                    V02_SOURCE_CONTEXT_ALGORITHM,
                    "capability source context algorithm",
                )
                continue
            if name in {
                "base_commit_sha",
                "base_root_tree_oid",
                "hidden_fixed_root_tree_oid",
                "fixing_head_commit_sha",
                "fixing_head_root_tree_oid",
            }:
                _git_sha(value, f"capability {name}")
            else:
                _sha256(value, f"capability {name}")
        _ascii(upstream_instance_id, "capability upstream instance ID", _INSTANCE_ID)
        _difficulty(difficulty)
        _positive_int(fixing_pr_number, "capability fixing PR number")
        _timestamp(verification_completed_at, "capability verification completion")
        if base_root_tree_oid == hidden_fixed_root_tree_oid:
            raise _rejection("Evaluator capability base and hidden-fixed trees are not distinct.")
        _validate_capability_dependencies(
            required=dependencies_required,
            receipt_sha256=dependency_receipt_sha256,
            plan_sha256=dependency_plan_sha256,
            tree_sha256=dependency_tree_sha256,
            runner_image_id=dependency_runner_image_id,
        )
        object.__setattr__(self, "case", case)
        for name, value in record.items():
            if name in {"algorithm", "case", "source_special_entries"}:
                continue
            object.__setattr__(self, name, value)
        object.__setattr__(self, "source_special_entries", validated_special_entries)
        object.__setattr__(
            self,
            "capability_sha256",
            hashlib.sha256(_canonical_json_bytes(record)).hexdigest(),
        )
        object.__setattr__(self, "_issuer", issuer)


def require_v02_evaluator_capability(value: object) -> VerifiedV02EvaluatorCapability:
    """Reject fabricated or corrupted evaluator authorities before causal execution."""

    if type(value) is not VerifiedV02EvaluatorCapability:
        raise _rejection("Evaluator capability type is invalid.")
    capability = value
    try:
        if capability._issuer is not _CAPABILITY_ISSUER:
            raise _rejection("Evaluator capability issuer is invalid.")
        case = _parse_case(asdict(capability.case), "evaluator capability case")
        record = {
            "algorithm": "reproassert-v02-evaluator-capability-v1",
            "case": asdict(case),
            "preregistration_sha256": capability.preregistration_sha256,
            "cohort_sha256": capability.cohort_sha256,
            "preregistered_case_sha256": capability.preregistered_case_sha256,
            "package_identity_sha256": capability.package_identity_sha256,
            "public_commitment_sha256": capability.public_commitment_sha256,
            "generator_projection_sha256": capability.generator_projection_sha256,
            "dataset_evidence_sha256": capability.dataset_evidence_sha256,
            "difficulty": capability.difficulty,
            "upstream_instance_id": capability.upstream_instance_id,
            "fixing_pr_number": capability.fixing_pr_number,
            "evaluator_commitment_nonce": capability.evaluator_commitment_nonce,
            "verification_completed_at": capability.verification_completed_at,
            "base_commit_sha": capability.base_commit_sha,
            "base_root_tree_oid": capability.base_root_tree_oid,
            "source_receipt_sha256": capability.source_receipt_sha256,
            "source_tree_sha256": capability.source_tree_sha256,
            "source_context_algorithm": capability.source_context_algorithm,
            "source_context_policy_sha256": capability.source_context_policy_sha256,
            "source_context_sha256": capability.source_context_sha256,
            "source_special_entries": [
                asdict(entry) for entry in capability.source_special_entries
            ],
            "hidden_fixed_root_tree_oid": capability.hidden_fixed_root_tree_oid,
            "fixing_head_commit_sha": capability.fixing_head_commit_sha,
            "fixing_head_root_tree_oid": capability.fixing_head_root_tree_oid,
            "production_patch_sha256": capability.production_patch_sha256,
            "developer_tests_sha256": capability.developer_tests_sha256,
            "dependencies_required": capability.dependencies_required,
            "dependency_receipt_sha256": capability.dependency_receipt_sha256,
            "dependency_plan_sha256": capability.dependency_plan_sha256,
            "dependency_tree_sha256": capability.dependency_tree_sha256,
            "dependency_runner_image_id": capability.dependency_runner_image_id,
            "isolation_receipt_sha256": capability.isolation_receipt_sha256,
            "isolation_policy_sha256": capability.isolation_policy_sha256,
            "reviewer_role_seal_sha256": capability.reviewer_role_seal_sha256,
            "semantic_verification_receipt_sha256": (
                capability.semantic_verification_receipt_sha256
            ),
        }
        _validate_capability_dependencies(
            required=capability.dependencies_required,
            receipt_sha256=capability.dependency_receipt_sha256,
            plan_sha256=capability.dependency_plan_sha256,
            tree_sha256=capability.dependency_tree_sha256,
            runner_image_id=capability.dependency_runner_image_id,
        )
        if validate_expected_git_special_entries(capability.source_special_entries) != (
            capability.source_special_entries
        ):
            raise _rejection("Evaluator capability special-entry profile is invalid.")
        expected = hashlib.sha256(_canonical_json_bytes(record)).hexdigest()
    except (AttributeError, TypeError, ValueError) as exc:
        raise _rejection("Evaluator capability fields are invalid.") from exc
    if capability.capability_sha256 != expected:
        raise _rejection("Evaluator capability digest is invalid.")
    return capability


def _validate_capability_dependencies(
    *,
    required: object,
    receipt_sha256: object,
    plan_sha256: object,
    tree_sha256: object,
    runner_image_id: object,
) -> None:
    values = (receipt_sha256, plan_sha256, tree_sha256, runner_image_id)
    if not isinstance(required, bool):
        raise _rejection("Evaluator capability dependency mode is invalid.")
    if not required:
        if any(value is not None for value in values):
            raise _rejection("Dependency-free capability contains dependency identities.")
        return
    for value, label in (
        (receipt_sha256, "dependency receipt"),
        (plan_sha256, "dependency plan"),
        (tree_sha256, "dependency tree"),
    ):
        _sha256(value, f"capability {label} SHA-256")
    _ascii(runner_image_id, "capability dependency runner image ID", _IMAGE_ID)


@dataclass(frozen=True)
class _UpstreamRecord:
    instance_id: str
    created_at: str
    production_patch_sha256: str
    developer_tests_sha256: str
    environment_setup_commit: str
    difficulty: str


@dataclass(frozen=True)
class _FixingPullRequestEvidence:
    number: int
    url: str
    created_at: str
    published_at: str
    merged_at: str
    captured_at: str
    target_sha256: str
    fixed_commit_sha: str
    base_root_tree_oid: str
    head_root_tree_oid: str


@dataclass(frozen=True)
class V02SemanticVerification:
    """Canonical external proof summary required before a case can become ready."""

    algorithm: str
    case: V02CaseIdentity
    completed_at: str
    tdd_bench_git_sha: str
    tdd_bench_root_tree_oid: str
    tdd_id_list_path: str
    tdd_id_list_blob_oid: str
    tdd_id_list_sha256: str
    tdd_membership_ordinal: int
    source_dataset_git_sha: str
    source_dataset_root_tree_oid: str
    source_dataset_split: str
    source_dataset_artifact_path: str
    source_dataset_artifact_git_blob_oid: str
    source_dataset_lfs_pointer_sha256: str
    source_dataset_artifact_lfs_sha256: str
    source_dataset_artifact_lfs_bytes: int
    source_dataset_artifact_xet_sha256: str
    source_dataset_artifact_sha256: str
    source_dataset_row_ordinal: int
    source_dataset_row_sha256: str
    source_dataset_transform: str
    dataset_evidence_sha256: str
    source_receipt_sha256: str
    source_base_commit_sha: str
    source_base_root_tree_oid: str
    source_tree_sha256: str
    source_context_algorithm: str
    source_context_policy_sha256: str
    source_context_sha256: str
    production_patch_sha256: str
    developer_tests_sha256: str
    hidden_fixed_root_tree_oid: str
    reconstructed_pr_head_root_tree_oid: str
    fixing_head_commit_sha: str
    fixing_head_root_tree_oid: str
    dependency_receipt_sha256: str
    dependency_case_id: str
    dependency_base_sha: str
    dependency_source_tree_sha256: str
    dependency_environment_setup_commit: str
    dependency_runner_image_id: str
    isolation_receipt_sha256: str
    isolation_policy_sha256: str
    scored_generator_mode: str
    arbitrary_host_command_generator_allowed: bool
    evaluator_paths_exposed: bool
    host_credentials_forwarded: bool
    network_after_dependency_prep: str
    production_isolation_accepted: bool
    reviewer_role_seal_sha256: str
    reviewer_roles_sealed: bool
    semantic_reviewer_ids: tuple[str, ...]
    gold_hidden_until_verdict: bool


@dataclass(frozen=True)
class V02SemanticVerificationContext:
    case: V02CaseIdentity
    package_root: Path
    mapping: FixMappingReceipt
    supporting_inputs: Mapping[str, ArtifactReference]
    generator_projection: ArtifactReference
    isolation_policy_sha256: str


class V02SemanticVerifier(Protocol):
    def verify(self, context: V02SemanticVerificationContext) -> V02SemanticVerification: ...


@dataclass(frozen=True)
class PreregisteredV02Case:
    id: str
    repo: str
    issue_url: str
    base_sha: str
    difficulty: str
    smoke: bool
    generator_projection_sha256: str
    evaluator_commitment_sha256: str
    source_context_sha256: str


@dataclass(frozen=True)
class V02Preregistration:
    path: Path | None
    raw_sha256: str
    frozen_at: str
    cases: tuple[PreregisteredV02Case, ...]
    decoded: Mapping[str, object]


@dataclass(frozen=True)
class V02CohortAudit:
    ready: bool
    expected_case_count: int
    verified_case_count: int
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class V02PublicationScan:
    safe: bool
    scanned_file_count: int
    scanned_bytes: int
    blockers: tuple[str, ...]


def generator_projection_bytes(case: V02CaseIdentity, snapshot: Mapping[str, str]) -> bytes:
    """Return the only case material permitted in the generator trust domain."""

    if set(snapshot) != {"title", "body", "snapshot_sha256"}:
        raise _rejection("Snapshot projection contains controller-only fields.")
    _validate_case(case)
    title = _snapshot_text(snapshot.get("title"), "snapshot title", MAX_TITLE_BYTES, title=True)
    body = _snapshot_text(snapshot.get("body"), "snapshot body", MAX_BODY_BYTES, title=False)
    canonical_snapshot = canonical_snapshot_content_bytes(title=title, body=body)
    if len(canonical_snapshot) > MAX_CANONICAL_BYTES:
        raise _rejection("Canonical snapshot projection exceeds its byte limit.")
    snapshot_sha256 = hashlib.sha256(canonical_snapshot).hexdigest()
    _require_equal(snapshot.get("snapshot_sha256"), snapshot_sha256, "snapshot SHA-256")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "case_id": case.id,
        "repo": case.repo,
        "issue_url": case.issue_url,
        "base_sha": case.base_sha,
        "issue_snapshot": {
            "title": title,
            "body": body,
            "snapshot_sha256": snapshot_sha256,
        },
    }
    return _canonical_json_bytes(payload) + b"\n"


def new_evaluator_commitment_nonce() -> str:
    """Generate the private 32-byte nonce used by a trusted package controller."""

    return secrets.token_hex(32)


def load_fix_mapping_receipt(
    receipt_path: Path,
    *,
    package_root: Path,
    expected_case: V02CaseIdentity,
) -> FixMappingReceipt:
    """Validate an evaluator-only fixing-PR mapping and every referenced artifact."""

    raw, decoded = _load_canonical_json(receipt_path, MAX_JSON_BYTES, "fix mapping receipt")
    root = _exact_object(decoded, _FIX_ROOT_KEYS, "fix mapping receipt")
    _require_equal(root.get("schema_version"), SCHEMA_VERSION, "fix mapping schema version")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")
    case = _parse_case(root.get("case"), "fix mapping case")
    if case != expected_case:
        raise _rejection("Fix mapping case does not match its package identity.")

    provenance = _exact_object(root.get("provenance"), _PROVENANCE_KEYS, "fix provenance")
    _require_equal(
        provenance.get("tdd_bench_repository_url"),
        "https://github.com/IBM/TDD-Bench-Verified",
        "TDD-Bench repository",
    )
    tdd_bench_git_sha = _git_sha(provenance.get("tdd_bench_git_sha"), "TDD-Bench Git SHA")
    tdd_bench_root_tree_oid = _git_sha(
        provenance.get("tdd_bench_root_tree_oid"), "TDD-Bench root tree OID"
    )
    tdd_id_list_path = _relative_path(provenance.get("tdd_id_list_path"), "TDD-Bench id-list")
    _require_equal(tdd_id_list_path, "id_list.txt", "TDD-Bench id-list repository path")
    tdd_id_list_blob_oid = _git_sha(
        provenance.get("tdd_id_list_blob_oid"), "TDD-Bench id-list blob OID"
    )
    tdd_id_list_ref = _load_artifact_reference(
        provenance.get("tdd_id_list"), package_root, "TDD-Bench id list"
    )
    tdd_membership_ordinal = _positive_int(
        provenance.get("tdd_membership_ordinal"), "TDD-Bench membership ordinal"
    )
    _require_equal(
        provenance.get("source_dataset_repository_url"),
        "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified",
        "source dataset repository",
    )
    source_dataset_git_sha = _git_sha(
        provenance.get("source_dataset_git_sha"), "source dataset Git SHA"
    )
    source_dataset_root_tree_oid = _git_sha(
        provenance.get("source_dataset_root_tree_oid"), "source dataset root tree OID"
    )
    source_dataset_split = "test"
    _require_equal(
        provenance.get("source_dataset_split"), source_dataset_split, "source dataset split"
    )
    source_dataset_artifact_path = _relative_path(
        provenance.get("source_dataset_artifact_path"), "source dataset repository artifact"
    )
    _require_equal(
        source_dataset_artifact_path,
        "default/test/0000.parquet",
        "source dataset repository artifact path",
    )
    source_dataset_artifact_git_blob_oid = _git_sha(
        provenance.get("source_dataset_artifact_git_blob_oid"),
        "source dataset artifact Git blob OID",
    )
    source_dataset_lfs_pointer_ref = _load_artifact_reference(
        provenance.get("source_dataset_lfs_pointer"), package_root, "source dataset LFS pointer"
    )
    source_dataset_artifact_lfs_sha256 = _sha256(
        provenance.get("source_dataset_artifact_lfs_sha256"),
        "source dataset artifact LFS SHA-256",
    )
    source_dataset_artifact_lfs_bytes = _positive_int(
        provenance.get("source_dataset_artifact_lfs_bytes"),
        "source dataset artifact LFS byte count",
    )
    source_dataset_artifact_xet_sha256 = _sha256(
        provenance.get("source_dataset_artifact_xet_sha256"),
        "source dataset artifact Xet SHA-256",
    )
    source_dataset_artifact_ref = _load_artifact_reference(
        provenance.get("source_dataset_artifact"), package_root, "source dataset split artifact"
    )
    _verify_lfs_artifact(
        package_root,
        pointer=source_dataset_lfs_pointer_ref,
        artifact=source_dataset_artifact_ref,
        expected_git_blob_oid=source_dataset_artifact_git_blob_oid,
        expected_lfs_sha256=source_dataset_artifact_lfs_sha256,
        expected_lfs_bytes=source_dataset_artifact_lfs_bytes,
    )
    source_dataset_row_ordinal = _nonnegative_int(
        provenance.get("source_dataset_row_ordinal"), "source dataset row ordinal"
    )
    instance_id = _ascii(provenance.get("instance_id"), "upstream instance ID", _INSTANCE_ID)
    _verify_tdd_id_list(
        package_root,
        tdd_id_list_ref,
        expected_blob_oid=tdd_id_list_blob_oid,
        instance_id=instance_id,
        membership_ordinal=tdd_membership_ordinal,
    )
    _require_equal(
        provenance.get("mapping_method"),
        "pinned_tdd_filter_plus_upstream_row_plus_pr_capture_plus_independent_review",
        "mapping method",
    )
    upstream_ref = _load_artifact_reference(
        provenance.get("upstream_record"), package_root, "upstream dataset record"
    )
    fixing_evidence_ref = _load_artifact_reference(
        provenance.get("fixing_pr_evidence"), package_root, "fixing PR evidence"
    )

    artifact_values = _exact_object(
        root.get("evaluator_artifacts"), _EVALUATOR_ARTIFACT_KEYS, "evaluator artifacts"
    )
    artifact_references = {
        name: _load_artifact_reference(
            artifact_values.get(name), package_root, f"evaluator artifact {name}"
        )
        for name in sorted(_EVALUATOR_ARTIFACT_KEYS)
    }
    upstream = _load_upstream_record(
        package_root,
        upstream_ref,
        case=case,
        expected_instance_id=instance_id,
        production_patch=artifact_references["production_patch"],
        developer_tests=artifact_references["developer_tests"],
    )
    evidence = _load_fixing_pr_evidence(
        package_root,
        fixing_evidence_ref,
        case=case,
        expected_instance_id=instance_id,
    )
    _require_equal(upstream.created_at, evidence.created_at, "upstream/fixing PR creation time")

    fixing = _exact_object(root.get("fixing_pull_request"), _FIX_PR_KEYS, "fixing pull request")
    _require_equal(fixing.get("number"), evidence.number, "fixing PR number")
    _require_equal(fixing.get("url"), evidence.url, "fixing PR URL")
    _require_equal(fixing.get("created_at"), evidence.created_at, "fixing PR creation")
    _require_equal(fixing.get("published_at"), evidence.published_at, "fixing PR publication")
    _require_equal(fixing.get("target_sha256"), evidence.target_sha256, "fixing PR target hash")
    _require_equal(fixing.get("fixed_commit_sha"), evidence.fixed_commit_sha, "fixed commit SHA")
    _require_equal(
        fixing.get("base_root_tree_oid"), evidence.base_root_tree_oid, "base root tree OID"
    )
    _require_equal(
        fixing.get("head_root_tree_oid"), evidence.head_root_tree_oid, "head root tree OID"
    )
    _require_equal(
        fixing.get("production_patch_sha256"),
        upstream.production_patch_sha256,
        "production patch SHA-256",
    )
    _require_equal(
        fixing.get("developer_tests_sha256"),
        upstream.developer_tests_sha256,
        "developer tests SHA-256",
    )

    artifacts = [
        tdd_id_list_ref,
        source_dataset_lfs_pointer_ref,
        source_dataset_artifact_ref,
        upstream_ref,
        fixing_evidence_ref,
        *artifact_references.values(),
    ]

    review = _exact_object(root.get("review"), _REVIEW_KEYS, "fix mapping review")
    _require_equal(review.get("status"), "approved", "mapping review status")
    reviewed_at = _timestamp(review.get("reviewed_at"), "mapping review time")
    if _timestamp_datetime(reviewed_at) < max(
        _timestamp_datetime(evidence.merged_at),
        _timestamp_datetime(evidence.captured_at),
    ):
        raise _rejection("Fix mapping review predates the merged evidence capture.")
    reviewer_ids = review.get("reviewer_ids")
    if not isinstance(reviewer_ids, list) or not 2 <= len(reviewer_ids) <= 3:
        raise _rejection("Fix mapping requires two or three independent reviewer IDs.")
    normalized_reviewers = tuple(
        _ascii(value, "mapping reviewer ID", _IDENTIFIER) for value in reviewer_ids
    )
    if normalized_reviewers != tuple(sorted(set(normalized_reviewers))):
        raise _rejection("Mapping reviewer IDs must be unique and sorted.")
    checklist = _load_artifact_reference(
        review.get("checklist"), package_root, "fix mapping review checklist"
    )
    artifacts.append(checklist)
    _require_equal(review.get("mapping_correct"), True, "mapping correctness review")
    _require_equal(review.get("upstream_license_reviewed"), True, "upstream license review")
    _require_equal(review.get("generator_access"), "forbidden", "mapping generator access")
    _validate_tool(root.get("tool"), "fix mapping tool")
    _require_unique_artifact_paths(artifacts, root=package_root)
    if sum(reference.bytes for reference in artifacts) > MAX_TOTAL_PACKAGE_BYTES:
        raise _rejection("Fix mapping artifacts exceed the total package byte limit.")
    return FixMappingReceipt(
        case=case,
        instance_id=instance_id,
        tdd_bench_git_sha=tdd_bench_git_sha,
        tdd_bench_root_tree_oid=tdd_bench_root_tree_oid,
        tdd_id_list_path=tdd_id_list_path,
        tdd_id_list_blob_oid=tdd_id_list_blob_oid,
        tdd_id_list_sha256=tdd_id_list_ref.sha256,
        tdd_membership_ordinal=tdd_membership_ordinal,
        source_dataset_git_sha=source_dataset_git_sha,
        source_dataset_root_tree_oid=source_dataset_root_tree_oid,
        source_dataset_split=source_dataset_split,
        source_dataset_artifact_path=source_dataset_artifact_path,
        source_dataset_artifact_git_blob_oid=source_dataset_artifact_git_blob_oid,
        source_dataset_lfs_pointer_sha256=source_dataset_lfs_pointer_ref.sha256,
        source_dataset_artifact_lfs_sha256=source_dataset_artifact_lfs_sha256,
        source_dataset_artifact_lfs_bytes=source_dataset_artifact_lfs_bytes,
        source_dataset_artifact_xet_sha256=source_dataset_artifact_xet_sha256,
        source_dataset_artifact_sha256=source_dataset_artifact_ref.sha256,
        source_dataset_row_ordinal=source_dataset_row_ordinal,
        upstream_record_sha256=upstream_ref.sha256,
        target_sha256=evidence.target_sha256,
        created_at=evidence.created_at,
        published_at=evidence.published_at,
        merged_at=evidence.merged_at,
        evidence_captured_at=evidence.captured_at,
        reviewed_at=reviewed_at,
        mapping_reviewer_ids=normalized_reviewers,
        fixing_pr_number=evidence.number,
        fixing_pr_url=evidence.url,
        fixed_commit_sha=evidence.fixed_commit_sha,
        base_root_tree_oid=evidence.base_root_tree_oid,
        head_root_tree_oid=evidence.head_root_tree_oid,
        production_patch_sha256=upstream.production_patch_sha256,
        developer_tests_sha256=upstream.developer_tests_sha256,
        environment_setup_commit=upstream.environment_setup_commit,
        difficulty=upstream.difficulty,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        artifacts=tuple(artifacts),
        tdd_id_list=tdd_id_list_ref,
        source_dataset_artifact=source_dataset_artifact_ref,
        source_dataset_lfs_pointer=source_dataset_lfs_pointer_ref,
        upstream_record=upstream_ref,
        fixing_pr_evidence=fixing_evidence_ref,
        production_patch=artifact_references["production_patch"],
        developer_tests=artifact_references["developer_tests"],
    )


def verify_v02_case_package(
    package_path: Path,
    *,
    trusted_semantic_verifier: V02SemanticVerifier | None = None,
) -> VerifiedV02CasePackage:
    """Verify one private package; external causal evidence fails closed by default.

    ``trusted_semantic_verifier`` must be application-selected controller code. It must never be
    loaded from a repository, issue, model output, plugin, or package-controlled executable. This
    public structural path deliberately never issues an L1 evaluator capability; that remains
    blocked until the application-owned source/dependency controller is wired in-process.
    """

    path = Path(package_path)
    package_root = path.parent
    require_private_directory(package_root)
    _require_outside_source_checkout(package_root)
    _, decoded = _load_canonical_json(path, MAX_JSON_BYTES, "v0.2 case package")
    root = _exact_object(decoded, _PACKAGE_ROOT_KEYS, "v0.2 case package")
    _require_equal(root.get("schema_version"), SCHEMA_VERSION, "case package schema version")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")
    case = _parse_case(root.get("case"), "case package identity")

    snapshot = _exact_object(root.get("snapshot"), _SNAPSHOT_KEYS, "snapshot package")
    snapshot_references = {
        name: _load_artifact_reference(snapshot.get(name), package_root, f"snapshot {name}")
        for name in sorted(_SNAPSHOT_KEYS)
    }
    receipt_ref = snapshot_references["receipt"]
    raw_ref = snapshot_references["raw_history"]
    cutoff_ref = snapshot_references["cutoff_basis"]
    receipt_path = package_root / receipt_ref.path
    projection = load_snapshot_receipt(
        receipt_path,
        raw_receipt_path=package_root / raw_ref.path,
        cutoff_basis_path=package_root / cutoff_ref.path,
        expected_case_id=case.id,
        expected_repo=case.repo,
        expected_issue_url=case.issue_url,
        expected_base_sha=case.base_sha,
    )
    _, snapshot_receipt = _load_canonical_json(receipt_path, MAX_JSON_BYTES, "snapshot receipt")
    snapshot_root = _object(snapshot_receipt, "snapshot receipt")
    privacy = _object(snapshot_root.get("privacy_review"), "snapshot privacy review")
    privacy_ref = snapshot_references["privacy_review"]
    _require_equal(
        privacy.get("checklist_sha256"), privacy_ref.sha256, "privacy checklist artifact"
    )
    expected_projection = generator_projection_bytes(case, projection)
    projection_ref = snapshot_references["generator_projection"]
    observed_projection = _read_artifact(package_root, projection_ref, "generator projection")
    if observed_projection != expected_projection:
        raise _rejection("Generator projection is not the exact safe snapshot projection.")

    fix_mapping_object = _exact_object(
        root.get("fix_mapping"), _FIX_MAPPING_KEYS, "fix mapping package"
    )
    mapping_ref = _load_artifact_reference(
        fix_mapping_object.get("receipt"), package_root, "fix mapping receipt"
    )
    mapping = load_fix_mapping_receipt(
        package_root / mapping_ref.path,
        package_root=package_root,
        expected_case=case,
    )
    if mapping.receipt_sha256 != mapping_ref.sha256:
        raise _rejection("Fix mapping receipt changed during package verification.")
    cutoff = _object(snapshot_root.get("cutoff"), "snapshot cutoff")
    redaction = _object(snapshot_root.get("redaction"), "snapshot redaction")
    cutoff_created_at = _snapshot_cutoff_created_at(package_root / cutoff_ref.path)
    _require_equal(cutoff_created_at, mapping.created_at, "snapshot/fix creation time")
    _require_equal(cutoff.get("timestamp"), mapping.published_at, "snapshot/fix cutoff")
    _require_equal(redaction.get("target_sha256"), mapping.target_sha256, "snapshot/fix target")

    supporting = _exact_object(root.get("supporting_inputs"), _SUPPORTING_KEYS, "supporting inputs")
    supporting_references = {
        name: _load_artifact_reference(supporting.get(name), package_root, f"supporting {name}")
        for name in sorted(_SUPPORTING_KEYS)
    }
    isolation = _exact_object(root.get("isolation"), _ISOLATION_KEYS, "package isolation")
    isolation_policy_sha256 = _sha256(isolation.get("policy_sha256"), "isolation policy")
    _require_equal(
        isolation.get("generator_visible_artifacts"),
        ["generator_projection"],
        "generator-visible artifact allowlist",
    )
    _require_equal(
        isolation.get("evaluator_artifacts_mounted_in_generator"),
        False,
        "evaluator mount policy",
    )
    _require_equal(
        isolation.get("network_after_dependency_prep"),
        "disabled",
        "post-preparation network policy",
    )
    if trusted_semantic_verifier is None:
        raise _rejection("A trusted external semantic verifier is required for readiness.")
    verification = trusted_semantic_verifier.verify(
        V02SemanticVerificationContext(
            case=case,
            package_root=package_root,
            mapping=mapping,
            supporting_inputs=supporting_references,
            generator_projection=projection_ref,
            isolation_policy_sha256=isolation_policy_sha256,
        )
    )
    privacy_reviewed_at = _timestamp(privacy.get("reviewed_at"), "privacy review time")
    _validate_semantic_verification(
        verification,
        case=case,
        mapping=mapping,
        supporting=supporting_references,
        isolation_policy_sha256=isolation_policy_sha256,
        privacy_reviewed_at=privacy_reviewed_at,
    )
    semantic_ref = supporting_references["semantic_verification_receipt"]
    observed_semantic_receipt = _read_artifact(
        package_root, semantic_ref, "semantic verification receipt"
    )
    expected_semantic_receipt = _canonical_json_bytes(asdict(verification)) + b"\n"
    if observed_semantic_receipt != expected_semantic_receipt:
        raise _rejection("Semantic verification receipt differs from trusted verifier output.")

    evaluator = _exact_object(
        root.get("evaluator_package"), _EVALUATOR_PACKAGE_KEYS, "evaluator package identity"
    )
    _require_equal(evaluator.get("algorithm"), EVALUATOR_PACKAGE_ALGORITHM, "package algorithm")
    _require_equal(
        evaluator.get("commitment_algorithm"),
        EVALUATOR_COMMITMENT_ALGORITHM,
        "commitment algorithm",
    )
    nonce = _sha256(evaluator.get("commitment_nonce"), "private commitment nonce")
    _require_equal(
        evaluator.get("nonce_generation"),
        "controller_secrets_token_bytes_32",
        "commitment nonce generation",
    )
    tool_identity = _validate_tool(root.get("tool"), "case package tool")
    identity = {
        "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
        "case": asdict(case),
        "snapshot": {name: asdict(value) for name, value in snapshot_references.items()},
        "fix_mapping": asdict(mapping_ref),
        "fix_artifacts": [asdict(value) for value in mapping.artifacts],
        "supporting_inputs": {name: asdict(value) for name, value in supporting_references.items()},
        "isolation_policy_sha256": isolation_policy_sha256,
        "semantic_verification": asdict(verification),
        "tool": tool_identity,
    }
    identity_sha256 = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    _require_equal(evaluator.get("identity_sha256"), identity_sha256, "package identity hash")
    public_commitment = _evaluator_commitment(nonce, identity_sha256)
    _require_equal(
        evaluator.get("public_commitment_sha256"),
        public_commitment,
        "public evaluator commitment",
    )
    all_references = [
        *snapshot_references.values(),
        mapping_ref,
        *mapping.artifacts,
        *supporting_references.values(),
    ]
    _require_unique_artifact_paths(all_references, root=package_root)
    if sum(reference.bytes for reference in all_references) > MAX_TOTAL_PACKAGE_BYTES:
        raise _rejection("Case package artifacts exceed the total byte limit.")
    return VerifiedV02CasePackage(
        case=case,
        generator_projection_sha256=projection_ref.sha256,
        evaluator_package_sha256=identity_sha256,
        evaluator_commitment_sha256=public_commitment,
        snapshot_sha256=projection["snapshot_sha256"],
        difficulty=mapping.difficulty,
        upstream_instance_id=mapping.instance_id,
        fixing_pr_number=mapping.fixing_pr_number,
        fixed_commit_sha=mapping.fixed_commit_sha,
        hidden_fixed_root_tree_oid=verification.hidden_fixed_root_tree_oid,
        evaluator_commitment_nonce=nonce,
        verification_completed_at=verification.completed_at,
        evaluator_capability=None,
    )


def build_v02_preregistration(
    cases: Sequence[PreregisteredV02Case],
    *,
    frozen_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> dict[str, object]:
    """Build the public freeze envelope from controller-supplied commitments.

    This pure encoder does not establish readiness. ``audit_v02_cohort_packages`` must verify all
    private packages with application-selected trusted controller code after the freeze.
    """

    _timestamp(frozen_at, "preregistration freeze time")
    _ascii(tool_name, "tool name", _IDENTIFIER)
    _ascii(tool_version, "tool version", _VERSION)
    _git_sha(tool_git_sha, "tool Git SHA")
    validated = tuple(_validate_preregistered_cases(cases))
    protocol = _protocol_record()
    artifact_contract = _artifact_contract_record()
    case_records = [asdict(case) for case in validated]
    envelope: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_version": BENCHMARK_VERSION,
        "status": "frozen",
        "frozen_at": frozen_at,
        "cohort": {
            "case_count": EXPECTED_CASE_COUNT,
            "selection_method": "preinference_preregistered_feasibility_cohort",
            "preinference_freeze": True,
        },
        "protocol": protocol,
        "artifact_contract": artifact_contract,
        "cases": case_records,
        "tool": {"name": tool_name, "version": tool_version, "git_sha": tool_git_sha},
    }
    envelope["cohort_sha256"] = _preregistration_envelope_sha256(envelope)
    return envelope


def canonical_preregistration_bytes(value: Mapping[str, object]) -> bytes:
    """Encode a preregistration for exclusive persistence by a controller."""

    return _canonical_json_bytes(value) + b"\n"


def load_v02_preregistration(path: Path) -> V02Preregistration:
    """Load and independently verify one frozen public v0.2 preregistration."""

    raw, decoded = _load_canonical_json(path, MAX_JSON_BYTES, "v0.2 preregistration")
    root = _exact_object(decoded, _PREREG_ROOT_KEYS, "v0.2 preregistration")
    _require_equal(root.get("schema_version"), SCHEMA_VERSION, "preregistration schema version")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")
    _require_equal(root.get("status"), "frozen", "preregistration status")
    frozen_at = _timestamp(root.get("frozen_at"), "preregistration freeze time")
    cohort = _exact_object(root.get("cohort"), _COHORT_KEYS, "cohort declaration")
    _require_equal(cohort.get("case_count"), EXPECTED_CASE_COUNT, "cohort case count")
    _require_equal(
        cohort.get("selection_method"),
        "preinference_preregistered_feasibility_cohort",
        "selection method",
    )
    _require_equal(cohort.get("preinference_freeze"), True, "preinference freeze")
    _require_equal(root.get("protocol"), _protocol_record(), "frozen protocol")
    _require_equal(root.get("artifact_contract"), _artifact_contract_record(), "artifact contract")
    case_values = root.get("cases")
    if not isinstance(case_values, list):
        raise _rejection("Preregistration cases must be an array.")
    cases: list[PreregisteredV02Case] = []
    for position, value in enumerate(case_values, start=1):
        case = _exact_object(value, _PREREG_CASE_KEYS, f"preregistered case {position}")
        cases.append(
            PreregisteredV02Case(
                id=_ascii(case.get("id"), "case ID", _CASE_ID),
                repo=_ascii(case.get("repo"), "case repository", _REPOSITORY),
                issue_url=_issue_url(case.get("issue_url"), "case issue URL"),
                base_sha=_git_sha(case.get("base_sha"), "case base SHA"),
                difficulty=_difficulty(case.get("difficulty")),
                smoke=_boolean(case.get("smoke"), "case smoke flag"),
                generator_projection_sha256=_sha256(
                    case.get("generator_projection_sha256"), "generator projection SHA-256"
                ),
                evaluator_commitment_sha256=_sha256(
                    case.get("evaluator_commitment_sha256"), "evaluator commitment SHA-256"
                ),
                source_context_sha256=_sha256(
                    case.get("source_context_sha256"), "source context SHA-256"
                ),
            )
        )
    validated = tuple(_validate_preregistered_cases(cases))
    _validate_tool(root.get("tool"), "preregistration tool")
    expected_cohort_sha256 = _preregistration_envelope_sha256(root)
    _require_equal(root.get("cohort_sha256"), expected_cohort_sha256, "cohort hash")
    return V02Preregistration(
        path=Path(path),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        frozen_at=frozen_at,
        cases=validated,
        decoded=root,
    )


def audit_v02_cohort_packages(
    preregistration_path: Path,
    *,
    packages_root: Path | None = None,
    trusted_semantic_verifier: V02SemanticVerifier | None = None,
    issued_packages: Sequence[VerifiedV02CasePackage] | None = None,
) -> V02CohortAudit:
    """Fail closed unless all 20 private packages match the frozen public commitments.

    The structural path reads packages from ``packages_root`` and remains useful before a freeze.
    The production path accepts only in-memory packages returned by the application-owned semantic
    issuer. Their nominal capabilities cannot be serialized and therefore must cross the all-case
    audit barrier in the same trusted controller process.
    """

    preregistration = load_v02_preregistration(preregistration_path)
    blockers: list[str] = []
    verified_count = 0
    seen_instances: dict[str, str] = {}
    seen_targets: dict[tuple[str, int], str] = {}
    seen_base_fix_pairs: dict[tuple[str, str], str] = {}
    seen_nonces: dict[str, str] = {}
    issued_by_id: dict[str, VerifiedV02CasePackage] | None = None
    if issued_packages is not None:
        if packages_root is not None or trusted_semantic_verifier is not None:
            return V02CohortAudit(
                ready=False,
                expected_case_count=EXPECTED_CASE_COUNT,
                verified_case_count=0,
                blockers=("issued_packages:mixed_audit_modes",),
            )
        issued_by_id = {}
        for package in issued_packages:
            if type(package) is not VerifiedV02CasePackage:
                blockers.append("issued_packages:invalid_package_type")
                continue
            if package.case.id in issued_by_id:
                blockers.append(f"{package.case.id}:issued_package_duplicate")
                continue
            issued_by_id[package.case.id] = package
        frozen_ids = {case.id for case in preregistration.cases}
        for extra in sorted(set(issued_by_id) - frozen_ids):
            blockers.append(f"{extra}:issued_package_not_preregistered")
    else:
        if packages_root is None:
            return V02CohortAudit(
                ready=False,
                expected_case_count=EXPECTED_CASE_COUNT,
                verified_case_count=0,
                blockers=("private_packages_root:missing",),
            )
        try:
            require_private_directory(packages_root)
        except (ReproAssertError, OSError) as exc:
            return V02CohortAudit(
                ready=False,
                expected_case_count=EXPECTED_CASE_COUNT,
                verified_case_count=0,
                blockers=(f"private_packages_root:{_error_code(exc)}",),
            )
    for frozen in preregistration.cases:
        try:
            if issued_by_id is not None:
                issued_package = issued_by_id.get(frozen.id)
                if issued_package is None:
                    raise _rejection("Issued package is missing for a frozen case.")
                package = issued_package
            else:
                package_path = cast(Path, packages_root) / frozen.id / CASE_PACKAGE_FILENAME
                package = verify_v02_case_package(
                    package_path, trusted_semantic_verifier=trusted_semantic_verifier
                )
            if package.case != V02CaseIdentity(
                id=frozen.id,
                repo=frozen.repo,
                issue_url=frozen.issue_url,
                base_sha=frozen.base_sha,
            ):
                raise _rejection("Private package identity differs from preregistration.")
            if package.generator_projection_sha256 != frozen.generator_projection_sha256:
                raise _rejection("Generator projection differs from preregistration.")
            if package.evaluator_commitment_sha256 != frozen.evaluator_commitment_sha256:
                raise _rejection("Evaluator commitment differs from preregistration.")
            if package.difficulty != frozen.difficulty:
                raise _rejection("Private package difficulty differs from preregistration.")
            capability = package.evaluator_capability
            if capability is None:
                raise _rejection("Private package lacks a nominal evaluator capability.")
            capability = require_v02_evaluator_capability(capability)
            _require_equal(capability.case, package.case, "evaluator capability case")
            _require_equal(
                capability.preregistration_sha256,
                preregistration.raw_sha256,
                "evaluator capability preregistration",
            )
            _require_equal(
                capability.cohort_sha256,
                preregistration.decoded["cohort_sha256"],
                "evaluator capability cohort",
            )
            _require_equal(
                capability.preregistered_case_sha256,
                hashlib.sha256(_canonical_json_bytes(asdict(frozen))).hexdigest(),
                "evaluator capability frozen case",
            )
            _require_equal(
                capability.generator_projection_sha256,
                frozen.generator_projection_sha256,
                "evaluator capability generator projection",
            )
            _require_equal(
                capability.base_commit_sha,
                frozen.base_sha,
                "evaluator capability base commit",
            )
            _require_equal(
                capability.package_identity_sha256,
                package.evaluator_package_sha256,
                "evaluator capability package identity",
            )
            _require_equal(
                capability.public_commitment_sha256,
                package.evaluator_commitment_sha256,
                "evaluator capability public commitment",
            )
            _require_equal(
                capability.difficulty,
                package.difficulty,
                "evaluator capability difficulty",
            )
            _require_equal(
                capability.upstream_instance_id,
                package.upstream_instance_id,
                "evaluator capability upstream instance",
            )
            _require_equal(
                capability.fixing_pr_number,
                package.fixing_pr_number,
                "evaluator capability fixing PR number",
            )
            _require_equal(
                capability.evaluator_commitment_nonce,
                package.evaluator_commitment_nonce,
                "evaluator capability commitment nonce",
            )
            _require_equal(
                capability.verification_completed_at,
                package.verification_completed_at,
                "evaluator capability verification completion",
            )
            _require_equal(
                capability.hidden_fixed_root_tree_oid,
                package.hidden_fixed_root_tree_oid,
                "evaluator capability hidden fixed tree",
            )
            _require_equal(
                capability.source_context_sha256,
                frozen.source_context_sha256,
                "evaluator capability source context",
            )
            _require_equal(
                capability.fixing_head_commit_sha,
                package.fixed_commit_sha,
                "evaluator capability fixing head",
            )
            if _timestamp_datetime(package.verification_completed_at) > _timestamp_datetime(
                preregistration.frozen_at
            ):
                raise _rejection("Case verification completed after the cohort freeze.")
        except (ReproAssertError, OSError, ValueError) as exc:
            blockers.append(f"{frozen.id}:{_error_code(exc)}")
            continue
        verified_count += 1
        _record_private_unique(
            seen_instances,
            package.upstream_instance_id,
            frozen.id,
            "upstream_instance_duplicate",
            blockers,
        )
        _record_private_unique(
            seen_targets,
            (package.case.repo, package.fixing_pr_number),
            frozen.id,
            "fixing_target_duplicate",
            blockers,
        )
        _record_private_unique(
            seen_base_fix_pairs,
            (package.case.base_sha, package.hidden_fixed_root_tree_oid),
            frozen.id,
            "base_fix_pair_duplicate",
            blockers,
        )
        _record_private_unique(
            seen_nonces,
            package.evaluator_commitment_nonce,
            frozen.id,
            "commitment_nonce_reused",
            blockers,
        )
    return V02CohortAudit(
        ready=not blockers and verified_count == EXPECTED_CASE_COUNT,
        expected_case_count=EXPECTED_CASE_COUNT,
        verified_case_count=verified_count,
        blockers=tuple(blockers),
    )


def scan_v02_publication_tree(
    public_root: Path, *, private_package_paths: Sequence[Path]
) -> V02PublicationScan:
    """Fail closed if evaluator-only material appears in a publication tree."""

    root = Path(public_root).resolve(strict=True)
    if not root.is_dir():
        raise _rejection("Publication scan root must be a directory.")
    secrets_to_find: list[tuple[str, bytes]] = []
    exact_private_artifacts: dict[str, list[str]] = {}

    def register_secret(label: str, value: str | bytes) -> None:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        if encoded:
            secrets_to_find.append((label, encoded))

    def register_private_artifact(
        package_root: Path,
        reference: ArtifactReference,
        *,
        label: str,
        substring_sensitive: bool = False,
    ) -> None:
        content = _read_artifact(package_root, reference, label)
        exact_private_artifacts.setdefault(reference.sha256, []).append(label)
        register_secret(f"{label}:sha256", reference.sha256)
        register_secret(f"{label}:path", reference.path)
        if substring_sensitive:
            register_secret(label, content)

    for package_path in private_package_paths:
        path = Path(package_path)
        package_root = path.parent
        require_private_directory(package_root)
        _require_outside_source_checkout(package_root)
        if (
            root == package_root.resolve(strict=True)
            or root in package_root.resolve(strict=True).parents
        ):
            raise _rejection("Private evaluator package is inside the publication tree.")
        package_raw, decoded = _load_canonical_json(path, MAX_JSON_BYTES, "v0.2 case package")
        package = _exact_object(decoded, _PACKAGE_ROOT_KEYS, "v0.2 case package")
        case = _parse_case(package.get("case"), "case package identity")
        package_label = f"{case.id}:case-package"
        package_sha256 = hashlib.sha256(package_raw).hexdigest()
        exact_private_artifacts.setdefault(package_sha256, []).append(package_label)
        register_secret(f"{package_label}:sha256", package_sha256)

        snapshot = _exact_object(package.get("snapshot"), _SNAPSHOT_KEYS, "snapshot package")
        snapshot_references = {
            name: _load_artifact_reference(snapshot.get(name), package_root, f"snapshot {name}")
            for name in sorted(_SNAPSHOT_KEYS)
        }
        for name, reference in snapshot_references.items():
            if name != "generator_projection":
                register_private_artifact(
                    package_root,
                    reference,
                    label=f"{case.id}:snapshot:{name}",
                )

        fix_package = _exact_object(
            package.get("fix_mapping"), _FIX_MAPPING_KEYS, "fix mapping package"
        )
        mapping_ref = _load_artifact_reference(
            fix_package.get("receipt"), package_root, "fix mapping receipt"
        )
        mapping = load_fix_mapping_receipt(
            package_root / mapping_ref.path,
            package_root=package_root,
            expected_case=case,
        )
        register_private_artifact(
            package_root,
            mapping_ref,
            label=f"{case.id}:fix-mapping",
        )
        sensitive_artifact_roles = {
            mapping.production_patch.path: "production_patch",
            mapping.developer_tests.path: "developer_tests",
        }
        for reference in mapping.artifacts:
            artifact_role = sensitive_artifact_roles.get(
                reference.path, f"fix-artifact:{reference.path}"
            )
            register_private_artifact(
                package_root,
                reference,
                label=f"{case.id}:{artifact_role}",
                substring_sensitive=reference.path in sensitive_artifact_roles,
            )

        supporting = _exact_object(
            package.get("supporting_inputs"), _SUPPORTING_KEYS, "supporting inputs"
        )
        supporting_references = {
            name: _load_artifact_reference(supporting.get(name), package_root, f"supporting {name}")
            for name in sorted(_SUPPORTING_KEYS)
        }
        for name, reference in supporting_references.items():
            register_private_artifact(
                package_root,
                reference,
                label=f"{case.id}:supporting:{name}",
            )

        evaluator = _exact_object(
            package.get("evaluator_package"), _EVALUATOR_PACKAGE_KEYS, "evaluator package identity"
        )
        nonce = _sha256(evaluator.get("commitment_nonce"), "private commitment nonce")
        identity_sha256 = _sha256(evaluator.get("identity_sha256"), "private package identity")
        for label, value in (
            ("fixing_url", mapping.fixing_pr_url),
            ("fixing_target", mapping.target_sha256),
            ("fixed_commit", mapping.fixed_commit_sha),
            ("base_root_tree", mapping.base_root_tree_oid),
            ("head_root_tree", mapping.head_root_tree_oid),
            ("production_patch_sha256", mapping.production_patch_sha256),
            ("developer_tests_sha256", mapping.developer_tests_sha256),
            ("upstream_instance", mapping.instance_id),
            ("fix_mapping_receipt_sha256", mapping.receipt_sha256),
            ("commitment_nonce", nonce),
            ("package_identity_sha256", identity_sha256),
        ):
            register_secret(f"{case.id}:{label}", value)
        for reviewer_id in mapping.mapping_reviewer_ids:
            register_secret(f"{case.id}:mapping_reviewer", reviewer_id)

        semantic_ref = supporting_references["semantic_verification_receipt"]
        _, semantic_decoded = _load_canonical_json(
            package_root / semantic_ref.path,
            MAX_ARTIFACT_BYTES,
            "semantic verification receipt",
        )
        semantic = _exact_object(
            semantic_decoded,
            set(V02SemanticVerification.__dataclass_fields__),
            "semantic verification receipt",
        )
        for field_name in (
            "source_base_root_tree_oid",
            "source_tree_sha256",
            "hidden_fixed_root_tree_oid",
            "reconstructed_pr_head_root_tree_oid",
            "fixing_head_commit_sha",
            "fixing_head_root_tree_oid",
            "dependency_receipt_sha256",
            "dependency_source_tree_sha256",
            "dependency_runner_image_id",
            "isolation_receipt_sha256",
            "isolation_policy_sha256",
            "reviewer_role_seal_sha256",
        ):
            semantic_value = semantic.get(field_name)
            if isinstance(semantic_value, str) and semantic_value:
                register_secret(f"{case.id}:semantic:{field_name}", semantic_value)
        reviewer_ids = semantic.get("semantic_reviewer_ids")
        if isinstance(reviewer_ids, list):
            for reviewer_id in reviewer_ids:
                if isinstance(reviewer_id, str) and reviewer_id:
                    register_secret(f"{case.id}:semantic_reviewer", reviewer_id)

    blockers: list[str] = []
    scanned_files = 0
    scanned_bytes = 0
    scanned_entries = 0

    def scan_name(relative: str, *, location: str) -> None:
        encoded = unicodedata.normalize("NFC", relative).encode("utf-8")
        for label, secret in secrets_to_find:
            if secret and secret in encoded:
                blockers.append(f"{relative}:{location}:{label}")

    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        traversable_names: list[str] = []
        for name in sorted(names):
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            scanned_entries += 1
            if scanned_entries > 40_000:
                raise _rejection("Publication scan exceeds its entry-count limit.")
            scan_name(relative, location="path")
            try:
                mode = path.lstat().st_mode
            except OSError:
                blockers.append(f"unscannable:{relative}")
                continue
            if stat.S_ISLNK(mode):
                blockers.append(f"symlink:{relative}")
                try:
                    target = os.readlink(path)
                except OSError:
                    blockers.append(f"unscannable-symlink-target:{relative}")
                else:
                    scan_name(target, location="symlink-target")
                continue
            if not stat.S_ISDIR(mode):
                blockers.append(f"special-entry:{relative}")
                continue
            if name == ".git":
                continue
            if name in {".venv", "__pycache__", ".pytest_cache", ".mypy_cache"}:
                blockers.append(f"excluded-directory:{relative}")
                continue
            traversable_names.append(name)
        names[:] = traversable_names
        for filename in sorted(filenames):
            path = directory_path / filename
            relative = path.relative_to(root).as_posix()
            scanned_entries += 1
            if scanned_entries > 40_000:
                raise _rejection("Publication scan exceeds its entry-count limit.")
            scanned_files += 1
            if scanned_files > 20_000:
                raise _rejection("Publication scan exceeds its file-count limit.")
            scan_name(relative, location="path")
            try:
                mode = path.lstat().st_mode
            except OSError:
                blockers.append(f"unscannable:{relative}")
                continue
            if stat.S_ISLNK(mode):
                blockers.append(f"symlink:{relative}")
                try:
                    target = os.readlink(path)
                except OSError:
                    blockers.append(f"unscannable-symlink-target:{relative}")
                else:
                    scan_name(target, location="symlink-target")
                continue
            if not stat.S_ISREG(mode):
                blockers.append(f"special-entry:{relative}")
                continue
            try:
                content = _read_bounded_regular(path, MAX_ARTIFACT_BYTES, "publication file")
            except (OSError, ReproAssertError):
                blockers.append(f"unscannable:{relative}")
                continue
            scanned_bytes += len(content)
            if scanned_bytes > 512 * 1024 * 1024:
                raise _rejection("Publication scan exceeds its total-byte limit.")
            content_sha256 = hashlib.sha256(content).hexdigest()
            for label in exact_private_artifacts.get(content_sha256, ()):
                blockers.append(f"{relative}:exact-private-artifact:{label}")
            for label, secret in secrets_to_find:
                if secret and secret in content:
                    blockers.append(f"{relative}:{label}")
    return V02PublicationScan(
        safe=not blockers,
        scanned_file_count=scanned_files,
        scanned_bytes=scanned_bytes,
        blockers=tuple(blockers),
    )


def _validate_preregistered_cases(
    cases: Sequence[PreregisteredV02Case],
) -> list[PreregisteredV02Case]:
    if len(cases) != EXPECTED_CASE_COUNT:
        raise _rejection(f"A frozen v0.2 cohort requires exactly {EXPECTED_CASE_COUNT} cases.")
    expected_ids = tuple(f"rk-v0.2-{index:03d}" for index in range(1, EXPECTED_CASE_COUNT + 1))
    actual_ids = tuple(case.id for case in cases)
    if actual_ids != expected_ids:
        raise _rejection("Preregistered cases must use the complete sorted neutral ID sequence.")
    seen_urls: set[str] = set()
    for case in cases:
        identity = V02CaseIdentity(case.id, case.repo, case.issue_url, case.base_sha)
        _validate_case(identity)
        _difficulty(case.difficulty)
        if not isinstance(case.smoke, bool):
            raise _rejection("Case smoke flag must be boolean.")
        _sha256(case.generator_projection_sha256, "generator projection SHA-256")
        _sha256(case.evaluator_commitment_sha256, "evaluator commitment SHA-256")
        _sha256(case.source_context_sha256, "source context SHA-256")
        if case.issue_url in seen_urls:
            raise _rejection("Preregistration repeats an issue URL.")
        seen_urls.add(case.issue_url)
    smoke_ids = tuple(case.id for case in cases if case.smoke)
    if len(smoke_ids) != EXPECTED_SMOKE_COUNT or smoke_ids != EXPECTED_SMOKE_CASE_IDS:
        raise _rejection("The frozen cohort smoke subset does not match its exact predeclared IDs.")
    difficulty_counts = {
        difficulty: sum(case.difficulty == difficulty for case in cases)
        for difficulty in _UPSTREAM_DIFFICULTIES.values()
    }
    if difficulty_counts != {"lt_15m": 14, "15m_to_1h": 6}:
        raise _rejection("The frozen cohort requires the preregistered 14/6 difficulty split.")
    if len({case.repo for case in cases}) != 10:
        raise _rejection("The frozen cohort requires exactly ten repositories.")
    return list(cases)


def _protocol_record() -> dict[str, object]:
    return {
        "cutoff": "pre_solution_pr_publication",
        "comments_included": False,
        "generator_visible_fields": [
            "repo",
            "issue_url",
            "base_sha",
            "issue_snapshot",
            "verified_source_context",
        ],
        "evaluator_only_fields": [
            "raw_issue_history",
            "fixing_pull_request",
            "fixed_commit_and_production_patch",
            "developer_tests",
            "oracle_rubric",
            "causal_controls",
            "reviewer_packet",
        ],
        "submitted_candidates_per_case": 1,
        "candidate_selection_uses_oracle": False,
        "semantic_valid_minimum": 6,
        "semantic_valid_denominator": 20,
    }


def _artifact_contract_record() -> dict[str, str]:
    return {
        "issue_history_query_sha256": ISSUE_HISTORY_QUERY_SHA256,
        "solution_cutoff_query_sha256": SOLUTION_CUTOFF_QUERY_SHA256,
        "fixing_pr_identity_query_sha256": FIXING_PR_IDENTITY_QUERY_SHA256,
        "redaction_policy_sha256": REDACTION_POLICY_SHA256,
        "generator_projection_algorithm": GENERATOR_PROJECTION_ALGORITHM,
        "evaluator_package_algorithm": EVALUATOR_PACKAGE_ALGORITHM,
        "evaluator_commitment_algorithm": EVALUATOR_COMMITMENT_ALGORITHM,
        "semantic_verification_algorithm": SEMANTIC_VERIFICATION_ALGORITHM,
        "source_dataset_transform": SOURCE_DATASET_TRANSFORM,
        "source_context_algorithm": V02_SOURCE_CONTEXT_ALGORITHM,
        "source_context_policy_sha256": V02_SOURCE_CONTEXT_POLICY_SHA256,
    }


def _preregistration_envelope_sha256(value: Mapping[str, object]) -> str:
    envelope = {key: item for key, item in value.items() if key != "cohort_sha256"}
    return hashlib.sha256(_canonical_json_bytes(envelope)).hexdigest()


def _evaluator_commitment(nonce: str, identity_sha256: str) -> str:
    return hashlib.sha256(
        EVALUATOR_COMMITMENT_ALGORITHM.encode("ascii")
        + b"\0"
        + bytes.fromhex(nonce)
        + b"\0"
        + bytes.fromhex(identity_sha256)
    ).hexdigest()


def _load_upstream_record(
    root: Path,
    reference: ArtifactReference,
    *,
    case: V02CaseIdentity,
    expected_instance_id: str,
    production_patch: ArtifactReference,
    developer_tests: ArtifactReference,
) -> _UpstreamRecord:
    _, decoded = _load_canonical_json(
        root / reference.path, MAX_ARTIFACT_BYTES, "upstream dataset record"
    )
    record = _exact_object(decoded, _UPSTREAM_RECORD_KEYS, "upstream dataset record")
    _require_equal(record.get("repo"), case.repo, "upstream repository")
    instance_id = _ascii(record.get("instance_id"), "upstream instance ID", _INSTANCE_ID)
    _require_equal(instance_id, expected_instance_id, "upstream instance ID")
    _require_equal(record.get("base_commit"), case.base_sha, "upstream base commit")
    production_patch_bytes = _utf8_field(
        record.get("patch"), "upstream production patch", allow_empty=False
    )
    developer_tests_bytes = _utf8_field(
        record.get("test_patch"), "upstream developer tests", allow_empty=False
    )
    _utf8_field(record.get("problem_statement"), "upstream problem statement", allow_empty=False)
    _utf8_field(record.get("hints_text"), "upstream hints", allow_empty=True)
    created_at = _timestamp(record.get("created_at"), "upstream PR creation time")
    version = record.get("version")
    if not isinstance(version, str) or not version or len(version.encode("utf-8")) > 256:
        raise _rejection("Upstream environment version is invalid.")
    environment_setup_commit = _git_sha(
        record.get("environment_setup_commit"), "upstream environment setup commit"
    )
    upstream_difficulty = record.get("difficulty")
    if (
        not isinstance(upstream_difficulty, str)
        or upstream_difficulty not in _UPSTREAM_DIFFICULTIES
    ):
        raise _rejection("Upstream difficulty is outside the frozen feasibility cohort.")
    observed_production_patch = _read_artifact(root, production_patch, "production patch")
    observed_developer_tests = _read_artifact(root, developer_tests, "developer tests")
    if observed_production_patch != production_patch_bytes:
        raise _rejection("Production patch does not equal the pinned upstream dataset row.")
    if observed_developer_tests != developer_tests_bytes:
        raise _rejection("Developer tests do not equal the pinned upstream dataset row.")
    return _UpstreamRecord(
        instance_id=instance_id,
        created_at=created_at,
        production_patch_sha256=hashlib.sha256(production_patch_bytes).hexdigest(),
        developer_tests_sha256=hashlib.sha256(developer_tests_bytes).hexdigest(),
        environment_setup_commit=environment_setup_commit,
        difficulty=_UPSTREAM_DIFFICULTIES[upstream_difficulty],
    )


def _load_fixing_pr_evidence(
    root: Path,
    reference: ArtifactReference,
    *,
    case: V02CaseIdentity,
    expected_instance_id: str,
) -> _FixingPullRequestEvidence:
    _, decoded = _load_canonical_json(
        root / reference.path, MAX_ARTIFACT_BYTES, "fixing PR evidence"
    )
    artifact = _exact_object(decoded, _FIXING_GRAPHQL_ARTIFACT_KEYS, "fixing PR evidence")
    _require_equal(artifact.get("format"), GRAPHQL_CAPTURE_FORMAT, "fixing PR evidence format")
    _require_equal(
        artifact.get("query_sha256"),
        FIXING_PR_IDENTITY_QUERY_SHA256,
        "fixing PR evidence query",
    )
    captured_at = _timestamp(artifact.get("captured_at"), "fixing PR evidence capture time")
    response = _exact_object(artifact.get("response"), _GRAPHQL_RESPONSE_KEYS, "fixing PR response")
    data = _exact_object(response.get("data"), _GRAPHQL_DATA_KEYS, "fixing PR response data")
    repository = _exact_object(
        data.get("repository"), _PR_EVIDENCE_REPOSITORY_KEYS, "fixing PR repository"
    )
    _require_equal(repository.get("nameWithOwner"), case.repo, "fixing PR repository")
    base_commit = _exact_object(repository.get("baseCommit"), _COMMIT_KEYS, "fixing PR base commit")
    _require_equal(base_commit.get("oid"), case.base_sha, "fixing PR base commit OID")
    base_tree = _exact_object(base_commit.get("tree"), _TREE_KEYS, "fixing PR base tree")
    base_root_tree_oid = _git_sha(base_tree.get("oid"), "fixing PR base root tree OID")
    pull = _exact_object(repository.get("pullRequest"), _PR_EVIDENCE_KEYS, "fixing PR evidence")
    number = _positive_int(pull.get("number"), "fixing PR number")
    expected_url = f"https://github.com/{case.repo}/pull/{number}"
    _require_equal(pull.get("url"), expected_url, "fixing PR URL")
    _require_equal(
        expected_instance_id,
        f"{case.repo.replace('/', '__')}-{number}",
        "fixing PR/upstream instance mapping",
    )
    base_repository = _exact_object(
        pull.get("baseRepository"), _BASE_REPOSITORY_KEYS, "fixing PR base repository"
    )
    _require_equal(base_repository.get("nameWithOwner"), case.repo, "fixing PR base repository")
    _require_equal(pull.get("isDraft"), False, "fixing PR draft status")
    created_at = _timestamp(pull.get("createdAt"), "fixing PR creation time")
    published_at = _timestamp(pull.get("publishedAt"), "fixing PR publication time")
    merged_at = _timestamp(pull.get("mergedAt"), "fixing PR merge time")
    if not (
        _timestamp_datetime(created_at)
        <= _timestamp_datetime(published_at)
        <= _timestamp_datetime(merged_at)
    ):
        raise _rejection("Fixing PR creation, publication, and merge times are inconsistent.")
    if _timestamp_datetime(captured_at) < _timestamp_datetime(merged_at):
        raise _rejection("Fixing PR evidence was captured before merge.")
    fixed_commit_sha = _git_sha(pull.get("headRefOid"), "fixing PR head commit")
    commits = _exact_object(pull.get("commits"), _COMMITS_KEYS, "fixing PR commits")
    if _positive_int(commits.get("totalCount"), "fixing PR commit count") < 1:
        raise _rejection("Fixing PR has no commits.")
    commit_nodes = commits.get("nodes")
    if not isinstance(commit_nodes, list) or len(commit_nodes) != 1:
        raise _rejection("Fixing PR head commit capture must contain exactly one node.")
    node = _exact_object(commit_nodes[0], _COMMIT_NODE_KEYS, "fixing PR head commit node")
    head_commit = _exact_object(node.get("commit"), _COMMIT_KEYS, "fixing PR head commit")
    _require_equal(head_commit.get("oid"), fixed_commit_sha, "fixing PR head commit OID")
    head_tree = _exact_object(head_commit.get("tree"), _TREE_KEYS, "fixing PR head tree")
    head_root_tree_oid = _git_sha(head_tree.get("oid"), "fixing PR head root tree OID")
    target = {"number": number, "repository": case.repo, "url": expected_url}
    return _FixingPullRequestEvidence(
        number=number,
        url=expected_url,
        created_at=created_at,
        published_at=published_at,
        merged_at=merged_at,
        captured_at=captured_at,
        target_sha256=hashlib.sha256(_canonical_json_bytes(target)).hexdigest(),
        fixed_commit_sha=fixed_commit_sha,
        base_root_tree_oid=base_root_tree_oid,
        head_root_tree_oid=head_root_tree_oid,
    )


def _snapshot_cutoff_created_at(path: Path) -> str:
    _, decoded = _load_canonical_json(path, MAX_ARTIFACT_BYTES, "snapshot cutoff basis")
    response = _object(decoded.get("response"), "snapshot cutoff response")
    data = _object(response.get("data"), "snapshot cutoff data")
    repository = _object(data.get("repository"), "snapshot cutoff repository")
    pull = _object(repository.get("pullRequest"), "snapshot cutoff pull request")
    return _timestamp(pull.get("createdAt"), "snapshot cutoff PR creation time")


def _validate_semantic_verification(
    value: V02SemanticVerification,
    *,
    case: V02CaseIdentity,
    mapping: FixMappingReceipt,
    supporting: Mapping[str, ArtifactReference],
    isolation_policy_sha256: str,
    privacy_reviewed_at: str,
) -> None:
    if not isinstance(value, V02SemanticVerification):
        raise _rejection("Trusted semantic verifier returned an unsupported result type.")
    _require_equal(
        value.algorithm,
        SEMANTIC_VERIFICATION_ALGORITHM,
        "semantic verification algorithm",
    )
    _require_equal(value.case, case, "semantic verification case")
    completed_at = _timestamp(value.completed_at, "semantic verification completion time")
    if _timestamp_datetime(completed_at) < max(
        _timestamp_datetime(mapping.reviewed_at),
        _timestamp_datetime(mapping.evidence_captured_at),
        _timestamp_datetime(privacy_reviewed_at),
    ):
        raise _rejection("Semantic verification predates required evidence and reviews.")

    expected_dataset = (
        mapping.tdd_bench_git_sha,
        mapping.tdd_bench_root_tree_oid,
        mapping.tdd_id_list_path,
        mapping.tdd_id_list_blob_oid,
        mapping.tdd_id_list_sha256,
        mapping.tdd_membership_ordinal,
        mapping.source_dataset_git_sha,
        mapping.source_dataset_root_tree_oid,
        mapping.source_dataset_split,
        mapping.source_dataset_artifact_path,
        mapping.source_dataset_artifact_git_blob_oid,
        mapping.source_dataset_lfs_pointer_sha256,
        mapping.source_dataset_artifact_lfs_sha256,
        mapping.source_dataset_artifact_lfs_bytes,
        mapping.source_dataset_artifact_xet_sha256,
        mapping.source_dataset_artifact_sha256,
        mapping.source_dataset_row_ordinal,
        mapping.upstream_record_sha256,
    )
    observed_dataset = (
        value.tdd_bench_git_sha,
        value.tdd_bench_root_tree_oid,
        value.tdd_id_list_path,
        value.tdd_id_list_blob_oid,
        value.tdd_id_list_sha256,
        value.tdd_membership_ordinal,
        value.source_dataset_git_sha,
        value.source_dataset_root_tree_oid,
        value.source_dataset_split,
        value.source_dataset_artifact_path,
        value.source_dataset_artifact_git_blob_oid,
        value.source_dataset_lfs_pointer_sha256,
        value.source_dataset_artifact_lfs_sha256,
        value.source_dataset_artifact_lfs_bytes,
        value.source_dataset_artifact_xet_sha256,
        value.source_dataset_artifact_sha256,
        value.source_dataset_row_ordinal,
        value.source_dataset_row_sha256,
    )
    _require_equal(observed_dataset, expected_dataset, "dataset membership verification")
    _require_equal(
        value.source_dataset_transform,
        SOURCE_DATASET_TRANSFORM,
        "source dataset transform",
    )
    _sha256(value.dataset_evidence_sha256, "verified dataset evidence SHA-256")

    _require_equal(
        value.source_receipt_sha256,
        supporting["source_receipt"].sha256,
        "source receipt verification",
    )
    _require_equal(value.source_base_commit_sha, case.base_sha, "verified source base commit")
    _require_equal(
        value.source_base_root_tree_oid,
        mapping.base_root_tree_oid,
        "verified source base root tree",
    )
    _sha256(value.source_tree_sha256, "verified source tree SHA-256")
    _ascii(value.source_context_algorithm, "verified source context algorithm", _IDENTIFIER)
    _sha256(value.source_context_policy_sha256, "verified source context policy SHA-256")
    _sha256(value.source_context_sha256, "verified source context SHA-256")
    _require_equal(
        value.production_patch_sha256,
        mapping.production_patch_sha256,
        "verified production patch",
    )
    _require_equal(
        value.developer_tests_sha256,
        mapping.developer_tests_sha256,
        "verified developer tests",
    )
    hidden_fixed_root = _git_sha(
        value.hidden_fixed_root_tree_oid, "hidden fixed evaluator root tree OID"
    )
    if hidden_fixed_root == mapping.base_root_tree_oid:
        raise _rejection("Production patch did not change the hidden fixed tree.")
    _require_equal(
        value.reconstructed_pr_head_root_tree_oid,
        mapping.head_root_tree_oid,
        "reconstructed full PR root tree",
    )
    _require_equal(
        value.fixing_head_commit_sha, mapping.fixed_commit_sha, "verified fixing head commit"
    )
    _require_equal(
        value.fixing_head_root_tree_oid,
        mapping.head_root_tree_oid,
        "verified fixing head root tree",
    )

    _require_equal(
        value.dependency_receipt_sha256,
        supporting["dependency_receipt"].sha256,
        "dependency receipt verification",
    )
    _require_equal(value.dependency_case_id, case.id, "dependency case")
    _require_equal(value.dependency_base_sha, case.base_sha, "dependency base SHA")
    _require_equal(
        value.dependency_source_tree_sha256,
        value.source_tree_sha256,
        "dependency/source tree",
    )
    _require_equal(
        value.dependency_environment_setup_commit,
        mapping.environment_setup_commit,
        "dependency environment setup revision",
    )
    _ascii(value.dependency_runner_image_id, "dependency runner image ID", _IMAGE_ID)

    _require_equal(
        value.isolation_receipt_sha256,
        supporting["isolation_canary_receipt"].sha256,
        "production isolation receipt",
    )
    _require_equal(value.isolation_policy_sha256, isolation_policy_sha256, "isolation policy")
    if value.scored_generator_mode not in {
        "trusted_builtin_provider_adapter",
        "sandboxed_generator_process",
    }:
        raise _rejection("Scored generator mode does not establish a production trust boundary.")
    _require_equal(
        value.arbitrary_host_command_generator_allowed,
        False,
        "arbitrary host command generator policy",
    )
    _require_equal(value.evaluator_paths_exposed, False, "evaluator path exposure")
    _require_equal(value.host_credentials_forwarded, False, "host credential forwarding")
    _require_equal(
        value.network_after_dependency_prep, "disabled", "post-preparation generator network"
    )
    _require_equal(
        value.production_isolation_accepted, True, "production generator isolation verification"
    )

    _require_equal(
        value.reviewer_role_seal_sha256,
        supporting["reviewer_role_seal"].sha256,
        "reviewer role seal",
    )
    _require_equal(value.reviewer_roles_sealed, True, "reviewer role status")
    reviewer_ids = tuple(
        _ascii(item, "semantic reviewer ID", _IDENTIFIER) for item in value.semantic_reviewer_ids
    )
    if not 2 <= len(reviewer_ids) <= 3 or reviewer_ids != tuple(sorted(set(reviewer_ids))):
        raise _rejection("Semantic reviewer IDs must contain two or three sorted unique values.")
    if set(reviewer_ids) & set(mapping.mapping_reviewer_ids):
        raise _rejection("Mapping and semantic reviewer roles are not independent.")
    _require_equal(value.gold_hidden_until_verdict, True, "semantic review gold isolation")


def _verify_tdd_id_list(
    root: Path,
    reference: ArtifactReference,
    *,
    expected_blob_oid: str,
    instance_id: str,
    membership_ordinal: int,
) -> None:
    content = _read_artifact(root, reference, "TDD-Bench id list")
    if (
        hashlib.sha1(f"blob {len(content)}\0".encode() + content, usedforsecurity=False).hexdigest()
        != expected_blob_oid
    ):
        raise _rejection("TDD-Bench id-list bytes do not match their Git blob OID.")
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _rejection("TDD-Bench id list is not ASCII.") from exc
    # The pinned upstream object is CRLF-delimited and intentionally has no final newline.
    # Hash/OID verification above is over those exact bytes; normalization is permitted only for
    # membership parsing and never changes the authenticated artifact identity.
    if "\r" in text.replace("\r\n", ""):
        raise _rejection("TDD-Bench id list contains a bare carriage return.")
    values = text.splitlines()
    if len(values) != 449 or len(values) != len(set(values)):
        raise _rejection("TDD-Bench id list is not the exact 449-member set.")
    for value in values:
        _ascii(value, "TDD-Bench member ID", _INSTANCE_ID)
    if membership_ordinal > len(values) or values[membership_ordinal - 1] != instance_id:
        raise _rejection("TDD-Bench membership ordinal does not identify the upstream instance.")


def _verify_lfs_artifact(
    root: Path,
    *,
    pointer: ArtifactReference,
    artifact: ArtifactReference,
    expected_git_blob_oid: str,
    expected_lfs_sha256: str,
    expected_lfs_bytes: int,
) -> None:
    pointer_bytes = _read_artifact(root, pointer, "source dataset LFS pointer")
    git_blob_oid = hashlib.sha1(
        f"blob {len(pointer_bytes)}\0".encode() + pointer_bytes,
        usedforsecurity=False,
    ).hexdigest()
    _require_equal(git_blob_oid, expected_git_blob_oid, "source dataset LFS pointer Git blob")
    expected_pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{expected_lfs_sha256}\n"
        f"size {expected_lfs_bytes}\n"
    ).encode("ascii")
    if pointer_bytes != expected_pointer:
        raise _rejection("Source dataset LFS pointer is not the exact canonical pointer.")
    artifact_bytes = _read_artifact(root, artifact, "source dataset split artifact")
    if (
        len(artifact_bytes) != expected_lfs_bytes
        or hashlib.sha256(artifact_bytes).hexdigest() != expected_lfs_sha256
    ):
        raise _rejection("Source dataset bytes do not match their LFS object identity.")


def _load_artifact_reference(value: object, root: Path, label: str) -> ArtifactReference:
    record = _exact_object(value, _ARTIFACT_KEYS, label)
    relative = _relative_path(record.get("path"), label)
    reference = ArtifactReference(
        path=relative,
        sha256=_sha256(record.get("sha256"), f"{label} SHA-256"),
        bytes=_positive_int(record.get("bytes"), f"{label} byte count"),
    )
    _read_artifact(root, reference, label)
    return reference


def _read_artifact(root: Path, reference: ArtifactReference, label: str) -> bytes:
    if reference.bytes > MAX_ARTIFACT_BYTES:
        raise _rejection(f"{label} exceeds its artifact byte limit.")
    path = Path(root) / reference.path
    content = _read_bounded_regular(path, MAX_ARTIFACT_BYTES, label)
    if len(content) != reference.bytes or hashlib.sha256(content).hexdigest() != reference.sha256:
        raise _rejection(f"{label} bytes do not match their reference.")
    return content


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii() or "\\" in value:
        raise _rejection(f"{label} path is invalid.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise _rejection(f"{label} path escapes the private package root.")
    if len(value) > 240:
        raise _rejection(f"{label} path is too long.")
    return value


def _require_unique_artifact_paths(references: Sequence[ArtifactReference], *, root: Path) -> None:
    paths = [reference.path for reference in references]
    if len(paths) != len(set(paths)):
        raise _rejection("Evaluator package reuses an artifact path across trust roles.")
    folded = [path.casefold() for path in paths]
    if len(folded) != len(set(folded)):
        raise _rejection("Evaluator package contains case-folded artifact path aliases.")
    content_identities = [(reference.sha256, reference.bytes) for reference in references]
    if len(content_identities) != len(set(content_identities)):
        raise _rejection("Evaluator package reuses identical bytes across trust roles.")
    file_identities: list[tuple[int, int]] = []
    for reference in references:
        try:
            metadata = os.lstat(Path(root) / reference.path)
        except OSError as exc:
            raise _rejection("Evaluator package artifact identity could not be rechecked.") from exc
        file_identities.append((metadata.st_dev, metadata.st_ino))
    if len(file_identities) != len(set(file_identities)):
        raise _rejection("Evaluator package reuses a hard-linked artifact across trust roles.")


def _require_outside_source_checkout(path: Path) -> None:
    resolved = Path(path).resolve(strict=True)
    for ancestor in (resolved, *resolved.parents):
        marker = ancestor / ".git"
        try:
            os.lstat(marker)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _rejection("Evaluator package Git-boundary check failed closed.") from exc
        raise _rejection("Evaluator packages must be stored outside every Git checkout.")


def _record_private_unique(
    seen: dict[_UniqueKey, str],
    key: _UniqueKey,
    case_id: str,
    code: str,
    blockers: list[str],
) -> None:
    previous = seen.get(key)
    if previous is None:
        seen[key] = case_id
        return
    blockers.append(f"{case_id}:{code}:{previous}")


def _parse_case(value: object, label: str) -> V02CaseIdentity:
    case = _exact_object(value, _CASE_KEYS, label)
    result = V02CaseIdentity(
        id=_ascii(case.get("id"), "case ID", _CASE_ID),
        repo=_ascii(case.get("repo"), "case repository", _REPOSITORY),
        issue_url=_issue_url(case.get("issue_url"), "case issue URL"),
        base_sha=_git_sha(case.get("base_sha"), "case base SHA"),
    )
    _validate_case(result)
    return result


def _validate_case(case: V02CaseIdentity) -> None:
    _ascii(case.id, "case ID", _CASE_ID)
    _ascii(case.repo, "case repository", _REPOSITORY)
    issue_url = _issue_url(case.issue_url, "case issue URL")
    location = parse_issue_url(issue_url)
    if case.repo != f"{location.owner}/{location.repo}":
        raise _rejection("Case repository does not match its issue URL.")
    _git_sha(case.base_sha, "case base SHA")


def _validate_tool(value: object, label: str) -> dict[str, str]:
    tool = _exact_object(value, _TOOL_KEYS, label)
    return {
        "name": _ascii(tool.get("name"), f"{label} name", _IDENTIFIER),
        "version": _ascii(tool.get("version"), f"{label} version", _VERSION),
        "git_sha": _git_sha(tool.get("git_sha"), f"{label} Git SHA"),
    }


def _difficulty(value: object) -> str:
    if value not in {"lt_15m", "15m_to_1h"}:
        raise _rejection("Case difficulty is outside the frozen feasibility buckets.")
    return value


def _issue_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise _rejection(f"{label} is invalid.")
    try:
        parse_issue_url(value)
    except PolicyRejection as exc:
        raise _rejection(f"{label} is not canonical.") from exc
    return value


def _load_canonical_json(path: Path, limit: int, label: str) -> tuple[bytes, Mapping[str, object]]:
    raw = _read_bounded_regular(path, limit, label)
    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _rejection(f"{label} is not strict UTF-8 JSON.") from exc
    root = _object(decoded, label)
    if raw != _canonical_json_bytes(root) + b"\n":
        raise _rejection(f"{label} is not canonical JSON with one trailing newline.")
    return raw, root


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    with open_regular_file(Path(path)) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise _rejection(f"{label} exceeds its byte limit.")
    return content


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _rejection("Value cannot be represented as canonical JSON.") from exc


def _exact_object(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    result = _object(value, label)
    if set(result) != keys:
        raise _rejection(f"{label} fields do not match the frozen contract.")
    return result


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _rejection(f"{label} must be an object.")
    return cast(Mapping[str, object], value)


def _ascii(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _rejection(f"{label} is invalid.")
    return value


def _sha256(value: object, label: str) -> str:
    return _ascii(value, label, _SHA256)


def _git_sha(value: object, label: str) -> str:
    return _ascii(value, label, _GIT_SHA)


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise _rejection(f"{label} must be an RFC 3339 UTC timestamp.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _rejection(f"{label} is not a real timestamp.") from exc
    return value


def _timestamp_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _utf8_field(value: object, label: str, *, allow_empty: bool) -> bytes:
    if not isinstance(value, str) or (not allow_empty and not value) or "\x00" in value:
        raise _rejection(f"{label} is invalid.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _rejection(f"{label} is not valid UTF-8 text.") from exc
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise _rejection(f"{label} exceeds its byte limit.")
    return encoded


def _snapshot_text(value: object, label: str, max_bytes: int, *, title: bool) -> str:
    if not isinstance(value, str) or (title and not value):
        raise _rejection(f"{label} must be canonical text.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _rejection(f"{label} is not valid UTF-8 text.") from exc
    if len(encoded) > max_bytes or "\r" in value or unicodedata.normalize("NFC", value) != value:
        raise _rejection(f"{label} is not bounded NFC/LF text.")
    if title and ("\n" in value or "\t" in value):
        raise _rejection("Snapshot title must be one line.")
    for character in value:
        if character in {"\n", "\t"}:
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            raise _rejection(f"{label} contains a forbidden control character.")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _rejection(f"{label} must be a positive integer.")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _rejection(f"{label} must be a non-negative integer.")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise _rejection(f"{label} must be boolean.")
    return value


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise _rejection(f"{label} does not match the frozen contract.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _error_code(error: BaseException) -> str:
    if isinstance(error, ReproAssertError):
        return error.code
    if isinstance(error, FileNotFoundError):
        return "artifact_missing"
    return "artifact_io_error"


def _rejection(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_package", message)
