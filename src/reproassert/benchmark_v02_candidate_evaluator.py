"""Strict, provider-disabled candidate evaluation in frozen instance images."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from defusedxml import ElementTree

from reproassert.benchmark_v02_amendment import (
    VerifiedV02BenchmarkAmendment,
    require_approved_v02_benchmark_amendment,
)
from reproassert.benchmark_v02_exact_capability import (
    CAPABILITY_ALGORITHM_V2,
    VerifiedV02ExactImageEvaluatorCapability,
    require_v02_exact_image_evaluator_capability,
)
from reproassert.benchmark_v02_hidden import (
    VerifiedV02HiddenExtraction,
    hidden_case_artifacts,
)
from reproassert.benchmark_v02_instance_controller import (
    MAX_GOLD_SMOKE_RECEIPT_BYTES,
    MAX_GOLD_SPECS_BYTES,
    GoldSmokeSpec,
    _load_gold_specs,
    verify_instance_gold_smoke_receipt,
)
from reproassert.benchmark_v02_instance_executor import (
    InstancePytestResult,
    InstanceRuntimeExecutor,
)
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    InstanceRuntimeManifest,
    load_instance_runtime_manifest,
)
from reproassert.benchmark_v021_automated_evidence import (
    VerifiedV021AutomatedEvidence,
    require_v021_automated_evidence,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, write_bytes_exclusive
from reproassert.sandbox import SandboxPolicy

SCHEMA_VERSION = "1.0.0"
ALGORITHM = "reproassert-v02-instance-candidate-evaluation-v1"
POLICY_PROFILE = "reproassert-v02-instance-candidate-evaluation-resources-v1"
MAX_CANDIDATE_BYTES = 256 * 1024
MAX_HIDDEN_PATCH_BYTES = 2 * 1024 * 1024
BASE_RUNS = 3
FIXED_RUNS = 3
RUN_ORDER: tuple[Literal["base", "fixed"], ...] = (
    "base",
    "fixed",
    "fixed",
    "base",
    "base",
    "fixed",
)

_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_TEST_FUNCTION = re.compile(r"test_[A-Za-z_][A-Za-z0-9_]{0,199}\Z")
_SYMPY_TEST_PATH = re.compile(r"sympy(?:/[A-Za-z0-9_]+)+/tests/test_[A-Za-z0-9_]+\.py\Z")
_INFRASTRUCTURE_MARKERS = (
    "modulenotfounderror",
    "importerror while importing test module",
    "internalerror>",
    "no tests ran",
    "collected 0 items",
    "permission denied",
    "no such file or directory",
    "network is unreachable",
    "temporary failure in name resolution",
    "name or service not known",
    "failed to establish a new connection",
    "connectionerror",
    "socket.gaierror",
)


@dataclass(frozen=True)
class CandidateArtifact:
    """Public generated test bytes; never includes production or gold oracle data."""

    relative_path: str
    content: bytes
    test_function: str | None = None


@dataclass(frozen=True)
class _ResolvedHiddenEvaluatorInputs:
    """Private oracle material resolved only from freshly verified authority."""

    production_patch: bytes
    gold_test_patch: bytes
    gold_targets: tuple[str, ...]


@dataclass(frozen=True)
class CandidateEvaluationReceipt:
    path: Path
    sha256: str
    case_id: str
    classification: str
    accepted: bool
    evaluator_wall_ms: int


@dataclass(frozen=True)
class CandidateExecutionProfile:
    """Frozen generation/execution contract for one runtime family and case."""

    profile_id: Literal["pytest-v1", "sympy-native-v1"]
    staging_path: str
    required_function: str
    command_profile: Literal["pytest-v1", "sympy-bin-test-v1"]

    def record(self) -> dict[str, object]:
        return {
            "command_profile": self.command_profile,
            "profile_id": self.profile_id,
            "required_function": self.required_function,
            "staging_path": self.staging_path,
            "staging_path_sha256": hashlib.sha256(self.staging_path.encode()).hexdigest(),
        }

    @property
    def sha256(self) -> str:
        return _sha256_json(self.record())


ExecutorFactory = Callable[[InstanceRuntimeManifest, str, SandboxPolicy], InstanceRuntimeExecutor]


def candidate_execution_profile(
    runtime: InstanceRuntime, *, case_id: str, candidate: CandidateArtifact
) -> CandidateExecutionProfile:
    """Resolve the only candidate path/function/runner contract permitted for this runtime."""

    checked_case = _case_id(case_id)
    if runtime.case_id != checked_case:
        raise _reject("Candidate profile case differs from the frozen runtime.")
    if runtime.test_command_profile == "pytest-v1":
        path, function = _pytest_candidate_contract(candidate)
        return CandidateExecutionProfile("pytest-v1", path, function, "pytest-v1")
    if runtime.test_command_profile == "sympy-bin-test-v1":
        suffix = checked_case.rsplit("-", 1)[1]
        path = f"sympy/reproassert/tests/test_issue_{suffix}.py"
        function = f"test_reproassert_issue_{suffix}"
        _sympy_candidate_contract(candidate, required_path=path, required_function=function)
        return CandidateExecutionProfile("sympy-native-v1", path, function, "sympy-bin-test-v1")
    raise _reject("Frozen candidate command profile is unsupported.")


def _resolve_hidden_evaluator_inputs(
    *,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    verified_hidden: VerifiedV02HiddenExtraction,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
) -> _ResolvedHiddenEvaluatorInputs:
    """Resolve private bytes and targets without accepting any caller-authored oracle value."""

    capability = require_v02_exact_image_evaluator_capability(evaluator_capability)
    # This call is the nominal-authority gate. It also rechecks the hidden receipt and artifacts
    # after fresh extraction verification, before any private path is opened here.
    refs = hidden_case_artifacts(verified_hidden, capability.case_id)
    if verified_hidden.prepared.receipt_sha256 != capability.hidden_extraction_receipt_sha256:
        raise _reject("Fresh hidden extraction differs from the evaluator capability.")
    production_patch = _read_committed_hidden_ref(
        refs.get("production_patch"),
        label="production patch",
        expected_sha256=capability.production_patch_sha256,
        expected_bytes=capability.production_patch_bytes,
    )
    developer_tests = _read_committed_hidden_ref(
        refs.get("developer_tests"),
        label="developer tests",
        expected_sha256=capability.developer_tests_sha256,
        expected_bytes=capability.developer_tests_bytes,
    )

    verified_gold = verify_instance_gold_smoke_receipt(Path(gold_smoke_receipt_path))
    gold_receipt_raw = _read_regular_bounded(
        Path(gold_smoke_receipt_path), MAX_GOLD_SMOKE_RECEIPT_BYTES, "gold-smoke receipt"
    )
    if (
        verified_gold.sha256 != capability.gold_smoke_receipt_sha256
        or hashlib.sha256(gold_receipt_raw).hexdigest() != verified_gold.sha256
    ):
        raise _reject("Gold-smoke receipt differs from the evaluator capability.")
    gold_receipt = json.loads(gold_receipt_raw)
    if (
        not isinstance(gold_receipt, dict)
        or gold_receipt.get("receipt_sha256") != capability.gold_smoke_receipt_commitment_sha256
    ):
        raise _reject("Gold-smoke receipt commitment differs from the evaluator capability.")
    gold_inputs = gold_receipt.get("inputs")
    if (
        not isinstance(gold_inputs, dict)
        or gold_inputs.get("hidden_extraction_receipt_sha256")
        != capability.hidden_extraction_receipt_sha256
    ):
        raise _reject("Gold-smoke receipt does not bind the supplied hidden extraction.")
    expected_specs_sha256 = _digest(gold_inputs.get("gold_specs_sha256"), "gold specs")
    gold_specs_raw = _read_regular_bounded(
        Path(gold_specs_path), MAX_GOLD_SPECS_BYTES, "gold specs"
    )
    if hashlib.sha256(gold_specs_raw).hexdigest() != expected_specs_sha256:
        raise _reject("Gold specs differ from the gold-smoke receipt commitment.")
    matches = tuple(
        spec
        for spec in _load_gold_specs(gold_specs_raw)
        if spec.instance_id == capability.runtime.instance_id
    )
    if len(matches) != 1:
        raise _reject("Gold specs do not resolve exactly one evaluator case.")
    spec: GoldSmokeSpec = matches[0]
    return _ResolvedHiddenEvaluatorInputs(
        production_patch=production_patch,
        gold_test_patch=developer_tests,
        gold_targets=spec.fail_to_pass,
    )


def _read_committed_hidden_ref(
    value: object,
    *,
    label: str,
    expected_sha256: str,
    expected_bytes: int,
) -> bytes:
    if not isinstance(value, dict) or set(value) != {"bytes", "path", "sha256"}:
        raise _reject(f"Verified {label} reference is invalid.")
    if value.get("sha256") != expected_sha256 or value.get("bytes") != expected_bytes:
        raise _reject(f"Verified {label} reference differs from the evaluator capability.")
    path = value.get("path")
    if not isinstance(path, Path):
        raise _reject(f"Verified {label} path is invalid.")
    content = _read_regular_bounded(path, MAX_HIDDEN_PATCH_BYTES, label)
    if len(content) != expected_bytes or hashlib.sha256(content).hexdigest() != expected_sha256:
        raise _reject(f"Verified {label} changed after authority verification.")
    return _hidden_bytes(content, label)


def _read_regular_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"Committed {label} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"Committed {label} exceeds its byte limit.")
    return content


def _require_candidate_execution_authority(
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    *,
    amendment_authority: VerifiedV02BenchmarkAmendment | None,
    automated_evidence_authority: VerifiedV021AutomatedEvidence | None,
    tool_git_sha: str,
) -> VerifiedV02ExactImageEvaluatorCapability:
    """Fail before private resolution or sandbox construction on unapproved v0.2.1 evidence."""

    capability = require_v02_exact_image_evaluator_capability(evaluator_capability)
    algorithm = getattr(capability, "capability_algorithm", None)
    if algorithm != CAPABILITY_ALGORITHM_V2:
        if amendment_authority is not None or automated_evidence_authority is not None:
            raise _reject("Legacy candidate execution cannot accept amendment authority.")
        return capability
    if automated_evidence_authority is not None:
        if amendment_authority is not None:
            raise _reject("Candidate execution requires exactly one v0.2.1 authority mode.")
        automated = require_v021_automated_evidence(automated_evidence_authority)
        raw = _read_regular_bounded(automated.path, MAX_HIDDEN_PATCH_BYTES, "automated evidence")
        if hashlib.sha256(raw).hexdigest() != automated.sha256:
            raise _reject("Automated evidence changed after authority verification.")
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise _reject("Automated evidence is invalid JSON.") from exc
        if not isinstance(record, dict) or raw != _canonical(record) + b"\n":
            raise _reject("Automated evidence is not canonical JSON.")
        claims = record.get("claims")
        evidence = record.get("evidence")
        if not isinstance(claims, dict) or not isinstance(evidence, dict):
            raise _reject("Automated evidence fields are invalid.")
        commitments = evidence.get("internal_commitments")
        if not isinstance(commitments, dict):
            raise _reject("Automated evidence commitments are invalid.")
        if (
            claims.get("automated_oracle_validated") is not True
            or claims.get("human_reviewed") is not False
            or claims.get("maintainer_validated") is not False
            or automated.tool_git_sha != tool_git_sha
            or capability.benchmark_amendment_review_status != "pending"
            or capability.benchmark_amendment_receipt_sha256 != automated.amendment_receipt_sha256
            or capability.runtime_manifest_sha256 != evidence.get("runtime_manifest_sha256")
            or capability.hidden_extraction_receipt_sha256
            != commitments.get("hidden_extraction_receipt_sha256")
            or capability.gold_smoke_receipt_sha256 != evidence.get("gold_smoke_raw_sha256")
        ):
            raise _reject("Automated authority does not bind the exact evaluator evidence.")
        return capability
    amendment = require_approved_v02_benchmark_amendment(amendment_authority)
    if (
        capability.benchmark_amendment_receipt_sha256 != amendment.receipt_sha256
        or capability.benchmark_amendment_review_status != amendment.review_status
        or capability.runtime_manifest_sha256 != amendment.runtime_manifest_sha256
        or capability.hidden_extraction_receipt_sha256 != amendment.hidden_extraction_receipt_sha256
        or capability.gold_smoke_receipt_sha256 != amendment.amended_gold_smoke_receipt_sha256
    ):
        raise _reject("Fresh amendment authority does not bind candidate execution evidence.")
    return capability


def evaluate_instance_candidate(
    *,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    verified_hidden: VerifiedV02HiddenExtraction,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
    case_id: str,
    candidate: CandidateArtifact,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
    executor_factory: ExecutorFactory | None = None,
    amendment_authority: VerifiedV02BenchmarkAmendment | None = None,
    automated_evidence_authority: VerifiedV021AutomatedEvidence | None = None,
) -> CandidateEvaluationReceipt:
    """Resolve private inputs from verified authority, then evaluate one candidate.

    Raw production patches, developer tests, and test targets are intentionally absent from this
    public scored API. The caller supplies fresh hidden-extraction authority plus committed evidence
    files; the evaluator derives and byte-verifies the private inputs internally.
    """

    evaluator_started_monotonic = time.monotonic()
    capability = _require_candidate_execution_authority(
        evaluator_capability,
        amendment_authority=amendment_authority,
        automated_evidence_authority=automated_evidence_authority,
        tool_git_sha=tool_git_sha,
    )
    hidden = _resolve_hidden_evaluator_inputs(
        evaluator_capability=capability,
        verified_hidden=verified_hidden,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        gold_specs_path=gold_specs_path,
    )
    return _evaluate_instance_candidate_with_resolved_hidden(
        evaluator_capability=capability,
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        case_id=case_id,
        candidate=candidate,
        hidden=hidden,
        output_path=output_path,
        executed_at=executed_at,
        tool_git_sha=tool_git_sha,
        executor_factory=executor_factory,
        evaluator_started_monotonic=evaluator_started_monotonic,
        amendment_authority=amendment_authority,
        automated_evidence_authority=automated_evidence_authority,
    )


def _evaluate_instance_candidate_with_resolved_hidden(
    *,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    manifest_path: Path,
    expected_manifest_sha256: str,
    case_id: str,
    candidate: CandidateArtifact,
    hidden: _ResolvedHiddenEvaluatorInputs,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
    executor_factory: ExecutorFactory | None = None,
    evaluator_started_monotonic: float | None = None,
    amendment_authority: VerifiedV02BenchmarkAmendment | None = None,
    automated_evidence_authority: VerifiedV021AutomatedEvidence | None = None,
) -> CandidateEvaluationReceipt:
    """Execute with private inputs already resolved by the scored public boundary.

    The hidden gold test/fix pair first attests the evaluator environment. The candidate must then
    collect on both trees, fail in every base run, and pass in every fixed run. This establishes a
    deterministic L1 causal signal only; semantic review and all remaining L2 controls are separate.
    """

    evaluator_started = (
        time.monotonic() if evaluator_started_monotonic is None else evaluator_started_monotonic
    )
    capability = _require_candidate_execution_authority(
        evaluator_capability,
        amendment_authority=amendment_authority,
        automated_evidence_authority=automated_evidence_authority,
        tool_git_sha=tool_git_sha,
    )
    checked_case = _case_id(case_id)
    if capability.case_id != checked_case:
        raise _reject("Exact-image evaluator capability is for a different case.")
    manifest = load_instance_runtime_manifest(manifest_path)
    if manifest.sha256 != _digest(expected_manifest_sha256, "manifest commitment"):
        raise _reject("Instance runtime manifest differs from its explicit commitment.")
    matches = tuple(entry for entry in manifest.entries if entry.case_id == checked_case)
    if len(matches) != 1:
        raise _reject("Case does not bind exactly one frozen instance runtime.")
    runtime = matches[0]
    if manifest.sha256 != capability.runtime_manifest_sha256 or runtime != capability.runtime:
        raise _reject("Runtime manifest or case entry differs from the evaluator capability.")
    profile = candidate_execution_profile(runtime, case_id=checked_case, candidate=candidate)
    candidate_path = profile.staging_path
    candidate_target = f"{profile.staging_path}::{profile.required_function}"
    production_patch = _hidden_bytes(hidden.production_patch, "production patch")
    gold_patch = _hidden_bytes(hidden.gold_test_patch, "gold test patch")
    if (
        hashlib.sha256(production_patch).hexdigest() != capability.production_patch_sha256
        or len(production_patch) != capability.production_patch_bytes
        or hashlib.sha256(gold_patch).hexdigest() != capability.developer_tests_sha256
        or len(gold_patch) != capability.developer_tests_bytes
    ):
        raise _reject("Private evaluator bytes differ from capability-bound commitments.")
    if (
        not isinstance(hidden.gold_targets, tuple)
        or not 1 <= len(hidden.gold_targets) <= 64
        or len(set(hidden.gold_targets)) != len(hidden.gold_targets)
    ):
        raise _reject("Hidden gold targets must be a bounded unique tuple.")

    policy = _evaluation_policy(runtime.image_id)
    factory = executor_factory or _executor_factory
    phases: dict[str, object] = {}
    classification = "controller_failure"
    accepted = False
    reason = "The evaluator did not complete all required phases."

    with factory(manifest, checked_case, policy) as executor:
        executor.acquire()
        executor.prepare_workspaces(fixed_patch=production_patch)
        executor.apply_patch(workspace="base", patch=gold_patch)
        executor.apply_patch(workspace="fixed", patch=gold_patch)

        if profile.profile_id == "pytest-v1":
            gold_base_collect = executor.run_test_command(
                workspace="base", targets=hidden.gold_targets, collect_only=True
            )
            gold_fixed_collect = executor.run_test_command(
                workspace="fixed", targets=hidden.gold_targets, collect_only=True
            )
            phases["gold_base_collect"] = _evidence(gold_base_collect)
            phases["gold_fixed_collect"] = _evidence(gold_fixed_collect)
            _require_clean_collection(gold_base_collect, gold_fixed_collect, "hidden gold")
            gold_base = executor.run_test_command(workspace="base", targets=hidden.gold_targets)
            gold_fixed = executor.run_test_command(workspace="fixed", targets=hidden.gold_targets)
        else:
            phases["gold_base_collect"] = None
            phases["gold_fixed_collect"] = None
            gold_path, gold_function = _derive_sympy_gold_contract(gold_patch, hidden.gold_targets)
            gold_base = executor.run_test_command(
                workspace="base",
                sympy_test_file=gold_path,
                sympy_test_identifier=gold_function,
            )
            gold_fixed = executor.run_test_command(
                workspace="fixed",
                sympy_test_file=gold_path,
                sympy_test_identifier=gold_function,
            )
        phases["gold_base"] = _evidence(gold_base)
        phases["gold_fixed"] = _evidence(gold_fixed)
        _require_gold_pair(gold_base, gold_fixed)

    candidate_runs: list[dict[str, object]] = []
    base_results: list[InstancePytestResult] = []
    fixed_results: list[InstancePytestResult] = []
    base_fingerprints: list[str | None] = []
    candidate_evidence_validity: list[bool] = []
    for workspace in RUN_ORDER:
        # Each scored observation receives new base/fixed volumes. Nothing from a prior collect or
        # test process can survive into the next observation.
        with factory(manifest, checked_case, policy) as executor:
            executor.acquire()
            executor.prepare_workspaces(fixed_patch=production_patch)
            executor.stage_candidate(relative_path=candidate_path, content=candidate.content)
            if profile.profile_id == "pytest-v1":
                collect = executor.run_pytest(
                    workspace=workspace,
                    targets=(candidate_target,),
                    collect_only=True,
                )
                _require_clean_collection(collect, collect, "candidate")
                result = executor.run_pytest(workspace=workspace, targets=(candidate_target,))
                collection_evidence: object = _evidence(collect)
            else:
                collection_evidence = None
                result = executor.run_test_command(
                    workspace=workspace,
                    sympy_test_file=profile.staging_path,
                    sympy_test_identifier=profile.required_function,
                )
            fingerprint, evidence_valid = _candidate_fingerprint_with_validity(
                result, profile=profile
            )
            candidate_evidence_validity.append(evidence_valid)
            candidate_runs.append(
                {
                    "collection": collection_evidence,
                    "failure_fingerprint_sha256": fingerprint,
                    "result": _evidence(result),
                    "workspace": workspace,
                }
            )
            if workspace == "base":
                base_results.append(result)
                base_fingerprints.append(fingerprint)
            else:
                fixed_results.append(result)
    phases["candidate_runs"] = candidate_runs
    classification, accepted, reason = _classify_candidate(
        tuple(base_results), tuple(fixed_results), tuple(base_fingerprints)
    )
    if accepted and not all(candidate_evidence_validity):
        classification = "wrong_or_flaky_failure"
        accepted = False
        reason = "A candidate run lacked attributable assertion evidence."

    candidate_sha256 = hashlib.sha256(candidate.content).hexdigest()
    record: dict[str, object] = {
        "algorithm": ALGORITHM,
        "benchmark_version": "0.2",
        "case_id": checked_case,
        "candidate": {
            "bytes": len(candidate.content),
            "relative_path": candidate_path,
            "sha256": candidate_sha256,
            "target": candidate_target,
        },
        "candidate_profile": {**profile.record(), "profile_sha256": profile.sha256},
        "causal_controls": {
            "candidate_on_fixed": "pass" if accepted else "fail",
            "l2_causal_controls_passed": False,
            "remaining_required_controls": [
                "fix_minus_issue_relevant_hunks",
                "base_plus_issue_relevant_hunks",
            ],
            "semantic_review_required": True,
        },
        "claims": {
            "hidden_bytes_emitted": False,
            "model_or_provider_invoked": False,
            "network_during_sandbox_execution": False,
            "provider_calls": 0,
        },
        "executed_at": _timestamp(executed_at),
        "evaluator_wall_ms": max(0, round((time.monotonic() - evaluator_started) * 1_000)),
        "inputs": {
            **capability.public_record(),
            "evaluator_public_commitment_sha256": (capability.evaluator_public_commitment_sha256),
        },
        "outcome": {
            "accepted": accepted,
            "base_consistency": f"{sum(r.exit_code == 1 for r in base_results)}/{BASE_RUNS}",
            "classification": classification,
            "fixed_consistency": f"{sum(r.exit_code == 0 for r in fixed_results)}/{FIXED_RUNS}",
            "reason": reason,
        },
        "phases": phases,
        "policy": {
            "base_runs": BASE_RUNS,
            "fixed_runs": FIXED_RUNS,
            "profile": POLICY_PROFILE,
            "sandbox": {
                "capabilities": "drop_all",
                "network_mode": "none",
                "no_new_privileges": True,
                "read_only_root": True,
                "test_user": "65532:65532",
            },
        },
        "receipt_sha256": "0" * 64,
        "schema_version": SCHEMA_VERSION,
        "tool_git_sha": _git_sha(tool_git_sha),
    }
    record["receipt_sha256"] = _self_hash(record)
    encoded = _canonical(record) + b"\n"
    write_bytes_exclusive(output_path, encoded)
    return CandidateEvaluationReceipt(
        path=output_path,
        sha256=hashlib.sha256(encoded).hexdigest(),
        case_id=checked_case,
        classification=classification,
        accepted=accepted,
        evaluator_wall_ms=cast(int, record["evaluator_wall_ms"]),
    )


def verify_instance_candidate_receipt(
    path: Path,
    *,
    raw: bytes | None = None,
    automated_evidence_authority: VerifiedV021AutomatedEvidence | None = None,
    expected_capability: VerifiedV02ExactImageEvaluatorCapability | None = None,
    structural_pending: bool = False,
) -> CandidateEvaluationReceipt:
    """Verify canonical encoding, self-commitment, redaction claims, and outcome invariants."""

    if raw is None:
        with open_regular_file(path) as stream:
            raw = stream.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise _reject("Candidate evaluation receipt exceeds the verifier limit.")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Candidate evaluation receipt is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject("Candidate evaluation receipt is not canonical JSON.")
    required = {
        "algorithm",
        "benchmark_version",
        "case_id",
        "candidate",
        "candidate_profile",
        "causal_controls",
        "claims",
        "executed_at",
        "evaluator_wall_ms",
        "inputs",
        "outcome",
        "phases",
        "policy",
        "receipt_sha256",
        "schema_version",
        "tool_git_sha",
    }
    if (
        set(value) != required
        or value.get("algorithm") != ALGORITHM
        or value.get("benchmark_version") != "0.2"
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("receipt_sha256") != _self_hash(value)
    ):
        raise _reject("Candidate evaluation receipt identity is invalid.")
    case_id = _case_id(value.get("case_id"))
    _timestamp(value.get("executed_at"))
    evaluator_wall_ms = value.get("evaluator_wall_ms")
    if (
        not isinstance(evaluator_wall_ms, int)
        or isinstance(evaluator_wall_ms, bool)
        or evaluator_wall_ms < 0
    ):
        raise _reject("Candidate evaluator wall duration is invalid.")
    _git_sha(value.get("tool_git_sha"))
    claims = value.get("claims")
    if claims != {
        "hidden_bytes_emitted": False,
        "model_or_provider_invoked": False,
        "network_during_sandbox_execution": False,
        "provider_calls": 0,
    }:
        raise _reject("Candidate evaluation trust claims are invalid.")
    _verify_capability_inputs(
        value.get("inputs"),
        case_id=case_id,
        automated_evidence_authority=automated_evidence_authority,
        expected_capability=expected_capability,
        structural_pending=structural_pending,
    )
    outcome = value.get("outcome")
    controls = value.get("causal_controls")
    if not isinstance(outcome, dict) or not isinstance(controls, dict):
        raise _reject("Candidate evaluation outcome is invalid.")
    accepted = outcome.get("accepted") is True
    if accepted != (outcome.get("classification") == "verified_reproduction"):
        raise _reject("Candidate acceptance and classification disagree.")
    if controls.get("l2_causal_controls_passed") is not False:
        raise _reject("An individual candidate receipt cannot assert completed L2 controls.")
    if set(controls) != {
        "candidate_on_fixed",
        "l2_causal_controls_passed",
        "remaining_required_controls",
        "semantic_review_required",
    } or controls.get("remaining_required_controls") != [
        "fix_minus_issue_relevant_hunks",
        "base_plus_issue_relevant_hunks",
    ]:
        raise _reject("Candidate causal-control projection is invalid.")
    if controls.get("semantic_review_required") is not True or controls.get(
        "candidate_on_fixed"
    ) != ("pass" if accepted else "fail"):
        raise _reject("Candidate causal-control outcome is invalid.")
    candidate = value.get("candidate")
    profile = value.get("candidate_profile")
    if not isinstance(candidate, dict) or not isinstance(profile, dict):
        raise _reject("Candidate evaluation commitments are invalid.")
    _digest(candidate.get("sha256"), "candidate")
    if set(profile) != {
        "command_profile",
        "profile_id",
        "profile_sha256",
        "required_function",
        "staging_path",
        "staging_path_sha256",
    }:
        raise _reject("Candidate execution profile is invalid.")
    profile_sha256 = _digest(profile.get("profile_sha256"), "candidate profile")
    unsigned_profile = dict(profile)
    unsigned_profile.pop("profile_sha256")
    if profile_sha256 != _sha256_json(unsigned_profile):
        raise _reject("Candidate execution profile commitment is invalid.")
    profile_id = profile.get("profile_id")
    if profile_id not in {"pytest-v1", "sympy-native-v1"}:
        raise _reject("Candidate execution profile ID is invalid.")
    if candidate.get("relative_path") != profile.get("staging_path"):
        raise _reject("Candidate path differs from its execution profile.")
    staging_path = profile.get("staging_path")
    required_function = profile.get("required_function")
    if not isinstance(staging_path, str) or not isinstance(required_function, str):
        raise _reject("Candidate execution profile values are invalid.")
    if candidate.get("target") != f"{staging_path}::{required_function}":
        raise _reject("Candidate target differs from its execution profile.")
    if profile.get("staging_path_sha256") != hashlib.sha256(staging_path.encode()).hexdigest():
        raise _reject("Candidate staging-path commitment is invalid.")
    if profile_id == "pytest-v1":
        if (
            profile.get("command_profile") != "pytest-v1"
            or not staging_path.startswith("tests/reproassert/test_")
            or _TEST_FUNCTION.fullmatch(required_function) is None
        ):
            raise _reject("Pytest candidate execution profile is invalid.")
    else:
        suffix = case_id.rsplit("-", 1)[1]
        if profile != {
            "command_profile": "sympy-bin-test-v1",
            "profile_id": "sympy-native-v1",
            "profile_sha256": profile_sha256,
            "required_function": f"test_reproassert_issue_{suffix}",
            "staging_path": f"sympy/reproassert/tests/test_issue_{suffix}.py",
            "staging_path_sha256": hashlib.sha256(
                f"sympy/reproassert/tests/test_issue_{suffix}.py".encode()
            ).hexdigest(),
        }:
            raise _reject("SymPy candidate execution profile is invalid.")
    policy = value.get("policy")
    if policy != {
        "base_runs": BASE_RUNS,
        "fixed_runs": FIXED_RUNS,
        "profile": POLICY_PROFILE,
        "sandbox": {
            "capabilities": "drop_all",
            "network_mode": "none",
            "no_new_privileges": True,
            "read_only_root": True,
            "test_user": "65532:65532",
        },
    }:
        raise _reject("Candidate evaluation policy is invalid.")
    phases = value.get("phases")
    if not isinstance(phases, dict) or set(phases) != {
        "gold_base_collect",
        "gold_fixed_collect",
        "gold_base",
        "gold_fixed",
        "candidate_runs",
    }:
        raise _reject("Candidate evaluation phases are invalid.")
    for name in ("gold_base", "gold_fixed"):
        _verify_evidence(phases[name])
    for name in ("gold_base_collect", "gold_fixed_collect"):
        if profile_id == "pytest-v1":
            _verify_evidence(phases[name])
        elif phases[name] is not None:
            raise _reject("SymPy native receipt cannot claim pytest collection evidence.")
    _verify_gold_receipt_evidence(phases, profile_id=profile_id)
    runs = phases["candidate_runs"]
    if not isinstance(runs, list) or len(runs) != len(RUN_ORDER):
        raise _reject("Candidate repeat evidence is invalid.")
    if [run.get("workspace") if isinstance(run, dict) else None for run in runs] != list(RUN_ORDER):
        raise _reject("Candidate repeat order is invalid.")
    base_fingerprints: list[str] = []
    for run in runs:
        if not isinstance(run, dict) or set(run) != {
            "collection",
            "failure_fingerprint_sha256",
            "result",
            "workspace",
        }:
            raise _reject("Candidate run evidence is invalid.")
        if profile_id == "pytest-v1":
            _verify_evidence(run["collection"])
            if not _bounded_clean_result(
                cast(dict[str, object], run["collection"]), expected_exit=0
            ):
                raise _reject("Candidate receipt collection evidence is not clean.")
        elif run["collection"] is not None:
            raise _reject("SymPy native run cannot claim pytest collection evidence.")
        _verify_evidence(run["result"])
        fingerprint = run["failure_fingerprint_sha256"]
        if run["workspace"] == "base":
            if fingerprint is None and not accepted:
                continue
            base_fingerprints.append(_digest(fingerprint, "base failure fingerprint"))
        elif fingerprint is not None and accepted:
            raise _reject("Fixed candidate run contains a failure fingerprint.")
    if accepted and len(set(base_fingerprints)) != 1:
        raise _reject("Accepted candidate base fingerprints are inconsistent.")
    _verify_recomputed_candidate_outcome(runs, outcome, profile_id=profile_id)
    return CandidateEvaluationReceipt(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        case_id=case_id,
        classification=str(outcome.get("classification")),
        accepted=accepted,
        evaluator_wall_ms=evaluator_wall_ms,
    )


def _verify_capability_inputs(
    value: object,
    *,
    case_id: str,
    automated_evidence_authority: VerifiedV021AutomatedEvidence | None = None,
    expected_capability: VerifiedV02ExactImageEvaluatorCapability | None = None,
    structural_pending: bool = False,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "benchmark_amendment_receipt_sha256",
        "benchmark_amendment_review_status",
        "case_id",
        "evaluator_public_commitment_sha256",
        "gold_smoke",
        "hidden_inputs",
        "runtime",
        "runtime_manifest_sha256",
    }:
        raise _reject("Exact-image evaluator input binding is invalid.")
    algorithm = value.get("algorithm")
    if (
        algorithm
        not in {
            "reproassert-v02-exact-image-evaluator-capability-v1",
            "reproassert-v02-exact-image-evaluator-capability-v2",
        }
        or value.get("case_id") != case_id
    ):
        raise _reject("Exact-image evaluator input identity is invalid.")
    amendment_sha = value.get("benchmark_amendment_receipt_sha256")
    amendment_status = value.get("benchmark_amendment_review_status")
    if algorithm.endswith("-v1"):
        if amendment_sha is not None or amendment_status is not None:
            raise _reject("Legacy exact-image authority cannot bind a benchmark amendment.")
    elif amendment_status == "pending":
        if structural_pending:
            if automated_evidence_authority is not None or expected_capability is not None:
                raise _reject("Structural pending inspection cannot accept live authority.")
        else:
            automated = require_v021_automated_evidence(automated_evidence_authority)
            capability = require_v02_exact_image_evaluator_capability(expected_capability)
            if (
                capability.case_id != case_id
                or capability.benchmark_amendment_receipt_sha256
                != automated.amendment_receipt_sha256
                or value
                != {
                    **capability.public_record(),
                    "evaluator_public_commitment_sha256": (
                        capability.evaluator_public_commitment_sha256
                    ),
                }
            ):
                raise _reject("Automated evidence does not bind this pending evaluator receipt.")
        _digest(amendment_sha, "benchmark amendment receipt")
    elif amendment_status != "approved":
        raise _reject("v0.2.1 benchmark amendment review is not approved for execution.")
    else:
        _digest(amendment_sha, "benchmark amendment receipt")
    commitment = _digest(
        value.get("evaluator_public_commitment_sha256"), "evaluator public commitment"
    )
    unsigned = dict(value)
    unsigned.pop("evaluator_public_commitment_sha256")
    if commitment != hashlib.sha256(_canonical(unsigned)).hexdigest():
        raise _reject("Exact-image evaluator public commitment is invalid.")
    _digest(value.get("runtime_manifest_sha256"), "runtime manifest")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {
        "base_sha",
        "base_tree_oid",
        "case_id",
        "image_digest",
        "image_id",
        "image_tag",
        "instance_id",
        "spec_sha256",
        "test_command_profile",
    }:
        raise _reject("Exact case runtime binding is invalid.")
    if runtime.get("case_id") != case_id:
        raise _reject("Exact case runtime differs from the receipt case.")
    for name in ("base_sha", "base_tree_oid"):
        _git_sha(runtime.get(name))
    _digest(runtime.get("spec_sha256"), "instance spec")
    for name in ("image_digest", "image_id"):
        image = runtime.get(name)
        if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
            raise _reject("Exact image binding is invalid.")
    if (
        not isinstance(runtime.get("image_tag"), str)
        or not isinstance(runtime.get("instance_id"), str)
        or runtime.get("test_command_profile") not in {"pytest-v1", "sympy-bin-test-v1"}
    ):
        raise _reject("Exact runtime identity is invalid.")
    gold = value.get("gold_smoke")
    if not isinstance(gold, dict) or set(gold) != {
        "case_classification",
        "case_reason",
        "receipt_commitment_sha256",
        "receipt_sha256",
    }:
        raise _reject("Gold-smoke binding is invalid.")
    _digest(gold.get("receipt_commitment_sha256"), "gold-smoke receipt commitment")
    _digest(gold.get("receipt_sha256"), "gold-smoke receipt")
    if case_id == "rk-v0.2-014" and algorithm.endswith("-v1"):
        expected_gold = ("infrastructure_failure", "network_dependency")
    else:
        expected_gold = ("semantic_valid", "fails_on_base_passes_on_fixed")
    if (gold.get("case_classification"), gold.get("case_reason")) != expected_gold:
        raise _reject("Gold-smoke case classification is invalid.")
    hidden = value.get("hidden_inputs")
    if not isinstance(hidden, dict) or set(hidden) != {
        "developer_tests_bytes",
        "developer_tests_sha256",
        "hidden_extraction_receipt_sha256",
        "production_patch_bytes",
        "production_patch_sha256",
    }:
        raise _reject("Hidden evaluator commitments are invalid.")
    for name in (
        "developer_tests_sha256",
        "hidden_extraction_receipt_sha256",
        "production_patch_sha256",
    ):
        _digest(hidden.get(name), "hidden evaluator input")
    for name in ("developer_tests_bytes", "production_patch_bytes"):
        size = hidden.get(name)
        if type(size) is not int or not 1 <= size <= MAX_HIDDEN_PATCH_BYTES:
            raise _reject("Hidden evaluator input size is invalid.")


def _classify_candidate(
    base: tuple[InstancePytestResult, ...],
    fixed: tuple[InstancePytestResult, ...],
    base_fingerprints: tuple[str | None, ...],
) -> tuple[str, bool, str]:
    all_results = (*base, *fixed)
    if any(result.timed_out for result in all_results):
        return "timeout", False, "At least one bounded candidate run timed out."
    if any(result.oom_killed for result in all_results):
        return "oom_killed", False, "At least one candidate sandbox exceeded its memory limit."
    if any(result.output_truncated for result in all_results):
        return "output_limit", False, "At least one candidate run exceeded the output limit."
    if any(_has_infrastructure_marker(result.output) for result in all_results):
        return (
            "infrastructure_failure",
            False,
            "Candidate output contains a setup or infrastructure failure.",
        )
    if any(result.exit_code not in {0, 1} for result in all_results):
        return "generic_crash", False, "Candidate produced a non-test pytest exit code."
    base_codes = {result.exit_code for result in base}
    fixed_codes = {result.exit_code for result in fixed}
    if len(base_codes) != 1 or len(fixed_codes) != 1:
        return "flaky", False, "Repeated candidate outcomes were inconsistent."
    if base_codes != {1}:
        return "does_not_fail_on_base", False, "Candidate did not fail on every buggy-base run."
    if fixed_codes != {0}:
        return "does_not_pass_on_fixed", False, "Candidate did not pass on every fixed-tree run."
    if None in base_fingerprints or len(set(base_fingerprints)) != 1:
        return (
            "wrong_or_flaky_failure",
            False,
            "Base runs did not preserve one normalized failure fingerprint.",
        )
    return (
        "verified_reproduction",
        True,
        "Candidate collected and failed 3/3 on base and passed 3/3 on fixed.",
    )


def _require_clean_collection(
    base: InstancePytestResult, fixed: InstancePytestResult, label: str
) -> None:
    for result in (base, fixed):
        if result.timed_out or result.output_truncated or result.exit_code != 0:
            raise _reject(f"{label.capitalize()} collection did not complete cleanly.")
        if _has_infrastructure_marker(result.output):
            raise _reject(
                f"{label.capitalize()} collection contains infrastructure failure evidence."
            )


def _require_gold_pair(base: InstancePytestResult, fixed: InstancePytestResult) -> None:
    if any(result.timed_out or result.output_truncated for result in (base, fixed)):
        raise _reject("Hidden gold execution exceeded a runtime bound.")
    if any(_has_infrastructure_marker(result.output) for result in (base, fixed)):
        raise _reject("Hidden gold execution contains infrastructure failure evidence.")
    if base.exit_code != 1 or fixed.exit_code != 0:
        raise _reject("Hidden gold tests do not attest the frozen buggy/fixed pair.")


def _pytest_candidate_contract(candidate: CandidateArtifact) -> tuple[str, str]:
    if not isinstance(candidate.content, bytes) or not (
        1 <= len(candidate.content) <= MAX_CANDIDATE_BYTES
    ):
        raise _reject("Candidate content is empty or exceeds the byte limit.")
    try:
        source = candidate.content.decode("utf-8")
        ast.parse(source)
    except (UnicodeDecodeError, SyntaxError, ValueError) as exc:
        raise _reject("Candidate must be valid UTF-8 Python syntax.") from exc
    path = PurePosixPath(candidate.relative_path)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".py"
        or not path.name.startswith("test_")
        or path.parts[:2] != ("tests", "reproassert")
    ):
        raise _reject("Pytest candidate path must be a safe tests/reproassert/test_*.py path.")
    function = candidate.test_function
    if not isinstance(function, str) or _TEST_FUNCTION.fullmatch(function) is None:
        raise _reject("Candidate must name exactly one valid pytest test function.")
    text = path.as_posix()
    return text, function


def _sympy_candidate_contract(
    candidate: CandidateArtifact, *, required_path: str, required_function: str
) -> None:
    if candidate.relative_path != required_path or candidate.test_function != required_function:
        raise _reject("SymPy candidate path and function must equal the frozen native profile.")
    if not isinstance(candidate.content, bytes) or not (
        1 <= len(candidate.content) <= MAX_CANDIDATE_BYTES
    ):
        raise _reject("Candidate content is empty or exceeds the byte limit.")
    try:
        source = candidate.content.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeDecodeError, SyntaxError, ValueError) as exc:
        raise _reject("SymPy candidate must be valid UTF-8 Python syntax.") from exc
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if len(functions) != 1 or functions[0].name != required_function:
        raise _reject("SymPy native candidate must define exactly its required test function.")
    function = functions[0]
    if (
        function.decorator_list
        or function.args.posonlyargs
        or function.args.args
        or function.args.kwonlyargs
        or function.args.vararg is not None
        or function.args.kwarg is not None
    ):
        raise _reject("SymPy native candidate rejects decorators and fixture arguments.")
    for node in tree.body:
        if isinstance(node, ast.Import):
            if any(
                (alias.name != "sympy" and not alias.name.startswith("sympy."))
                or "pytest" in alias.name.split(".")
                for alias in node.names
            ):
                raise _reject("SymPy native candidate imports must come only from SymPy.")
        elif isinstance(node, ast.ImportFrom):
            if (
                node.level != 0
                or node.module is None
                or not (node.module == "sympy" or node.module.startswith("sympy."))
                or "pytest" in node.module.split(".")
            ):
                raise _reject("SymPy native candidate imports must come only from SymPy.")
        elif node is not function:
            raise _reject("SymPy native candidate forbids module-level execution and fixtures.")
    forbidden_nodes = (
        ast.AsyncFunctionDef,
        ast.Await,
        ast.ClassDef,
        ast.Global,
        ast.Lambda,
        ast.Nonlocal,
        ast.Try,
        ast.With,
        ast.Yield,
        ast.YieldFrom,
    )
    forbidden_calls = {"__import__", "compile", "eval", "exec", "open"}
    for walked in ast.walk(function):
        if isinstance(walked, forbidden_nodes):
            raise _reject("SymPy native candidate contains an unsupported construct.")
        if isinstance(walked, (ast.Import, ast.ImportFrom)):
            raise _reject("SymPy native candidate imports must remain at module scope.")
        if isinstance(walked, ast.FunctionDef) and walked is not function:
            raise _reject("SymPy native candidate cannot define nested functions or fixtures.")
        if isinstance(walked, ast.Name) and walked.id == "pytest":
            raise _reject("SymPy native candidate cannot use pytest APIs or fixtures.")
        if (
            isinstance(walked, ast.Call)
            and isinstance(walked.func, ast.Name)
            and walked.func.id in forbidden_calls
        ):
            raise _reject("SymPy native candidate contains an unsafe dynamic call.")
    if not any(isinstance(node, ast.Assert) for node in ast.walk(function)):
        raise _reject("SymPy native candidate must contain at least one plain assert.")


def _derive_sympy_gold_contract(
    developer_patch: bytes, fail_to_pass: tuple[str, ...]
) -> tuple[str, str]:
    if len(fail_to_pass) != 1 or _TEST_FUNCTION.fullmatch(fail_to_pass[0]) is None:
        raise _reject("SymPy gold requires exactly one safe bare test identifier.")
    try:
        lines = developer_patch.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise _reject("SymPy gold patch is not valid UTF-8.") from exc
    paths = {
        line[6:]
        for line in lines
        if line.startswith("+++ b/") and _SYMPY_TEST_PATH.fullmatch(line[6:]) is not None
    }
    if len(paths) != 1:
        raise _reject("SymPy gold patch must bind exactly one native test file.")
    return next(iter(paths)), fail_to_pass[0]


def _hidden_bytes(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_HIDDEN_PATCH_BYTES:
        raise _reject(f"Hidden {label} is empty or exceeds the evaluator limit.")
    return value


def _evidence(result: InstancePytestResult) -> dict[str, object]:
    encoded = result.output.encode("utf-8", errors="replace")
    return {
        "exit_code": result.exit_code,
        "output_bytes": len(encoded),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "junit_sha256": (
            hashlib.sha256(result.junit_xml).hexdigest() if result.junit_xml is not None else None
        ),
        "oom_killed": result.oom_killed,
        "output_stored": False,
        "output_truncated": result.output_truncated,
        "timed_out": result.timed_out,
    }


def _junit_fingerprint(result: InstancePytestResult, *, expected_failure: bool) -> str | None:
    if result.junit_xml is None:
        raise _reject("Candidate execution did not return required JUnit evidence.")
    try:
        root = ElementTree.fromstring(result.junit_xml)
    except (ElementTree.ParseError, ValueError) as exc:
        raise _reject("Candidate JUnit evidence is invalid XML.") from exc
    testcases = list(root.iter("testcase"))
    if len(testcases) != 1:
        raise _reject("Candidate JUnit evidence does not contain exactly one test case.")
    testcase = testcases[0]
    failures = list(testcase.findall("failure"))
    errors = list(testcase.findall("error"))
    skipped = list(testcase.findall("skipped"))
    if errors or skipped or len(failures) != (1 if expected_failure else 0):
        raise _reject("Candidate JUnit outcome is not one clean assertion result.")
    if not expected_failure:
        return None
    failure = failures[0]
    raw = "\n".join((failure.get("type") or "", failure.get("message") or "", failure.text or ""))
    normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", raw)
    normalized = re.sub(r"[ \t]+", " ", normalized).strip()
    if not normalized:
        raise _reject("Candidate base failure has no attributable assertion evidence.")
    return hashlib.sha256(normalized.encode()).hexdigest()


def _candidate_fingerprint_or_none(
    result: InstancePytestResult, *, profile: CandidateExecutionProfile
) -> str | None:
    return _candidate_fingerprint_with_validity(result, profile=profile)[0]


def _candidate_fingerprint_with_validity(
    result: InstancePytestResult, *, profile: CandidateExecutionProfile
) -> tuple[str | None, bool]:
    if (
        result.timed_out
        or result.oom_killed
        or result.output_truncated
        or _has_infrastructure_marker(result.output)
        or result.exit_code not in {0, 1}
    ):
        return None, False
    if profile.profile_id == "pytest-v1":
        try:
            return (
                _junit_fingerprint(result, expected_failure=result.exit_code == 1),
                True,
            )
        except PolicyRejection:
            # The sandbox completed, but the candidate did not produce the exact
            # assertion evidence required for attribution.  This is a scored
            # candidate failure, not a controller failure: preserve the bounded
            # run evidence and let _classify_candidate reject the fingerprint.
            return None, False
    if result.exit_code == 0:
        return None, True
    if profile.required_function not in result.output:
        return None, False
    normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", result.output)
    normalized = re.sub(r"\b[0-9]+(?:\.[0-9]+)?(?:ms|s| seconds?)\b", "DURATION", normalized)
    normalized = re.sub(r"[ \t]+", " ", normalized).strip()
    if not normalized:
        return None, False
    return hashlib.sha256(normalized.encode()).hexdigest(), True


def _verify_gold_receipt_evidence(phases: dict[str, object], *, profile_id: object) -> None:
    gold_base = cast(dict[str, object], phases["gold_base"])
    gold_fixed = cast(dict[str, object], phases["gold_fixed"])
    if not _bounded_clean_result(gold_base, expected_exit=1) or not _bounded_clean_result(
        gold_fixed, expected_exit=0
    ):
        raise _reject("Receipt gold evidence does not attest the buggy/fixed pair.")
    if profile_id == "pytest-v1":
        for name in ("gold_base_collect", "gold_fixed_collect"):
            if not _bounded_clean_result(cast(dict[str, object], phases[name]), expected_exit=0):
                raise _reject("Receipt gold collection evidence is not clean.")


def _verify_recomputed_candidate_outcome(
    runs: list[object], outcome: dict[str, object], *, profile_id: object
) -> None:
    base = [
        cast(dict[str, object], cast(dict[str, object], run)["result"])
        for run in runs
        if cast(dict[str, object], run)["workspace"] == "base"
    ]
    fixed = [
        cast(dict[str, object], cast(dict[str, object], run)["result"])
        for run in runs
        if cast(dict[str, object], run)["workspace"] == "fixed"
    ]
    all_results = [*base, *fixed]
    if any(result["timed_out"] is True for result in all_results):
        classification = "timeout"
    elif any(result["oom_killed"] is True for result in all_results):
        classification = "oom_killed"
    elif any(result["output_truncated"] is True for result in all_results):
        classification = "output_limit"
    elif any(cast(int, result["exit_code"]) not in {0, 1} for result in all_results):
        classification = "generic_crash"
    elif (
        len({result["exit_code"] for result in base}) != 1
        or len({result["exit_code"] for result in fixed}) != 1
    ):
        classification = "flaky"
    elif {result["exit_code"] for result in base} != {1}:
        classification = "does_not_fail_on_base"
    elif {result["exit_code"] for result in fixed} != {0}:
        classification = "does_not_pass_on_fixed"
    elif profile_id == "pytest-v1" and any(
        result["junit_sha256"] is None for result in all_results
    ):
        classification = "wrong_or_flaky_failure"
    else:
        fingerprints = [
            cast(dict[str, object], run)["failure_fingerprint_sha256"]
            for run in runs
            if cast(dict[str, object], run)["workspace"] == "base"
        ]
        classification = (
            "verified_reproduction"
            if None not in fingerprints and len(set(fingerprints)) == 1
            else "wrong_or_flaky_failure"
        )
    accepted = classification == "verified_reproduction"
    if (
        outcome.get("classification") != classification
        or outcome.get("accepted") is not accepted
        or outcome.get("base_consistency")
        != f"{sum(result['exit_code'] == 1 for result in base)}/{BASE_RUNS}"
        or outcome.get("fixed_consistency")
        != f"{sum(result['exit_code'] == 0 for result in fixed)}/{FIXED_RUNS}"
    ):
        raise _reject("Candidate receipt outcome does not recompute from bounded evidence.")


def _bounded_clean_result(value: dict[str, object], *, expected_exit: int) -> bool:
    return (
        value.get("exit_code") == expected_exit
        and value.get("timed_out") is False
        and value.get("oom_killed") is False
        and value.get("output_truncated") is False
    )


def _verify_evidence(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "exit_code",
        "junit_sha256",
        "oom_killed",
        "output_bytes",
        "output_sha256",
        "output_stored",
        "output_truncated",
        "timed_out",
    }:
        raise _reject("Candidate phase evidence is invalid.")
    exit_code = value.get("exit_code")
    output_bytes = value.get("output_bytes")
    if (
        type(exit_code) is not int
        or not 0 <= exit_code <= 255
        or type(output_bytes) is not int
        or not 0 <= output_bytes <= 2 * 1024 * 1024
        or value.get("output_stored") is not False
        or type(value.get("oom_killed")) is not bool
        or type(value.get("output_truncated")) is not bool
        or type(value.get("timed_out")) is not bool
    ):
        raise _reject("Candidate phase evidence values are invalid.")
    _digest(value.get("output_sha256"), "phase output")
    junit_sha256 = value.get("junit_sha256")
    if junit_sha256 is not None:
        _digest(junit_sha256, "JUnit")


def _has_infrastructure_marker(output: str) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in _INFRASTRUCTURE_MARKERS)


def _evaluation_policy(image: str) -> SandboxPolicy:
    return SandboxPolicy(
        image=image,
        timeout_seconds=600.0,
        max_output_bytes=2 * 1024 * 1024,
        memory_bytes=4 * 1024 * 1024 * 1024,
        cpus=2.0,
        pids=512,
        tmpfs_bytes=512 * 1024 * 1024,
        tmpfs_inodes=32_768,
    )


def _executor_factory(
    manifest: InstanceRuntimeManifest, case_id: str, policy: SandboxPolicy
) -> InstanceRuntimeExecutor:
    return InstanceRuntimeExecutor(manifest, case_id=case_id, policy=policy)


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Case ID is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} SHA-256 is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Execution timestamp is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned["receipt_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_candidate_evaluator", message)
