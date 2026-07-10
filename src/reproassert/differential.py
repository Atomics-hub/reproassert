from __future__ import annotations

import hashlib
import re
import tempfile
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from reproassert.benchmark_v02_package import (
    VerifiedV02EvaluatorCapability,
    require_v02_evaluator_capability,
)
from reproassert.candidate import (
    ValidatedCandidate,
    candidate_function,
    validate_candidate_payload,
)
from reproassert.candidate_workspace import prepare_candidate_workspace
from reproassert.errors import PolicyRejection
from reproassert.intake import parse_issue_url
from reproassert.models import ClaimLevel
from reproassert.sandbox import DockerRunResult, DockerSandbox
from reproassert.source_attestation import SourceTreeAttestation, attest_source_tree
from reproassert.verifier import (
    JunitSummary,
    VerificationOutcome,
    classify_base_runs,
    classify_collection_run,
    parse_junit,
)

if TYPE_CHECKING:
    from reproassert.dependency_executor import DependencyVolumeHandle

DIFFERENTIAL_SCHEDULE = ("base", "fixed", "fixed", "base", "base", "fixed")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ScheduledRun:
    source_role: str
    role_ordinal: int
    schedule_ordinal: int
    result: DockerRunResult
    output_sha256: str
    junit_sha256: str | None
    evaluator_output_redacted: bool


@dataclass(frozen=True)
class DifferentialVerificationOutcome:
    accepted: bool
    claim_level: ClaimLevel
    outcome: str
    fingerprint: str | None
    base_verification: VerificationOutcome
    scheduled_runs: tuple[ScheduledRun, ...]
    base_tree: SourceTreeAttestation
    fixed_tree: SourceTreeAttestation | None
    evaluator_capability_sha256: str
    evaluator_package_sha256: str
    evaluator_public_commitment_sha256: str
    dependency_receipt_sha256: str | None
    dependency_plan_sha256: str | None
    dependency_tree_sha256: str | None
    dependency_image_id: str | None

    @property
    def base_runs(self) -> tuple[DockerRunResult, ...]:
        return tuple(item.result for item in self.scheduled_runs if item.source_role == "base")

    @property
    def fixed_runs(self) -> tuple[DockerRunResult, ...]:
        return tuple(item.result for item in self.scheduled_runs if item.source_role == "fixed")

    def public_record(self) -> dict[str, object]:
        """Project the evaluator result without raw fixed-tree process evidence."""

        return {
            "accepted": self.accepted,
            "claim_level": self.claim_level.value,
            "outcome": self.outcome,
            "fingerprint": self.fingerprint,
            "schedule": [
                {
                    "source_role": item.source_role,
                    "role_ordinal": item.role_ordinal,
                    "schedule_ordinal": item.schedule_ordinal,
                    "exit_code": item.result.exit_code,
                    "duration_seconds": item.result.duration_seconds,
                    "timed_out": item.result.timed_out,
                    "oom_killed": item.result.oom_killed,
                    "output_truncated": item.result.output_truncated,
                    "output_sha256": item.output_sha256,
                    "junit_sha256": item.junit_sha256,
                    "evaluator_output_redacted": item.evaluator_output_redacted,
                }
                for item in self.scheduled_runs
            ],
            "base_tree": asdict(self.base_tree),
            "fixed_tree_redacted": self.fixed_tree is not None,
            "evaluator_commitment_sha256": self.evaluator_public_commitment_sha256,
            "dependency": {
                "receipt_sha256": self.dependency_receipt_sha256,
                "plan_sha256": self.dependency_plan_sha256,
                "tree_sha256": self.dependency_tree_sha256,
                "image_id": self.dependency_image_id,
            },
        }


def verify_differential_candidate(
    *,
    sandbox: DockerSandbox,
    base_source: Path,
    fixed_source: Path,
    relative_path: str,
    candidate: ValidatedCandidate,
    evaluator_capability: VerifiedV02EvaluatorCapability,
    run_id: str,
    dependency_handle: DependencyVolumeHandle | None = None,
) -> DifferentialVerificationOutcome:
    """Run the frozen interleaved buggy/fixed evaluator schedule.

    Both source paths must be pristine trees. The nominal evaluator capability binds their exact
    Git identities; this controller copies them into private workspaces, adds only the revalidated
    candidate, attests the staged bytes, and never invokes a generator. Raw fixed-container output
    and JUnit bytes are reduced to digests before return.
    """

    capability = require_v02_evaluator_capability(evaluator_capability)
    issue = parse_issue_url(capability.case.issue_url)
    candidate_path = _candidate_path(relative_path, candidate.test_function)
    if candidate_path.name != f"test_issue_{issue.number}.py":
        raise PolicyRejection(
            "differential_candidate", "Candidate path does not match the evaluator issue."
        )
    revalidated = validate_candidate_payload(
        {
            "test_content": candidate.test_content,
            "expected_symptom": candidate.expected_symptom,
            "rationale": candidate.rationale,
        },
        issue_number=issue.number,
    )
    if revalidated != candidate:
        raise PolicyRejection(
            "differential_candidate", "Candidate does not match strict policy revalidation."
        )
    candidate_sha256 = candidate.sha256
    if _SHA256.fullmatch(candidate_sha256) is None:
        raise PolicyRejection("differential_candidate", "Candidate SHA-256 is invalid.")
    if capability.case.base_sha != capability.base_commit_sha:
        raise PolicyRejection(
            "differential_capability", "Evaluator base commit identity is inconsistent."
        )

    with tempfile.TemporaryDirectory(prefix="reproassert-differential-") as temporary:
        workspace_root = Path(temporary).resolve(strict=True)
        base_expected = attest_source_tree(
            base_source,
            expected_git_tree_oid=capability.base_root_tree_oid,
        )
        if base_expected.tree_sha256 != capability.source_tree_sha256:
            raise PolicyRejection(
                "differential_base_tree", "Buggy source tree differs from evaluator capability."
            )
        base_prepared = prepare_candidate_workspace(
            source=base_source,
            destination=workspace_root / "base",
            relative_path=relative_path,
            candidate=candidate,
            expected_pristine=base_expected,
        )
        fixed_expected = attest_source_tree(
            fixed_source,
            expected_git_tree_oid=capability.hidden_fixed_root_tree_oid,
        )
        fixed_prepared = prepare_candidate_workspace(
            source=fixed_source,
            destination=workspace_root / "fixed",
            relative_path=relative_path,
            candidate=candidate,
            expected_pristine=fixed_expected,
        )
        base_workspace = base_prepared.path
        base_tree = base_prepared.candidate_applied_tree
        fixed_workspace = fixed_prepared.path
        fixed_tree = fixed_prepared.candidate_applied_tree
        target = f"{candidate_path.as_posix()}::{candidate.test_function}"
        scheduled: list[ScheduledRun] = []
        raw_base_runs: list[DockerRunResult] = []
        raw_fixed_runs: list[DockerRunResult] = []
        if capability.dependencies_required != (dependency_handle is not None):
            raise PolicyRejection(
                "differential_dependencies",
                "Evaluator dependency capability and live handle presence differ.",
            )
        dependency_context = (
            nullcontext(None)
            if dependency_handle is None
            else sandbox.borrow_dependency_volume(dependency_handle)
        )
        try:
            with dependency_context as dependency_volume:
                dependency_receipt_sha256 = None
                dependency_plan_sha256 = None
                dependency_tree_sha256 = None
                dependency_image_id = None
                if dependency_handle is not None:
                    dependency_receipt_sha256 = dependency_handle.execution_receipt_sha256
                    dependency_plan_sha256 = dict(dependency_handle.labels).get(
                        "io.reproassert.plan-sha256"
                    )
                    dependency_tree_sha256 = dependency_handle.tree_attestation.tree_sha256
                    dependency_image_id = dependency_handle.image_id
                    if (
                        dependency_receipt_sha256 != capability.dependency_receipt_sha256
                        or dependency_plan_sha256 != capability.dependency_plan_sha256
                        or dependency_tree_sha256 != capability.dependency_tree_sha256
                        or dependency_image_id != capability.dependency_runner_image_id
                    ):
                        raise PolicyRejection(
                            "differential_dependencies",
                            "Live dependency evidence differs from evaluator capability.",
                        )

                def outcome(
                    *,
                    accepted: bool,
                    claim_level: ClaimLevel,
                    outcome_code: str,
                    fingerprint: str | None,
                    base_verification: VerificationOutcome,
                    runs: tuple[ScheduledRun, ...],
                    include_fixed_tree: bool,
                ) -> DifferentialVerificationOutcome:
                    return DifferentialVerificationOutcome(
                        accepted=accepted,
                        claim_level=claim_level,
                        outcome=outcome_code,
                        fingerprint=fingerprint,
                        base_verification=base_verification,
                        scheduled_runs=runs,
                        base_tree=base_tree,
                        fixed_tree=fixed_tree if include_fixed_tree else None,
                        evaluator_capability_sha256=capability.capability_sha256,
                        evaluator_package_sha256=capability.package_identity_sha256,
                        evaluator_public_commitment_sha256=(capability.public_commitment_sha256),
                        dependency_receipt_sha256=dependency_receipt_sha256,
                        dependency_plan_sha256=dependency_plan_sha256,
                        dependency_tree_sha256=dependency_tree_sha256,
                        dependency_image_id=dependency_image_id,
                    )

                base_volume = sandbox.stage_attested_source(
                    base_workspace,
                    run_id=f"{run_id}-base",
                    expected=base_tree,
                )
                collection = sandbox.run_pytest(
                    volume=base_volume,
                    dependency_volume=dependency_volume,
                    target=target,
                    phase="collect_base",
                    run_id=run_id,
                    collect_only=True,
                )
                collection_rejection = classify_collection_run(collection, target)
                if collection_rejection:
                    base = VerificationOutcome(
                        False,
                        ClaimLevel.REJECTED,
                        collection_rejection,
                        None,
                        collection,
                        (),
                    )
                    return outcome(
                        accepted=False,
                        claim_level=ClaimLevel.REJECTED,
                        outcome_code=collection_rejection,
                        fingerprint=None,
                        base_verification=base,
                        runs=(),
                        include_fixed_tree=False,
                    )

                fixed_volume = sandbox.stage_attested_source(
                    fixed_workspace,
                    run_id=f"{run_id}-fixed",
                    expected=fixed_tree,
                )
                role_counts = {"base": 0, "fixed": 0}
                for schedule_ordinal, source_role in enumerate(DIFFERENTIAL_SCHEDULE, start=1):
                    role_counts[source_role] += 1
                    role_ordinal = role_counts[source_role]
                    result = sandbox.run_pytest(
                        volume=base_volume if source_role == "base" else fixed_volume,
                        dependency_volume=dependency_volume,
                        target=target,
                        phase=f"{source_role}_{role_ordinal}",
                        run_id=run_id,
                    )
                    if source_role == "base":
                        raw_base_runs.append(result)
                    else:
                        raw_fixed_runs.append(result)
                    junit_sha256 = (
                        hashlib.sha256(result.junit_xml).hexdigest()
                        if result.junit_xml is not None
                        else None
                    )
                    stored_result = (
                        result
                        if source_role == "base"
                        else replace(result, output="", junit_xml=None)
                    )
                    scheduled.append(
                        ScheduledRun(
                            source_role=source_role,
                            role_ordinal=role_ordinal,
                            schedule_ordinal=schedule_ordinal,
                            result=stored_result,
                            output_sha256=hashlib.sha256(result.output.encode("utf-8")).hexdigest(),
                            junit_sha256=junit_sha256,
                            evaluator_output_redacted=source_role == "fixed",
                        )
                    )

                base_runs = tuple(raw_base_runs)
                base_outcome, fingerprint = classify_base_runs(
                    base_runs,
                    expected_symptom=candidate.expected_symptom,
                    test_function=candidate.test_function,
                )
                base_accepted = base_outcome == "repeatable_base_failure"
                base = VerificationOutcome(
                    base_accepted,
                    ClaimLevel.REPEATABLE_BASE_FAILURE if base_accepted else ClaimLevel.COLLECTED,
                    base_outcome,
                    fingerprint,
                    collection,
                    base_runs,
                )
                if not base_accepted:
                    return outcome(
                        accepted=False,
                        claim_level=base.claim_level,
                        outcome_code=base_outcome,
                        fingerprint=fingerprint,
                        base_verification=base,
                        runs=tuple(scheduled),
                        include_fixed_tree=True,
                    )

                fixed_runs = tuple(raw_fixed_runs)
                fixed_outcome = _classify_fixed_runs(
                    fixed_runs, test_function=candidate.test_function
                )
                if fixed_outcome == "benchmark_infrastructure_error":
                    return outcome(
                        accepted=False,
                        claim_level=ClaimLevel.REJECTED,
                        outcome_code=fixed_outcome,
                        fingerprint=fingerprint,
                        base_verification=base,
                        runs=tuple(scheduled),
                        include_fixed_tree=True,
                    )
                accepted = fixed_outcome == "fixed_pass"
                return outcome(
                    accepted=accepted,
                    claim_level=(
                        ClaimLevel.DIFFERENTIAL_REPRODUCTION
                        if accepted
                        else ClaimLevel.REPEATABLE_BASE_FAILURE
                    ),
                    outcome_code=("differential_reproduction" if accepted else fixed_outcome),
                    fingerprint=fingerprint,
                    base_verification=base,
                    runs=tuple(scheduled),
                    include_fixed_tree=True,
                )
        finally:
            sandbox.cleanup()


def _classify_fixed_runs(runs: tuple[DockerRunResult, ...], *, test_function: str) -> str:
    if len(runs) != 3:
        return "fail_on_fix"
    if any(
        run.timed_out or run.oom_killed or run.output_truncated or run.exit_code is None
        for run in runs
    ):
        return "benchmark_infrastructure_error"
    if any(run.junit_xml is None or parse_junit(run.junit_xml) is None for run in runs):
        return "benchmark_infrastructure_error"
    passed = tuple(_is_exact_target_pass(run, test_function=test_function) for run in runs)
    if all(passed):
        return "fixed_pass"
    if any(passed):
        return "flaky_fix"
    return "fail_on_fix"


def _is_exact_target_pass(run: DockerRunResult, *, test_function: str) -> bool:
    if run.exit_code != 0:
        return False
    summary = parse_junit(run.junit_xml)
    return summary is not None and _summary_is_exact_target_pass(
        summary, test_function=test_function
    )


def _summary_is_exact_target_pass(summary: JunitSummary, *, test_function: str) -> bool:
    return (
        summary.tests == 1
        and summary.failures == 0
        and summary.errors == 0
        and summary.skipped == 0
        and len(summary.cases) == 1
        and summary.cases[0].name == test_function
        and summary.cases[0].failure_type is None
    )


def _candidate_path(value: str, test_function: str) -> PurePosixPath:
    path = PurePosixPath(value)
    match = re.fullmatch(r"test_issue_([1-9][0-9]*)\.py", path.name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or len(path.parts) != 3
        or path.parts[:2] != ("tests", "reproassert")
        or match is None
        or candidate_function(int(match.group(1))) != test_function
    ):
        raise PolicyRejection(
            "differential_candidate", "Candidate path is outside the controller-owned test tree."
        )
    return path
