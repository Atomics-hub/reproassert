from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import reproassert.benchmark_v02_package as package_module
from reproassert.benchmark_v02_package import V02CaseIdentity, VerifiedV02EvaluatorCapability
from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.differential import DIFFERENTIAL_SCHEDULE, verify_differential_candidate
from reproassert.errors import PolicyRejection
from reproassert.sandbox import DockerRunResult
from reproassert.source_attestation import attest_source_tree


def _result(
    phase: str,
    *,
    exit_code: int,
    message: str = "",
    passed: bool = False,
    failure_type: str = "AssertionError",
) -> DockerRunResult:
    name = "test_issue_9_reproduction"
    if passed:
        xml = (
            '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            f'<testcase classname="test_issue_9" name="{name}" />'
            "</testsuite></testsuites>"
        ).encode()
        output = "1 passed in 0.01s"
    else:
        xml = (
            '<testsuites><testsuite tests="1" failures="1" errors="0" skipped="0">'
            f'<testcase classname="test_issue_9" name="{name}">'
            f'<failure type="{failure_type}" message="{message}">{message}</failure>'
            "</testcase></testsuite></testsuites>"
        ).encode()
        output = message
    return DockerRunResult(
        phase=phase,
        exit_code=exit_code,
        duration_seconds=0.01,
        output=output,
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        junit_xml=xml,
        container_name=phase,
    )


class _Sandbox:
    def __init__(self, executions: list[DockerRunResult]) -> None:
        self.executions = iter(executions)
        self.calls: list[dict[str, Any]] = []
        self.cleaned = False

    def stage_attested_source(self, source: Path, **_kwargs: object) -> str:
        return f"volume-{source.name}"

    @contextmanager
    def borrow_dependency_volume(self, _handle: object) -> Iterator[str]:
        yield "dependencies"

    def run_pytest(self, **kwargs: Any) -> DockerRunResult:
        self.calls.append(kwargs)
        return next(self.executions)

    def cleanup(self) -> None:
        self.cleaned = True


def _collection() -> DockerRunResult:
    return DockerRunResult(
        phase="collect",
        exit_code=0,
        duration_seconds=0.01,
        output="tests/reproassert/test_issue_9.py::test_issue_9_reproduction",
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        junit_xml=None,
        container_name="collect",
    )


def _workspaces(
    tmp_path: Path, *, symptom: str = "empty blueprint name"
) -> tuple[Path, Path, ValidatedCandidate, VerifiedV02EvaluatorCapability]:
    candidate = validate_candidate_payload(
        {
            "test_content": (
                "from example_project import normalize\n\n"
                "def test_issue_9_reproduction():\n"
                '    result = normalize("a//b")\n'
                f'    assert result == "a/b", "{symptom}"\n'
            ),
            "expected_symptom": symptom,
            "rationale": "Exercises the public normalization behavior.",
        },
        issue_number=9,
    )
    base = tmp_path / "base"
    fixed = tmp_path / "fixed"
    base.mkdir()
    fixed.mkdir()
    (base / "example_project.py").write_text("STATE = 'buggy'\n")
    (fixed / "example_project.py").write_text("STATE = 'fixed'\n")
    return base, fixed, candidate, _capability(base, fixed)


def _capability(
    base: Path,
    fixed: Path,
    *,
    dependencies_required: bool = False,
) -> VerifiedV02EvaluatorCapability:
    base_tree = attest_source_tree(base)
    fixed_tree = attest_source_tree(fixed)
    return package_module.VerifiedV02EvaluatorCapability(
        package_module._CAPABILITY_ISSUER,
        case=V02CaseIdentity(
            id="rk-v0.2-009",
            repo="owner/repo",
            issue_url="https://github.com/owner/repo/issues/9",
            base_sha="a" * 40,
        ),
        preregistration_sha256="6" * 64,
        cohort_sha256="7" * 64,
        preregistered_case_sha256="8" * 64,
        package_identity_sha256="b" * 64,
        public_commitment_sha256="c" * 64,
        generator_projection_sha256="9" * 64,
        dataset_evidence_sha256="a" * 64,
        difficulty="lt_15m",
        upstream_instance_id="owner__repo-9",
        fixing_pr_number=9,
        evaluator_commitment_nonce="f" * 64,
        verification_completed_at="2026-07-10T14:00:00Z",
        base_commit_sha="a" * 40,
        base_root_tree_oid=base_tree.reconstructed_git_tree_oid,
        source_receipt_sha256="d" * 64,
        source_tree_sha256=base_tree.tree_sha256,
        source_context_algorithm="reproassert-v02-source-context-v1",
        source_context_policy_sha256="e" * 64,
        source_context_sha256="0" * 64,
        hidden_fixed_root_tree_oid=fixed_tree.reconstructed_git_tree_oid,
        fixing_head_commit_sha="d" * 40,
        fixing_head_root_tree_oid="e" * 40,
        production_patch_sha256="f" * 64,
        developer_tests_sha256="1" * 64,
        dependencies_required=dependencies_required,
        dependency_receipt_sha256="2" * 64 if dependencies_required else None,
        dependency_plan_sha256="3" * 64 if dependencies_required else None,
        dependency_tree_sha256="4" * 64 if dependencies_required else None,
        dependency_runner_image_id=(f"sha256:{'5' * 64}" if dependencies_required else None),
        isolation_receipt_sha256="6" * 64,
        isolation_policy_sha256="7" * 64,
        reviewer_role_seal_sha256="8" * 64,
        semantic_verification_receipt_sha256="9" * 64,
    )


def test_interleaves_three_base_failures_and_three_fixed_passes(tmp_path: Path) -> None:
    symptom = "empty blueprint name"
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom=symptom)
    executions = [_collection()]
    for role in DIFFERENTIAL_SCHEDULE:
        executions.append(
            _result(
                role,
                exit_code=1 if role == "base" else 0,
                message=symptom,
                passed=role == "fixed",
            )
        )
    sandbox = _Sandbox(executions)

    result = verify_differential_candidate(
        sandbox=sandbox,  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert result.accepted
    assert result.claim_level.value == "differential_reproduction"
    assert result.outcome == "differential_reproduction"
    assert len(result.base_runs) == 3
    assert len(result.fixed_runs) == 3
    assert tuple(item.source_role for item in result.scheduled_runs) == DIFFERENTIAL_SCHEDULE
    assert [call["volume"] for call in sandbox.calls[1:]] == [
        "volume-base" if role == "base" else "volume-fixed" for role in DIFFERENTIAL_SCHEDULE
    ]
    assert all(call["dependency_volume"] is None for call in sandbox.calls)
    assert sandbox.cleaned


def test_rejects_incidental_base_failure_that_still_fails_on_fix(tmp_path: Path) -> None:
    symptom = "empty blueprint name"
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom=symptom)
    executions = [_collection()]
    executions.extend(_result(role, exit_code=1, message=symptom) for role in DIFFERENTIAL_SCHEDULE)

    result = verify_differential_candidate(
        sandbox=_Sandbox(executions),  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert not result.accepted
    assert result.claim_level.value == "repeatable_base_failure"
    assert result.outcome == "fail_on_fix"


def test_rejects_flaky_fixed_execution(tmp_path: Path) -> None:
    symptom = "empty blueprint name"
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom=symptom)
    executions = [_collection()]
    fixed_seen = 0
    for role in DIFFERENTIAL_SCHEDULE:
        if role == "fixed":
            fixed_seen += 1
        passes = role == "fixed" and fixed_seen != 2
        executions.append(
            _result(
                role,
                exit_code=0 if passes else 1,
                message=symptom,
                passed=passes,
            )
        )

    result = verify_differential_candidate(
        sandbox=_Sandbox(executions),  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert not result.accepted
    assert result.outcome == "flaky_fix"


def test_collection_failure_stops_before_hidden_fixed_execution(tmp_path: Path) -> None:
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom="symptom")
    collection = DockerRunResult(
        phase="collect",
        exit_code=2,
        duration_seconds=0.01,
        output="ModuleNotFoundError: missing",
        timed_out=False,
        oom_killed=False,
        output_truncated=False,
        junit_xml=None,
        container_name="collect",
    )
    sandbox = _Sandbox([collection])

    result = verify_differential_candidate(
        sandbox=sandbox,  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert not result.accepted
    assert result.outcome == "setup_failure"
    assert result.scheduled_runs == ()
    assert len(sandbox.calls) == 1
    assert sandbox.cleaned


def test_rejects_fixed_source_drift_from_causal_capability(tmp_path: Path) -> None:
    base, fixed, candidate, capability = _workspaces(tmp_path)
    (fixed / "example_project.py").write_text("STATE = 'invented fix'\n", encoding="utf-8")
    sandbox = _Sandbox([])

    with pytest.raises(PolicyRejection, match="Git tree"):
        verify_differential_candidate(
            sandbox=sandbox,  # type: ignore[arg-type]
            base_source=base,
            fixed_source=fixed,
            relative_path="tests/reproassert/test_issue_9.py",
            candidate=candidate,
            evaluator_capability=capability,
            run_id="case-9",
        )

    assert not sandbox.calls


def test_rejects_extra_generated_fixture_drift(tmp_path: Path) -> None:
    base, fixed, candidate, _ = _workspaces(tmp_path)
    (fixed / "tests" / "reproassert").mkdir(parents=True)
    (fixed / "tests" / "reproassert" / "fixture.py").write_text(
        "SECRET = 'hidden evaluator drift'\n",
        encoding="utf-8",
    )
    capability = _capability(base, fixed)
    sandbox = _Sandbox([])

    with pytest.raises(PolicyRejection, match="reserved candidate directory"):
        verify_differential_candidate(
            sandbox=sandbox,  # type: ignore[arg-type]
            base_source=base,
            fixed_source=fixed,
            relative_path="tests/reproassert/test_issue_9.py",
            candidate=candidate,
            evaluator_capability=capability,
            run_id="case-9",
        )

    assert not sandbox.calls


def test_dependency_required_capability_rejects_missing_handle(tmp_path: Path) -> None:
    base, fixed, candidate, _ = _workspaces(tmp_path)
    capability = _capability(base, fixed, dependencies_required=True)

    with pytest.raises(PolicyRejection, match="handle presence"):
        verify_differential_candidate(
            sandbox=_Sandbox([]),  # type: ignore[arg-type]
            base_source=base,
            fixed_source=fixed,
            relative_path="tests/reproassert/test_issue_9.py",
            candidate=candidate,
            evaluator_capability=capability,
            run_id="case-9",
        )


def test_dependency_required_capability_rejects_mismatched_live_receipt(
    tmp_path: Path,
) -> None:
    base, fixed, candidate, _ = _workspaces(tmp_path)
    capability = _capability(base, fixed, dependencies_required=True)
    handle = SimpleNamespace(
        execution_receipt_sha256="9" * 64,
        labels=(("io.reproassert.plan-sha256", "3" * 64),),
        tree_attestation=SimpleNamespace(tree_sha256="4" * 64),
        image_id=f"sha256:{'5' * 64}",
    )
    sandbox = _Sandbox([])

    with pytest.raises(PolicyRejection, match="differs from evaluator capability"):
        verify_differential_candidate(
            sandbox=sandbox,  # type: ignore[arg-type]
            base_source=base,
            fixed_source=fixed,
            relative_path="tests/reproassert/test_issue_9.py",
            candidate=candidate,
            evaluator_capability=capability,
            run_id="case-9",
            dependency_handle=handle,  # type: ignore[arg-type]
        )

    assert sandbox.cleaned
    assert not sandbox.calls


def test_fixed_pass_stdout_fallback_does_not_accept_eleven_tests(tmp_path: Path) -> None:
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom="symptom")
    symptom = "symptom"
    executions = [_collection()]
    for role in DIFFERENTIAL_SCHEDULE:
        if role == "base":
            executions.append(_result(role, exit_code=1, message=symptom))
        else:
            executions.append(
                DockerRunResult(
                    phase=role,
                    exit_code=0,
                    duration_seconds=0.01,
                    output="11 passed in 0.01s",
                    timed_out=False,
                    oom_killed=False,
                    output_truncated=False,
                    junit_xml=None,
                    container_name=role,
                )
            )

    result = verify_differential_candidate(
        sandbox=_Sandbox(executions),  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert not result.accepted
    assert result.outcome == "benchmark_infrastructure_error"
    assert result.claim_level.value == "rejected"


def test_fixed_pass_rejects_malformed_present_junit_even_with_valid_stdout(
    tmp_path: Path,
) -> None:
    symptom = "symptom"
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom=symptom)
    executions = [_collection()]
    for role in DIFFERENTIAL_SCHEDULE:
        if role == "base":
            executions.append(_result(role, exit_code=1, message=symptom))
        else:
            executions.append(
                DockerRunResult(
                    phase=role,
                    exit_code=0,
                    duration_seconds=0.01,
                    output="1 passed in 0.01s",
                    timed_out=False,
                    oom_killed=False,
                    output_truncated=False,
                    junit_xml=b"<testsuites>",
                    container_name=role,
                )
            )

    result = verify_differential_candidate(
        sandbox=_Sandbox(executions),  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert not result.accepted
    assert result.outcome == "benchmark_infrastructure_error"
    assert result.claim_level.value == "rejected"


def test_fixed_evaluator_output_is_redacted_before_return(tmp_path: Path) -> None:
    symptom = "symptom"
    base, fixed, candidate, capability = _workspaces(tmp_path, symptom=symptom)
    executions = [_collection()]
    for role in DIFFERENTIAL_SCHEDULE:
        run = _result(
            role,
            exit_code=1 if role == "base" else 0,
            message=symptom,
            passed=role == "fixed",
        )
        if role == "fixed":
            run = DockerRunResult(
                **{
                    **run.__dict__,
                    "output": "HIDDEN_FIXED_SENTINEL\n1 passed in 0.01s",
                }
            )
        executions.append(run)

    result = verify_differential_candidate(
        sandbox=_Sandbox(executions),  # type: ignore[arg-type]
        base_source=base,
        fixed_source=fixed,
        relative_path="tests/reproassert/test_issue_9.py",
        candidate=candidate,
        evaluator_capability=capability,
        run_id="case-9",
    )

    assert result.accepted
    assert all(run.output == "" and run.junit_xml is None for run in result.fixed_runs)
    public = result.public_record()
    serialized = json.dumps(public)
    assert "HIDDEN_FIXED_SENTINEL" not in serialized
    assert result.fixed_tree is not None
    assert result.fixed_tree.reconstructed_git_tree_oid not in serialized
    assert public["fixed_evaluation"] == {
        "executed": True,
        "run_count": 3,
        "per_run_evidence_redacted": True,
    }
    assert len(public["base_schedule"]) == 3
    assert all(run["source_role"] == "base" for run in public["base_schedule"])
    for run in result.scheduled_runs:
        if run.source_role != "fixed":
            continue
        assert run.output_sha256 not in serialized
        assert run.junit_sha256 is not None
        assert run.junit_sha256 not in serialized
    assert "receipt_sha256" not in serialized
    assert "plan_sha256" not in serialized
    assert "tree_sha256" not in public.get("dependency", {})
    assert "image_id" not in serialized
