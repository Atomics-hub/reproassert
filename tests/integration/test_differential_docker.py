from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest

import reproassert.benchmark_v02_package as package_module
from reproassert.benchmark_v02_package import V02CaseIdentity
from reproassert.candidate import validate_candidate_payload
from reproassert.differential import DIFFERENTIAL_SCHEDULE, verify_differential_candidate
from reproassert.sandbox import DockerSandbox
from reproassert.source_attestation import ExpectedGitSpecialEntry, attest_source_tree


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1",
    reason="set REPROASSERT_RUN_DOCKER_TESTS=1 after building the sandbox image",
)
def test_real_docker_interleaves_buggy_failure_and_fixed_pass() -> None:
    repository = Path(__file__).parents[2]
    buggy_fixture = repository / "examples" / "fixtures" / "buggy_slug"
    fixed_fixture = repository / "examples" / "fixtures" / "fixed_slug"
    content = (buggy_fixture / "tests" / "reproassert" / "test_issue_1.py").read_text()
    candidate = validate_candidate_payload(
        {
            "test_content": content,
            "expected_symptom": "duplicate separators remain",
            "rationale": "Exercises repeated whitespace through the public slug function.",
        },
        issue_number=1,
    )
    sandbox = DockerSandbox()
    with tempfile.TemporaryDirectory(prefix="reproassert-differential-fixture-") as temporary:
        root = Path(temporary).resolve(strict=True)
        base = shutil.copytree(buggy_fixture, root / "base")
        fixed = shutil.copytree(fixed_fixture, root / "fixed")
        shutil.rmtree(base / "tests" / "reproassert")
        shutil.rmtree(fixed / "tests" / "reproassert")
        target = "slugger.py"
        target_bytes = target.encode()
        digest = hashlib.sha1(f"blob {len(target_bytes)}\0".encode(), usedforsecurity=False)
        digest.update(target_bytes)
        special_entries = (
            ExpectedGitSpecialEntry("slugger-link.py", "120000", digest.hexdigest(), target),
            ExpectedGitSpecialEntry("vendor", "160000", "1" * 40),
        )
        for source in (base, fixed):
            os.symlink(target, source / "slugger-link.py")
            (source / "vendor").mkdir()
        base_tree = attest_source_tree(base, expected_special_entries=special_entries)
        fixed_tree = attest_source_tree(fixed, expected_special_entries=special_entries)
        capability = package_module.VerifiedV02EvaluatorCapability(
            package_module._CAPABILITY_ISSUER,
            case=V02CaseIdentity(
                id="rk-v0.2-001",
                repo="owner/repo",
                issue_url="https://github.com/owner/repo/issues/1",
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
            upstream_instance_id="owner__repo-1",
            fixing_pr_number=1,
            evaluator_commitment_nonce="f" * 64,
            verification_completed_at="2026-07-10T14:00:00Z",
            base_commit_sha="a" * 40,
            base_root_tree_oid=base_tree.reconstructed_git_tree_oid,
            source_receipt_sha256="d" * 64,
            source_tree_sha256=base_tree.tree_sha256,
            source_context_algorithm="reproassert-v02-source-context-v1",
            source_context_policy_sha256="e" * 64,
            source_context_sha256="0" * 64,
            source_special_entries=special_entries,
            hidden_fixed_root_tree_oid=fixed_tree.reconstructed_git_tree_oid,
            fixing_head_commit_sha="d" * 40,
            fixing_head_root_tree_oid="e" * 40,
            production_patch_sha256="f" * 64,
            developer_tests_sha256="1" * 64,
            dependencies_required=False,
            dependency_receipt_sha256=None,
            dependency_plan_sha256=None,
            dependency_tree_sha256=None,
            dependency_runner_image_id=None,
            isolation_receipt_sha256="6" * 64,
            isolation_policy_sha256="7" * 64,
            reviewer_role_seal_sha256="8" * 64,
            semantic_verification_receipt_sha256="9" * 64,
        )

        result = verify_differential_candidate(
            sandbox=sandbox,
            base_source=base,
            fixed_source=fixed,
            relative_path="tests/reproassert/test_issue_1.py",
            candidate=candidate,
            evaluator_capability=capability,
            run_id="integration-differential",
        )

    assert result.accepted
    assert result.outcome == "differential_reproduction"
    assert tuple(item.source_role for item in result.scheduled_runs) == DIFFERENTIAL_SCHEDULE
    assert len(result.base_runs) == 3
    assert len(result.fixed_runs) == 3
    assert all(run.exit_code == 1 for run in result.base_runs)
    assert all(run.exit_code == 0 and run.output == "" for run in result.fixed_runs)
    assert not sandbox._containers
    assert not sandbox._volumes
