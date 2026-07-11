from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

import reproassert.benchmark_v02_exact_controls as controls
from reproassert.benchmark_v02_candidate_evaluator import (
    CandidateArtifact,
    CandidateExecutionProfile,
    _candidate_fingerprint_or_none,
)
from reproassert.benchmark_v02_instance_executor import InstancePytestResult
from reproassert.benchmark_v02_instance_runtime import InstanceRuntime, InstanceRuntimeManifest
from reproassert.errors import PolicyRejection

PATCH = (
    b"diff --git a/pkg/mod.py b/pkg/mod.py\n"
    b"index 1111111..2222222 100644\n"
    b"--- a/pkg/mod.py\n+++ b/pkg/mod.py\n"
    b"@@ -1,1 +1,1 @@\n-old_one\n+new_one\n"
    b"diff --git a/pkg/other.py b/pkg/other.py\n"
    b"index 3333333..4444444 100644\n"
    b"--- a/pkg/other.py\n+++ b/pkg/other.py\n"
    b"@@ -10,1 +10,1 @@\n-old_two\n+new_two\n"
)

SAME_FILE_PATCH = (
    b"diff --git a/pkg/mod.py b/pkg/mod.py\n"
    b"index 1111111..2222222 100644\n"
    b"--- a/pkg/mod.py\n+++ b/pkg/mod.py\n"
    b"@@ -1,1 +1,1 @@\n-old_one\n+new_one\n"
    b"@@ -10,1 +10,1 @@\n-old_two\n+new_two\n"
)


def _manifest() -> InstanceRuntimeManifest:
    return InstanceRuntimeManifest(
        harness_git_sha="a" * 40,
        harness_specs_sha256="b" * 64,
        entries=(
            InstanceRuntime(
                case_id="rk-v0.2-001",
                instance_id="project__repo-1001",
                base_sha="c" * 40,
                base_tree_oid="d" * 40,
                spec_sha256="e" * 64,
                image_tag="swebench/sweb.eval.x86_64.project_repo-1001:v1",
                image_digest=f"sha256:{'f' * 64}",
                image_id=f"sha256:{'1' * 64}",
                test_command_profile="pytest-v1",
            ),
        ),
        sha256="2" * 64,
    )


class FakeExecutor:
    def __init__(self) -> None:
        self.fixed_patch = b""
        self.base_plus = False

    def __enter__(self) -> FakeExecutor:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def acquire(self) -> None:
        return None

    def prepare_workspaces(self, *, fixed_patch: bytes) -> None:
        self.fixed_patch = fixed_patch

    def apply_patch(self, *, workspace: str, patch: bytes) -> None:
        assert workspace == "base" and patch
        self.base_plus = True

    def stage_candidate(self, *, relative_path: str, content: bytes) -> None:
        assert relative_path == "tests/reproassert/test_generated.py" and content

    def run_pytest(
        self, *, workspace: str, targets: tuple[str, ...], collect_only: bool = False
    ) -> InstancePytestResult:
        assert targets == ("tests/reproassert/test_generated.py::test_bug",)
        if collect_only:
            code, output, junit = 0, "collected 1 item", None
        elif self.base_plus or (workspace == "fixed" and self.fixed_patch == PATCH):
            code, output, junit = (
                0,
                "1 passed",
                b'<testsuite><testcase name="test_bug"/></testsuite>',
            )
        else:
            code, output = 1, "assertion failed"
            junit = (
                b'<testsuite><testcase name="test_bug"><failure type="AssertionError">'
                b"stable failure</failure></testcase></testsuite>"
            )
        return InstancePytestResult(
            workspace=workspace,  # type: ignore[arg-type]
            exit_code=code,
            output=output,
            timed_out=False,
            output_truncated=False,
            junit_xml=junit,
        )


def test_executes_three_controls_in_nine_fresh_contexts() -> None:
    inventory = controls.inventory_unified_diff(PATCH, case_id="rk-v0.2-001")
    selected, remainder, reason = controls._partition_patch(
        PATCH,
        case_id="rk-v0.2-001",
        selected_ids=(str(inventory[0]["atomic_id"]),),
    )
    assert reason is None and selected and remainder
    profile = CandidateExecutionProfile(
        "pytest-v1", "tests/reproassert/test_generated.py", "test_bug", "pytest-v1"
    )
    candidate = CandidateArtifact(
        profile.staging_path, b"def test_bug(): assert True\n", "test_bug"
    )
    failure = FakeExecutor().run_pytest(
        workspace="fixed", targets=(f"{profile.staging_path}::{profile.required_function}",)
    )
    fingerprint = _candidate_fingerprint_or_none(failure, profile=profile)
    assert fingerprint is not None
    created: list[FakeExecutor] = []

    def factory(*_args: object) -> FakeExecutor:
        executor = FakeExecutor()
        created.append(executor)
        return executor

    results = [
        controls._run_control(
            name=name,
            manifest=_manifest(),
            case_id="rk-v0.2-001",
            profile=profile,
            candidate=candidate,
            full_patch=PATCH,
            selected_patch=selected,
            remainder_patch=remainder,
            expected_failure_fingerprint=fingerprint,
            executor_factory=factory,  # type: ignore[arg-type]
        )
        for name in ("full_fix", "fix_minus_selected", "base_plus_selected")
    ]
    assert len(created) == 9
    assert [result["status"] for result in results] == ["conclusive_pass"] * 3
    assert all(len(result["runs"]) == 3 for result in results)


def test_patch_algebra_supports_all_selected_and_rejects_inseparable_or_noncommutative() -> None:
    inventory = controls.inventory_unified_diff(PATCH, case_id="rk-v0.2-001")
    ids = tuple(str(row["atomic_id"]) for row in inventory)
    selected, remainder, reason = controls._partition_patch(
        PATCH, case_id="rk-v0.2-001", selected_ids=ids
    )
    assert selected == PATCH
    assert remainder == b""
    assert reason is None
    assert (
        controls._partition_patch(
            PATCH, case_id="rk-v0.2-001", selected_ids=("rk-v0.2-001:h999:0000000000000000",)
        )[2]
        == "inseparable_mapping"
    )


def test_all_selected_mapping_runs_fix_minus_control_on_true_buggy_base() -> None:
    inventory = controls.inventory_unified_diff(PATCH, case_id="rk-v0.2-001")
    ids = tuple(str(row["atomic_id"]) for row in inventory)
    selected, remainder, reason = controls._partition_patch(
        PATCH, case_id="rk-v0.2-001", selected_ids=ids
    )
    assert selected == PATCH and remainder == b"" and reason is None
    profile = CandidateExecutionProfile(
        "pytest-v1", "tests/reproassert/test_generated.py", "test_bug", "pytest-v1"
    )
    candidate = CandidateArtifact(
        profile.staging_path, b"def test_bug(): assert True\n", "test_bug"
    )
    failure = FakeExecutor().run_pytest(
        workspace="base", targets=(f"{profile.staging_path}::{profile.required_function}",)
    )
    fingerprint = _candidate_fingerprint_or_none(failure, profile=profile)
    assert fingerprint is not None
    created: list[FakeExecutor] = []

    def factory(*_args: object) -> FakeExecutor:
        executor = FakeExecutor()
        created.append(executor)
        return executor

    result = controls._run_control(
        name="fix_minus_selected",
        manifest=_manifest(),
        case_id="rk-v0.2-001",
        profile=profile,
        candidate=candidate,
        full_patch=PATCH,
        selected_patch=selected,
        remainder_patch=remainder,
        expected_failure_fingerprint=fingerprint,
        executor_factory=factory,  # type: ignore[arg-type]
    )
    assert result["status"] == "conclusive_pass"
    assert len(created) == 3
    same_file_ids = controls.inventory_unified_diff(SAME_FILE_PATCH, case_id="rk-v0.2-001")
    assert (
        controls._partition_patch(
            SAME_FILE_PATCH,
            case_id="rk-v0.2-001",
            selected_ids=(str(same_file_ids[0]["atomic_id"]),),
        )[2]
        == "noncommutative_same_file_hunks"
    )


def test_receipt_verifier_rejects_forged_l2_and_schema_accepts_honest_inconclusive(
    tmp_path: Path,
) -> None:
    record: dict[str, object] = {
        "algorithm": controls.ALGORITHM,
        "benchmark_version": "0.2",
        "candidate": {
            "evaluation_receipt_sha256": "1" * 64,
            "failure_fingerprint_sha256": "2" * 64,
            "profile_sha256": "3" * 64,
            "sha256": "4" * 64,
        },
        "case_id": "rk-v0.2-001",
        "claims": {
            "hidden_bytes_emitted": False,
            "l2_causal_controls_passed": False,
            "network_during_sandbox_execution": False,
            "provider_calls": 0,
        },
        "controls": [
            controls._inconclusive_control(name, "degenerate_fix_minus_empty")
            for name in ("full_fix", "fix_minus_selected", "base_plus_selected")
        ],
        "evaluator_public_commitment_sha256": "5" * 64,
        "executed_at": "2026-07-11T12:00:00Z",
        "mapping": {
            "consensus_sha256": "6" * 64,
            "selected_hunk_count": 1,
            "selected_hunks_sha256": "7" * 64,
        },
        "policy": {
            "fresh_contexts_per_control": 3,
            "network_mode": "none",
            "profile": "reproassert-v02-exact-image-causal-controls-v1",
        },
        "receipt_sha256": "0" * 64,
        "schema_version": "1.0.0",
        "status": "inconclusive_no_l2_claim",
        "tool_git_sha": "8" * 40,
    }
    record["receipt_sha256"] = controls._self_hash(record)
    path = tmp_path / "controls.json"
    path.write_bytes(controls._canonical(record) + b"\n")
    assert not controls.verify_exact_image_causal_control_receipt(path).l2_causal_controls_passed
    schema = json.loads(
        Path("schemas/benchmark-v02-exact-image-causal-controls.schema.json").read_text()
    )
    jsonschema.validate(record, schema)
    assert (
        Path(
            "src/reproassert/schemas/benchmark-v02-exact-image-causal-controls.schema.json"
        ).read_bytes()
        == Path("schemas/benchmark-v02-exact-image-causal-controls.schema.json").read_bytes()
    )

    record["policy"]["network_mode"] = "bridge"  # type: ignore[index]
    record["receipt_sha256"] = controls._self_hash(record)
    path.write_bytes(controls._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="execution policy"):
        controls.verify_exact_image_causal_control_receipt(path)
    record["policy"]["network_mode"] = "none"  # type: ignore[index]

    record["claims"]["l2_causal_controls_passed"] = True  # type: ignore[index]
    record["status"] = "l2_controls_passed"
    record["receipt_sha256"] = controls._self_hash(record)
    path.write_bytes(controls._canonical(record) + b"\n")
    with pytest.raises(PolicyRejection, match="claims disagree"):
        controls.verify_exact_image_causal_control_receipt(path)
