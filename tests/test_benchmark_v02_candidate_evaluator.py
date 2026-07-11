from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

import reproassert.benchmark_v02_candidate_evaluator as evaluator
from reproassert.benchmark_v02_candidate_evaluator import (
    CandidateArtifact,
    HiddenEvaluatorInputs,
)
from reproassert.benchmark_v02_instance_executor import InstancePytestResult
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    instance_runtime_manifest_bytes,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection
from reproassert.sandbox import SandboxPolicy
from reproassert.schema import schema_text


def _manifest(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "manifest.json"
    path.write_bytes(
        instance_runtime_manifest_bytes(
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
        )
    )
    return path, load_instance_runtime_manifest(path).sha256


def _sympy_manifest(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "sympy-manifest.json"
    path.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="a" * 40,
            harness_specs_sha256="b" * 64,
            entries=(
                InstanceRuntime(
                    case_id="rk-v0.2-016",
                    instance_id="sympy__sympy-15345",
                    base_sha="c" * 40,
                    base_tree_oid="d" * 40,
                    spec_sha256="e" * 64,
                    image_tag="swebench/sweb.eval.x86_64.sympy_1776_sympy-15345:v1",
                    image_digest=f"sha256:{'f' * 64}",
                    image_id=f"sha256:{'1' * 64}",
                    test_command_profile="sympy-bin-test-v1",
                ),
            ),
        )
    )
    return path, load_instance_runtime_manifest(path).sha256


class FakeExecutor:
    def __init__(self, *, candidate_base_codes: tuple[int, ...] = (1, 1, 1)) -> None:
        self.candidate_base_codes = list(candidate_base_codes)
        self.candidate_staged = False
        self.patch_calls: list[tuple[str, bytes]] = []
        self.prepare_count = 0
        self.observed_candidate_workspaces: list[str] = []

    def __enter__(self) -> FakeExecutor:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def acquire(self) -> None:
        return None

    def prepare_workspaces(self, *, fixed_patch: bytes) -> None:
        assert fixed_patch == b"PRIVATE PRODUCTION FIX"
        self.prepare_count += 1
        self.candidate_staged = False
        self.patch_calls = []

    def apply_patch(self, *, workspace: str, patch: bytes) -> None:
        self.patch_calls.append((workspace, patch))
        assert patch == b"PRIVATE GOLD TESTS"

    def stage_candidate(self, *, relative_path: str, content: bytes) -> None:
        assert self.patch_calls == []
        assert relative_path == "tests/reproassert/test_generated.py"
        assert content == b"def test_bug():\n    assert True\n"
        self.candidate_staged = True

    def run_pytest(
        self, *, workspace: str, targets: tuple[str, ...], collect_only: bool = False
    ) -> InstancePytestResult:
        if collect_only:
            code, output = 0, "collected 1 item"
        elif not self.candidate_staged:
            code = 1 if workspace == "base" else 0
            output = "gold test failed as expected" if code else "gold test passed"
        elif workspace == "base":
            self.observed_candidate_workspaces.append(workspace)
            code = self.candidate_base_codes.pop(0)
            output = "assertion failed" if code else "1 passed"
        else:
            self.observed_candidate_workspaces.append(workspace)
            code, output = 0, "1 passed"
        junit = None
        if self.candidate_staged and not collect_only:
            failure = '<failure type="AssertionError">stable assertion</failure>' if code else ""
            junit = (
                f'<testsuite tests="1"><testcase name="test_bug">{failure}</testcase></testsuite>'
            ).encode()
        return InstancePytestResult(
            workspace=workspace,  # type: ignore[arg-type]
            exit_code=code,
            output=output,
            timed_out=False,
            output_truncated=False,
            junit_xml=junit,
        )

    def run_test_command(
        self, *, workspace: str, targets: tuple[str, ...], collect_only: bool = False
    ) -> InstancePytestResult:
        return self.run_pytest(workspace=workspace, targets=targets, collect_only=collect_only)


def _run(tmp_path: Path, fake: FakeExecutor) -> evaluator.CandidateEvaluationReceipt:
    manifest, digest = _manifest(tmp_path)
    return evaluator.evaluate_instance_candidate(
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact(
            relative_path="tests/reproassert/test_generated.py",
            content=b"def test_bug():\n    assert True\n",
            test_function="test_bug",
        ),
        hidden=HiddenEvaluatorInputs(
            production_patch=b"PRIVATE PRODUCTION FIX",
            gold_test_patch=b"PRIVATE GOLD TESTS",
            gold_targets=("tests/test_gold.py::test_gold",),
        ),
        output_path=tmp_path / "receipt.json",
        executed_at="2026-07-11T01:02:03Z",
        tool_git_sha="9" * 40,
        executor_factory=lambda _manifest, _case, policy: _factory(fake, policy),
    )


def _factory(fake: FakeExecutor, policy: SandboxPolicy) -> FakeExecutor:
    assert policy.image == f"sha256:{'1' * 64}"
    return fake


def test_accepts_consistent_causal_candidate_and_redacts_hidden_bytes(tmp_path: Path) -> None:
    fake = FakeExecutor()
    result = _run(tmp_path, fake)
    raw = result.path.read_bytes()
    receipt = json.loads(raw)

    assert result.accepted is True
    assert result.classification == "verified_reproduction"
    assert fake.prepare_count == 7
    assert fake.observed_candidate_workspaces == ["base", "fixed", "fixed", "base", "base", "fixed"]
    assert receipt["outcome"]["base_consistency"] == "3/3"
    assert receipt["outcome"]["fixed_consistency"] == "3/3"
    assert receipt["causal_controls"] == {
        "candidate_on_fixed": "pass",
        "l2_causal_controls_passed": False,
        "remaining_required_controls": [
            "fix_minus_issue_relevant_hunks",
            "base_plus_issue_relevant_hunks",
        ],
        "semantic_review_required": True,
    }
    assert b"PRIVATE" not in raw
    assert b"assertion failed" not in raw
    assert "hidden_inputs" not in receipt
    assert evaluator.verify_instance_candidate_receipt(result.path).sha256 == result.sha256
    schema = json.loads(
        Path(
            "src/reproassert/schemas/benchmark-v02-instance-candidate-evaluation.schema.json"
        ).read_text()
    )
    jsonschema.validate(receipt, schema)
    public_schema = Path(
        "schemas/benchmark-v02-instance-candidate-evaluation.schema.json"
    ).read_text()
    assert schema_text("benchmark-v02-instance-candidate-evaluation") == public_schema


def test_flaky_base_is_rejected_without_claiming_l2(tmp_path: Path) -> None:
    result = _run(tmp_path, FakeExecutor(candidate_base_codes=(1, 0, 1)))
    receipt = json.loads(result.path.read_bytes())
    assert result.accepted is False
    assert result.classification == "flaky"
    assert receipt["causal_controls"]["l2_causal_controls_passed"] is False


def test_rejects_syntax_and_manifest_mismatch_before_executor(tmp_path: Path) -> None:
    manifest, digest = _manifest(tmp_path)
    called = False

    def factory(*_args: object) -> FakeExecutor:
        nonlocal called
        called = True
        return FakeExecutor()

    arguments = dict(
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact("tests/test_bad.py", b"def nope(:\n"),
        hidden=HiddenEvaluatorInputs(b"fix", b"gold", ("tests/test_gold.py",)),
        output_path=tmp_path / "bad.json",
        executed_at="2026-07-11T01:02:03Z",
        tool_git_sha="9" * 40,
        executor_factory=factory,
    )
    with pytest.raises(PolicyRejection, match="Python syntax"):
        evaluator.evaluate_instance_candidate(**arguments)
    assert called is False

    arguments["expected_manifest_sha256"] = "0" * 64
    with pytest.raises(PolicyRejection, match="explicit commitment"):
        evaluator.evaluate_instance_candidate(**arguments)
    assert called is False


def test_verifier_rejects_tampered_acceptance(tmp_path: Path) -> None:
    result = _run(tmp_path, FakeExecutor())
    receipt = json.loads(result.path.read_bytes())
    receipt["outcome"]["accepted"] = False
    receipt["receipt_sha256"] = evaluator._self_hash(receipt)
    result.path.write_bytes(evaluator._canonical(receipt) + b"\n")
    with pytest.raises(PolicyRejection, match="disagree"):
        evaluator.verify_instance_candidate_receipt(result.path)


class FakeSympyExecutor(FakeExecutor):
    def apply_patch(self, *, workspace: str, patch: bytes) -> None:
        assert workspace in {"base", "fixed"}
        assert b"sympy/core/tests/test_basic.py" in patch

    def stage_candidate(self, *, relative_path: str, content: bytes) -> None:
        assert relative_path == "sympy/reproassert/tests/test_issue_016.py"
        assert b"pytest" not in content
        self.candidate_staged = True

    def run_test_command(
        self,
        *,
        workspace: str,
        targets: tuple[str, ...] = (),
        collect_only: bool = False,
        sympy_test_file: str | None = None,
        sympy_test_identifier: str | None = None,
    ) -> InstancePytestResult:
        assert not targets and collect_only is False
        if self.candidate_staged:
            assert sympy_test_file == "sympy/reproassert/tests/test_issue_016.py"
            assert sympy_test_identifier == "test_reproassert_issue_016"
            code = 1 if workspace == "base" else 0
            output = (
                "test_reproassert_issue_016 F\nAssertionError: stable native failure\n0.12 seconds"
                if code
                else "test_reproassert_issue_016 ok\n0.09 seconds"
            )
            self.observed_candidate_workspaces.append(workspace)
        else:
            assert sympy_test_file == "sympy/core/tests/test_basic.py"
            assert sympy_test_identifier == "test_gold"
            code = 1 if workspace == "base" else 0
            output = "gold assertion" if code else "gold passed"
        return InstancePytestResult(
            workspace=workspace,  # type: ignore[arg-type]
            exit_code=code,
            output=output,
            timed_out=False,
            output_truncated=False,
        )


def test_sympy_native_profile_executes_all_six_fresh_runs(tmp_path: Path) -> None:
    manifest, digest = _sympy_manifest(tmp_path)
    fake = FakeSympyExecutor()
    candidate = CandidateArtifact(
        relative_path="sympy/reproassert/tests/test_issue_016.py",
        content=(
            b"from sympy import Symbol\n\n"
            b"def test_reproassert_issue_016():\n"
            b"    value = Symbol('value')\n"
            b"    assert value == value\n"
        ),
        test_function="test_reproassert_issue_016",
    )
    output = tmp_path / "sympy-receipt.json"
    result = evaluator.evaluate_instance_candidate(
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-016",
        candidate=candidate,
        hidden=HiddenEvaluatorInputs(
            production_patch=b"PRIVATE PRODUCTION FIX",
            gold_test_patch=(
                b"diff --git a/sympy/core/tests/test_basic.py b/sympy/core/tests/test_basic.py\n"
                b"--- a/sympy/core/tests/test_basic.py\n"
                b"+++ b/sympy/core/tests/test_basic.py\n"
                b"@@ -1 +1 @@\n-old\n+new\n"
            ),
            gold_targets=("test_gold",),
        ),
        output_path=output,
        executed_at="2026-07-11T01:02:03Z",
        tool_git_sha="9" * 40,
        executor_factory=lambda _manifest, _case, _policy: fake,
    )

    receipt = json.loads(output.read_bytes())
    assert result.accepted is True
    assert receipt["candidate_profile"]["profile_id"] == "sympy-native-v1"
    assert receipt["candidate_profile"]["command_profile"] == "sympy-bin-test-v1"
    assert receipt["phases"]["gold_base_collect"] is None
    assert [run["collection"] for run in receipt["phases"]["candidate_runs"]] == [None] * 6
    assert fake.prepare_count == 7
    assert evaluator.verify_instance_candidate_receipt(output).accepted is True
    schema = json.loads(
        Path(
            "src/reproassert/schemas/benchmark-v02-instance-candidate-evaluation.schema.json"
        ).read_text()
    )
    jsonschema.validate(receipt, schema)


@pytest.mark.parametrize(
    "content",
    [
        b"import pytest\ndef test_reproassert_issue_016():\n    assert True\n",
        (
            b"from sympy.testing.pytest import raises\n"
            b"def test_reproassert_issue_016():\n    assert True\n"
        ),
        b"def test_reproassert_issue_016(tmp_path):\n    assert tmp_path\n",
        b"def test_reproassert_issue_016():\n    with open('x'):\n        assert True\n",
    ],
)
def test_sympy_profile_rejects_pytest_fixtures_and_unsupported_constructs(
    tmp_path: Path, content: bytes
) -> None:
    manifest_path, _digest = _sympy_manifest(tmp_path)
    runtime = load_instance_runtime_manifest(manifest_path).entries[0]
    with pytest.raises(PolicyRejection, match="SymPy native"):
        evaluator.candidate_execution_profile(
            runtime,
            case_id="rk-v0.2-016",
            candidate=CandidateArtifact(
                "sympy/reproassert/tests/test_issue_016.py",
                content,
                "test_reproassert_issue_016",
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "classification"),
    [
        ({"output": "ModuleNotFoundError: bad setup"}, "infrastructure_failure"),
        ({"output": "ConnectionError: network is unreachable"}, "infrastructure_failure"),
        ({"exit_code": 2}, "generic_crash"),
        ({"timed_out": True}, "timeout"),
        ({"oom_killed": True}, "oom_killed"),
    ],
)
def test_candidate_specific_failure_classification(
    mutation: dict[str, object], classification: str
) -> None:
    defaults: dict[str, object] = {
        "workspace": "base",
        "exit_code": 1,
        "output": "assertion failed",
        "timed_out": False,
        "output_truncated": False,
        "junit_xml": (
            b'<testsuite><testcase><failure type="AssertionError">'
            b"stable</failure></testcase></testsuite>"
        ),
        "oom_killed": False,
    }
    defaults.update(mutation)
    bad = InstancePytestResult(**defaults)  # type: ignore[arg-type]
    good_base = InstancePytestResult(
        workspace="base",
        exit_code=1,
        output="assertion failed",
        timed_out=False,
        output_truncated=False,
        junit_xml=b"x",
    )
    good_fixed = InstancePytestResult(
        workspace="fixed",
        exit_code=0,
        output="passed",
        timed_out=False,
        output_truncated=False,
        junit_xml=b"x",
    )
    outcome = evaluator._classify_candidate(
        (bad, good_base, good_base),
        (good_fixed, good_fixed, good_fixed),
        ("a" * 64, "a" * 64, "a" * 64),
    )
    assert outcome[0] == classification
