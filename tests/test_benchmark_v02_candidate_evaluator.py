from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

import reproassert.benchmark_v02_amendment as amendment_module
import reproassert.benchmark_v02_candidate_evaluator as evaluator
import reproassert.benchmark_v02_exact_capability as capability_module
import reproassert.benchmark_v021_automated_evidence as automated_evidence
from reproassert.benchmark_v02_candidate_evaluator import CandidateArtifact
from reproassert.benchmark_v02_instance_controller import GoldSmokeReceipt
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


def _capability(
    manifest_path: Path,
    *,
    case_id: str,
    production_patch: bytes,
    developer_tests: bytes,
    v2: bool = False,
) -> capability_module.VerifiedV02ExactImageEvaluatorCapability:
    """Issue a test-local nominal value without invoking Docker-backed hidden verification."""

    manifest = load_instance_runtime_manifest(manifest_path)
    runtime = next(entry for entry in manifest.entries if entry.case_id == case_id)
    value = object.__new__(capability_module.VerifiedV02ExactImageEvaluatorCapability)
    fields: dict[str, object] = {
        "case_id": case_id,
        "runtime_manifest_sha256": manifest.sha256,
        "runtime": runtime,
        "gold_smoke_receipt_sha256": "2" * 64,
        "gold_smoke_receipt_commitment_sha256": "3" * 64,
        "gold_smoke_classification": "semantic_valid",
        "gold_smoke_reason": "fails_on_base_passes_on_fixed",
        "hidden_extraction_receipt_sha256": "4" * 64,
        "production_patch_sha256": hashlib.sha256(production_patch).hexdigest(),
        "production_patch_bytes": len(production_patch),
        "developer_tests_sha256": hashlib.sha256(developer_tests).hexdigest(),
        "developer_tests_bytes": len(developer_tests),
        "_issuer": capability_module._ISSUER,
        "capability_algorithm": (
            capability_module.CAPABILITY_ALGORITHM_V2
            if v2
            else capability_module.CAPABILITY_ALGORITHM
        ),
        "benchmark_amendment_receipt_sha256": "8" * 64 if v2 else None,
        "benchmark_amendment_review_status": "pending" if v2 else None,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, "evaluator_public_commitment_sha256", "")
    object.__setattr__(
        value,
        "evaluator_public_commitment_sha256",
        hashlib.sha256(capability_module._canonical(value.public_record())).hexdigest(),
    )
    return value


def _pending_amendment(
    authority: capability_module.VerifiedV02ExactImageEvaluatorCapability,
) -> amendment_module.VerifiedV02BenchmarkAmendment:
    value = object.__new__(amendment_module.VerifiedV02BenchmarkAmendment)
    fields = {
        "receipt_path": Path("amendment.json"),
        "receipt_sha256": "8" * 64,
        "runtime_manifest_sha256": authority.runtime_manifest_sha256,
        "hidden_extraction_receipt_sha256": authority.hidden_extraction_receipt_sha256,
        "original_gold_smoke_receipt_sha256": "7" * 64,
        "amended_gold_smoke_receipt_sha256": authority.gold_smoke_receipt_sha256,
        "review_status": "pending",
        "reviewer_ids": (),
        "provider_calls": 0,
        "tool_git_sha": "9" * 40,
        "_issuer": amendment_module._ISSUER,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


def _resolution_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: capability_module.VerifiedV02ExactImageEvaluatorCapability,
    *,
    production_patch: bytes,
    developer_tests: bytes,
    gold_target: str,
) -> tuple[object, Path, Path, Path]:
    production_path = tmp_path / "production.patch"
    developer_path = tmp_path / "developer-tests.patch"
    production_path.write_bytes(production_patch)
    developer_path.write_bytes(developer_tests)
    verified_hidden = SimpleNamespace(
        prepared=SimpleNamespace(receipt_sha256=authority.hidden_extraction_receipt_sha256)
    )
    refs = {
        "production_patch": {
            "bytes": len(production_patch),
            "path": production_path,
            "sha256": hashlib.sha256(production_patch).hexdigest(),
        },
        "developer_tests": {
            "bytes": len(developer_tests),
            "path": developer_path,
            "sha256": hashlib.sha256(developer_tests).hexdigest(),
        },
    }

    def resolve_hidden(supplied: object, case_id: str) -> dict[str, dict[str, object]]:
        if supplied is not verified_hidden or case_id != authority.case_id:
            raise evaluator._reject("Freshly verified hidden extraction authority is required.")
        return refs

    monkeypatch.setattr(evaluator, "hidden_case_artifacts", resolve_hidden)
    specs = [
        {
            "FAIL_TO_PASS": [gold_target if number == 1 else f"tests/test_{number}.py"],
            "PASS_TO_PASS": [],
            "instance_id": (
                authority.runtime.instance_id if number == 1 else f"dummy__repo-{number}"
            ),
            "version": "1.0",
        }
        for number in range(1, 21)
    ]
    specs_path = tmp_path / "gold-specs.json"
    specs_path.write_bytes(evaluator._canonical(specs) + b"\n")
    receipt = {
        "inputs": {
            "gold_specs_sha256": hashlib.sha256(specs_path.read_bytes()).hexdigest(),
            "hidden_extraction_receipt_sha256": authority.hidden_extraction_receipt_sha256,
        },
        "receipt_sha256": authority.gold_smoke_receipt_commitment_sha256,
    }
    receipt_path = tmp_path / "gold-smoke.json"
    receipt_path.write_bytes(evaluator._canonical(receipt) + b"\n")
    object.__setattr__(
        authority,
        "gold_smoke_receipt_sha256",
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    )
    object.__setattr__(authority, "evaluator_public_commitment_sha256", "")
    object.__setattr__(
        authority,
        "evaluator_public_commitment_sha256",
        hashlib.sha256(capability_module._canonical(authority.public_record())).hexdigest(),
    )

    def verify_receipt(path: Path) -> GoldSmokeReceipt:
        raw = path.read_bytes()
        return GoldSmokeReceipt(path, hashlib.sha256(raw).hexdigest(), 20, 19, 1)

    monkeypatch.setattr(evaluator, "verify_instance_gold_smoke_receipt", verify_receipt)
    return verified_hidden, receipt_path, specs_path, production_path


def _rebind_gold_receipt_file(
    authority: capability_module.VerifiedV02ExactImageEvaluatorCapability,
    receipt_path: Path,
) -> None:
    object.__setattr__(
        authority,
        "gold_smoke_receipt_sha256",
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    )
    object.__setattr__(authority, "evaluator_public_commitment_sha256", "")
    object.__setattr__(
        authority,
        "evaluator_public_commitment_sha256",
        hashlib.sha256(capability_module._canonical(authority.public_record())).hexdigest(),
    )


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
    capability = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
    )
    return evaluator._evaluate_instance_candidate_with_resolved_hidden(
        evaluator_capability=capability,
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact(
            relative_path="tests/reproassert/test_generated.py",
            content=b"def test_bug():\n    assert True\n",
            test_function="test_bug",
        ),
        hidden=evaluator._ResolvedHiddenEvaluatorInputs(
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


def test_public_scored_api_derives_private_inputs_and_gold_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
    )
    verified_hidden, gold_receipt, gold_specs, _production_path = _resolution_evidence(
        tmp_path,
        monkeypatch,
        authority,
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        gold_target="tests/test_gold.py::test_gold",
    )
    fake = FakeExecutor()

    result = evaluator.evaluate_instance_candidate(
        evaluator_capability=authority,
        verified_hidden=verified_hidden,  # type: ignore[arg-type]
        gold_smoke_receipt_path=gold_receipt,
        gold_specs_path=gold_specs,
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact(
            "tests/reproassert/test_generated.py",
            b"def test_bug():\n    assert True\n",
            "test_bug",
        ),
        output_path=tmp_path / "public-receipt.json",
        executed_at="2026-07-11T01:02:03Z",
        tool_git_sha="9" * 40,
        executor_factory=lambda _manifest, _case, policy: _factory(fake, policy),
    )

    assert result.accepted is True
    assert fake.patch_calls == []
    assert b"PRIVATE" not in result.path.read_bytes()
    parameters = inspect.signature(evaluator.evaluate_instance_candidate).parameters
    assert "hidden" not in parameters
    assert "gold_targets" not in parameters
    assert "verified_hidden" in parameters

    with pytest.raises(TypeError, match="unexpected keyword argument 'hidden'"):
        evaluator.evaluate_instance_candidate(  # type: ignore[call-arg]
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
            manifest_path=manifest,
            expected_manifest_sha256=digest,
            case_id="rk-v0.2-001",
            candidate=CandidateArtifact(
                "tests/reproassert/test_generated.py",
                b"def test_bug():\n    assert True\n",
                "test_bug",
            ),
            hidden=evaluator._ResolvedHiddenEvaluatorInputs(  # type: ignore[call-arg]
                b"CALLER FIX", b"CALLER TEST", ("caller::target",)
            ),
            output_path=tmp_path / "caller-controlled.json",
            executed_at="2026-07-11T01:02:03Z",
            tool_git_sha="9" * 40,
        )


def test_pending_v021_amendment_rejects_before_hidden_resolution_or_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        v2=True,
    )
    pending = _pending_amendment(authority)
    hidden_calls = 0
    executor_calls = 0

    def forbidden_hidden(**_kwargs: object) -> object:
        nonlocal hidden_calls
        hidden_calls += 1
        raise AssertionError("hidden resolution must not run")

    def forbidden_executor(*_args: object, **_kwargs: object) -> object:
        nonlocal executor_calls
        executor_calls += 1
        raise AssertionError("executor construction must not run")

    monkeypatch.setattr(evaluator, "_resolve_hidden_evaluator_inputs", forbidden_hidden)
    output = tmp_path / "pending-v021.json"
    with pytest.raises(PolicyRejection, match="review is pending"):
        evaluator.evaluate_instance_candidate(
            evaluator_capability=authority,
            amendment_authority=pending,
            verified_hidden=SimpleNamespace(),  # type: ignore[arg-type]
            gold_smoke_receipt_path=tmp_path / "gold.json",
            gold_specs_path=tmp_path / "specs.json",
            manifest_path=manifest,
            expected_manifest_sha256=digest,
            case_id="rk-v0.2-001",
            candidate=CandidateArtifact(
                "tests/reproassert/test_generated.py",
                b"def test_bug():\n    assert True\n",
                "test_bug",
            ),
            output_path=output,
            executed_at="2026-07-11T01:02:03Z",
            tool_git_sha="9" * 40,
            executor_factory=forbidden_executor,  # type: ignore[arg-type]
        )
    assert hidden_calls == 0
    assert executor_calls == 0
    assert not output.exists()


def test_automated_oracle_authority_unlocks_pending_v021_without_human_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, digest = _manifest(tmp_path)
    capability = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        v2=True,
    )
    record = {
        "claims": {
            "automated_oracle_validated": True,
            "human_reviewed": False,
            "maintainer_validated": False,
        },
        "evidence": {
            "gold_smoke_raw_sha256": capability.gold_smoke_receipt_sha256,
            "runtime_manifest_sha256": capability.runtime_manifest_sha256,
            "internal_commitments": {
                "hidden_extraction_receipt_sha256": capability.hidden_extraction_receipt_sha256
            },
        },
    }
    raw = evaluator._canonical(record) + b"\n"
    path = tmp_path / "automated-evidence.json"
    path.write_bytes(raw)
    authority = object.__new__(automated_evidence.VerifiedV021AutomatedEvidence)
    for name, value in {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": "1" * 64,
        "amendment_receipt_sha256": capability.benchmark_amendment_receipt_sha256,
        "request_set_sha256": "2" * 64,
        "tool_git_sha": "9" * 40,
        "case_count": 20,
        "provider_calls": 0,
        "human_reviewed": False,
        "maintainer_validated": False,
        "_issuer": automated_evidence._ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    sentinel = SimpleNamespace(classification="accepted")
    monkeypatch.setattr(
        evaluator,
        "_resolve_hidden_evaluator_inputs",
        lambda **_kwargs: evaluator._ResolvedHiddenEvaluatorInputs(b"fix", b"tests", ("target",)),
    )
    monkeypatch.setattr(
        evaluator,
        "_evaluate_instance_candidate_with_resolved_hidden",
        lambda **_kwargs: sentinel,
    )

    result = evaluator.evaluate_instance_candidate(
        evaluator_capability=capability,
        automated_evidence_authority=authority,
        verified_hidden=SimpleNamespace(),  # type: ignore[arg-type]
        gold_smoke_receipt_path=tmp_path / "gold.json",
        gold_specs_path=tmp_path / "specs.json",
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact(
            "tests/reproassert/test_generated.py",
            b"def test_bug():\n    assert True\n",
            "test_bug",
        ),
        output_path=tmp_path / "result.json",
        executed_at="2026-07-12T01:02:03Z",
        tool_git_sha="9" * 40,
    )

    assert result is sentinel


def test_hidden_resolution_rejects_forged_authority_and_post_verification_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
    )
    verified_hidden, gold_receipt, gold_specs, production_path = _resolution_evidence(
        tmp_path,
        monkeypatch,
        authority,
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        gold_target="tests/test_gold.py::test_gold",
    )

    with pytest.raises(PolicyRejection, match="Freshly verified hidden extraction"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=SimpleNamespace(  # type: ignore[arg-type]
                prepared=SimpleNamespace(receipt_sha256=authority.hidden_extraction_receipt_sha256)
            ),
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )

    verified_hidden.prepared.receipt_sha256 = "0" * 64  # type: ignore[attr-defined]
    with pytest.raises(PolicyRejection, match="Fresh hidden extraction differs"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )
    verified_hidden.prepared.receipt_sha256 = (  # type: ignore[attr-defined]
        authority.hidden_extraction_receipt_sha256
    )

    production_path.write_bytes(b"MUTATED AFTER VERIFICATION")
    with pytest.raises(PolicyRejection, match="changed after authority verification"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )


def test_hidden_resolution_rejects_substituted_gold_specs_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
    )
    verified_hidden, gold_receipt, gold_specs, _production_path = _resolution_evidence(
        tmp_path,
        monkeypatch,
        authority,
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        gold_target="tests/test_gold.py::test_gold",
    )

    original_specs = gold_specs.read_bytes()
    gold_specs.write_bytes(original_specs + b" ")
    with pytest.raises(PolicyRejection, match="Gold specs differ"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )
    gold_specs.write_bytes(original_specs)

    gold_receipt.write_bytes(gold_receipt.read_bytes() + b" ")
    with pytest.raises(PolicyRejection, match="Gold-smoke receipt differs"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )


def test_hidden_resolution_rejects_rebound_receipt_claims_and_unmatched_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
    )
    verified_hidden, gold_receipt, gold_specs, _production_path = _resolution_evidence(
        tmp_path,
        monkeypatch,
        authority,
        production_patch=b"PRIVATE PRODUCTION FIX",
        developer_tests=b"PRIVATE GOLD TESTS",
        gold_target="tests/test_gold.py::test_gold",
    )
    receipt = json.loads(gold_receipt.read_bytes())
    receipt["receipt_sha256"] = "0" * 64
    gold_receipt.write_bytes(evaluator._canonical(receipt) + b"\n")
    _rebind_gold_receipt_file(authority, gold_receipt)
    with pytest.raises(PolicyRejection, match="receipt commitment differs"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )

    receipt["receipt_sha256"] = authority.gold_smoke_receipt_commitment_sha256
    receipt["inputs"]["hidden_extraction_receipt_sha256"] = "0" * 64
    gold_receipt.write_bytes(evaluator._canonical(receipt) + b"\n")
    _rebind_gold_receipt_file(authority, gold_receipt)
    with pytest.raises(PolicyRejection, match="does not bind the supplied hidden extraction"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )

    receipt["inputs"]["hidden_extraction_receipt_sha256"] = (
        authority.hidden_extraction_receipt_sha256
    )
    specs = json.loads(gold_specs.read_bytes())
    specs[0]["instance_id"] = "different__repo-999"
    gold_specs.write_bytes(evaluator._canonical(specs) + b"\n")
    receipt["inputs"]["gold_specs_sha256"] = hashlib.sha256(gold_specs.read_bytes()).hexdigest()
    gold_receipt.write_bytes(evaluator._canonical(receipt) + b"\n")
    _rebind_gold_receipt_file(authority, gold_receipt)
    with pytest.raises(PolicyRejection, match="exactly one evaluator case"):
        evaluator._resolve_hidden_evaluator_inputs(
            evaluator_capability=authority,
            verified_hidden=verified_hidden,  # type: ignore[arg-type]
            gold_smoke_receipt_path=gold_receipt,
            gold_specs_path=gold_specs,
        )


def test_committed_hidden_reference_rejects_shape_identity_path_and_unsafe_file(
    tmp_path: Path,
) -> None:
    content = b"private"
    digest = hashlib.sha256(content).hexdigest()
    path = tmp_path / "private.patch"
    path.write_bytes(content)
    with pytest.raises(PolicyRejection, match="reference is invalid"):
        evaluator._read_committed_hidden_ref(
            None, label="developer tests", expected_sha256=digest, expected_bytes=len(content)
        )
    with pytest.raises(PolicyRejection, match="differs from the evaluator capability"):
        evaluator._read_committed_hidden_ref(
            {"bytes": len(content), "path": path, "sha256": "0" * 64},
            label="developer tests",
            expected_sha256=digest,
            expected_bytes=len(content),
        )
    with pytest.raises(PolicyRejection, match="path is invalid"):
        evaluator._read_committed_hidden_ref(
            {"bytes": len(content), "path": str(path), "sha256": digest},
            label="developer tests",
            expected_sha256=digest,
            expected_bytes=len(content),
        )
    with pytest.raises(PolicyRejection, match="could not be read safely"):
        evaluator._read_committed_hidden_ref(
            {"bytes": len(content), "path": tmp_path / "missing.patch", "sha256": digest},
            label="developer tests",
            expected_sha256=digest,
            expected_bytes=len(content),
        )


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
        evaluator_capability=_capability(
            manifest,
            case_id="rk-v0.2-001",
            production_patch=b"fix",
            developer_tests=b"gold",
        ),
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-001",
        candidate=CandidateArtifact("tests/test_bad.py", b"def nope(:\n"),
        hidden=evaluator._ResolvedHiddenEvaluatorInputs(b"fix", b"gold", ("tests/test_gold.py",)),
        output_path=tmp_path / "bad.json",
        executed_at="2026-07-11T01:02:03Z",
        tool_git_sha="9" * 40,
        executor_factory=factory,
    )
    with pytest.raises(PolicyRejection, match="Python syntax"):
        evaluator._evaluate_instance_candidate_with_resolved_hidden(**arguments)
    assert called is False

    arguments["expected_manifest_sha256"] = "0" * 64
    with pytest.raises(PolicyRejection, match="explicit commitment"):
        evaluator._evaluate_instance_candidate_with_resolved_hidden(**arguments)
    assert called is False


def test_verifier_rejects_tampered_acceptance(tmp_path: Path) -> None:
    result = _run(tmp_path, FakeExecutor())
    receipt = json.loads(result.path.read_bytes())
    receipt["outcome"]["accepted"] = False
    receipt["receipt_sha256"] = evaluator._self_hash(receipt)
    result.path.write_bytes(evaluator._canonical(receipt) + b"\n")
    with pytest.raises(PolicyRejection, match="disagree"):
        evaluator.verify_instance_candidate_receipt(result.path)


def test_verifier_rejects_tampered_exact_image_binding(tmp_path: Path) -> None:
    result = _run(tmp_path, FakeExecutor())
    receipt = json.loads(result.path.read_bytes())
    receipt["inputs"]["runtime"]["image_id"] = f"sha256:{'0' * 64}"
    receipt["receipt_sha256"] = evaluator._self_hash(receipt)
    result.path.write_bytes(evaluator._canonical(receipt) + b"\n")
    with pytest.raises(PolicyRejection, match="public commitment"):
        evaluator.verify_instance_candidate_receipt(result.path)


@pytest.mark.parametrize(
    "mutation",
    ["fixed_exit", "base_exit", "timeout", "oom", "gold_pair", "collection"],
)
def test_verifier_recomputes_outcome_from_bounded_evidence(tmp_path: Path, mutation: str) -> None:
    result = _run(tmp_path, FakeExecutor())
    receipt = json.loads(result.path.read_bytes())
    runs = receipt["phases"]["candidate_runs"]
    base = next(run for run in runs if run["workspace"] == "base")
    fixed = next(run for run in runs if run["workspace"] == "fixed")
    if mutation == "fixed_exit":
        fixed["result"]["exit_code"] = 1
    elif mutation == "base_exit":
        base["result"]["exit_code"] = 0
    elif mutation == "timeout":
        base["result"]["timed_out"] = True
    elif mutation == "oom":
        base["result"]["oom_killed"] = True
    elif mutation == "gold_pair":
        receipt["phases"]["gold_base"]["exit_code"] = 0
    else:
        base["collection"]["exit_code"] = 1
    receipt["receipt_sha256"] = evaluator._self_hash(receipt)
    result.path.write_bytes(evaluator._canonical(receipt) + b"\n")

    with pytest.raises(PolicyRejection, match=r"outcome|gold|collection"):
        evaluator.verify_instance_candidate_receipt(result.path)


def test_evaluator_rejects_hidden_bytes_not_bound_by_capability(tmp_path: Path) -> None:
    manifest, digest = _manifest(tmp_path)
    authority = _capability(
        manifest,
        case_id="rk-v0.2-001",
        production_patch=b"expected fix",
        developer_tests=b"expected tests",
    )
    with pytest.raises(PolicyRejection, match="capability-bound commitments"):
        evaluator._evaluate_instance_candidate_with_resolved_hidden(
            evaluator_capability=authority,
            manifest_path=manifest,
            expected_manifest_sha256=digest,
            case_id="rk-v0.2-001",
            candidate=CandidateArtifact(
                "tests/reproassert/test_generated.py",
                b"def test_bug():\n    assert True\n",
                "test_bug",
            ),
            hidden=evaluator._ResolvedHiddenEvaluatorInputs(
                b"substituted fix", b"expected tests", ("tests/test_gold.py",)
            ),
            output_path=tmp_path / "must-not-exist.json",
            executed_at="2026-07-11T01:02:03Z",
            tool_git_sha="9" * 40,
            executor_factory=lambda *_args: pytest.fail("executor must not be reached"),
        )


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
    production_patch = b"PRIVATE PRODUCTION FIX"
    developer_tests = (
        b"diff --git a/sympy/core/tests/test_basic.py b/sympy/core/tests/test_basic.py\n"
        b"--- a/sympy/core/tests/test_basic.py\n"
        b"+++ b/sympy/core/tests/test_basic.py\n"
        b"@@ -1 +1 @@\n-old\n+new\n"
    )
    result = evaluator._evaluate_instance_candidate_with_resolved_hidden(
        evaluator_capability=_capability(
            manifest,
            case_id="rk-v0.2-016",
            production_patch=production_patch,
            developer_tests=developer_tests,
        ),
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        case_id="rk-v0.2-016",
        candidate=candidate,
        hidden=evaluator._ResolvedHiddenEvaluatorInputs(
            production_patch=production_patch,
            gold_test_patch=developer_tests,
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


def test_candidate_evaluator_helpers_reject_malformed_execution_evidence() -> None:
    def result(**changes: object) -> InstancePytestResult:
        values: dict[str, object] = {
            "workspace": "base",
            "exit_code": 0,
            "output": "1 passed",
            "timed_out": False,
            "output_truncated": False,
            "junit_xml": b'<testsuite><testcase name="test_one"/></testsuite>',
            "oom_killed": False,
        }
        values.update(changes)
        return InstancePytestResult(**values)  # type: ignore[arg-type]

    failed = result(exit_code=1, output="assertion failed")
    passed = result()
    for base, fixed, fingerprints, classification in (
        (
            (result(output_truncated=True), failed, failed),
            (passed,) * 3,
            ("x",) * 3,
            "output_limit",
        ),
        ((passed,) * 3, (passed,) * 3, (None,) * 3, "does_not_fail_on_base"),
        ((failed,) * 3, (failed,) * 3, ("x",) * 3, "does_not_pass_on_fixed"),
        ((failed,) * 3, (passed,) * 3, ("x", "y", "x"), "wrong_or_flaky_failure"),
    ):
        assert evaluator._classify_candidate(base, fixed, fingerprints)[0] == classification

    with pytest.raises(PolicyRejection, match="collection did not complete"):
        evaluator._require_clean_collection(result(exit_code=1), passed, "candidate")
    with pytest.raises(PolicyRejection, match="infrastructure failure"):
        evaluator._require_clean_collection(
            result(output="ModuleNotFoundError: dependency"), passed, "candidate"
        )
    with pytest.raises(PolicyRejection, match="runtime bound"):
        evaluator._require_gold_pair(result(timed_out=True), passed)
    with pytest.raises(PolicyRejection, match="infrastructure failure"):
        evaluator._require_gold_pair(result(exit_code=1, output="network is unreachable"), passed)
    with pytest.raises(PolicyRejection, match="buggy/fixed pair"):
        evaluator._require_gold_pair(passed, passed)

    for candidate, message in (
        (CandidateArtifact("tests/reproassert/test_x.py", b"", "test_x"), "byte limit"),
        (CandidateArtifact("outside/test_x.py", b"def test_x(): pass\n", "test_x"), "path"),
        (
            CandidateArtifact("tests/reproassert/test_x.py", b"def test_x(): pass\n", None),
            "test function",
        ),
    ):
        with pytest.raises(PolicyRejection, match=message):
            evaluator._pytest_candidate_contract(candidate)

    sympy_path = "sympy/reproassert/tests/test_issue_016.py"
    sympy_function = "test_reproassert_issue_016"

    def sympy(content: bytes, *, path: str = sympy_path) -> None:
        evaluator._sympy_candidate_contract(
            CandidateArtifact(path, content, sympy_function),
            required_path=sympy_path,
            required_function=sympy_function,
        )

    for content, message in (
        (b"", "byte limit"),
        (b"def broken(:\n", "UTF-8 Python syntax"),
        (b"def wrong():\n    assert True\n", "required test function"),
        (
            b"value = 1\ndef test_reproassert_issue_016():\n    assert value\n",
            "module-level execution",
        ),
        (
            b"def test_reproassert_issue_016():\n"
            b"    def helper(): return True\n"
            b"    assert helper()\n",
            "nested functions",
        ),
        (b"def test_reproassert_issue_016():\n    pytest\n    assert True\n", "pytest APIs"),
        (b"def test_reproassert_issue_016():\n    eval('1')\n    assert True\n", "unsafe"),
        (b"def test_reproassert_issue_016():\n    value = 1\n", "plain assert"),
    ):
        with pytest.raises(PolicyRejection, match=message):
            sympy(content)
    with pytest.raises(PolicyRejection, match="path and function"):
        sympy(b"def test_reproassert_issue_016():\n    assert True\n", path="wrong.py")

    for patch, targets, message in (
        (b"+++ b/sympy/core/tests/test_x.py\n", ("unsafe target",), "safe bare"),
        (b"\xff", ("test_gold",), "valid UTF-8"),
        (b"+++ b/not/a/sympy/test.py\n", ("test_gold",), "native test file"),
    ):
        with pytest.raises(PolicyRejection, match=message):
            evaluator._derive_sympy_gold_contract(patch, targets)
    with pytest.raises(PolicyRejection, match="Hidden production patch"):
        evaluator._hidden_bytes(b"", "production patch")

    for junit, expected_failure, message in (
        (None, True, "required JUnit"),
        (b"<broken", True, "invalid XML"),
        (b"<testsuite></testsuite>", True, "exactly one test case"),
        (
            b"<testsuite><testcase><error/></testcase></testsuite>",
            True,
            "clean assertion",
        ),
        (
            b'<testsuite><testcase><failure type="" message=""/></testcase></testsuite>',
            True,
            "no attributable assertion",
        ),
    ):
        with pytest.raises(PolicyRejection, match=message):
            evaluator._junit_fingerprint(result(junit_xml=junit), expected_failure=expected_failure)

    pytest_profile = evaluator.CandidateExecutionProfile(
        profile_id="pytest-v1",
        command_profile="pytest-v1",
        staging_path="reproassert_tests/test_issue_001.py",
        required_function="test_reproassert_issue_001",
    )
    assert (
        evaluator._candidate_fingerprint_or_none(
            result(exit_code=1, junit_xml=None), profile=pytest_profile
        )
        is None
    )

    with pytest.raises(PolicyRejection, match="phase evidence is invalid"):
        evaluator._verify_evidence({})
    invalid_evidence = evaluator._evidence(result())
    invalid_evidence["exit_code"] = 999
    with pytest.raises(PolicyRejection, match="evidence values"):
        evaluator._verify_evidence(invalid_evidence)
    for function, value, message in (
        (evaluator._case_id, "bad", "Case ID"),
        (lambda item: evaluator._digest(item, "receipt"), "bad", "SHA-256"),
        (evaluator._timestamp, "bad", "timestamp"),
        (evaluator._git_sha, "bad", "Git SHA"),
    ):
        with pytest.raises(PolicyRejection, match=message):
            function(value)
    with pytest.raises(ValueError, match="duplicate"):
        evaluator._reject_duplicates([("key", 1), ("key", 2)])
