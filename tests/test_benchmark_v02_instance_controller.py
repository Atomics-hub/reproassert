from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

import reproassert.benchmark_v02_instance_controller as controller
from reproassert.benchmark_v02_instance_executor import InstancePytestResult
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    instance_runtime_manifest_bytes,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection
from reproassert.sandbox import SandboxPolicy


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _inputs(tmp_path: Path) -> tuple[Path, str, Path, str]:
    entries = tuple(
        InstanceRuntime(
            case_id=f"rk-v0.2-{number:03d}",
            instance_id=f"project__repo-{1000 + number}",
            base_sha="a" * 40,
            base_tree_oid="b" * 40,
            spec_sha256="c" * 64,
            image_tag=f"swebench/sweb.eval.x86_64.project_repo-{1000 + number}:v1",
            image_digest=f"sha256:{'d' * 64}",
            image_id=f"sha256:{'e' * 64}",
            test_command_profile="pytest-v1",
        )
        for number in range(1, 21)
    )
    manifest_path = tmp_path / "runtimes.json"
    manifest_path.write_bytes(
        instance_runtime_manifest_bytes(
            harness_git_sha="f" * 40,
            harness_specs_sha256="1" * 64,
            entries=entries,
        )
    )
    manifest_sha = load_instance_runtime_manifest(manifest_path).sha256
    specs = [
        {
            "FAIL_TO_PASS": [f"tests/test_{number}.py::test_issue[param]"],
            "PASS_TO_PASS": [],
            "instance_id": f"project__repo-{1000 + number}",
            "version": "1.0",
        }
        for number in range(1, 21)
    ]
    specs_path = tmp_path / "gold-specs.json"
    specs_path.write_bytes(_canonical(specs))
    return (
        manifest_path,
        manifest_sha,
        specs_path,
        hashlib.sha256(specs_path.read_bytes()).hexdigest(),
    )


class FakeExecutor:
    def __init__(self, case_id: str, *, network_failure: bool = False) -> None:
        self.case_id = case_id
        self.network_failure = network_failure

    def __enter__(self) -> FakeExecutor:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def acquire(self) -> None:
        return None

    def prepare_workspaces(self, *, fixed_patch: bytes) -> None:
        assert fixed_patch == b"private production bytes"

    def apply_patch(self, *, workspace: str, patch: bytes) -> None:
        assert workspace in {"base", "fixed"}
        assert patch == b"private developer bytes"

    def run_test_command(
        self, *, workspace: str, targets: tuple[str, ...], collect_only: bool = False
    ) -> InstancePytestResult:
        assert targets[0].endswith("::test_issue[param]")
        if self.network_failure and not collect_only:
            output = "ConnectionError: Failed to establish a new connection SECRET"
            code = 1
        else:
            output = "collected" if collect_only else "semantic output SECRET"
            code = 0 if collect_only or workspace == "fixed" else 1
        return InstancePytestResult(
            workspace=workspace,  # type: ignore[arg-type]
            exit_code=code,
            output=output,
            timed_out=False,
            output_truncated=False,
        )


def _install_hidden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    hidden_receipt = tmp_path / "hidden.json"
    hidden_receipt.write_text("{}")
    os.chmod(tmp_path, 0o700)
    production = tmp_path / "production.patch"
    developer = tmp_path / "developer.patch"
    production.write_bytes(b"private production bytes")
    developer.write_bytes(b"private developer bytes")
    verified = SimpleNamespace(prepared=SimpleNamespace(receipt_sha256="9" * 64))
    monkeypatch.setattr(controller, "verify_v02_hidden_gold", lambda _path: verified)

    def artifacts(_verified: object, _case_id: str) -> dict[str, dict[str, object]]:
        return {
            "metadata": {"bytes": 1, "path": tmp_path / "metadata", "sha256": "0" * 64},
            "production_patch": {
                "bytes": production.stat().st_size,
                "path": production,
                "sha256": hashlib.sha256(production.read_bytes()).hexdigest(),
            },
            "developer_tests": {
                "bytes": developer.stat().st_size,
                "path": developer,
                "sha256": hashlib.sha256(developer.read_bytes()).hexdigest(),
            },
        }

    monkeypatch.setattr(controller, "hidden_case_artifacts", artifacts)
    return hidden_receipt


def test_single_case_preserves_denominator_and_never_stores_hidden_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, specs, specs_sha = _inputs(tmp_path)
    hidden = _install_hidden(monkeypatch, tmp_path)
    output = tmp_path / "receipt.json"
    policies: list[SandboxPolicy] = []

    def factory(_manifest: object, case_id: str, policy: SandboxPolicy) -> FakeExecutor:
        policies.append(policy)
        return FakeExecutor(case_id)

    result = controller.run_instance_gold_smoke(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        hidden_extraction_receipt=hidden,
        gold_specs_path=specs,
        expected_gold_specs_sha256=specs_sha,
        output_path=output,
        executed_at="2026-07-10T23:30:00Z",
        tool_git_sha="a" * 40,
        case_id="rk-v0.2-001",
        executor_factory=factory,
    )

    receipt = json.loads(output.read_bytes())
    assert len(receipt["results"]) == 20
    assert receipt["counts"] == {
        "infrastructure_failure": 0,
        "not_run": 19,
        "selected": 1,
        "semantic_failure": 0,
        "semantic_valid": 1,
    }
    assert result.semantic_valid_count == 1
    assert policies == [
        SandboxPolicy(
            image=f"sha256:{'e' * 64}",
            timeout_seconds=600.0,
            max_output_bytes=2 * 1024 * 1024,
            memory_bytes=4 * 1024 * 1024 * 1024,
            cpus=2.0,
            pids=512,
            tmpfs_bytes=512 * 1024 * 1024,
            tmpfs_inodes=32_768,
        )
    ]
    verified = controller.verify_instance_gold_smoke_receipt(output)
    assert verified.semantic_valid_count == 1
    assert b"SECRET" not in output.read_bytes()
    assert b"private production bytes" not in output.read_bytes()
    schema = json.loads(Path("schemas/benchmark-v02-instance-gold-smoke.schema.json").read_text())
    jsonschema.validate(receipt, schema)

    receipt["policy"]["sandbox"]["cpus"] = 1.0
    receipt["receipt_sha256"] = controller._self_hash(receipt)
    output.write_bytes(_canonical(receipt))
    with pytest.raises(PolicyRejection, match="trust claims"):
        controller.verify_instance_gold_smoke_receipt(output)


def test_network_dependency_is_infrastructure_not_semantic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, manifest_sha, specs, specs_sha = _inputs(tmp_path)
    hidden = _install_hidden(monkeypatch, tmp_path)
    output = tmp_path / "network.json"

    controller.run_instance_gold_smoke(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        hidden_extraction_receipt=hidden,
        gold_specs_path=specs,
        expected_gold_specs_sha256=specs_sha,
        output_path=output,
        executed_at="2026-07-10T23:30:00Z",
        tool_git_sha="a" * 40,
        case_id="rk-v0.2-014",
        executor_factory=lambda _manifest, case_id, _policy: FakeExecutor(
            case_id, network_failure=True
        ),
    )

    selected = next(row for row in json.loads(output.read_bytes())["results"] if row["selected"])
    assert selected["classification"] == "infrastructure_failure"
    assert selected["reason"] == "network_dependency"
    assert b"SECRET" not in output.read_bytes()


def test_rejects_wrong_explicit_commitment_before_hidden_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _manifest_sha, specs, specs_sha = _inputs(tmp_path)
    monkeypatch.setattr(
        controller,
        "verify_v02_hidden_gold",
        lambda _path: pytest.fail("hidden data must not be accessed"),
    )

    with pytest.raises(PolicyRejection, match="explicit frozen commitment"):
        controller.run_instance_gold_smoke(
            manifest_path=manifest,
            expected_manifest_sha256="0" * 64,
            hidden_extraction_receipt=tmp_path / "hidden.json",
            gold_specs_path=specs,
            expected_gold_specs_sha256=specs_sha,
            output_path=tmp_path / "receipt.json",
            executed_at="2026-07-10T23:30:00Z",
            tool_git_sha="a" * 40,
        )


def test_rejects_unsafe_gold_target(tmp_path: Path) -> None:
    _, _, specs, _ = _inputs(tmp_path)
    value = json.loads(specs.read_bytes())
    value[0]["FAIL_TO_PASS"] = ["--pwn"]
    raw = _canonical(value)
    with pytest.raises(PolicyRejection, match="unsafe"):
        controller._load_gold_specs(raw)


def test_missing_runtime_dependency_is_infrastructure() -> None:
    result = InstancePytestResult(
        workspace="fixed",
        exit_code=1,
        output="ModuleNotFoundError: No module named 'required_dependency' SECRET",
        timed_out=False,
        output_truncated=False,
    )

    assert controller._infrastructure_reason(result, collecting=False) == "setup_failure"
