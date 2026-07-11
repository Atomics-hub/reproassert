from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

import reproassert.cli as cli
from reproassert.cli import main
from reproassert.dependency_execution_receipt import VerifiedDependencyExecutionReceipt
from reproassert.errors import ReproAssertError
from reproassert.generator import OpenAIResponsesGenerator
from reproassert.isolation_canary import IsolationCanaryResult
from reproassert.sandbox import DockerDoctor
from reproassert.workflow import WorkflowResult


class ReadySandbox:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def require_ready(self) -> DockerDoctor:
        return DockerDoctor(True, True, True, "1", "sha256:x")

    def build_image(self) -> str:
        return "sha256:built"

    def doctor(self) -> DockerDoctor:
        return self.require_ready()


def test_issue_requires_a_generator_even_when_openai_key_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    result = CliRunner().invoke(main, ["issue", "https://github.com/o/r/issues/1"])
    assert result.exit_code == 1
    assert "Choose exactly one" in result.output


def test_issue_renders_verified_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "from fixture_project import reproduce\n\n"
        "def test_issue_1_reproduction():\n"
        "    assert reproduce() == 2, 'one is unexpectedly two'\n"
    )
    result_value = WorkflowResult(
        run_dir=tmp_path,
        report_path=tmp_path / "reproassert-report.json",
        patch_path=tmp_path / "candidate.patch",
        claim_level="repeatable_base_failure",
        outcome="repeatable_base_failure",
        replay_command="reproassert replay report.json",
    )
    monkeypatch.setattr(cli, "DockerSandbox", ReadySandbox)  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "run_issue_workflow", lambda *_args, **_kwargs: result_value)  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "console", Console(width=40))

    result = CliRunner().invoke(
        main,
        [
            "issue",
            "https://github.com/o/r/issues/1",
            "--candidate-file",
            str(candidate),
            "--expected-symptom",
            "one is unexpectedly two",
            "--rationale",
            "fixture",
            "--run-base",
            str(tmp_path / "runs"),
        ],
        terminal_width=40,
    )

    assert result.exit_code == 0, result.output
    assert "REPEATABLE BASE FAILURE" in result.output
    assert str(result_value.report_path) in result.output
    assert str(result_value.patch_path) in result.output
    assert result_value.replay_command in result.output


def test_doctor_and_sandbox_build_render_ready(monkeypatch: object) -> None:
    monkeypatch.setattr(cli, "DockerSandbox", ReadySandbox)  # type: ignore[attr-defined]

    doctor = CliRunner().invoke(main, ["doctor"])
    build = CliRunner().invoke(main, ["sandbox", "build"])

    assert doctor.exit_code == 0
    assert "Native fallback" in doctor.output
    assert build.exit_code == 0
    assert "sha256:built" in build.output


def test_sandbox_isolation_canary_renders_machine_receipt(monkeypatch: object) -> None:
    receipt = IsolationCanaryResult(
        version="reproassert-generator-evaluator-isolation-v1",
        tool_version="0.1.0",
        tool_git_sha=None,
        policy_sha256="a" * 64,
        config_sha256="b" * 64,
        image_id="sha256:" + "c" * 64,
        sentinel_sha256="d" * 64,
        positive_control_passed=True,
        negative_control_passed=True,
        positive_mount_destinations=("/evaluator",),
        generator_mount_destinations=("/workspace",),
        process_env_names=("HOME",),
        image_env_names_cleared=("PATH",),
        cleanup_succeeded=True,
    )
    monkeypatch.setattr(cli, "DockerSandbox", ReadySandbox)  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "run_isolation_canary", lambda _sandbox, **_kwargs: receipt)

    result = CliRunner().invoke(main, ["sandbox", "isolation-canary", "--json-output"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["accepted"] is True
    assert payload["sentinel_sha256"] == "d" * 64
    assert "canary-value" not in result.output


def test_benchmark_source_commands_are_preparation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    root = tmp_path / "prepared"
    captured: dict[str, object] = {}

    def fake_prepare(
        manifest_path: Path,
        case_id: str,
        output_root: Path,
        **kwargs: object,
    ) -> Path:
        captured.update(
            manifest=manifest_path,
            case_id=case_id,
            output_root=output_root,
            kwargs=kwargs,
        )
        case_dir = output_root / case_id
        case_dir.mkdir(mode=0o700)
        receipt = case_dir / "benchmark-source-receipt.json"
        receipt.write_text("{}")
        return receipt

    monkeypatch.setattr(cli, "prepare_source_case", fake_prepare)
    prepared = CliRunner().invoke(
        main,
        [
            "benchmark",
            "prepare-source",
            "rk-v0.1-001",
            "--manifest",
            str(manifest),
            "--output-root",
            str(root),
            "--tool-git-sha",
            "a" * 40,
        ],
    )

    assert prepared.exit_code == 0, prepared.output
    assert json.loads(prepared.output)["campaign_readiness_changed"] is False
    assert captured["case_id"] == "rk-v0.1-001"
    assert captured["kwargs"] == {"tool_git_sha": "a" * 40, "timeout_seconds": 15.0}

    receipt_path = root / "rk-v0.1-001" / "benchmark-source-receipt.json"
    monkeypatch.setattr(
        cli,
        "verify_source_receipt",
        lambda *_args, **_kwargs: {
            "source": {
                "github_root_tree_oid": "b" * 40,
                "archive": {"sha256": "c" * 64},
                "attestation": {"tree_sha256": "d" * 64},
            }
        },
    )
    verified = CliRunner().invoke(
        main,
        [
            "benchmark",
            "verify-source",
            str(receipt_path),
            "--manifest",
            str(manifest),
            "--case-id",
            "rk-v0.1-001",
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["verified"] is True


def test_benchmark_source_index_discovers_the_frozen_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    root = tmp_path / "receipts"
    root.mkdir(mode=0o700)
    output = root / "benchmark-source-index.json"
    cases = tuple(SimpleNamespace(id=f"rk-v0.1-{index:03d}") for index in range(1, 21))
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_frozen_manifest", lambda _path: SimpleNamespace(cases=cases))

    def fake_build(*args: object, **kwargs: object) -> Path:
        captured["args"] = args
        captured["kwargs"] = kwargs
        output.write_text("{}")
        return output

    monkeypatch.setattr(cli, "build_source_index", fake_build)
    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-source-index",
            "--manifest",
            str(manifest),
            "--receipts-root",
            str(root),
            "--tool-git-sha",
            "e" * 40,
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["receipt_count"] == 20
    args = captured["args"]
    assert isinstance(args, tuple)
    assert len(args[2]) == 20  # type: ignore[arg-type]


def test_schema_command_prints_the_exact_bundled_report_schema() -> None:
    result = CliRunner().invoke(main, ["schema"])

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["$id"] == (
        "https://atomics-hub.github.io/reproassert/reproassert-report.schema.json"
    )
    assert (
        result.output
        == (Path(__file__).parents[1] / "schemas" / "reproassert-report.schema.json").read_text()
    )


def test_schema_command_prints_preparation_receipt_schemas() -> None:
    root = Path(__file__).parents[1]
    for name, filename in (
        ("benchmark-snapshot-receipt", "benchmark-snapshot-receipt.schema.json"),
        ("benchmark-source-receipt", "benchmark-source-receipt.schema.json"),
        ("benchmark-source-index", "benchmark-source-index.schema.json"),
        ("benchmark-v02-fix-mapping", "benchmark-v02-fix-mapping.schema.json"),
        (
            "benchmark-v02-chronology-evidence",
            "benchmark-v02-chronology-evidence.schema.json",
        ),
        ("benchmark-v02-case-package", "benchmark-v02-case-package.schema.json"),
        ("benchmark-v02-preregistration", "benchmark-v02-preregistration.schema.json"),
        (
            "benchmark-v02-exact-preregistration",
            "benchmark-v02-exact-preregistration.schema.json",
        ),
        (
            "benchmark-v02-semantic-verification",
            "benchmark-v02-semantic-verification.schema.json",
        ),
        ("benchmark-v02-execution-freeze", "benchmark-v02-execution-freeze.schema.json"),
        (
            "benchmark-v02-exact-image-authorization",
            "benchmark-v02-exact-image-authorization.schema.json",
        ),
        (
            "benchmark-v02-exact-image-capability-index",
            "benchmark-v02-exact-image-capability-index.schema.json",
        ),
        ("dependency-execution-receipt", "dependency-execution-receipt.schema.json"),
    ):
        result = CliRunner().invoke(main, ["schema", "--name", name])
        assert result.exit_code == 0, result.output
        assert result.output == (root / "schemas" / filename).read_text()


def test_verify_dependency_receipt_command_binds_reviewed_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = tmp_path / "receipt.json"
    plan = tmp_path / "plan.json"
    receipt.write_text("{}")
    plan.write_text("{}")
    captured: dict[str, object] = {}
    verified = VerifiedDependencyExecutionReceipt(
        receipt_sha256="1" * 64,
        case_id="rk-v0.2-001",
        base_sha="2" * 40,
        source_tree_sha256="3" * 64,
        plan_raw_sha256="4" * 64,
        plan_sha256="5" * 64,
        requirements_sha256="6" * 64,
        image_id=f"sha256:{'7' * 64}",
        policy_sha256="8" * 64,
        wheelhouse_sha256="9" * 64,
        dependency_tree_sha256="a" * 64,
        evaluator_package_sha256="b" * 64,
        sequence_sha256="c" * 64,
        tool_name="reproassert",
        tool_version="0.1.0",
        tool_git_sha="d" * 40,
    )

    def fake_load(path: Path, **kwargs: object) -> VerifiedDependencyExecutionReceipt:
        captured.update({"path": path, **kwargs})
        return verified

    monkeypatch.setattr(cli, "load_dependency_execution_receipt", fake_load)
    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "verify-dependency-receipt",
            str(receipt),
            "--plan",
            str(plan),
            "--expected-receipt-sha256",
            "1" * 64,
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["receipt_sha256"] == "1" * 64
    assert captured["path"] == receipt
    assert captured["expected_plan_path"] == plan


def test_doctor_returns_nonzero_when_boundary_missing(monkeypatch: object) -> None:
    class MissingSandbox(ReadySandbox):
        def doctor(self) -> DockerDoctor:
            return DockerDoctor(True, False, False, None, None)

    monkeypatch.setattr(cli, "DockerSandbox", MissingSandbox)  # type: ignore[attr-defined]
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 1
    assert "not ready" in result.output


def test_replay_renders_json_and_rejection_exit(tmp_path: Path, monkeypatch: object) -> None:
    report = tmp_path / "report.json"
    report.write_text("{}")
    rejected = WorkflowResult(
        run_dir=tmp_path,
        report_path=tmp_path / "new-report.json",
        patch_path=tmp_path / "candidate.patch",
        claim_level="collected",
        outcome="wrong_failure",
        replay_command="reproassert replay new-report.json",
    )
    monkeypatch.setattr(cli, "DockerSandbox", ReadySandbox)  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "run_replay_workflow", lambda *_args, **_kwargs: rejected)  # type: ignore[attr-defined]

    result = CliRunner().invoke(main, ["replay", str(report), "--json-output"])

    assert result.exit_code == 2
    assert '"outcome": "wrong_failure"' in result.output


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"generator_command": "echo", "candidate_file": Path("candidate.py")},
        {"generator_command": "echo", "expected_symptom": "x"},
        {"candidate_file": Path("candidate.py"), "expected_symptom": "x"},
    ],
)
def test_generator_option_combinations_fail_closed(kwargs: dict[str, object]) -> None:
    options: dict[str, object] = {
        "issue_number": 1,
        "generator_command": None,
        "provider": None,
        "model": None,
        "pass_env": (),
        "candidate_file": None,
        "expected_symptom": None,
        "rationale": None,
    }
    options.update(kwargs)
    with pytest.raises(ReproAssertError):
        cli._select_generator(**options)  # type: ignore[arg-type]


def test_openai_provider_selection_is_explicit_and_model_aware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")

    generator = cli._select_generator(
        issue_number=1,
        generator_command=None,
        provider="openai",
        model="gpt-5.4-mini-test",
        pass_env=(),
        candidate_file=None,
        expected_symptom=None,
        rationale=None,
    )

    assert isinstance(generator, OpenAIResponsesGenerator)
    assert generator.model == "gpt-5.4-mini-test"


def test_issue_cli_selects_openai_provider_without_calling_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    result_value = WorkflowResult(
        run_dir=tmp_path,
        report_path=tmp_path / "reproassert-report.json",
        patch_path=tmp_path / "candidate.patch",
        claim_level="repeatable_base_failure",
        outcome="repeatable_base_failure",
        replay_command="reproassert replay report.json",
    )

    def fake_workflow(*_args: object, **kwargs: object) -> WorkflowResult:
        captured.update(kwargs)
        return result_value

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-only")
    monkeypatch.setattr(cli, "DockerSandbox", ReadySandbox)
    monkeypatch.setattr(cli, "run_issue_workflow", fake_workflow)

    result = CliRunner().invoke(
        main,
        [
            "issue",
            "https://github.com/o/r/issues/1",
            "--provider",
            "openai",
            "--model",
            "gpt-5.4-mini-test",
            "--run-base",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == 0, result.output
    generator = captured["generator"]
    assert isinstance(generator, OpenAIResponsesGenerator)
    assert generator.model == "gpt-5.4-mini-test"


@pytest.mark.parametrize(
    "updates",
    [
        {"provider": "openai", "generator_command": "echo"},
        {"provider": "openai", "candidate_file": Path("candidate.py")},
        {"provider": "openai", "pass_env": ("OPENAI_API_KEY",)},
        {"provider": "openai", "expected_symptom": "wrong result"},
        {"model": "gpt-5.4-mini"},
    ],
)
def test_openai_provider_rejects_mixed_candidate_sources(
    updates: dict[str, object],
) -> None:
    options: dict[str, object] = {
        "issue_number": 1,
        "generator_command": None,
        "provider": None,
        "model": None,
        "pass_env": (),
        "candidate_file": None,
        "expected_symptom": None,
        "rationale": None,
    }
    options.update(updates)

    with pytest.raises(ReproAssertError):
        cli._select_generator(**options)  # type: ignore[arg-type]


def test_fail_sanitizes_plain_exceptions() -> None:
    with pytest.raises(click.ClickException, match="bad"):
        cli._fail(ValueError("bad\x1b[31m"))
