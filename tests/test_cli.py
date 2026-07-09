from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

import reproassert.cli as cli
from reproassert.cli import main
from reproassert.errors import ReproAssertError
from reproassert.generator import OpenAIResponsesGenerator
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
