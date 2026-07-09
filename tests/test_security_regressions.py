from __future__ import annotations

import hashlib
import json
from pathlib import Path

import click
import pytest

import reproassert.cli as cli
from reproassert.candidate import validate_candidate_payload
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.report import MAX_REPORT_BYTES, load_replay_spec, write_report
from reproassert.safeio import sanitize_log
from reproassert.sandbox import DockerSandbox, SandboxPolicy


def _candidate_payload(content: str) -> dict[str, str]:
    return {
        "test_content": content,
        "expected_symptom": "expected symptom",
        "rationale": "A bounded red-team fixture.",
    }


def _valid_report() -> dict[str, object]:
    content = (
        "from fixture_project import reproduce\n\n"
        "def test_issue_9_reproduction():\n"
        "    assert reproduce() == 2, 'expected symptom'\n"
    )
    return {
        "schema_version": "1.0",
        "issue": {
            "url": "https://github.com/owner/repo/issues/9",
            "title": "Expected fixture behavior",
            "body_sha256": "b" * 64,
        },
        "source": {
            "repository_url": "https://github.com/owner/repo",
            "sha": "a" * 40,
        },
        "candidate": {
            "test_content": content,
            "test_content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "expected_symptom": "expected symptom",
            "rationale": "A bounded replay fixture.",
        },
        "policy": {"repeats": 3},
    }


def test_report_command_fields_are_inert_data(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    command = f"touch {marker}"
    report = _valid_report()
    report["command"] = command
    report["replay"] = {"display_command": command, "argv": ["sh", "-c", command]}
    candidate = report["candidate"]
    assert isinstance(candidate, dict)
    candidate["command"] = command
    path = tmp_path / "report.json"
    write_report(path, report)

    spec = load_replay_spec(path)

    assert spec.source_sha == "a" * 40
    assert spec.candidate.test_function == "test_issue_9_reproduction"
    assert not marker.exists()


def test_cli_error_rendering_removes_terminal_injection() -> None:
    hostile = "bad\x1b[31mred\x1b[0m\rrewrite\x1b]52;c;Y2xpcGJvYXJk\x07\x00"

    with pytest.raises(click.ClickException) as exc:
        cli._fail(ReproAssertError("hostile", hostile))

    rendered = exc.value.format_message()
    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "\x00" not in rendered
    assert "clipboard" not in rendered


def test_pytest_target_cannot_begin_with_dash() -> None:
    sandbox = DockerSandbox(SandboxPolicy())
    sandbox._volumes.add("controller-volume")

    with pytest.raises(ReproAssertError) as exc:
        sandbox.run_pytest(
            volume="controller-volume",
            target="--help",
            phase="collect",
            run_id="red-team",
        )

    assert exc.value.code == "sandbox_target"


def test_replay_refuses_symlink_and_oversized_reports(tmp_path: Path) -> None:
    real_report = tmp_path / "real-report.json"
    real_report.write_text(json.dumps(_valid_report()))
    symlink_report = tmp_path / "symlink-report.json"
    symlink_report.symlink_to(real_report)

    with pytest.raises((OSError, PolicyRejection)):
        load_replay_spec(symlink_report)

    oversized = tmp_path / "oversized-report.json"
    oversized.write_bytes(b"{" + b" " * MAX_REPORT_BYTES + b"}")
    with pytest.raises(PolicyRejection) as exc:
        load_replay_spec(oversized)
    assert exc.value.code == "invalid_report"


def test_report_writer_refuses_symlink_output(tmp_path: Path) -> None:
    sensitive = tmp_path / "sensitive"
    sensitive.write_text("unchanged")
    output = tmp_path / "report.json"
    output.symlink_to(sensitive)

    with pytest.raises(PolicyRejection):
        write_report(output, _valid_report())

    assert sensitive.read_text() == "unchanged"


def test_report_writer_rejects_oversized_output_before_creating_file(tmp_path: Path) -> None:
    report = _valid_report()
    report["padding"] = "x" * MAX_REPORT_BYTES
    output = tmp_path / "report.json"

    with pytest.raises(PolicyRejection) as exc:
        write_report(output, report)

    assert exc.value.code == "report_too_large"
    assert not output.exists()


def test_terminal_sanitizer_removes_csi_osc_clipboard_cr_and_controls() -> None:
    hostile = (
        "start\x1b[2Jafter-csi\rrewrite"
        "\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\"
        "\x1b]52;c;Y2xpcGJvYXJk\x07\x00\x08\u202eend"
    )

    sanitized = sanitize_log(hostile)

    assert sanitized == "startafter-csi\nrewritelinkend"
    assert all(character not in sanitized for character in ("\x1b", "\r", "\x00", "\x08"))


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (
            "SIDE_EFFECT = print('runs during collection')\n\n"
            "def test_issue_9_reproduction():\n"
            "    assert True, 'expected symptom'\n",
            "candidate_top_level_execution",
        ),
        (
            "import socket\n\n"
            "def test_issue_9_reproduction():\n"
            "    assert True, 'expected symptom'\n",
            "candidate_forbidden_import",
        ),
        (
            "from os import system as harmless_name\n\n"
            "def test_issue_9_reproduction():\n"
            "    harmless_name('echo blocked')\n"
            "    assert True, 'expected symptom'\n",
            "candidate_forbidden_import",
        ),
        (
            "import pytest\n\n"
            "@pytest.mark.skip(reason='not a reproduction')\n"
            "def test_issue_9_reproduction():\n"
            "    assert True, 'expected symptom'\n",
            "candidate_skip_marker",
        ),
        (
            "import pytest\n\n"
            "def test_issue_9_reproduction():\n"
            "    pytest.xfail('not a reproduction')\n"
            "    assert True, 'expected symptom'\n",
            "candidate_forbidden_call",
        ),
    ],
)
def test_candidate_rejects_top_level_network_process_and_skip_patterns(
    content: str, code: str
) -> None:
    with pytest.raises(PolicyRejection) as exc:
        validate_candidate_payload(_candidate_payload(content), issue_number=9)
    assert exc.value.code == code


def test_candidate_keeps_literal_top_level_test_data() -> None:
    content = (
        "from fixture_project import normalize\n\n"
        "CASES = [('a--b', 'a-b'), ('c--d', 'c-d')]\n\n"
        "def test_issue_9_reproduction():\n"
        "    assert normalize(CASES[0][0]) == CASES[0][1], 'expected symptom'\n"
    )

    candidate = validate_candidate_payload(_candidate_payload(content), issue_number=9)

    assert candidate.test_function == "test_issue_9_reproduction"


@pytest.mark.parametrize("primitive", ["_exit", "popen", "system"])
def test_candidate_rejects_aliased_os_process_imports(primitive: str) -> None:
    content = (
        f"from os import {primitive} as harmless_name\n\n"
        "def test_issue_9_reproduction():\n"
        "    harmless_name('blocked')\n"
        "    assert True, 'expected symptom'\n"
    )

    with pytest.raises(PolicyRejection) as exc:
        validate_candidate_payload(_candidate_payload(content), issue_number=9)
    assert exc.value.code == "candidate_forbidden_import"


def test_candidate_resolves_module_and_function_aliases() -> None:
    module_alias = (
        "import os as harmless_module\n\n"
        "def test_issue_9_reproduction():\n"
        "    harmless_module.system('blocked')\n"
        "    assert True, 'expected symptom'\n"
    )
    function_alias = (
        "from time import sleep as pause\n\n"
        "def test_issue_9_reproduction():\n"
        "    pause(1)\n"
        "    assert True, 'expected symptom'\n"
    )

    for content in (module_alias, function_alias):
        with pytest.raises(PolicyRejection) as exc:
            validate_candidate_payload(_candidate_payload(content), issue_number=9)
        assert exc.value.code == "candidate_forbidden_call"


def test_docker_verification_args_exclude_binds_secrets_and_proxy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "top-secret-token")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/host/agent.sock")
    monkeypatch.setenv("HTTPS_PROXY", "http://host-proxy.invalid")
    sandbox = DockerSandbox(SandboxPolicy(image="sandbox@sha256:" + "f" * 64))

    args = sandbox.verification_create_args(
        name="run",
        volume="controller-volume",
        run_id="red-team",
        process_args=[
            "/usr/local/bin/python",
            "-m",
            "pytest",
            "tests/reproassert/test_issue_9.py::test_issue_9_reproduction",
        ],
    )
    joined = " ".join(args)

    assert "--network none" in joined
    assert "--read-only" in args
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges=true" in args
    assert "--pull never" in joined
    assert "type=volume,src=controller-volume,dst=/workspace,readonly" in args
    assert "type=bind" not in joined
    assert "/var/run/docker.sock" not in joined
    assert "top-secret-token" not in joined
    assert "/host/agent.sock" not in joined
    assert "host-proxy.invalid" not in joined
    assert "GITHUB_TOKEN" not in joined
    assert "SSH_AUTH_SOCK" not in joined
    assert "HTTP_PROXY" not in joined
    assert "HTTPS_PROXY" not in joined
    assert args[args.index("--entrypoint") + 1] == "/usr/bin/env"
    assert "-i" in args
