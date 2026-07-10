from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

import reproassert.sandbox as sandbox_module
from reproassert.errors import ReproAssertError
from reproassert.sandbox import DockerSandbox, SandboxPolicy


def completed(
    args: list[str] | None = None, *, code: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args or ["docker"], code, stdout, stderr)


def test_doctor_and_readiness_classify_engine_and_image(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/usr/local/bin/docker"
    responses = iter(
        [
            completed(stdout=json.dumps({"ServerVersion": "29.3.1"})),
            completed(stdout="sha256:image\n"),
        ]
    )
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: next(responses))

    status = sandbox.require_ready()

    assert status.server_version == "29.3.1"
    assert status.image_available
    assert status.image_id == "sha256:image"

    sandbox._docker = None
    with pytest.raises(ReproAssertError, match="Docker CLI"):
        sandbox.require_ready()


def test_doctor_handles_engine_and_image_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/docker"
    monkeypatch.setattr(
        sandbox, "_control", lambda *_args, **_kwargs: completed(code=1, stderr="off")
    )
    assert not sandbox.doctor().engine_available
    with pytest.raises(ReproAssertError, match="not running"):
        sandbox.require_ready()

    responses = iter([completed(stdout="not-json"), completed(code=1)])
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: next(responses))
    status = sandbox.doctor()
    assert status.engine_available
    assert status.server_version is None
    monkeypatch.setattr(sandbox, "doctor", lambda: status)
    with pytest.raises(ReproAssertError, match="Sandbox image"):
        sandbox.require_ready()


def test_build_image_uses_embedded_hash_locked_context(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/docker"
    calls: list[list[str]] = []

    def fake_control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return completed(stdout="sha256:built\n" if args[:2] == ["image", "inspect"] else "")

    monkeypatch.setattr(sandbox, "_control", fake_control)

    image_id = sandbox.build_image()

    assert image_id == "sha256:built"
    build = next(args for args in calls if args[0] == "build")
    assert "--pull" in build
    assert sandbox.policy.image in build


def test_runner_facts_are_probed_without_mounts_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/docker"
    monkeypatch.setattr(sandbox, "require_ready", lambda: None)
    calls: list[list[str]] = []

    def fake_control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "run":
            return completed(
                stdout=json.dumps(
                    {
                        "python_version": "3.12.11",
                        "python_implementation": "CPython",
                        "pytest_version": "9.1.1",
                        "platform_system": "Linux",
                        "platform_release": "6.12",
                        "machine": "x86_64",
                    }
                )
            )
        return completed()

    monkeypatch.setattr(sandbox, "_control", fake_control)

    facts = sandbox.runner_facts()

    assert facts["pytest_version"] == "9.1.1"
    run = next(args for args in calls if args[0] == "run")
    assert "none" in run
    assert "--read-only" in run
    assert "--cap-drop" in run
    assert not any("mount" in argument for argument in run)


def test_stage_source_creates_controller_volume_without_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n")
    sandbox = DockerSandbox()
    calls: list[list[str]] = []
    monkeypatch.setattr(sandbox, "require_ready", lambda: None)
    monkeypatch.setattr(
        sandbox,
        "_control",
        lambda args, **_kwargs: calls.append(list(args)) or completed(),
    )
    monkeypatch.setattr(sandbox, "_set_workspace_owner", lambda *_args, **_kwargs: None)

    volume = sandbox.stage_source(source, run_id="run-123")

    assert volume in sandbox._volumes
    assert any(args[:2] == ["volume", "create"] for args in calls)
    copy_args = next(args for args in calls if args[0] == "cp")
    assert copy_args[1] == "-a"
    assert all("type=bind" not in " ".join(args) for args in calls)


def test_run_pytest_builds_inspects_and_cleans_container(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    sandbox._volumes.add("volume")
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: completed())
    monkeypatch.setattr(sandbox, "_assert_container_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        sandbox,
        "_start_attached",
        lambda _name: sandbox_module._AttachedResult("1 failed", False, False, False),
    )
    monkeypatch.setattr(
        sandbox,
        "_container_state",
        lambda _name: {"ExitCode": 1, "OOMKilled": False},
    )
    monkeypatch.setattr(sandbox, "_copy_junit", lambda *_args: b"<testsuite/>")

    result = sandbox.run_pytest(
        volume="volume",
        target="tests/reproassert/test_issue_1.py::test_issue_1_reproduction",
        phase="verify",
        run_id="run",
    )

    assert result.exit_code == 1
    assert result.junit_xml == b"<testsuite/>"
    assert result.argv[:3] == ("/usr/local/bin/python", "-m", "pytest")
    assert not sandbox._containers
    with pytest.raises(ReproAssertError):
        sandbox.run_pytest(
            volume="other",
            target="tests/reproassert/test.py",
            phase="x",
            run_id="x",
        )
    with pytest.raises(ReproAssertError):
        sandbox.run_pytest(
            volume="volume",
            target="--help",
            phase="x",
            run_id="x",
        )


def test_container_policy_inspection_accepts_exact_hardening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    inspected = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "PidsLimit": 128,
            "Memory": 1024 * 1024 * 1024,
            "MemorySwap": 1024 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Devices": [],
            "Binds": None,
        },
        "Config": {"User": "65532:65532"},
        "Mounts": [
            {
                "Type": "volume",
                "Name": "volume",
                "Destination": "/workspace",
                "RW": False,
            }
        ],
    }
    monkeypatch.setattr(sandbox, "_inspect", lambda _name: inspected)
    sandbox._assert_container_policy("container", volume="volume")

    inspected["HostConfig"]["NetworkMode"] = "bridge"
    monkeypatch.setattr(sandbox, "_remove_container", lambda _name: None)
    with pytest.raises(ReproAssertError, match="network_none"):
        sandbox._assert_container_policy("container", volume="volume")


def test_container_policy_requires_exact_read_only_dependency_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    inspected = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "PidsLimit": 128,
            "Memory": 1024 * 1024 * 1024,
            "MemorySwap": 1024 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Devices": [],
            "Binds": None,
        },
        "Config": {"User": "65532:65532"},
        "Mounts": [
            {
                "Type": "volume",
                "Name": "source",
                "Destination": "/workspace",
                "RW": False,
            },
            {
                "Type": "volume",
                "Name": "dependencies",
                "Destination": "/dependencies",
                "RW": False,
            },
        ],
    }
    monkeypatch.setattr(sandbox, "_inspect", lambda _name: inspected)
    sandbox._assert_container_policy("container", volume="source", dependency_volume="dependencies")

    inspected["Mounts"][1]["RW"] = True
    monkeypatch.setattr(sandbox, "_remove_container", lambda _name: None)
    with pytest.raises(ReproAssertError, match="dependencies_ro"):
        sandbox._assert_container_policy(
            "container", volume="source", dependency_volume="dependencies"
        )


def test_workspace_owner_and_cleanup_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        sandbox,
        "_control",
        lambda args, **_kwargs: calls.append(list(args)) or completed(),
    )
    monkeypatch.setattr(sandbox, "_container_state", lambda _name: {"ExitCode": 0})

    sandbox._set_workspace_owner("volume", run_id="run")

    owner_create = next(args for args in calls if args[0] == "create")
    assert "CHOWN" in owner_create
    assert "DAC_READ_SEARCH" in owner_create
    assert "--network" in owner_create and "none" in owner_create
    assert "--read-only" in owner_create
    assert "/bin/chown" in owner_create
    sandbox._containers.add("leftover")
    sandbox._volumes.add("volume")
    sandbox.cleanup()
    assert not sandbox._containers
    assert not sandbox._volumes


def test_copy_junit_accepts_only_small_regular_file(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()

    def fake_control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        Path(args[-1]).write_bytes(b"<testsuite/>")
        return completed()

    monkeypatch.setattr(sandbox, "_control", fake_control)
    assert sandbox._copy_junit("container", "/tmp/result.xml") == b"<testsuite/>"

    monkeypatch.setattr(
        sandbox, "_control", lambda *_args, **_kwargs: completed(code=1, stderr="missing")
    )
    assert sandbox._copy_junit("container", "/tmp/missing.xml") is None


def test_inspect_and_control_reject_invalid_or_failed_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/docker"
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: completed(stdout="[]"))
    with pytest.raises(ReproAssertError, match="invalid data"):
        sandbox._inspect("container")

    control_sandbox = DockerSandbox()
    control_sandbox._docker = "/docker"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(code=2, stderr="\x1b[31mfailed\x1b[0m"),
    )
    with pytest.raises(ReproAssertError, match="failed"):
        control_sandbox._control(["info"])
    assert control_sandbox._control(["info"], check=False).returncode == 2


class ImmediateProcess:
    def __init__(self, output: bytes) -> None:
        self.stdout = io.BytesIO(output)

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        pass


def test_attached_output_is_bounded_and_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox(SandboxPolicy(max_output_bytes=64))
    sandbox._docker = "/docker"
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: ImmediateProcess(b"ok\x1b[31m red\x1b[0m"),
    )

    result = sandbox._start_attached("container")

    assert result.output == "ok red"
    assert not result.output_truncated
