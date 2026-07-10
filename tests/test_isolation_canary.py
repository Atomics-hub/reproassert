from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

import reproassert.isolation_canary as canary
import reproassert.sandbox as sandbox_module
from reproassert.errors import ReproAssertError
from reproassert.sandbox import DockerDoctor, DockerSandbox, SandboxPolicy

IMAGE_ID = "sha256:" + "a" * 64
IMAGE_ENVIRONMENT = (
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "PYTHON_VERSION=3.12.13",
)
SECRET = b"canary-value-must-never-leak!!!!"


def completed(
    args: list[str], *, code: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, code, stdout, stderr)


class FakeDocker:
    def __init__(self, *, drift: str | None = None, negative_passes: bool = True) -> None:
        self.drift = drift
        self.negative_passes = negative_passes
        self.calls: list[list[str]] = []

    def install(self, sandbox: DockerSandbox, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sandbox,
            "require_ready",
            lambda: DockerDoctor(True, True, True, "29.3.1", IMAGE_ID),
        )
        monkeypatch.setattr(sandbox, "_control", self.control)
        monkeypatch.setattr(sandbox, "_inspect", self.inspect)
        monkeypatch.setattr(sandbox, "_start_attached", self.start_attached)
        monkeypatch.setattr(sandbox, "_container_state", lambda _name: {"ExitCode": 0})

    def control(self, args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        call = list(args)
        self.calls.append(call)
        if call[:2] == ["image", "inspect"]:
            return completed(
                call,
                stdout=json.dumps([{"Id": IMAGE_ID, "Config": {"Env": list(IMAGE_ENVIRONMENT)}}]),
            )
        return completed(call)

    def inspect(self, name: str) -> dict[str, Any]:
        args = next(
            call
            for call in reversed(self.calls)
            if call[0] == "create" and call[call.index("--name") + 1] == name
        )
        mount = _mount_fields(args[args.index("--mount") + 1])
        image_index = args.index("sandbox@sha256:" + "b" * 64)
        tmpfs = args[args.index("--tmpfs") + 1].partition(":")[2]
        inspected: dict[str, Any] = {
            "Image": IMAGE_ID,
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
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
                "Tmpfs": {"/tmp": tmpfs},
                "LogConfig": {
                    "Type": "local",
                    "Config": {"max-size": "128k", "max-file": "1", "compress": "false"},
                },
            },
            "Config": {
                "User": "65532:65532",
                "Env": list(IMAGE_ENVIRONMENT),
                "Entrypoint": ["/usr/bin/env"],
                "Cmd": args[image_index + 1 :],
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": mount["src"],
                    "Destination": mount["dst"],
                    "RW": False,
                }
            ],
        }
        if "generator" in name:
            if self.drift == "network":
                inspected["HostConfig"]["NetworkMode"] = "bridge"
            elif self.drift == "mount":
                inspected["Mounts"].append(
                    {
                        "Type": "volume",
                        "Name": "evaluator-oracle",
                        "Destination": "/evaluator",
                        "RW": False,
                    }
                )
            elif self.drift == "env":
                inspected["Config"]["Cmd"].insert(1, "GITHUB_TOKEN=unexpected")
        return inspected

    def start_attached(self, name: str) -> sandbox_module._AttachedResult:
        if "positive" in name:
            output = canary.POSITIVE_MARKER
        elif self.negative_passes:
            output = canary.NEGATIVE_MARKER
        else:
            output = "negative control failed"
        return sandbox_module._AttachedResult(output, False, False, False)


def _mount_fields(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in value.split(","):
        key, separator, item = part.partition("=")
        if separator:
            fields[key] = item
    return fields


def _run_fake(
    monkeypatch: pytest.MonkeyPatch,
    *,
    drift: str | None = None,
    negative_passes: bool = True,
    control_wrapper: Callable[
        [Callable[..., subprocess.CompletedProcess[str]]],
        Callable[..., subprocess.CompletedProcess[str]],
    ]
    | None = None,
) -> tuple[canary.IsolationCanaryResult, FakeDocker]:
    sandbox = DockerSandbox(SandboxPolicy(image="sandbox@sha256:" + "b" * 64))
    fake = FakeDocker(drift=drift, negative_passes=negative_passes)
    fake.install(sandbox, monkeypatch)
    if control_wrapper is not None:
        monkeypatch.setattr(sandbox, "_control", control_wrapper(fake.control))
    monkeypatch.setattr(canary.secrets, "token_bytes", lambda _size: SECRET)
    return canary.run_isolation_canary(sandbox), fake


def test_canary_uses_two_exact_views_and_returns_hash_only_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, fake = _run_fake(monkeypatch)

    assert result.accepted
    assert result.tool_version
    assert result.tool_git_sha is None
    assert result.positive_control_passed
    assert result.negative_control_passed
    assert result.cleanup_succeeded
    assert result.sentinel_sha256 == hashlib.sha256(SECRET).hexdigest()
    assert result.positive_mount_destinations == ("/evaluator",)
    assert result.generator_mount_destinations == ("/workspace",)
    assert result.process_env_names == (
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "TZ",
    )
    assert result.image_env_names_cleared == ("PATH", "PYTHON_VERSION")
    assert len(result.policy_sha256) == 64
    assert len(result.config_sha256) == 64

    controls = [
        call
        for call in fake.calls
        if call[0] == "create" and "canary-stage" not in call[call.index("--name") + 1]
    ]
    assert len(controls) == 2
    mounts = {
        call[call.index("--name") + 1].split("-canary-")[1].split("-")[0]: call[
            call.index("--mount") + 1
        ]
        for call in controls
    }
    assert "dst=/evaluator,readonly" in mounts["positive"]
    assert "dst=/workspace,readonly" in mounts["generator"]
    for call in controls:
        joined = " ".join(call)
        assert "--pull never" in joined
        assert "--network none" in joined
        assert "--read-only" in call
        assert "--user 65532:65532" in joined
        assert "--cap-drop ALL" in joined
        assert "no-new-privileges=true" in call
        assert "--pids-limit 128" in joined
        assert "--memory 1073741824" in joined
        assert "--cpus 1.0" in joined
        assert "type=bind" not in joined
    assert len([call for call in fake.calls if call[:3] == ["volume", "rm", "-f"]]) == 2
    assert SECRET.decode() not in json.dumps(fake.calls)
    assert SECRET.decode() not in repr(result)


def test_configuration_hash_commits_full_policy_and_tool_revision() -> None:
    policy = SandboxPolicy(image="sandbox@sha256:" + "b" * 64)
    policy_sha = canary._json_sha256(canary.asdict(policy))
    base = canary._configuration_record(
        policy,
        image_id=IMAGE_ID,
        image_environment=IMAGE_ENVIRONMENT,
        policy_sha256=policy_sha,
        tool_git_sha=None,
    )
    revised = canary._configuration_record(
        policy,
        image_id=IMAGE_ID,
        image_environment=IMAGE_ENVIRONMENT,
        policy_sha256=policy_sha,
        tool_git_sha="f" * 40,
    )

    assert canary._json_sha256(base) != canary._json_sha256(revised)
    controls = base["container_policy"]
    assert isinstance(controls, dict)
    for name in (
        "network",
        "root_filesystem",
        "cap_drop",
        "security_options",
        "pids",
        "memory_bytes",
        "cpus",
        "ulimits",
        "tmpfs",
        "mount_read_only",
        "log_options",
        "process_environment_clear",
    ):
        assert name in controls


@pytest.mark.parametrize("drift", ["network", "mount", "env"])
def test_effective_network_mount_and_environment_drift_fail_closed_without_secret_leak(
    monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    sandbox = DockerSandbox(SandboxPolicy(image="sandbox@sha256:" + "b" * 64))
    fake = FakeDocker(drift=drift)
    fake.install(sandbox, monkeypatch)
    monkeypatch.setattr(canary.secrets, "token_bytes", lambda _size: SECRET)

    with pytest.raises(ReproAssertError) as captured:
        canary.run_isolation_canary(sandbox)

    assert captured.value.code == "isolation_canary_policy"
    assert SECRET.decode() not in str(captured.value)
    assert SECRET.decode() not in json.dumps(fake.calls)
    assert len([call for call in fake.calls if call[:3] == ["volume", "rm", "-f"]]) == 2


def test_negative_control_failure_is_recorded_not_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _fake = _run_fake(monkeypatch, negative_passes=False)

    assert result.positive_control_passed
    assert not result.negative_control_passed
    assert result.cleanup_succeeded
    assert not result.accepted


def test_cleanup_failure_is_recorded_not_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_volume_cleanup(
        control: Callable[..., subprocess.CompletedProcess[str]],
    ) -> Callable[..., subprocess.CompletedProcess[str]]:
        def wrapped(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[:3] == ["volume", "rm", "-f"]:
                return completed(args, code=1, stderr="volume busy")
            return control(args, **kwargs)

        return wrapped

    result, _fake = _run_fake(monkeypatch, control_wrapper=fail_volume_cleanup)

    assert not result.cleanup_succeeded
    assert not result.accepted


def test_invalid_policy_is_rejected_before_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox(SandboxPolicy(timeout_seconds=0))
    monkeypatch.setattr(
        sandbox,
        "require_ready",
        lambda: pytest.fail("Docker readiness must not run for an invalid policy"),
    )

    with pytest.raises(ReproAssertError, match="finite and positive"):
        canary.run_isolation_canary(sandbox)


def test_invalid_tool_revision_is_rejected_before_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    monkeypatch.setattr(
        sandbox,
        "require_ready",
        lambda: pytest.fail("Docker readiness must not run for an invalid revision"),
    )

    with pytest.raises(ReproAssertError, match="40 lowercase"):
        canary.run_isolation_canary(sandbox, tool_git_sha="ABC")


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("REPROASSERT_RUN_DOCKER_TESTS") != "1",
    reason="set REPROASSERT_RUN_DOCKER_TESTS=1 after building the sandbox image",
)
def test_real_docker_generator_view_cannot_read_evaluator_sentinel() -> None:
    result = canary.run_isolation_canary(DockerSandbox())

    assert result.accepted
    assert result.positive_control_passed
    assert result.negative_control_passed
    assert result.cleanup_succeeded
    assert result.positive_mount_destinations == ("/evaluator",)
    assert result.generator_mount_destinations == ("/workspace",)
