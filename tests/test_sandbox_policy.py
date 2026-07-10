from __future__ import annotations

import math

import pytest

from reproassert.sandbox import DockerSandbox, SandboxPolicy


def test_verification_command_has_no_host_mount_or_network() -> None:
    sandbox = DockerSandbox(SandboxPolicy(image="sandbox@sha256:" + "a" * 64))
    args = sandbox.verification_create_args(
        name="run",
        volume="controller-volume",
        run_id="abc",
        process_args=["/usr/local/bin/python", "-m", "pytest", "tests/reproassert/test.py"],
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
    assert "SSH_AUTH_SOCK" not in joined
    assert "GITHUB_TOKEN" not in joined
    assert "HTTP_PROXY" not in joined
    assert "/usr/bin/env" in args
    assert "-i" in args
    assert "PYTHONPATH=/workspace:/workspace/src:/workspace/.reproassert-deps" in args
    assert not any("/dependencies" in argument for argument in args)


def test_verification_command_has_resource_limits() -> None:
    sandbox = DockerSandbox(SandboxPolicy())
    args = sandbox.verification_create_args(
        name="run",
        volume="volume",
        run_id="abc",
        process_args=["python", "-m", "pytest", "test.py"],
    )
    joined = " ".join(args)

    assert "--pids-limit 128" in joined
    assert "--memory 1073741824" in joined
    assert "--memory-swap 1073741824" in joined
    assert "--cpus 1.0" in joined
    assert "nofile=256:256" in args
    assert "core=0:0" in args
    assert "nr_inodes=4096" in joined
    assert "max-size=128k" in args
    assert "compress=false" in args


def test_verification_command_mounts_prepared_dependencies_read_only_and_offline() -> None:
    sandbox = DockerSandbox(SandboxPolicy())
    args = sandbox.verification_create_args(
        name="run",
        volume="source-volume",
        dependency_volume="dependency-volume",
        run_id="abc",
        process_args=["python", "-m", "pytest", "test.py"],
    )
    joined = " ".join(args)

    assert "--network none" in joined
    assert "type=volume,src=dependency-volume,dst=/dependencies,readonly" in args
    assert "PYTHONPATH=/workspace:/workspace/src:/dependencies:/workspace/.reproassert-deps" in args


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image", "--privileged"),
        ("timeout_seconds", -1),
        ("timeout_seconds", math.inf),
        ("max_output_bytes", -1),
        ("memory_bytes", 0),
        ("cpus", 0),
        ("cpus", math.nan),
        ("pids", -1),
        ("tmpfs_bytes", 0),
        ("tmpfs_inodes", 0),
    ],
)
def test_sandbox_policy_rejects_disabled_or_non_finite_limits(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        SandboxPolicy(**{field: value})  # type: ignore[arg-type]


def test_zero_timeout_and_output_limits_remain_valid_fail_closed_settings() -> None:
    policy = SandboxPolicy(timeout_seconds=0, max_output_bytes=0)
    assert policy.timeout_seconds == 0
    assert policy.max_output_bytes == 0
