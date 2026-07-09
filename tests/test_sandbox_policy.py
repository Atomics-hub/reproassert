from __future__ import annotations

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
