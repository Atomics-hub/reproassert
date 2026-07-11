from __future__ import annotations

import json
from typing import ClassVar

import pytest

from reproassert.benchmark_v02_instance_executor import InstanceRuntimeExecutor
from reproassert.benchmark_v02_instance_runtime import InstanceRuntime, InstanceRuntimeManifest
from reproassert.dependency_executor import CommandResult
from reproassert.errors import PolicyRejection
from reproassert.sandbox import SandboxPolicy


def _runtime() -> InstanceRuntime:
    return InstanceRuntime(
        case_id="rk-v0.2-001",
        instance_id="astropy__astropy-14309",
        base_sha="a" * 40,
        base_tree_oid="b" * 40,
        spec_sha256="c" * 64,
        image_tag="swebench/sweb.eval.x86_64.astropy_1776_astropy-14309:latest",
        image_digest=f"sha256:{'d' * 64}",
        image_id=f"sha256:{'e' * 64}",
    )


def _manifest() -> InstanceRuntimeManifest:
    return InstanceRuntimeManifest(
        harness_git_sha="f" * 40,
        harness_specs_sha256="1" * 64,
        entries=(_runtime(),),
        sha256="2" * 64,
    )


class FakeDocker:
    commands: ClassVar[list[list[str]]]

    def __init__(self) -> None:
        self.commands = []
        self.containers: dict[str, dict[str, object]] = {}

    def run(
        self,
        args: list[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        del timeout_seconds, max_output_bytes, input_bytes
        self.commands.append(list(args))
        if args[:2] == ["image", "inspect"]:
            runtime = _runtime()
            return self._result(
                json.dumps(
                    [
                        {
                            "Architecture": "amd64",
                            "Id": runtime.image_id,
                            "Os": "linux",
                            "RepoDigests": [
                                f"{runtime.image_tag.rsplit(':', 1)[0]}@{runtime.image_digest}"
                            ],
                        }
                    ]
                )
            )
        if args[:2] == ["volume", "inspect"]:
            return self._result("not found", returncode=1)
        if args[:2] == ["volume", "create"]:
            return self._result(args[-1] + "\n")
        if args[0] == "create":
            name = args[args.index("--name") + 1]
            mount_args = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
            parsed_mounts = [
                dict(part.split("=", 1) for part in value.split(",")) for value in mount_args
            ]
            image_id = _runtime().image_id
            image_index = args.index(image_id)
            self.containers[name] = {
                "Config": {
                    "Cmd": args[image_index + 1 :],
                    "Entrypoint": [args[args.index("--entrypoint") + 1]],
                    "Env": ["PATH=/usr/bin:/bin", "HOME=/tmp/home"],
                    "User": "0:0",
                },
                "HostConfig": {
                    "Binds": None,
                    "CapDrop": ["ALL"],
                    "Memory": 1024 * 1024 * 1024,
                    "MemorySwap": 1024 * 1024 * 1024,
                    "NanoCpus": 1_000_000_000,
                    "NetworkMode": "none",
                    "PidsLimit": 128,
                    "ReadonlyRootfs": "--read-only" in args,
                    "SecurityOpt": ["no-new-privileges"],
                    "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=67108864,nr_inodes=4096"},
                },
                "Image": image_id,
                "Mounts": [
                    {
                        "Destination": mount["dst"],
                        "Name": mount["src"],
                        "RW": True,
                        "Type": "volume",
                    }
                    for mount in parsed_mounts
                ],
            }
            return self._result("3" * 64 + "\n")
        if args[:2] == ["container", "inspect"]:
            return self._result(json.dumps([self.containers[args[2]]]))
        if args[:3] == ["container", "rm", "--force"]:
            self.containers.pop(args[3], None)
            return self._result("")
        if args[:2] == ["start", "--attach"] and "pytest" in args[2]:
            return self._result("one failed\n", returncode=1)
        return self._result("")

    @staticmethod
    def _result(output: str, *, returncode: int = 0) -> CommandResult:
        return CommandResult(returncode=returncode, output=output)


def _executor(fake: FakeDocker) -> InstanceRuntimeExecutor:
    return InstanceRuntimeExecutor(
        _manifest(),
        case_id="rk-v0.2-001",
        policy=SandboxPolicy(image=_runtime().image_id),
        runner=fake,
    )


def test_acquisition_is_separate_and_requires_digest_id_and_amd64() -> None:
    fake = FakeDocker()
    executor = _executor(fake)

    executor.acquire()

    assert fake.commands[0] == [
        "pull",
        "--platform",
        "linux/amd64",
        _runtime().image_tag,
    ]
    assert fake.commands[1] == ["image", "inspect", _runtime().image_tag]
    assert not any(command[0] == "create" for command in fake.commands)


def test_prepares_two_fresh_workspaces_and_runs_bounded_pytest() -> None:
    fake = FakeDocker()
    executor = _executor(fake)
    executor.acquire()

    workspaces = executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")
    executor.stage_candidate(
        relative_path="tests/test_reproassert_issue_14305.py",
        content=b"def test_repro():\n    assert False\n",
    )
    result = executor.run_pytest(
        workspace="base",
        targets=("tests/test_reproassert_issue_14305.py::test_case[param-1]",),
        collect_only=True,
    )

    assert workspaces.base_volume != workspaces.fixed_volume
    assert result.exit_code == 1
    creates = [command for command in fake.commands if command[0] == "create"]
    assert creates
    assert all(
        "--network" in command and command[command.index("--network") + 1] == "none"
        for command in creates
    )
    assert all(
        "--platform" in command and command[command.index("--platform") + 1] == "linux/amd64"
        for command in creates
    )
    assert all("--read-only" in command for command in creates)
    assert all("--cap-drop" in command and "ALL" in command for command in creates)
    assert all("type=bind" not in " ".join(command) for command in creates)
    assert any(command[0] == "cp" and ":/input/" in command[-1] for command in fake.commands)
    pytest_create = next(command for command in creates if "pytest-base" in " ".join(command))
    assert "--collect-only" in pytest_create
    assert "tests/test_reproassert_issue_14305.py::test_case[param-1]" in pytest_create
    assert "/opt/miniconda3/envs/testbed/bin/python -I -m pytest" in " ".join(pytest_create)
    assert "HOME=/tmp/home" in pytest_create

    executor.cleanup()
    assert not fake.containers


@pytest.mark.parametrize(
    "target",
    [
        "--pwn",
        "/etc/passwd",
        "../test.py",
        "tests/../../escape.py",
        "tests/test.py::",
        "tests/test.py::node\n--pwn",
    ],
)
def test_rejects_untrusted_pytest_targets(target: str) -> None:
    fake = FakeDocker()
    executor = _executor(fake)
    executor.acquire()
    executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")

    with pytest.raises(PolicyRejection):
        executor.run_pytest(workspace="base", targets=(target,))


def test_rejects_wrong_policy_image() -> None:
    with pytest.raises(PolicyRejection, match="frozen image ID"):
        InstanceRuntimeExecutor(
            _manifest(),
            case_id="rk-v0.2-001",
            policy=SandboxPolicy(image=f"sha256:{'9' * 64}"),
            runner=FakeDocker(),
        )


def test_git_operations_use_isolated_home_and_safe_directory() -> None:
    fake = FakeDocker()
    executor = _executor(fake)
    executor.acquire()
    executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")

    creates = [command for command in fake.commands if command[0] == "create"]
    copy_command = next(command for command in creates if "copy-base" in " ".join(command))
    patch_command = next(
        command
        for command in fake.commands
        if command[0] == "exec" and "reproassert-patch" in " ".join(command)
    )
    assert "git config --global --add safe.directory /workspace" in " ".join(copy_command)
    assert "git config --global --add safe.directory /workspace" in " ".join(patch_command)


def test_public_patch_api_can_stage_developer_tests_on_both_workspaces() -> None:
    fake = FakeDocker()
    executor = _executor(fake)
    executor.acquire()
    executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")

    executor.apply_patch(workspace="base", patch=b"diff --git a/t b/t\n")
    executor.apply_patch(workspace="fixed", patch=b"diff --git a/t b/t\n")

    patch_execs = [
        command
        for command in fake.commands
        if command[0] == "exec" and "reproassert-patch" in " ".join(command)
    ]
    assert len(patch_execs) == 3
    assert any("stage-patch-base" in " ".join(command) for command in fake.commands)
