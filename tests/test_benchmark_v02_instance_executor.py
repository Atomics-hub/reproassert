from __future__ import annotations

import json
from dataclasses import replace
from typing import ClassVar

import pytest

from reproassert.benchmark_v02_instance_executor import InstanceRuntimeExecutor
from reproassert.benchmark_v02_instance_runtime import InstanceRuntime, InstanceRuntimeManifest
from reproassert.dependency_executor import CommandResult
from reproassert.errors import PolicyRejection, ReproAssertError
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
        test_command_profile="pytest-v1",
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

    def __init__(
        self,
        runtime: InstanceRuntime | None = None,
        policy: SandboxPolicy | None = None,
    ) -> None:
        self.commands = []
        self.containers: dict[str, dict[str, object]] = {}
        self.runtime = runtime or _runtime()
        self.policy = policy or SandboxPolicy(image=self.runtime.image_id)

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
            runtime = self.runtime
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
            image_id = self.runtime.image_id
            image_index = args.index(image_id)
            controller_env = [
                args[index + 1] for index, value in enumerate(args) if value == "--env"
            ]
            self.containers[name] = {
                "Config": {
                    "Cmd": args[image_index + 1 :],
                    "Entrypoint": [args[args.index("--entrypoint") + 1]],
                    "Env": ["PATH=/usr/bin:/bin", *controller_env],
                    "User": args[args.index("--user") + 1],
                },
                "HostConfig": {
                    "Binds": None,
                    "CapAdd": [
                        args[index + 1] for index, value in enumerate(args) if value == "--cap-add"
                    ],
                    "CapDrop": ["ALL"],
                    "Memory": self.policy.memory_bytes,
                    "MemorySwap": self.policy.memory_bytes,
                    "NanoCpus": int(self.policy.cpus * 1_000_000_000),
                    "NetworkMode": "none",
                    "PidsLimit": self.policy.pids,
                    "ReadonlyRootfs": "--read-only" in args,
                    "SecurityOpt": ["no-new-privileges"],
                    "Tmpfs": {
                        "/tmp": (
                            "rw,noexec,nosuid,nodev,"
                            f"size={self.policy.tmpfs_bytes},"
                            f"nr_inodes={self.policy.tmpfs_inodes}"
                        )
                    },
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
        if args[:2] == ["start", "--attach"] and "test-base" in args[2]:
            return self._result("one failed\n", returncode=1)
        return self._result("")

    @staticmethod
    def _result(output: str, *, returncode: int = 0) -> CommandResult:
        return CommandResult(returncode=returncode, output=output)


def _executor(fake: FakeDocker, runtime: InstanceRuntime | None = None) -> InstanceRuntimeExecutor:
    selected = runtime or _runtime()
    return InstanceRuntimeExecutor(
        replace(_manifest(), entries=(selected,)),
        case_id=selected.case_id,
        policy=SandboxPolicy(image=selected.image_id),
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
    pytest_create = next(command for command in creates if "test-base" in " ".join(command))
    assert "--collect-only" in pytest_create
    assert "tests/test_reproassert_issue_14305.py::test_case[param-1]" in pytest_create
    assert "/opt/miniconda3/envs/testbed/bin/python -m pytest" in " ".join(pytest_create)
    assert "HOME=/tmp/home" in pytest_create
    assert "PYTHONPATH=/workspace:/workspace/src" in pytest_create
    assert pytest_create[pytest_create.index("--user") + 1] == "65532:65532"
    controller_creates = [command for command in creates if command is not pytest_create]
    assert all(command[command.index("--user") + 1] == "0:0" for command in controller_creates)
    assert all("PYTHONPATH=" not in " ".join(command) for command in controller_creates)
    assert all(
        "=" in command[index + 1]
        for command in creates
        for index, value in enumerate(command)
        if value == "--env"
    )

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
    assert "git config --global --add safe.directory /testbed" in " ".join(copy_command)
    assert "git config --global --add safe.directory /workspace" in " ".join(patch_command)
    assert "chmod -R" not in " ".join(copy_command)
    assert "chown -R 65532:65532 /workspace" in " ".join(copy_command)
    assert "source_diff=" in " ".join(copy_command)
    assert "workspace_diff=" in " ".join(copy_command)
    assert 'test -z "$(git status' not in " ".join(copy_command)
    assert copy_command[copy_command.index("--cap-add") + 1] == "CHOWN"
    non_copy_creates = [command for command in creates if "copy-" not in " ".join(command)]
    assert all("--cap-add" not in command for command in non_copy_creates)


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


def test_sympy_profile_runs_only_frozen_bin_test_as_nonroot() -> None:
    runtime = replace(
        _runtime(),
        case_id="rk-v0.2-016",
        instance_id="sympy__sympy-15345",
        image_tag="swebench/sweb.eval.x86_64.sympy_1776_sympy-15345:latest",
        test_command_profile="sympy-bin-test-v1",
    )
    fake = FakeDocker(runtime)
    executor = _executor(fake, runtime)
    executor.acquire()
    executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")

    result = executor.run_test_command(
        workspace="base", targets=("sympy/core/tests/test_basic.py",)
    )

    assert result.exit_code == 1
    test_create = next(
        command
        for command in fake.commands
        if command[0] == "create" and "test-base" in " ".join(command)
    )
    rendered = " ".join(test_create)
    assert "/opt/miniconda3/envs/testbed/bin/python bin/test -C --verbose" in rendered
    assert "PYTHONWARNINGS=" in rendered
    assert test_create[test_create.index("--user") + 1] == "65532:65532"
    assert "PYTHONPATH=/workspace:/workspace/src" in test_create
    with pytest.raises(ReproAssertError, match="does not use the pytest"):
        executor.run_pytest(workspace="base", targets=("sympy/core/tests/test_basic.py",))


def test_custom_resource_policy_is_enforced_by_container_inspection() -> None:
    policy = SandboxPolicy(
        image=_runtime().image_id,
        timeout_seconds=600.0,
        max_output_bytes=2 * 1024 * 1024,
        memory_bytes=4 * 1024 * 1024 * 1024,
        cpus=2.0,
        pids=512,
        tmpfs_bytes=512 * 1024 * 1024,
        tmpfs_inodes=32_768,
    )
    fake = FakeDocker(policy=policy)
    executor = InstanceRuntimeExecutor(
        _manifest(), case_id="rk-v0.2-001", policy=policy, runner=fake
    )

    executor.acquire()
    executor.prepare_workspaces(fixed_patch=b"diff --git a/a b/a\n")
    executor.run_test_command(workspace="base", targets=("tests/test_issue.py",))

    creates = [command for command in fake.commands if command[0] == "create"]
    assert any("4294967296" in command for command in creates)
    assert any(any("536870912" in token for token in command) for command in creates)
    assert any("--cpus" in command and "2" in command for command in creates)
    assert any("--pids-limit" in command and "512" in command for command in creates)
