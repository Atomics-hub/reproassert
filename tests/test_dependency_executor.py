from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from reproassert.dependency_attestor import (
    DEPENDENCY_TREE_ATTESTOR_SCRIPT,
    parse_container_tree_attestation,
)
from reproassert.dependency_command_contract import dependency_phase_command
from reproassert.dependency_executor import (
    CleanupOwnership,
    CommandResult,
    DependencyExecutor,
    DependencyVolumeHandle,
    EffectivePhasePolicy,
    ExecutionState,
    MountExpectation,
    PhaseOutcome,
    SubprocessDockerRunner,
    VolumeFileEvidence,
    VolumeProbe,
    VolumeSpec,
    _build_execution_receipt,
    _canonical_json_bytes,
    _ContainerResource,
)
from reproassert.dependency_prep import (
    DependencyPlan,
    LockedPackage,
    WheelArtifact,
    WheelhouseAttestation,
)
from reproassert.errors import ReproAssertError
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import attest_source_tree

IMAGE_ID = "sha256:" + "a" * 64


class QueueRunner:
    def __init__(
        self,
        responses: Sequence[CommandResult] | Callable[[tuple[str, ...]], CommandResult],
    ) -> None:
        self.responses = list(responses) if not callable(responses) else responses
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        del timeout_seconds, max_output_bytes, input_bytes
        command = tuple(args)
        self.calls.append(command)
        if callable(self.responses):
            return self.responses(command)
        if not self.responses:
            raise AssertionError(f"Unexpected Docker command: {command}")
        return self.responses.pop(0)


def _plan(*, wheel_sha256: str = "1" * 64) -> DependencyPlan:
    return DependencyPlan(
        case_id="rk-v0.2-001",
        base_sha="b" * 40,
        source_tree_sha256="c" * 64,
        python_version="3.12.13",
        runner_image="reproassert-sandbox:0.1.0",
        packages=(LockedPackage("example-dep", "1.2.3", (wheel_sha256,)),),
        raw_sha256="d" * 64,
        canonical_sha256="e" * 64,
    )


def _executor(
    runner: QueueRunner | None = None,
    *,
    wheel_sha256: str = "1" * 64,
    trusted_runner: bool = False,
) -> DependencyExecutor:
    with tempfile.TemporaryDirectory(prefix="reproassert-executor-unit-") as temporary:
        plan_path = Path(temporary).resolve() / "dependency-plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "schema_version": "0.1.0",
                    "case_id": "rk-v0.2-001",
                    "source": {"base_sha": "b" * 40, "tree_sha256": "c" * 64},
                    "runtime": {
                        "python_version": "3.12.13",
                        "runner_image": "reproassert-sandbox:0.1.0",
                    },
                    "index_policy": "pypi-hash-locked-wheels-v1",
                    "packages": [
                        {
                            "name": "example-dep",
                            "version": "1.2.3",
                            "sha256": [wheel_sha256],
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n"
        )
        if trusted_runner:
            with patch("reproassert.dependency_executor.shutil.which", return_value="/docker"):
                return DependencyExecutor(
                    plan_path,
                    policy=SandboxPolicy(image="reproassert-sandbox:0.1.0"),
                )
        return DependencyExecutor(
            plan_path,
            policy=SandboxPolicy(image="reproassert-sandbox:0.1.0"),
            runner=runner or QueueRunner([]),
        )


def _labels(executor: DependencyExecutor, role: str) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(executor._labels(role).items()))


def _volume_spec(executor: DependencyExecutor, role: str = "dependencies") -> VolumeSpec:
    size = 512 * 1024 * 1024 if role != "input" else 1024 * 1024
    return VolumeSpec(
        role=role,
        name=f"volume-{role}",
        size_bytes=size,
        max_inodes=32_768 if role == "dependencies" else 1024,
        labels=_labels(executor, role),
    )


def _empty_probe(*, digest: str = "1" * 64) -> VolumeProbe:
    return VolumeProbe(
        algorithm="reproassert-volume-probe-v1",
        tree_sha256=digest,
        member_count=0,
        file_count=0,
        directory_count=0,
        total_bytes=0,
        root_uid=65532,
        root_gid=65532,
        root_mode=0o700,
        single_file_path=None,
        single_file_sha256=None,
        files=(),
    )


def _phase_policy(*, phase: str = "install", network: str = "none") -> EffectivePhasePolicy:
    return EffectivePhasePolicy(
        phase=phase,
        image_id=IMAGE_ID,
        network_mode=network,
        user="65532:65532",
        read_only_root=True,
        cap_drop=("ALL",),
        no_new_privileges=True,
        healthcheck_disabled=True,
        trusted_phase_command=True,
        pids=128,
        memory_bytes=1024 * 1024 * 1024,
        memory_swap_bytes=1024 * 1024 * 1024,
        nano_cpus=1_000_000_000,
        mounts=(),
        command_sha256="2" * 64,
        config_sha256="3" * 64,
    )


def _install_mounts() -> tuple[MountExpectation, ...]:
    return (
        MountExpectation("input", "input-volume", "/input", False),
        MountExpectation("wheelhouse", "wheel-volume", "/wheelhouse", False),
        MountExpectation("dependencies", "dependency-volume", "/dependencies", True),
    )


def _install_command() -> tuple[str, ...]:
    return dependency_phase_command("install")


def _container_payload(
    executor: DependencyExecutor,
    name: str,
    *,
    mounts: tuple[MountExpectation, ...],
    command: tuple[str, ...],
) -> dict[str, object]:
    return {
        "Image": IMAGE_ID,
        "Config": {
            "Labels": dict(executor._containers[name].labels),
            "User": "65532:65532",
            "Entrypoint": ["/usr/bin/env"],
            "Cmd": list(command),
            "WorkingDir": "/tmp",
            "Healthcheck": {"Test": ["NONE"]},
            "OpenStdin": False,
        },
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
            "Binds": [],
            "Init": True,
            "ShmSize": 64 * 1024 * 1024,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=67108864,nr_inodes=4096"},
            "Ulimits": [
                {"Name": "nofile", "Soft": 256, "Hard": 256},
                {"Name": "core", "Soft": 0, "Hard": 0},
                {"Name": "fsize", "Soft": 134217728, "Hard": 134217728},
            ],
            "LogConfig": {
                "Type": "local",
                "Config": {"max-size": "128k", "max-file": "1", "compress": "false"},
            },
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": item.volume,
                "Destination": item.destination,
                "RW": item.writable,
            }
            for item in mounts
        ],
    }


def _inspect_policy(
    executor: DependencyExecutor,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    *,
    name: str,
    mounts: tuple[MountExpectation, ...],
    command: tuple[str, ...],
) -> EffectivePhasePolicy:
    monkeypatch.setattr(executor, "_inspect_container", lambda _name: payload)
    return executor._inspect_container_policy(
        name,
        phase="install",
        image_id=IMAGE_ID,
        network="none",
        user="65532:65532",
        mounts=mounts,
        entrypoint="/usr/bin/env",
        command=command,
        phase_resources=True,
    )


def test_public_executor_requires_strict_plan_path(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="dependency-plan Path"):
        DependencyExecutor(_plan())  # type: ignore[arg-type]

    invalid = tmp_path / "dependency-plan.json"
    invalid.write_text('{"schema_version":"0.1.0"}\n')
    with pytest.raises(ReproAssertError):
        DependencyExecutor(invalid)


def test_fixed_in_container_attestor_matches_host_algorithm(tmp_path: Path) -> None:
    root = tmp_path / "dependencies"
    package = root / "example_dep"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n")
    (root / "example_dep-1.2.3.dist-info").mkdir()
    (root / "example_dep-1.2.3.dist-info" / "METADATA").write_text("Name: example-dep\n")

    expected = attest_source_tree(root)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            DEPENDENCY_TREE_ATTESTOR_SCRIPT,
            str(root),
            "20000",
            "20000",
            "20000",
            str(512 * 1024 * 1024),
            str(512 * 1024 * 1024),
            "4096",
            "255",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    observed = parse_container_tree_attestation(result.stdout)
    assert observed == expected


def test_fixed_attestor_rejects_links_without_copying_to_host(tmp_path: Path) -> None:
    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "target.py").write_text("VALUE = 1\n")
    (root / "alias.py").symlink_to("target.py")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            DEPENDENCY_TREE_ATTESTOR_SCRIPT,
            str(root),
            "100",
            "100",
            "100",
            "1048576",
            "1048576",
            "4096",
            "255",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode != 0
    assert "symlink" in result.stderr


def test_shared_container_attestation_parser_is_bounded_duplicate_free_and_canonical(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n")
    payload = attest_source_tree(root).__dict__
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"

    assert parse_container_tree_attestation(canonical).tree_sha256 == payload["tree_sha256"]
    with pytest.raises(ReproAssertError, match="canonical JSON"):
        parse_container_tree_attestation(json.dumps(payload, sort_keys=True))
    duplicate = canonical.replace(
        '"algorithm":"reproassert-source-tree-v1"',
        ('"algorithm":"reproassert-source-tree-v1","algorithm":"reproassert-source-tree-v1"'),
        1,
    )
    with pytest.raises(ReproAssertError, match="invalid JSON"):
        parse_container_tree_attestation(duplicate)
    with pytest.raises(ReproAssertError, match="invalid JSON"):
        parse_container_tree_attestation(" " * (16 * 1024 + 1))


def test_exact_container_inspect_accepts_immutable_offline_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _executor(trusted_runner=True)
    name = "install-container"
    executor._containers[name] = _ContainerResource(name, _labels(executor, "install"))
    mounts = _install_mounts()
    command = _install_command()
    payload = _container_payload(executor, name, mounts=mounts, command=command)

    policy = _inspect_policy(
        executor, monkeypatch, payload, name=name, mounts=mounts, command=command
    )

    assert policy.image_id == IMAGE_ID
    assert policy.network_mode == "none"
    assert policy.healthcheck_disabled is True
    assert policy.trusted_phase_command is True
    assert ("wheelhouse", "/wheelhouse", False) in policy.mounts


@pytest.mark.parametrize(
    "attack",
    [
        "label_swap",
        "tag_swap",
        "extra_bind",
        "docker_socket",
        "bridge_install",
        "rw_wheelhouse",
        "healthcheck",
        "nonisolated_pip",
    ],
)
def test_exact_container_inspect_rejects_policy_attacks(
    monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    executor = _executor(trusted_runner=True)
    name = "install-container"
    executor._containers[name] = _ContainerResource(name, _labels(executor, "install"))
    mounts = _install_mounts()
    command = _install_command()
    payload = _container_payload(executor, name, mounts=mounts, command=command)
    mutated_command = command
    if attack == "label_swap":
        payload["Config"]["Labels"]["io.reproassert.role"] = "download"  # type: ignore[index]
    elif attack == "tag_swap":
        payload["Image"] = "sha256:" + "f" * 64
    elif attack == "extra_bind":
        payload["HostConfig"]["Binds"] = ["/host:/host:rw"]  # type: ignore[index]
    elif attack == "docker_socket":
        payload["Mounts"].append(  # type: ignore[union-attr]
            {
                "Type": "bind",
                "Name": "",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        )
    elif attack == "bridge_install":
        payload["HostConfig"]["NetworkMode"] = "bridge"  # type: ignore[index]
    elif attack == "rw_wheelhouse":
        payload["Mounts"][1]["RW"] = True  # type: ignore[index]
    elif attack == "healthcheck":
        payload["Config"]["Healthcheck"] = {"Test": ["CMD", "curl", "host"]}  # type: ignore[index]
    elif attack == "nonisolated_pip":
        mutated_command = tuple(item for item in command if item != "--isolated")
        payload["Config"]["Cmd"] = list(mutated_command)  # type: ignore[index]

    with pytest.raises(ReproAssertError, match="exact install policy"):
        _inspect_policy(
            executor,
            monkeypatch,
            payload,
            name=name,
            mounts=mounts,
            command=mutated_command,
        )


def test_oom_killed_exit_zero_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = QueueRunner([CommandResult(0, "a" * 64), CommandResult(0, "phase output")])
    executor = _executor(runner)
    monkeypatch.setattr(
        executor, "_inspect_container_policy", lambda *args, **kwargs: _phase_policy()
    )
    monkeypatch.setattr(
        executor,
        "_inspect_container_state",
        lambda _name: {
            "ExitCode": 0,
            "OOMKilled": True,
            "Status": "exited",
            "Running": False,
            "Dead": False,
            "Error": "",
        },
    )

    with pytest.raises(ReproAssertError, match="outcome policy"):
        executor._create_inspect_start_phase(
            "install",
            "install-container",
            ["create", "--pull", "never", IMAGE_ID, *_install_command()],
            _install_mounts(),
            "none",
            IMAGE_ID,
        )


def test_missing_inspect_requires_successful_exact_name_absence_proof() -> None:
    missing = CommandResult(1, "Error: No such object: target")
    runner = QueueRunner([missing, CommandResult(0, "")])
    executor = _executor(runner)

    assert executor._inspect_optional(["inspect", "target"]) is None
    assert runner.calls[1] == (
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "name=^/target$",
        "--format",
        "{{.Names}}",
    )

    contradictory = QueueRunner([missing, CommandResult(0, "target\n")])
    with pytest.raises(ReproAssertError, match="prove exact"):
        _executor(contradictory)._inspect_optional(["inspect", "target"])

    permission = QueueRunner([CommandResult(1, "permission denied")])
    with pytest.raises(ReproAssertError, match="optional inspect failed"):
        _executor(permission)._inspect_optional(["inspect", "target"])
    assert len(permission.calls) == 1


def test_volume_creation_proves_absence_exact_labels_quota_and_distinct_roles() -> None:
    executor: DependencyExecutor

    def respond(command: tuple[str, ...]) -> CommandResult:
        if command[:2] == ("volume", "inspect"):
            name = command[2]
            spec = next((item for item in executor._volumes.values() if item.name == name), None)
            if spec is None or command_counts.get(name, 0) == 0:
                command_counts[name] = 1
                return CommandResult(1, f"Error: No such volume: {name}")
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Name": spec.name,
                            "Driver": "local",
                            "Scope": "local",
                            "Options": spec.options,
                            "Labels": dict(spec.labels),
                        }
                    ]
                ),
            )
        if command[:2] == ("volume", "ls"):
            return CommandResult(0, "")
        if command[:2] == ("volume", "create"):
            return CommandResult(0, command[-1])
        raise AssertionError(command)

    command_counts: dict[str, int] = {}
    runner = QueueRunner(respond)
    executor = _executor(runner)

    executor._create_role_volumes()

    assert set(executor._volumes) == {"input", "wheelhouse", "dependencies"}
    assert len({spec.name for spec in executor._volumes.values()}) == 3
    expected_inodes = {"input": 64, "wheelhouse": 1024, "dependencies": 32_768}
    for role, spec in executor._volumes.items():
        assert dict(spec.labels) == executor._labels(role)
        assert spec.options["type"] == "tmpfs"
        assert spec.options["device"] == "tmpfs"
        assert "uid=65532" in spec.options["o"]
        assert "gid=65532" in spec.options["o"]
        assert "mode=0700" in spec.options["o"]
        assert f"nr_inodes={expected_inodes[role]}" in spec.options["o"]


def test_volume_inspect_rejects_missing_or_changed_inode_quota() -> None:
    executor = _executor()
    spec = _volume_spec(executor)
    changed_options = dict(spec.options)
    changed_options["o"] = changed_options["o"].replace("nr_inodes=32768", "nr_inodes=32769")
    executor.runner = QueueRunner(
        [
            CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Name": spec.name,
                            "Driver": "local",
                            "Scope": "local",
                            "Options": changed_options,
                            "Labels": dict(spec.labels),
                        }
                    ]
                ),
            )
        ]
    )

    with pytest.raises(ReproAssertError, match="exact labeled quota"):
        executor._inspect_volume(spec)


def test_preexisting_volume_is_rejected_before_create() -> None:
    runner = QueueRunner(
        [
            CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "Name": "preexisting",
                            "Driver": "local",
                            "Scope": "local",
                            "Options": {},
                            "Labels": {},
                        }
                    ]
                ),
            )
        ]
    )
    executor = _executor(runner)

    with pytest.raises(ReproAssertError, match="pre-existing"):
        executor._create_role_volumes()

    assert all(command[:2] != ("volume", "create") for command in runner.calls)


def test_volume_cleanup_verifies_labels_uses_no_force_and_proves_absence() -> None:
    executor = _executor()
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    inspect = CommandResult(
        0,
        json.dumps([{"Name": spec.name, "Labels": dict(spec.labels)}]),
    )
    runner = QueueRunner(
        [
            inspect,
            CommandResult(0, spec.name),
            CommandResult(1, f"Error: No such volume: {spec.name}"),
            CommandResult(0, ""),
        ]
    )
    executor.runner = runner

    executor._remove_volume_verified("dependencies")

    assert ("volume", "rm", spec.name) in runner.calls
    assert all("-f" not in command for command in runner.calls if command[:2] == ("volume", "rm"))
    assert "dependencies" not in executor._volumes


def test_volume_cleanup_refuses_label_swap_and_failed_absence() -> None:
    executor = _executor()
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    swapped = dict(spec.labels)
    swapped["io.reproassert.role"] = "input"
    runner = QueueRunner([CommandResult(0, json.dumps([{"Labels": swapped}]))])
    executor.runner = runner

    with pytest.raises(ReproAssertError, match="labels changed"):
        executor._remove_volume_verified("dependencies")
    assert all(command[:2] != ("volume", "rm") for command in runner.calls)

    executor.runner = QueueRunner(
        [
            CommandResult(0, json.dumps([{"Labels": dict(spec.labels)}])),
            CommandResult(0, spec.name),
            CommandResult(0, json.dumps([{"Labels": dict(spec.labels)}])),
        ]
    )
    with pytest.raises(ReproAssertError, match="remains after removal"):
        executor._remove_volume_verified("dependencies")


def _wheel_bytes() -> bytes:
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "example_dep-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: example-dep\nVersion: 1.2.3\n\n",
        )
        archive.writestr("example_dep/__init__.py", "VALUE = 1\n")
    return output.getvalue()


def test_wheel_copy_is_individual_flat_and_hash_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = _wheel_bytes()
    digest = hashlib.sha256(wheel).hexdigest()
    executor = _executor(wheel_sha256=digest)
    spec = _volume_spec(executor, "wheelhouse")
    executor._volumes["wheelhouse"] = spec
    filename = "example_dep-1.2.3-py3-none-any.whl"
    probe = VolumeProbe(
        algorithm="reproassert-volume-probe-v1",
        tree_sha256="4" * 64,
        member_count=1,
        file_count=1,
        directory_count=0,
        total_bytes=len(wheel),
        root_uid=65532,
        root_gid=65532,
        root_mode=0o700,
        single_file_path=filename,
        single_file_sha256=digest,
        files=(VolumeFileEvidence(filename, digest),),
    )
    monkeypatch.setattr(executor, "_create_helper", lambda **kwargs: "copy-container")
    monkeypatch.setattr(executor, "_remove_container_verified", lambda _name: None)
    calls: list[list[str]] = []

    def copy_one(args: Sequence[str], *, timeout: float) -> CommandResult:
        del timeout
        command = list(args)
        calls.append(command)
        assert command[:2] == ["cp", f"copy-container:/data/{filename}"]
        Path(command[2]).write_bytes(wheel)
        return CommandResult(0, "")

    monkeypatch.setattr(executor, "_run", copy_one)

    attestation = executor._export_and_attest_wheelhouse(IMAGE_ID, probe=probe)

    assert attestation.sha256
    assert len(calls) == 1
    assert "-a" not in calls[0]
    assert "/data/." not in " ".join(calls[0])


def test_typed_handle_revalidates_attestation_and_executor_owns_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n")
    tree = attest_source_tree(root)
    probe = replace(
        _empty_probe(digest="5" * 64),
        member_count=1,
        file_count=1,
        total_bytes=10,
    )
    executor = _executor(trusted_runner=True)
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    executor._resolved_image_id = IMAGE_ID
    executor._entered = True
    executor.state = ExecutionState.READY
    handle = executor._issue_dependency_handle(
        spec=spec,
        image_id=IMAGE_ID,
        execution_receipt_sha256="9" * 64,
        volume_probe=probe,
        tree_attestation=tree,
    )
    monkeypatch.setattr(executor, "_inspect_volume", lambda _spec: {})
    probes = iter([probe, probe])
    monkeypatch.setattr(executor, "_probe_volume", lambda *args, **kwargs: next(probes))
    monkeypatch.setattr(executor, "_export_and_attest_dependencies", lambda _image: tree)

    validation = handle.revalidate_for_mount()

    assert validation.name == spec.name
    assert validation.image_id == IMAGE_ID
    assert validation.execution_receipt_sha256 == "9" * 64
    assert validation.tree_attestation == tree
    assert handle.cleanup_ownership is CleanupOwnership.EXECUTOR_CONTEXT


def test_handle_revalidation_rejects_post_attestation_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n")
    tree = attest_source_tree(root)
    original = replace(_empty_probe(digest="6" * 64), member_count=1, file_count=1)
    changed = replace(original, tree_sha256="7" * 64)
    executor = _executor(trusted_runner=True)
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    executor._resolved_image_id = IMAGE_ID
    executor._entered = True
    executor.state = ExecutionState.READY
    handle = executor._issue_dependency_handle(
        spec=spec,
        image_id=IMAGE_ID,
        execution_receipt_sha256="9" * 64,
        volume_probe=original,
        tree_attestation=tree,
    )
    monkeypatch.setattr(executor, "_inspect_volume", lambda _spec: {})
    probes = iter([original, changed])
    monkeypatch.setattr(executor, "_probe_volume", lambda *args, **kwargs: next(probes))
    monkeypatch.setattr(executor, "_export_and_attest_dependencies", lambda _image: tree)

    with pytest.raises(ReproAssertError, match="changed before verification"):
        handle.revalidate_for_mount()


def test_dependency_handle_rejects_public_construction_forgery_and_stale_use(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="issued only"):
        DependencyVolumeHandle()

    class ForgedExecutor(DependencyExecutor):
        def _revalidate_dependency_handle(self, handle: DependencyVolumeHandle) -> object:
            return handle

    subclass_forge = object.__new__(DependencyVolumeHandle)
    object.__setattr__(subclass_forge, "_executor", object.__new__(ForgedExecutor))
    with pytest.raises(ReproAssertError, match="capability is invalid"):
        subclass_forge.revalidate_for_mount()

    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n")
    tree = attest_source_tree(root)
    probe = replace(_empty_probe(digest="8" * 64), member_count=1, file_count=1)
    executor = _executor(trusted_runner=True)
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    executor._resolved_image_id = IMAGE_ID
    executor._entered = True
    executor.state = ExecutionState.READY
    issued = executor._issue_dependency_handle(
        spec=spec,
        image_id=IMAGE_ID,
        execution_receipt_sha256="9" * 64,
        volume_probe=probe,
        tree_attestation=tree,
    )
    forged = object.__new__(DependencyVolumeHandle)
    for name in (
        "name",
        "labels",
        "image_id",
        "execution_receipt_sha256",
        "quota",
        "volume_probe",
        "tree_attestation",
        "cleanup_ownership",
        "_executor",
    ):
        object.__setattr__(forged, name, getattr(issued, name))
    object.__setattr__(forged, "_capability", object())

    with pytest.raises(ReproAssertError, match="active ready executor"):
        forged.revalidate_for_mount()

    object.__setattr__(issued, "execution_receipt_sha256", "0" * 64)
    with pytest.raises(ReproAssertError, match="identity changed"):
        issued.revalidate_for_mount()
    object.__setattr__(issued, "execution_receipt_sha256", "9" * 64)

    executor._volumes.clear()
    executor.cleanup()
    with pytest.raises(ReproAssertError, match="active ready executor"):
        issued.revalidate_for_mount()


def test_fake_command_runner_cannot_issue_dependency_capability(tmp_path: Path) -> None:
    root = tmp_path / "dependencies"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n")
    executor = _executor(QueueRunner([]))
    spec = _volume_spec(executor)
    executor._volumes["dependencies"] = spec
    executor._resolved_image_id = IMAGE_ID
    executor._entered = True
    executor.state = ExecutionState.READY

    with pytest.raises(ReproAssertError, match="concrete trusted Docker runner"):
        executor._issue_dependency_handle(
            spec=spec,
            image_id=IMAGE_ID,
            execution_receipt_sha256="9" * 64,
            volume_probe=replace(_empty_probe(), member_count=1, file_count=1),
            tree_attestation=attest_source_tree(root),
        )

    explicit_fake = _executor(SubprocessDockerRunner("/tmp/fake-docker"))  # type: ignore[arg-type]
    explicit_fake._volumes["dependencies"] = _volume_spec(explicit_fake)
    explicit_fake._resolved_image_id = IMAGE_ID
    explicit_fake._entered = True
    explicit_fake.state = ExecutionState.READY
    with pytest.raises(ReproAssertError, match="concrete trusted Docker runner"):
        explicit_fake._issue_dependency_handle(
            spec=explicit_fake._volumes["dependencies"],
            image_id=IMAGE_ID,
            execution_receipt_sha256="9" * 64,
            volume_probe=replace(_empty_probe(), member_count=1, file_count=1),
            tree_attestation=attest_source_tree(root),
        )


def test_canonical_execution_receipt_is_bounded_and_omits_random_volume_names(
    tmp_path: Path,
) -> None:
    dependency_root = tmp_path / "dependencies"
    dependency_root.mkdir()
    (dependency_root / "module.py").write_text("VALUE = 1\n")
    tree = attest_source_tree(dependency_root)
    executor = _executor()
    specs = {role: _volume_spec(executor, role) for role in ("input", "wheelhouse", "dependencies")}
    wheelhouse = WheelhouseAttestation(
        algorithm="reproassert-wheelhouse-v1",
        sha256="8" * 64,
        file_count=1,
        total_bytes=100,
        total_unpacked_bytes=200,
        files=(WheelArtifact("example-dep", "1.2.3", "example.whl", "9" * 64, 100, 200),),
    )
    empty = {role: _empty_probe(digest=str(index) * 64) for index, role in enumerate(specs, 1)}
    input_probe = replace(
        _empty_probe(digest="4" * 64),
        member_count=1,
        file_count=1,
        total_bytes=10,
        single_file_path="requirements.lock",
        single_file_sha256="5" * 64,
        files=(VolumeFileEvidence("requirements.lock", "5" * 64),),
    )
    wheel_probe = replace(_empty_probe(digest="6" * 64), member_count=1, file_count=1)
    dependency_probe = replace(
        _empty_probe(digest="7" * 64),
        member_count=tree.member_count,
        file_count=tree.file_count,
        directory_count=tree.directory_count,
        total_bytes=tree.total_bytes,
    )
    receipt = _build_execution_receipt(
        base_receipt={"schema_version": "0.1.0"},
        image_id=IMAGE_ID,
        runtime_version="3.12.13",
        volume_specs=specs,
        empty_probes=empty,
        input_probe=input_probe,
        download_policy=_phase_policy(phase="download", network="bridge"),
        download_outcome=PhaseOutcome("download", 0, False, False, False),
        wheel_probe=wheel_probe,
        wheelhouse=wheelhouse,
        dependency_preinstall=empty["dependencies"],
        install_policy=_phase_policy(),
        install_outcome=PhaseOutcome("install", 0, False, False, False),
        dependency_probe=dependency_probe,
        dependency_tree=tree,
    )
    canonical = _canonical_json_bytes(receipt) + b"\n"

    assert len(canonical) < 1024 * 1024
    assert receipt["campaign_readiness_changed"] is False
    assert all(spec.name.encode() not in canonical for spec in specs.values())
    assert b'"install_network":"none"' in canonical
