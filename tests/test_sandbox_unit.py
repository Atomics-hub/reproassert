from __future__ import annotations

import base64
import io
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import reproassert.sandbox as sandbox_module
from reproassert.dependency_executor import (
    CleanupOwnership,
    DependencyVolumeHandle,
    VolumeFileEvidence,
    VolumeProbe,
    VolumeQuotaEvidence,
)
from reproassert.errors import ReproAssertError
from reproassert.sandbox import DockerDoctor, DockerSandbox, SandboxPolicy
from reproassert.source_attestation import (
    SOURCE_TREE_ALGORITHM,
    SourceTreeAttestation,
    attest_source_tree,
)


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
            completed(stdout=f"sha256:{'a' * 64}\n"),
        ]
    )
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: next(responses))

    status = sandbox.require_ready()

    assert status.server_version == "29.3.1"
    assert status.image_available
    assert status.image_id == f"sha256:{'a' * 64}"

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
        return completed(stdout=f"sha256:{'b' * 64}\n" if args[:2] == ["image", "inspect"] else "")

    monkeypatch.setattr(sandbox, "_control", fake_control)
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    image_id = sandbox.build_image()

    assert image_id == f"sha256:{'b' * 64}"
    build = next(args for args in calls if args[0] == "build")
    assert "--pull" in build
    assert sandbox.policy.image in build


def test_ready_sandbox_pins_image_id_and_rejects_tag_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    first = DockerDoctor(True, True, True, "29.3.1", f"sha256:{'a' * 64}")
    second = DockerDoctor(True, True, True, "29.3.1", f"sha256:{'b' * 64}")
    statuses = iter([first, second])
    monkeypatch.setattr(sandbox, "doctor", lambda: next(statuses))

    sandbox.require_ready()

    assert sandbox._image_reference() == first.image_id
    with pytest.raises(ReproAssertError, match="tag changed"):
        sandbox.require_ready()


def test_forged_dependency_volume_handle_is_rejected_by_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_id = f"sha256:{'a' * 64}"
    sandbox = DockerSandbox()
    monkeypatch.setattr(
        sandbox,
        "doctor",
        lambda: DockerDoctor(True, True, True, "29.3.1", image_id),
    )
    quota = VolumeQuotaEvidence(
        driver="local",
        scope="local",
        type="tmpfs",
        device="tmpfs",
        size_bytes=512 * 1024 * 1024,
        max_inodes=32_768,
        uid=65532,
        gid=65532,
        mode=0o700,
    )
    probe = VolumeProbe(
        algorithm="reproassert-volume-probe-v1",
        tree_sha256="b" * 64,
        member_count=2,
        file_count=1,
        directory_count=1,
        total_bytes=10,
        root_uid=65532,
        root_gid=65532,
        root_mode=0o700,
        single_file_path=None,
        single_file_sha256=None,
        files=(VolumeFileEvidence("example.py", "f" * 64),),
    )
    tree = SourceTreeAttestation(
        algorithm=SOURCE_TREE_ALGORITHM,
        tree_sha256="c" * 64,
        reconstructed_git_tree_oid="d" * 40,
        expected_git_tree_oid=None,
        member_count=2,
        file_count=1,
        directory_count=1,
        total_bytes=10,
        executable_count=0,
        git_metadata_absent=True,
    )
    labels = (
        ("io.reproassert.owner", "controller-v1"),
        ("io.reproassert.plan-sha256", "e" * 64),
        ("io.reproassert.role", "dependencies"),
        ("io.reproassert.run", "run-001"),
    )

    handle = object.__new__(DependencyVolumeHandle)
    for name, value in {
        "name": "reproassert-dependencies-run-001",
        "labels": labels,
        "image_id": image_id,
        "quota": quota,
        "volume_probe": probe,
        "tree_attestation": tree,
        "execution_receipt_sha256": "2" * 64,
        "cleanup_ownership": CleanupOwnership.EXECUTOR_CONTEXT,
        "_executor": object(),
        "_capability": object(),
    }.items():
        object.__setattr__(handle, name, value)

    with (
        pytest.raises(ReproAssertError, match="capability"),
        sandbox.borrow_dependency_volume(handle),
    ):
        raise AssertionError("forged dependency capability must never be borrowed")

    assert not sandbox._borrowed_dependency_volumes


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
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    facts = sandbox.runner_facts()

    assert facts["pytest_version"] == "9.1.1"
    run = next(args for args in calls if args[0] == "run")
    assert "none" in run
    assert "--read-only" in run
    assert "--cap-drop" in run
    assert "--no-healthcheck" in run
    assert "--cgroupns" in run and "private" in run
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
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    volume = sandbox.stage_source(source, run_id="run-123")

    assert volume in sandbox._volumes
    assert any(args[:2] == ["volume", "create"] for args in calls)
    copy_args = next(args for args in calls if args[0] == "cp")
    assert copy_args[1] == "-a"
    assert all("type=bind" not in " ".join(args) for args in calls)


@pytest.mark.parametrize("failing_operation", ["cp", "owner"])
def test_stage_source_cleans_volume_when_copy_or_owner_step_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_operation: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    sandbox = DockerSandbox()

    def control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[0] == failing_operation:
            raise ReproAssertError("test_failure", "injected stage failure")
        return completed()

    monkeypatch.setattr(sandbox, "require_ready", lambda: None)
    monkeypatch.setattr(sandbox, "_control", control)
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )
    monkeypatch.setattr(sandbox, "_remove_volume", lambda name: sandbox._volumes.discard(name))
    if failing_operation == "owner":
        monkeypatch.setattr(
            sandbox,
            "_set_workspace_owner",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                ReproAssertError("test_failure", "injected stage failure")
            ),
        )
    else:
        monkeypatch.setattr(sandbox, "_set_workspace_owner", lambda *_args, **_kwargs: None)

    with pytest.raises(ReproAssertError, match="injected"):
        sandbox.stage_source(source, run_id="run-123")

    assert not sandbox._volumes
    assert not sandbox._containers


def test_staged_source_is_attested_inside_pinned_read_only_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n")
    expected = attest_source_tree(source)
    sandbox = DockerSandbox()
    sandbox._volumes.add("volume")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        sandbox,
        "_control",
        lambda args, **_kwargs: calls.append(list(args)) or completed(),
    )
    monkeypatch.setattr(sandbox, "_assert_container_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        sandbox,
        "_start_attached",
        lambda _name: sandbox_module._AttachedResult(
            json.dumps(expected.__dict__, sort_keys=True, separators=(",", ":")) + "\n",
            False,
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        sandbox,
        "_container_state",
        lambda _name: {
            "ExitCode": 0,
            "OOMKilled": False,
            "Status": "exited",
            "Running": False,
            "Dead": False,
            "Error": "",
        },
    )
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    observed = sandbox.attest_staged_source("volume", run_id="run-123")

    assert observed == expected
    create = next(args for args in calls if args[0] == "create")
    assert "--network" in create and create[create.index("--network") + 1] == "none"
    assert "type=volume,src=volume,dst=/workspace,readonly" in create
    assert "/usr/local/bin/python" in create and "-I" in create and "-c" in create
    assert not sandbox._containers


def test_stage_attested_source_rejects_executed_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n")
    expected = attest_source_tree(source)
    sandbox = DockerSandbox()

    def fake_stage(*_args: object, **_kwargs: object) -> str:
        sandbox._volumes.add("volume")
        return "volume"

    monkeypatch.setattr(sandbox, "stage_source", fake_stage)
    monkeypatch.setattr(
        sandbox,
        "attest_staged_source",
        lambda *_args, **_kwargs: replace(expected, tree_sha256="f" * 64),
    )
    monkeypatch.setattr(sandbox, "_remove_volume", lambda name: sandbox._volumes.discard(name))

    with pytest.raises(ReproAssertError, match="differs"):
        sandbox.stage_attested_source(source, run_id="run-123", expected=expected)

    assert not sandbox._volumes


def test_result_volume_has_exact_tmpfs_byte_and_inode_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    calls: list[list[str]] = []

    def control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return completed(stdout=f"{args[-1]}\n")

    monkeypatch.setattr(sandbox, "_control", control)
    monkeypatch.setattr(
        sandbox,
        "_inspect_volume",
        lambda name: {
            "Name": name,
            "Driver": "local",
            "Scope": "local",
            "Labels": {
                "io.reproassert.owner": "controller-v1",
                "io.reproassert.run": "run-123",
                "io.reproassert.role": "junit-result",
            },
            "Options": {
                "type": "tmpfs",
                "device": "tmpfs",
                "o": "size=2097152,nr_inodes=64,uid=65532,gid=65532,mode=0700",
            },
        },
    )
    monkeypatch.setattr(sandbox, "_start_result_anchor", lambda *_args, **_kwargs: None)

    volume = sandbox._create_result_volume(run_id="run-123")

    assert volume in sandbox._volumes
    create = calls[0]
    assert "o=size=2097152,nr_inodes=64,uid=65532,gid=65532,mode=0700" in create


def test_junit_reader_decodes_one_bounded_result_from_live_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._containers.add("anchor")
    sandbox._result_anchors["result-volume"] = "anchor"
    payload = b"<testsuites />"
    encoded = base64.b64encode(payload) + b"\n"
    monkeypatch.setattr(
        sandbox,
        "_run_bounded_docker_command",
        lambda *_args, **_kwargs: sandbox_module._BoundedCommandResult(0, encoded, False, False),
    )

    assert sandbox._copy_junit("result-volume", "/results/junit.xml") == payload

    monkeypatch.setattr(
        sandbox,
        "_run_bounded_docker_command",
        lambda *_args, **_kwargs: sandbox_module._BoundedCommandResult(
            0, b"not base64!\n", False, False
        ),
    )
    assert sandbox._copy_junit("result-volume", "/results/junit.xml") is None


def test_staged_attestor_rejects_oom_even_with_zero_exit_and_valid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    expected = attest_source_tree(source)
    sandbox = DockerSandbox()
    sandbox._volumes.add("volume")
    monkeypatch.setattr(sandbox, "_control", lambda *_args, **_kwargs: completed())
    monkeypatch.setattr(sandbox, "_assert_container_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        sandbox,
        "_start_attached",
        lambda _name: sandbox_module._AttachedResult(
            json.dumps(expected.__dict__, sort_keys=True, separators=(",", ":")) + "\n",
            False,
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        sandbox,
        "_container_state",
        lambda _name: {
            "ExitCode": 0,
            "OOMKilled": True,
            "Status": "exited",
            "Running": False,
            "Dead": False,
            "Error": "",
        },
    )
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    with pytest.raises(ReproAssertError, match="rejected"):
        sandbox.attest_staged_source("volume", run_id="run-123")

    assert not sandbox._containers


def test_run_pytest_builds_inspects_and_cleans_container(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = DockerSandbox()
    sandbox._volumes.add("volume")
    monkeypatch.setattr(
        sandbox,
        "_create_result_volume",
        lambda **_kwargs: sandbox._volumes.add("result-volume") or "result-volume",
    )
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
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )
    monkeypatch.setattr(sandbox, "_remove_volume", lambda name: sandbox._volumes.discard(name))

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
    assert "result-volume" not in sandbox._volumes
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
    sandbox._volumes.add("dependencies")
    with pytest.raises(ReproAssertError, match="active typed borrow"):
        sandbox.run_pytest(
            volume="volume",
            dependency_volume="dependencies",
            target="tests/reproassert/test_issue_1.py::test_issue_1_reproduction",
            phase="x",
            run_id="x",
        )
    with pytest.raises(ReproAssertError):
        sandbox.run_pytest(
            volume="volume",
            target=("tests/reproassert/../../some_existing_test.py::test_issue_1_reproduction"),
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
            "CgroupnsMode": "private",
            "PidsLimit": 128,
            "Memory": 1024 * 1024 * 1024,
            "MemorySwap": 1024 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Devices": [],
            "Binds": None,
        },
        "Config": {"User": "65532:65532", "Healthcheck": {"Test": ["NONE"]}},
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
            "CgroupnsMode": "private",
            "PidsLimit": 128,
            "Memory": 1024 * 1024 * 1024,
            "MemorySwap": 1024 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Devices": [],
            "Binds": None,
        },
        "Config": {"User": "65532:65532", "Healthcheck": {"Test": ["NONE"]}},
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
    monkeypatch.setattr(
        sandbox, "_remove_container", lambda name: sandbox._containers.discard(name)
    )

    sandbox._set_workspace_owner("volume", run_id="run")

    owner_create = next(args for args in calls if args[0] == "create")
    assert "CHOWN" in owner_create
    assert "DAC_READ_SEARCH" in owner_create
    assert "--network" in owner_create and "none" in owner_create
    assert "--read-only" in owner_create
    assert "/bin/chown" in owner_create
    sandbox._containers.add("leftover")
    sandbox._volumes.add("volume")
    removed: list[str] = []

    def remove_volume(name: str) -> None:
        removed.append(name)
        sandbox._volumes.discard(name)

    monkeypatch.setattr(sandbox, "_remove_volume", remove_volume)
    sandbox.cleanup()
    assert not sandbox._containers
    assert not sandbox._volumes
    assert removed == ["volume"]


def test_cleanup_verifies_volume_label_removal_and_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._volumes.add("owned")
    calls: list[list[str]] = []
    present = True

    def control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal present
        calls.append(list(args))
        if args[:2] == ["volume", "inspect"]:
            if not present:
                return completed(code=1, stderr="missing")
            return completed(
                stdout=json.dumps(
                    [
                        {
                            "Name": "owned",
                            "Labels": {"io.reproassert.owner": "controller-v1"},
                        }
                    ]
                )
            )
        if args[:2] == ["volume", "rm"]:
            present = False
        return completed()

    monkeypatch.setattr(sandbox, "_control", control)

    sandbox.cleanup()

    assert not sandbox._volumes
    assert ["volume", "rm", "owned"] in calls
    assert ["volume", "rm", "-f", "owned"] not in calls


def test_cleanup_refuses_label_swap_and_keeps_volume_tracked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._volumes.add("hijacked")
    monkeypatch.setattr(
        sandbox,
        "_control",
        lambda *_args, **_kwargs: completed(
            stdout=json.dumps(
                [
                    {
                        "Name": "hijacked",
                        "Labels": {"io.reproassert.owner": "somebody-else"},
                    }
                ]
            )
        ),
    )

    with pytest.raises(ReproAssertError, match="controller label"):
        sandbox.cleanup()

    assert sandbox._volumes == {"hijacked"}


def test_cleanup_does_not_treat_inspect_transport_error_as_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._volumes.add("uncertain")

    def control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:2] in (["volume", "inspect"], ["volume", "ls"]):
            return completed(code=1, stderr="daemon unavailable")
        return completed()

    monkeypatch.setattr(sandbox, "_control", control)

    with pytest.raises(ReproAssertError, match="prove volume absence"):
        sandbox.cleanup()

    assert sandbox._volumes == {"uncertain"}


def test_container_removal_requires_label_and_proves_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    sandbox._docker = "/docker"
    sandbox._containers.add("owned")
    present = True

    def control(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal present
        if args[:2] == ["container", "inspect"]:
            if not present:
                return completed(code=1, stderr="missing")
            return completed(
                stdout=json.dumps(
                    [
                        {
                            "Name": "/owned",
                            "Config": {"Labels": {"io.reproassert.owner": "controller-v1"}},
                        }
                    ]
                )
            )
        if args[:3] == ["container", "rm", "-f"]:
            present = False
            return completed()
        if args[:2] == ["container", "ls"]:
            return completed(stdout="owned\n" if present else "")
        return completed()

    monkeypatch.setattr(sandbox, "_control", control)

    sandbox.cleanup()

    assert not sandbox._containers


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
