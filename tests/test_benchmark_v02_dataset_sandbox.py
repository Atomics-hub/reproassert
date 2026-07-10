from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import reproassert.benchmark_v02_dataset_sandbox as sandbox
from reproassert.errors import PolicyRejection

IMAGE = "sha256:" + "a" * 64


def _policy() -> sandbox.DatasetParserContainerPolicy:
    return sandbox.DatasetParserContainerPolicy(image_digest=IMAGE)


def _inspection(
    input_root: Path,
    policy: sandbox.DatasetParserContainerPolicy,
    command: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "Config": {
            "Cmd": list(command),
            "Entrypoint": ["/usr/bin/env"],
            "Healthcheck": {"Test": ["NONE"]},
            "Image": policy.image_digest,
            "Labels": {
                "io.reproassert.owner": "controller-v1",
                "io.reproassert.role": "dataset-parser-v1",
            },
            "User": "65532:65532",
            "WorkingDir": "/tmp",
        },
        "HostConfig": {
            "CapDrop": ["ALL"],
            "CgroupnsMode": "private",
            "Devices": [],
            "IpcMode": "private",
            "Memory": policy.memory_bytes,
            "MemorySwap": policy.memory_bytes,
            "NanoCpus": int(policy.cpus * 1_000_000_000),
            "NetworkMode": "none",
            "PidMode": "",
            "PidsLimit": policy.pids,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges=true"],
            "Tmpfs": {
                "/tmp": (f"rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},nr_inodes=256,mode=700")
            },
        },
        "Image": policy.image_digest,
        "Mounts": [
            {
                "Destination": "/input",
                "RW": False,
                "Source": str(input_root),
                "Type": "bind",
            }
        ],
        "Name": "/reproassert-dataset-test",
        "State": {"Status": "created"},
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"image_digest": "reproassert:latest"},
        {"image_digest": IMAGE, "timeout_seconds": 0},
        {"image_digest": IMAGE, "memory_bytes": 1},
        {"image_digest": IMAGE, "pids": 1},
        {"image_digest": IMAGE, "max_output_bytes": 1},
    ],
)
def test_policy_rejects_mutable_images_and_unbounded_or_illusory_limits(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        sandbox.DatasetParserContainerPolicy(**kwargs)  # type: ignore[arg-type]


def test_create_command_clears_environment_and_applies_every_boundary_control(
    tmp_path: Path,
) -> None:
    policy = _policy()
    command = sandbox._container_command(("owner__repo-1",))
    args = sandbox._create_args("reproassert-dataset-test", tmp_path, policy, command)

    assert args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert args[args.index("--pids-limit") + 1] == str(policy.pids)
    assert args[args.index("--memory") + 1] == str(policy.memory_bytes)
    assert args[args.index("--memory-swap") + 1] == str(policy.memory_bytes)
    assert args[args.index("--entrypoint") + 1] == "/usr/bin/env"
    assert args[args.index(policy.image_digest) + 1] == "-i"
    assert not any("TOKEN" in value or "SECRET" in value for value in args)
    assert "/input/request.json" in args


@pytest.mark.parametrize(
    "mutation",
    ["network", "memory", "image", "mount", "command", "privileged", "pids", "tmpfs"],
)
def test_inspection_rejects_docker_policy_bypass(tmp_path: Path, mutation: str) -> None:
    input_root = tmp_path.resolve(strict=True)
    policy = _policy()
    command = sandbox._container_command(())
    inspected = _inspection(input_root, policy, command)
    host = inspected["HostConfig"]
    if mutation == "network":
        host["NetworkMode"] = "bridge"
    elif mutation == "memory":
        host["Memory"] = 0
    elif mutation == "image":
        inspected["Image"] = "sha256:" + "b" * 64
    elif mutation == "mount":
        inspected["Mounts"][0]["RW"] = True
    elif mutation == "command":
        inspected["Config"]["Cmd"] = ["python"]
    elif mutation == "privileged":
        host["Privileged"] = True
    elif mutation == "pids":
        host["PidsLimit"] = 0
    else:
        host["Tmpfs"] = {}
    with pytest.raises(PolicyRejection, match="did not apply"):
        sandbox._verify_container_inspection(
            inspected, "reproassert-dataset-test", input_root, policy, command
        )


def test_exact_inspection_passes_and_attested_handoff_is_tamper_evident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    input_root = tmp_path.resolve(strict=True)
    policy = _policy()
    command = sandbox._container_command(())
    inspected = _inspection(input_root, policy, command)
    sandbox._verify_container_inspection(
        inspected, "reproassert-dataset-test", input_root, policy, command
    )

    receipt = b'{"prepared":true}\n'
    attestation = sandbox._render_attestation(
        policy=policy,
        before_inspection_sha256="1" * 64,
        id_list=b"ids",
        parquet=b"parquet",
        worker_source=b"worker",
        request=None,
        output=b"output",
        parser_receipt=receipt,
        upstream_evidence_sha256="2" * 64,
    )
    monkeypatch.setattr(sandbox.dataset, "_validate_private_receipt", lambda _value: {})
    value = sandbox._issue_attested_parse(
        image_digest=policy.image_digest,
        parser_receipt=receipt,
        boundary_attestation=attestation,
        upstream_evidence_sha256="2" * 64,
    )
    assert sandbox.require_attested_v02_dataset_parse(value) is value
    assert value.production_eligible is True
    object.__setattr__(value, "parser_receipt", b"tampered\n")
    with pytest.raises(PolicyRejection, match="receipt digest"):
        sandbox.require_attested_v02_dataset_parse(value)


def test_projection_request_is_canonical_bounded_and_duplicate_safe() -> None:
    request = sandbox._projection_request(("owner__repo-1", "owner__repo-2"))
    assert request is not None
    assert json.loads(request) == {
        "instance_ids": ["owner__repo-1", "owner__repo-2"],
        "protocol": "reproassert-v02-dataset-projection-request-v1",
    }
    with pytest.raises(PolicyRejection, match="duplicated"):
        sandbox._validate_projection_ids(("owner__repo-1", "owner__repo-1"))
    with pytest.raises(PolicyRejection, match="invalid"):
        sandbox._validate_projection_ids(("not/an/id",))


class _FakeEngine:
    def __init__(self, policy: sandbox.DatasetParserContainerPolicy) -> None:
        self.policy = policy
        self.created = False
        self.removed = False
        self.started = False
        self.input_root: Path | None = None
        self.command: tuple[str, ...] = ()
        self.result = sandbox._AttachedResult(0, b"worker output\n", False, False)
        self.oom_killed = False

    def require_exact_image(self, image_digest: str) -> None:
        assert image_digest == self.policy.image_digest

    def create(self, args: list[str]) -> None:
        self.created = True
        mount = args[args.index("--mount") + 1]
        source = mount.split(",src=", 1)[1].split(",dst=", 1)[0]
        self.input_root = Path(source)
        self.command = tuple(args[args.index(self.policy.image_digest) + 1 :])

    def inspect(self, name: str) -> dict[str, Any]:
        assert self.input_root is not None
        value = _inspection(self.input_root, self.policy, self.command)
        value["Name"] = f"/{name}"
        if self.started:
            value["State"] = {
                "ExitCode": self.result.returncode,
                "OOMKilled": self.oom_killed,
                "Status": "exited",
            }
        return value

    def start(
        self, _name: str, _timeout_seconds: float, _max_output_bytes: int
    ) -> sandbox._AttachedResult:
        self.started = True
        return self.result

    def remove(self, _name: str) -> None:
        self.removed = True


def _patch_full_boundary(monkeypatch: pytest.MonkeyPatch, engine: _FakeEngine) -> None:
    upstream = SimpleNamespace(evidence_sha256="6" * 64)
    monkeypatch.setattr(sandbox, "verify_v02_upstream_provenance", lambda *_a, **_k: upstream)
    monkeypatch.setattr(
        sandbox.dataset,
        "_read_bounded_regular",
        lambda _path, _limit, label: (
            b"id-list" if "id list" in label else b"parquet" if "dataset" in label else b"worker"
        ),
    )
    monkeypatch.setattr(sandbox, "_DockerEngine", lambda: engine)
    monkeypatch.setattr(sandbox, "_decode_worker_output", lambda _value: {})
    monkeypatch.setattr(sandbox.dataset, "_assemble_receipt", lambda **_kwargs: b'{"ok":true}\n')
    monkeypatch.setattr(sandbox.dataset, "_validate_private_receipt", lambda _value: {})


def test_full_boundary_handoff_uses_only_inspected_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = _policy()
    engine = _FakeEngine(policy)
    _patch_full_boundary(monkeypatch, engine)

    value = sandbox.run_attested_v02_dataset_parser(
        tdd_id_list_path=tmp_path / "ids",
        source_dataset_path=tmp_path / "parquet",
        upstream_object_witness_path=tmp_path / "witness",
        policy=policy,
        projection_instance_ids=("owner__repo-1",),
    )

    assert engine.created and engine.started and engine.removed
    assert value.production_eligible is True
    assert value.image_digest == IMAGE
    attestation = json.loads(value.boundary_attestation)
    assert attestation["policy"]["network_mode"] == "none"
    assert attestation["policy"]["environment_cleared_with_env_i"] is True
    assert attestation["inputs"]["projection_request_sha256"] is not None


@pytest.mark.parametrize("failure", ["timeout", "output", "exit", "oom"])
def test_full_boundary_fails_closed_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    policy = _policy()
    engine = _FakeEngine(policy)
    if failure == "timeout":
        engine.result = sandbox._AttachedResult(-9, b"", True, False)
    elif failure == "output":
        engine.result = sandbox._AttachedResult(-9, b"x", False, True)
    elif failure == "exit":
        engine.result = sandbox._AttachedResult(7, b"failure", False, False)
    else:
        engine.oom_killed = True
    _patch_full_boundary(monkeypatch, engine)

    with pytest.raises(PolicyRejection):
        sandbox.run_attested_v02_dataset_parser(
            tdd_id_list_path=tmp_path / "ids",
            source_dataset_path=tmp_path / "parquet",
            upstream_object_witness_path=tmp_path / "witness",
            policy=policy,
        )
    assert engine.removed is True


def test_docker_engine_control_wrappers_validate_image_and_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = object.__new__(sandbox._DockerEngine)
    engine._docker = "/usr/bin/docker"
    calls: list[list[str]] = []

    def fake_run(
        _self: object,
        args: list[str],
        _timeout: float,
        **_kwargs: object,
    ) -> sandbox._AttachedResult:
        calls.append(args)
        if args[:2] == ["image", "inspect"]:
            return sandbox._AttachedResult(0, (IMAGE + "\n").encode(), False, False)
        if args[:2] == ["container", "inspect"]:
            return sandbox._AttachedResult(0, b'[{"Name":"/x"}]', False, False)
        return sandbox._AttachedResult(0, b"ok\n", False, False)

    monkeypatch.setattr(sandbox._DockerEngine, "_run", fake_run)
    engine.require_exact_image(IMAGE)
    engine.create(["create", IMAGE])
    assert engine.inspect("x") == {"Name": "/x"}
    assert engine.start("x", 1, 1024).returncode == 0
    engine.remove("x")
    assert [call[0] for call in calls] == ["image", "create", "container", "start", "container"]


def test_worker_output_decoder_rejects_noncanonical_or_wrong_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(PolicyRejection, match="structured"):
        sandbox._decode_worker_output(b"not-json")
    with pytest.raises(PolicyRejection, match="protocol"):
        sandbox._decode_worker_output(b'{"parser_protocol":"wrong","result":{}}\n')
    monkeypatch.setattr(sandbox.dataset, "_validate_worker_result", lambda value: [])
    valid = b'{"parser_protocol":"reproassert-v02-pyarrow-worker-v1","result":{}}\n'
    assert sandbox._decode_worker_output(valid) == {}


@pytest.mark.parametrize("failure", ["image", "create", "inspect-json", "inspect-shape"])
def test_docker_engine_wrappers_fail_closed(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    engine = object.__new__(sandbox._DockerEngine)
    engine._docker = "/usr/bin/docker"

    def fake_run(
        _self: object,
        args: list[str],
        _timeout: float,
        **_kwargs: object,
    ) -> sandbox._AttachedResult:
        if failure == "image":
            return sandbox._AttachedResult(1, b"missing", False, False)
        if failure == "create":
            return sandbox._AttachedResult(1, b"failed", False, False)
        if failure == "inspect-json":
            return sandbox._AttachedResult(0, b"not-json", False, False)
        return sandbox._AttachedResult(0, b"[]", False, False)

    monkeypatch.setattr(sandbox._DockerEngine, "_run", fake_run)
    with pytest.raises(PolicyRejection):
        if failure == "image":
            engine.require_exact_image(IMAGE)
        elif failure == "create":
            engine.create(["create", IMAGE])
        else:
            engine.inspect("x")


class _FakeProcess:
    def __init__(self, output: bytes, *, running: bool = False) -> None:
        self.stdout = io.BytesIO(output)
        self.returncode = 0
        self.running = running

    def poll(self) -> int | None:
        return None if self.running else self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode

    def kill(self) -> None:
        self.running = False
        self.returncode = -9


def test_bounded_docker_process_capture_success_overflow_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = object.__new__(sandbox._DockerEngine)
    engine._docker = "/usr/bin/docker"
    process = _FakeProcess(b"ok\n")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: process)
    result = engine._run(["info"], 1)
    assert result.output == b"ok\n"
    assert result.output_truncated is False

    removed: list[list[str]] = []
    overflow = _FakeProcess(b"0123456789", running=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: overflow)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **_kwargs: removed.append(args) or subprocess.CompletedProcess(args, 0),
    )
    result = engine._run(["start", "-a", "owned"], 1, max_output_bytes=4, kill_container="owned")
    assert result.output == b"0123"
    assert result.output_truncated is True
    assert removed[0][-1] == "owned"

    timeout = _FakeProcess(b"", running=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: timeout)
    result = engine._run(["info"], -1, check=False)
    assert result.timed_out is True


@pytest.mark.integration
@pytest.mark.skipif(
    not (
        os.environ.get("REPROASSERT_DATASET_PARSER_IMAGE_DIGEST")
        and Path("/private/tmp/reproassert-upstream/id_list.txt").is_file()
        and Path("/private/tmp/reproassert-upstream/0000.parquet").is_file()
    ),
    reason="exact dataset parser image and authentic frozen artifacts are unavailable",
)
def test_authentic_dataset_parser_container_boundary() -> None:
    digest = os.environ["REPROASSERT_DATASET_PARSER_IMAGE_DIGEST"]
    value = sandbox.run_attested_v02_dataset_parser(
        tdd_id_list_path=Path("/private/tmp/reproassert-upstream/id_list.txt"),
        source_dataset_path=Path("/private/tmp/reproassert-upstream/0000.parquet"),
        upstream_object_witness_path=Path("benchmarks/v0.2-draft/upstream-object-witness.json"),
        policy=sandbox.DatasetParserContainerPolicy(image_digest=digest),
    )
    assert sandbox.require_attested_v02_dataset_parse(value) is value
    assert value.production_eligible is True
