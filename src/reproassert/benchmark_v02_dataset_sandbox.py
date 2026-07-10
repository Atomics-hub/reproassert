"""Attested Docker boundary for production-eligible benchmark v0.2 dataset parsing."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import reproassert.benchmark_v02_dataset as dataset
from reproassert.benchmark_v02_upstream import verify_v02_upstream_provenance
from reproassert.errors import PolicyRejection
from reproassert.safeio import write_bytes_exclusive
from reproassert.semantic_issuer import OFFICIAL_SOURCE_DATASET_BYTES, OFFICIAL_TDD_ID_LIST_BYTES

DATASET_CONTAINER_ATTESTATION_ALGORITHM = "reproassert-v02-dataset-container-attestation-v1"
_ATTESTATION_ISSUER = object()
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_LABEL = "io.reproassert.owner=controller-v1"
_ROLE_LABEL = "io.reproassert.role=dataset-parser-v1"
_SAFE_ENV = (
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PYTHONHASHSEED=0",
    "PYTHONNOUSERSITE=1",
    "REPROASSERT_DATASET_CONTAINER=attested-v1",
)
_MAX_CONTROL_OUTPUT = 1024 * 1024
_CONTAINER_TMP = "/tmp"  # noqa: S108 -- isolated, size-bounded container tmpfs


@dataclass(frozen=True)
class DatasetParserContainerPolicy:
    """Fixed security and resource contract for the immutable parser image."""

    image_digest: str
    timeout_seconds: float = 60.0
    max_output_bytes: int = 2 * 1024 * 1024
    memory_bytes: int = 1024 * 1024 * 1024
    cpus: float = 1.0
    pids: int = 32
    tmpfs_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.image_digest, str) or _IMAGE_ID.fullmatch(self.image_digest) is None:
            raise ValueError("image_digest must be an exact immutable sha256 image ID")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or not 1 <= float(self.timeout_seconds) <= 300
        ):
            raise ValueError("timeout_seconds must be finite and between 1 and 300")
        _bounded_int(self.max_output_bytes, "max_output_bytes", 64 * 1024, 8 * 1024 * 1024)
        _bounded_int(self.memory_bytes, "memory_bytes", 256 * 1024 * 1024, 4 * 1024**3)
        if (
            not isinstance(self.cpus, (int, float))
            or isinstance(self.cpus, bool)
            or not math.isfinite(float(self.cpus))
            or not 0.25 <= float(self.cpus) <= 4
        ):
            raise ValueError("cpus must be finite and between 0.25 and 4")
        _bounded_int(self.pids, "pids", 8, 128)
        _bounded_int(self.tmpfs_bytes, "tmpfs_bytes", 1024 * 1024, 128 * 1024 * 1024)


@dataclass(frozen=True)
class _AttachedResult:
    returncode: int
    output: bytes
    timed_out: bool
    output_truncated: bool


@dataclass(frozen=True, init=False)
class AttestedV02DatasetParse:
    """Nominal production-boundary result; the semantic issuer must require this exact type."""

    image_digest: str
    parser_receipt: bytes = field(repr=False)
    parser_receipt_sha256: str
    boundary_attestation: bytes = field(repr=False)
    boundary_attestation_sha256: str
    upstream_evidence_sha256: str
    production_eligible: bool
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AttestedV02DatasetParse is Docker-boundary-issued only")


def run_attested_v02_dataset_parser(
    *,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
    upstream_object_witness_path: Path,
    policy: DatasetParserContainerPolicy,
    projection_instance_ids: tuple[str, ...] = (),
) -> AttestedV02DatasetParse:
    """Run the fixed worker in a freshly inspected no-network Docker container."""

    if type(policy) is not DatasetParserContainerPolicy:
        raise _reject("The exact dataset parser container policy is required.")
    _validate_projection_ids(projection_instance_ids)
    id_list_path = Path(tdd_id_list_path)
    parquet_path = Path(source_dataset_path)
    upstream = verify_v02_upstream_provenance(
        Path(upstream_object_witness_path),
        tdd_id_list_path=id_list_path,
        source_dataset_path=parquet_path,
    )
    id_list = dataset._read_bounded_regular(
        id_list_path, OFFICIAL_TDD_ID_LIST_BYTES, "pinned TDD-Bench id list"
    )
    parquet = dataset._read_bounded_regular(
        parquet_path, OFFICIAL_SOURCE_DATASET_BYTES, "pinned source dataset"
    )
    worker_source = dataset._read_bounded_regular(
        Path(dataset.__file__).with_name("_benchmark_v02_parquet_worker.py"),
        dataset._MAX_WORKER_BYTES,
        "trusted Parquet worker",
    )
    request = _projection_request(projection_instance_ids)
    engine = _DockerEngine()
    engine.require_exact_image(policy.image_digest)
    name = f"reproassert-dataset-{uuid.uuid4().hex[:16]}"
    created = False
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-dataset-container-") as temporary:
        input_root = Path(temporary).resolve(strict=True)
        os.chmod(input_root, 0o700)
        write_bytes_exclusive(input_root / "parser.py", worker_source)
        write_bytes_exclusive(input_root / "0000.parquet", parquet)
        if request is not None:
            write_bytes_exclusive(input_root / "request.json", request)
        for child in input_root.iterdir():
            os.chmod(child, 0o400)
        command = _container_command(projection_instance_ids)
        args = _create_args(name, input_root, policy, command)
        try:
            engine.create(args)
            created = True
            before = engine.inspect(name)
            _verify_container_inspection(before, name, input_root, policy, command)
            before_sha256 = hashlib.sha256(_canonical(before)).hexdigest()
            attached = engine.start(name, policy.timeout_seconds, policy.max_output_bytes)
            if attached.timed_out:
                raise _reject("Dataset parser container exceeded its wall-clock limit.")
            if attached.output_truncated:
                raise _reject("Dataset parser container exceeded its output limit.")
            after = engine.inspect(name)
            state = after.get("State")
            if (
                attached.returncode != 0
                or not isinstance(state, dict)
                or state.get("ExitCode") != 0
                or state.get("OOMKilled") is not False
            ):
                raise _reject("Dataset parser container failed or exhausted its memory limit.")
            worker = _decode_worker_output(attached.output)
            receipt = dataset._assemble_receipt(
                id_list=id_list,
                parquet=parquet,
                upstream_evidence=upstream,
                worker_source=worker_source,
                worker=worker,
            )
            attestation = _render_attestation(
                policy=policy,
                before_inspection_sha256=before_sha256,
                id_list=id_list,
                parquet=parquet,
                worker_source=worker_source,
                request=request,
                output=attached.output,
                parser_receipt=receipt,
                upstream_evidence_sha256=upstream.evidence_sha256,
            )
        finally:
            if created:
                engine.remove(name)
    return _issue_attested_parse(
        image_digest=policy.image_digest,
        parser_receipt=receipt,
        boundary_attestation=attestation,
        upstream_evidence_sha256=upstream.evidence_sha256,
    )


def require_attested_v02_dataset_parse(value: object) -> AttestedV02DatasetParse:
    """Revalidate the exact nominal Docker-boundary handoff for the semantic issuer."""

    if type(value) is not AttestedV02DatasetParse:
        raise _reject("Attested production dataset parse is required.")
    if value._issuer is not _ATTESTATION_ISSUER or value.production_eligible is not True:
        raise _reject("Dataset parser boundary issuer is invalid.")
    if _IMAGE_ID.fullmatch(value.image_digest) is None:
        raise _reject("Dataset parser image identity is invalid.")
    if hashlib.sha256(value.parser_receipt).hexdigest() != value.parser_receipt_sha256:
        raise _reject("Dataset parser receipt digest is invalid.")
    if hashlib.sha256(value.boundary_attestation).hexdigest() != value.boundary_attestation_sha256:
        raise _reject("Dataset parser boundary attestation digest is invalid.")
    root = _decode_attestation(value.boundary_attestation)
    if (
        root["image_digest"] != value.image_digest
        or root["parser_receipt_sha256"] != value.parser_receipt_sha256
        or root["upstream_evidence_sha256"] != value.upstream_evidence_sha256
        or root["production_eligible"] is not True
    ):
        raise _reject("Dataset parser boundary handoff differs from its attestation.")
    dataset._validate_private_receipt(value.parser_receipt)
    return value


def _issue_attested_parse(
    *,
    image_digest: str,
    parser_receipt: bytes,
    boundary_attestation: bytes,
    upstream_evidence_sha256: str,
) -> AttestedV02DatasetParse:
    value = object.__new__(AttestedV02DatasetParse)
    object.__setattr__(value, "image_digest", image_digest)
    object.__setattr__(value, "parser_receipt", parser_receipt)
    object.__setattr__(value, "parser_receipt_sha256", hashlib.sha256(parser_receipt).hexdigest())
    object.__setattr__(value, "boundary_attestation", boundary_attestation)
    object.__setattr__(
        value,
        "boundary_attestation_sha256",
        hashlib.sha256(boundary_attestation).hexdigest(),
    )
    object.__setattr__(value, "upstream_evidence_sha256", upstream_evidence_sha256)
    object.__setattr__(value, "production_eligible", True)
    object.__setattr__(value, "_issuer", _ATTESTATION_ISSUER)
    return require_attested_v02_dataset_parse(value)


def _create_args(
    name: str,
    input_root: Path,
    policy: DatasetParserContainerPolicy,
    command: tuple[str, ...],
) -> list[str]:
    return [
        "create",
        "--name",
        name,
        "--label",
        _OWNER_LABEL,
        "--label",
        _ROLE_LABEL,
        "--pull",
        "never",
        "--no-healthcheck",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--cgroupns",
        "private",
        "--ipc",
        "private",
        "--pids-limit",
        str(policy.pids),
        "--memory",
        str(policy.memory_bytes),
        "--memory-swap",
        str(policy.memory_bytes),
        "--cpus",
        str(policy.cpus),
        "--ulimit",
        "cpu=60:60",
        "--ulimit",
        "nofile=64:64",
        "--tmpfs",
        f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},nr_inodes=256,mode=700",
        "--mount",
        f"type=bind,src={input_root},dst=/input,readonly",
        "--workdir",
        _CONTAINER_TMP,
        "--entrypoint",
        "/usr/bin/env",
        policy.image_digest,
        *command,
    ]


def _container_command(projection_instance_ids: tuple[str, ...]) -> tuple[str, ...]:
    command = (
        "-i",
        *_SAFE_ENV,
        "/usr/local/bin/python",
        "-I",
        "-B",
        "/input/parser.py",
        "/input/0000.parquet",
    )
    return (*command, "/input/request.json") if projection_instance_ids else command


def _verify_container_inspection(
    raw: dict[str, Any],
    name: str,
    input_root: Path,
    policy: DatasetParserContainerPolicy,
    command: tuple[str, ...],
) -> None:
    config = raw.get("Config")
    host = raw.get("HostConfig")
    mounts = raw.get("Mounts")
    state = raw.get("State")
    if not all(isinstance(value, dict) for value in (config, host, state)) or not isinstance(
        mounts, list
    ):
        raise _reject("Docker returned incomplete dataset parser inspection evidence.")
    config = cast(dict[str, Any], config)
    host = cast(dict[str, Any], host)
    state = cast(dict[str, Any], state)
    cap_drop = host.get("CapDrop") or []
    security_opt = host.get("SecurityOpt") or []
    labels = config.get("Labels")
    tmpfs = host.get("Tmpfs")
    expected_nano_cpus = int(float(policy.cpus) * 1_000_000_000)
    checks = {
        "name": raw.get("Name") == f"/{name}",
        "created": state.get("Status") == "created",
        "image": raw.get("Image") == policy.image_digest,
        "config_image": config.get("Image") == policy.image_digest,
        "network_none": host.get("NetworkMode") == "none",
        "readonly_root": host.get("ReadonlyRootfs") is True,
        "non_root": config.get("User") == "65532:65532",
        "caps_dropped": isinstance(cap_drop, list) and "ALL" in cap_drop,
        "no_new_privileges": isinstance(security_opt, list)
        and "no-new-privileges=true" in security_opt,
        "not_privileged": host.get("Privileged") is False,
        "pid_private": not host.get("PidMode"),
        "ipc_private": host.get("IpcMode") == "private",
        "cgroup_private": host.get("CgroupnsMode") == "private",
        "pids": host.get("PidsLimit") == policy.pids,
        "memory": host.get("Memory") == policy.memory_bytes,
        "memory_swap": host.get("MemorySwap") == policy.memory_bytes,
        "cpus": host.get("NanoCpus") == expected_nano_cpus,
        "no_devices": not host.get("Devices"),
        "entrypoint": config.get("Entrypoint") == ["/usr/bin/env"],
        "cleared_environment": config.get("Cmd") == list(command) and command[:1] == ("-i",),
        "labels": isinstance(labels, dict)
        and labels.get("io.reproassert.owner") == "controller-v1"
        and labels.get("io.reproassert.role") == "dataset-parser-v1",
        "workdir": config.get("WorkingDir") == _CONTAINER_TMP,
        "healthcheck_disabled": config.get("Healthcheck") == {"Test": ["NONE"]},
        "tmpfs": isinstance(tmpfs, dict)
        and set(tmpfs) == {_CONTAINER_TMP}
        and f"size={policy.tmpfs_bytes}" in cast(str, tmpfs[_CONTAINER_TMP]),
        "mount": _exact_readonly_input_mount(mounts, input_root),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise _reject("Docker did not apply dataset parser controls: " + ", ".join(failed))


def _exact_readonly_input_mount(mounts: list[object], input_root: Path) -> bool:
    if len(mounts) != 1 or not isinstance(mounts[0], dict):
        return False
    mount = cast(dict[str, object], mounts[0])
    try:
        source = Path(cast(str, mount.get("Source"))).resolve(strict=True)
    except (OSError, TypeError):
        return False
    return (
        mount.get("Type") == "bind"
        and source == input_root
        and mount.get("Destination") == "/input"
        and mount.get("RW") is False
    )


def _projection_request(instance_ids: tuple[str, ...]) -> bytes | None:
    if not instance_ids:
        return None
    return (
        _canonical(
            {
                "instance_ids": list(instance_ids),
                "protocol": dataset.PROJECTION_REQUEST_PROTOCOL,
            }
        )
        + b"\n"
    )


def _validate_projection_ids(instance_ids: tuple[str, ...]) -> None:
    if (
        not isinstance(instance_ids, tuple)
        or len(instance_ids) > 20
        or len(set(instance_ids)) != len(instance_ids)
        or any(_INSTANCE_ID.fullmatch(value) is None for value in instance_ids)
    ):
        raise _reject("Dataset projection instance IDs are invalid or duplicated.")


def _decode_worker_output(content: bytes) -> dict[str, object]:
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject("Dataset parser container returned invalid structured output.") from exc
    if (
        not isinstance(decoded, dict)
        or content != _canonical(decoded) + b"\n"
        or set(decoded) != {"parser_protocol", "result"}
        or decoded.get("parser_protocol") != dataset.PARSER_PROTOCOL
        or not isinstance(decoded.get("result"), dict)
    ):
        raise _reject("Dataset parser container output protocol is invalid.")
    worker = cast(dict[str, object], decoded["result"])
    dataset._validate_worker_result(worker)
    return worker


def _render_attestation(
    *,
    policy: DatasetParserContainerPolicy,
    before_inspection_sha256: str,
    id_list: bytes,
    parquet: bytes,
    worker_source: bytes,
    request: bytes | None,
    output: bytes,
    parser_receipt: bytes,
    upstream_evidence_sha256: str,
) -> bytes:
    record: dict[str, object] = {
        "algorithm": DATASET_CONTAINER_ATTESTATION_ALGORITHM,
        "container_inspection_sha256": before_inspection_sha256,
        "image_digest": policy.image_digest,
        "inputs": {
            "id_list_sha256": hashlib.sha256(id_list).hexdigest(),
            "parquet_sha256": hashlib.sha256(parquet).hexdigest(),
            "projection_request_sha256": (
                hashlib.sha256(request).hexdigest() if request is not None else None
            ),
            "worker_sha256": hashlib.sha256(worker_source).hexdigest(),
        },
        "parser_output_bytes": len(output),
        "parser_output_sha256": hashlib.sha256(output).hexdigest(),
        "parser_receipt_sha256": hashlib.sha256(parser_receipt).hexdigest(),
        "policy": {
            "capabilities_dropped": "ALL",
            "cpus": policy.cpus,
            "environment_cleared_with_env_i": True,
            "host_credentials_forwarded": False,
            "input_mount_read_only": True,
            "memory_bytes": policy.memory_bytes,
            "memory_swap_bytes": policy.memory_bytes,
            "network_mode": "none",
            "no_new_privileges": True,
            "pids": policy.pids,
            "privileged": False,
            "read_only_root": True,
            "timeout_seconds": policy.timeout_seconds,
            "tmpfs_bytes": policy.tmpfs_bytes,
            "user": "65532:65532",
        },
        "production_eligible": True,
        "upstream_evidence_sha256": upstream_evidence_sha256,
    }
    return _canonical(record) + b"\n"


def _decode_attestation(content: bytes) -> dict[str, object]:
    try:
        root = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject("Dataset parser boundary attestation is invalid JSON.") from exc
    if (
        not isinstance(root, dict)
        or content != _canonical(root) + b"\n"
        or root.get("algorithm") != DATASET_CONTAINER_ATTESTATION_ALGORITHM
        or set(root)
        != {
            "algorithm",
            "container_inspection_sha256",
            "image_digest",
            "inputs",
            "parser_output_bytes",
            "parser_output_sha256",
            "parser_receipt_sha256",
            "policy",
            "production_eligible",
            "upstream_evidence_sha256",
        }
    ):
        raise _reject("Dataset parser boundary attestation is not canonical or complete.")
    return cast(dict[str, object], root)


class _DockerEngine:
    def __init__(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise _reject("Docker CLI is required for production dataset parsing.")
        self._docker = docker

    def require_exact_image(self, image_digest: str) -> None:
        result = self._run(["image", "inspect", image_digest, "--format", "{{.Id}}"], 15)
        if (
            result.returncode != 0
            or result.output.decode("utf-8", "replace").strip() != image_digest
        ):
            raise _reject("The exact immutable dataset parser image is unavailable.")

    def create(self, args: list[str]) -> None:
        result = self._run(args, 30)
        if result.returncode != 0 or result.timed_out or result.output_truncated:
            raise _reject("Docker could not create the dataset parser container.")

    def inspect(self, name: str) -> dict[str, Any]:
        result = self._run(["container", "inspect", name], 20)
        try:
            values = json.loads(result.output)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _reject("Docker returned invalid dataset parser inspection JSON.") from exc
        if result.returncode != 0 or not isinstance(values, list) or len(values) != 1:
            raise _reject("Docker could not inspect the dataset parser container.")
        value = values[0]
        if not isinstance(value, dict):
            raise _reject("Docker dataset parser inspection has an invalid shape.")
        return cast(dict[str, Any], value)

    def start(self, name: str, timeout_seconds: float, max_output_bytes: int) -> _AttachedResult:
        return self._run(
            ["start", "-a", name],
            timeout_seconds,
            max_output_bytes=max_output_bytes,
            kill_container=name,
        )

    def remove(self, name: str) -> None:
        self._run(["container", "rm", "-f", name], 20, check=False)

    def _run(
        self,
        args: list[str],
        timeout_seconds: float,
        *,
        max_output_bytes: int = _MAX_CONTROL_OUTPUT,
        kill_container: str | None = None,
        check: bool = True,
    ) -> _AttachedResult:
        process = subprocess.Popen(
            [self._docker, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
        )
        output = bytearray()
        overflow = threading.Event()

        def read_output() -> None:
            stream = process.stdout
            if stream is None:
                return
            while chunk := stream.read(8192):
                remaining = max_output_bytes - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        reader = threading.Thread(target=read_output, name="dataset-docker-output", daemon=True)
        reader.start()
        started = time.monotonic()
        timed_out = False
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() - started > timeout_seconds:
                timed_out = not overflow.is_set()
                if kill_container is not None:
                    subprocess.run(
                        [self._docker, "container", "rm", "-f", kill_container],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env={
                            "LANG": "C.UTF-8",
                            "LC_ALL": "C.UTF-8",
                            "PATH": "/usr/local/bin:/usr/bin:/bin",
                        },
                        timeout=20,
                        check=False,
                    )
                process.kill()
                break
            time.sleep(0.02)
        process.wait(timeout=5)
        reader.join(timeout=2)
        result = _AttachedResult(process.returncode, bytes(output), timed_out, overflow.is_set())
        if check and result.returncode != 0 and kill_container is None:
            raise _reject("Docker control command failed.")
        return result


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _reject("Dataset container evidence cannot be encoded as canonical JSON.") from exc


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_dataset_sandbox", message)
