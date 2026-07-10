from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, TypedDict, cast

from reproassert.dependency_attestor import (
    DEPENDENCY_TREE_ATTESTOR_SCRIPT,
    parse_container_tree_attestation,
)
from reproassert.dependency_command_contract import dependency_phase_command
from reproassert.dependency_prep import (
    MAX_PLAN_BYTES,
    MAX_WHEEL_BYTES,
    MAX_WHEELHOUSE_BYTES,
    MAX_WHEELHOUSE_UNPACKED_BYTES,
    WheelhouseAttestation,
    attest_wheelhouse,
    build_dependency_receipt,
    dependency_download_create_args,
    dependency_install_create_args,
    load_dependency_plan,
    render_requirements_lock,
)
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.safeio import open_regular_file, sanitize_log
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import (
    SourceAttestationLimits,
    SourceTreeAttestation,
)

DEPENDENCY_EXECUTION_SCHEMA_VERSION = "0.1.0"
DEPENDENCY_CAUSALITY_ALGORITHM = "reproassert-dependency-causality-v1"
VOLUME_PROBE_ALGORITHM = "reproassert-volume-probe-v1"
MAX_EXECUTION_RECEIPT_BYTES = 1024 * 1024
OWNER_LABEL_KEY = "io.reproassert.owner"
OWNER_LABEL_VALUE = "controller-v1"
RUN_LABEL_KEY = "io.reproassert.run"
ROLE_LABEL_KEY = "io.reproassert.role"
PLAN_LABEL_KEY = "io.reproassert.plan-sha256"

_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")
_DOCKER_OBJECT_MISSING = re.compile(r"no such (?:object|container|volume)", re.IGNORECASE)
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_WHEEL_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.whl")
_CONTROL_OUTPUT_BYTES = 2 * 1024 * 1024
_INPUT_VOLUME_BYTES = 1024 * 1024
_DEPENDENCY_VOLUME_BYTES = MAX_WHEELHOUSE_UNPACKED_BYTES
_INPUT_VOLUME_INODES = 64
_WHEELHOUSE_VOLUME_INODES = 1024
_DEPENDENCY_VOLUME_INODES = 32_768
DEPENDENCY_VOLUME_QUOTA_CONTRACT = (
    ("input", _INPUT_VOLUME_BYTES, _INPUT_VOLUME_INODES),
    ("wheelhouse", MAX_WHEELHOUSE_BYTES, _WHEELHOUSE_VOLUME_INODES),
    ("dependencies", _DEPENDENCY_VOLUME_BYTES, _DEPENDENCY_VOLUME_INODES),
)
_PROBE_MAX_MEMBERS = 20_000
_PROBE_MAX_DIRECTORIES = 20_000
_PROBE_MAX_FILES = 20_000
_PROBE_MAX_PATH_BYTES = 4096
_PROBE_MAX_COMPONENT_BYTES = 255
_CONTAINER_TMP = "/tmp"  # noqa: S108 - isolated container path, never a host path
_HELPER_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=16777216,nr_inodes=1024"  # noqa: S108

_DEPENDENCY_ATTESTATION_LIMITS = SourceAttestationLimits(
    max_members=_PROBE_MAX_MEMBERS,
    max_files=_PROBE_MAX_FILES,
    max_directories=_PROBE_MAX_DIRECTORIES,
    max_file_bytes=MAX_WHEELHOUSE_UNPACKED_BYTES,
    max_total_bytes=_DEPENDENCY_VOLUME_BYTES,
    max_path_bytes=_PROBE_MAX_PATH_BYTES,
    max_component_bytes=_PROBE_MAX_COMPONENT_BYTES,
)


class ExecutionState(str, Enum):
    NEW = "new"
    ENTERED = "entered"
    IMAGE_RESOLVED = "image_resolved"
    VOLUMES_CREATED = "volumes_created"
    VOLUMES_PROVEN_EMPTY = "volumes_proven_empty"
    INPUT_STAGED = "input_staged"
    DOWNLOAD_COMPLETED = "download_completed"
    WHEELHOUSE_ATTESTED = "wheelhouse_attested"
    INSTALL_COMPLETED = "install_completed"
    ARTIFACTS_ATTESTED = "artifacts_attested"
    READY = "ready"
    FAILED = "failed"
    CLEANED = "cleaned"


class CleanupOwnership(str, Enum):
    EXECUTOR_CONTEXT = "dependency_executor_context"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str
    timed_out: bool = False
    output_truncated: bool = False


class CommandRunner(Protocol):
    def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_bytes: bytes | None = None,
    ) -> CommandResult: ...


class SubprocessDockerRunner:
    """Run Docker CLI commands with a cleared environment and bounded combined output."""

    def __init__(self, docker_path: str | None = None) -> None:
        self.docker_path = docker_path or shutil.which("docker") or ""
        if not self.docker_path:
            raise ReproAssertError("sandbox_unavailable", "Docker CLI is required.")

    def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        if (
            not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or not 1 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("Docker command bounds are invalid")
        if input_bytes is not None and not 1 <= len(input_bytes) <= MAX_PLAN_BYTES:
            raise ValueError("Docker command input is outside the dependency plan bound")
        process = subprocess.Popen(
            [self.docker_path, *args],
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
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

        reader = threading.Thread(target=read_output, name="dependency-docker-output", daemon=True)
        reader.start()
        writer: threading.Thread | None = None
        if input_bytes is not None:

            def write_input() -> None:
                stream = process.stdin
                if stream is None:
                    return
                try:
                    stream.write(input_bytes)
                    stream.flush()
                except BrokenPipeError:
                    pass
                finally:
                    stream.close()

            writer = threading.Thread(
                target=write_input,
                name="dependency-docker-input",
                daemon=True,
            )
            writer.start()
        started = time.monotonic()
        timed_out = False
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() - started > timeout_seconds:
                timed_out = not overflow.is_set()
                process.kill()
                break
            time.sleep(0.05)
        process.wait(timeout=5)
        reader.join(timeout=2)
        if writer is not None:
            writer.join(timeout=2)
        return CommandResult(
            returncode=process.returncode,
            output=sanitize_log(output.decode("utf-8", errors="replace")),
            timed_out=timed_out,
            output_truncated=overflow.is_set(),
        )


@dataclass(frozen=True)
class VolumeSpec:
    role: str
    name: str
    size_bytes: int
    max_inodes: int
    labels: tuple[tuple[str, str], ...]

    @property
    def options(self) -> dict[str, str]:
        return {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (
                f"size={self.size_bytes},nr_inodes={self.max_inodes},uid=65532,gid=65532,mode=0700"
            ),
        }


@dataclass(frozen=True)
class VolumeFileEvidence:
    path: str
    sha256: str


@dataclass(frozen=True)
class VolumeProbe:
    algorithm: str
    tree_sha256: str
    member_count: int
    file_count: int
    directory_count: int
    total_bytes: int
    root_uid: int
    root_gid: int
    root_mode: int
    single_file_path: str | None
    single_file_sha256: str | None
    files: tuple[VolumeFileEvidence, ...]


@dataclass(frozen=True)
class VolumeQuotaEvidence:
    driver: str
    scope: str
    type: str
    device: str
    size_bytes: int
    max_inodes: int
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True)
class DependencyVolumeValidation:
    name: str
    labels: tuple[tuple[str, str], ...]
    image_id: str
    execution_receipt_sha256: str
    quota: VolumeQuotaEvidence
    volume_probe: VolumeProbe
    tree_attestation: SourceTreeAttestation


@dataclass(frozen=True, init=False)
class DependencyVolumeHandle:
    """Executor-owned capability for one attested dependency volume."""

    name: str
    labels: tuple[tuple[str, str], ...]
    image_id: str
    execution_receipt_sha256: str
    quota: VolumeQuotaEvidence
    volume_probe: VolumeProbe
    tree_attestation: SourceTreeAttestation
    cleanup_ownership: CleanupOwnership
    _executor: DependencyExecutor = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("DependencyVolumeHandle instances are issued only by DependencyExecutor")

    def revalidate_for_mount(self) -> DependencyVolumeValidation:
        """Re-inspect and re-attest this volume immediately before a read-only mount."""

        try:
            executor = self._executor
        except AttributeError as exc:
            raise ReproAssertError(
                "dependency_handle_capability", "Dependency handle capability is invalid."
            ) from exc
        if type(executor) is not DependencyExecutor:
            raise ReproAssertError(
                "dependency_handle_capability", "Dependency handle capability is invalid."
            )
        return executor._revalidate_dependency_handle(self)


@dataclass(frozen=True)
class MountExpectation:
    role: str
    volume: str
    destination: str
    writable: bool


@dataclass(frozen=True)
class EffectivePhasePolicy:
    phase: str
    image_id: str
    network_mode: str
    user: str
    read_only_root: bool
    cap_drop: tuple[str, ...]
    no_new_privileges: bool
    healthcheck_disabled: bool
    trusted_phase_command: bool
    pids: int
    memory_bytes: int
    memory_swap_bytes: int
    nano_cpus: int
    mounts: tuple[tuple[str, str, bool], ...]
    command_sha256: str
    config_sha256: str


@dataclass(frozen=True)
class PhaseOutcome:
    phase: str
    exit_code: int
    oom_killed: bool
    timed_out: bool
    output_truncated: bool


class DependencyExecutionReceipt(TypedDict):
    schema_version: str
    kind: str
    dependency_preparation: dict[str, object]
    execution: dict[str, object]
    campaign_readiness_changed: bool


@dataclass(frozen=True)
class DependencyExecution:
    dependency_handle: DependencyVolumeHandle
    image_id: str
    receipt: DependencyExecutionReceipt
    canonical_receipt: bytes
    wheelhouse: WheelhouseAttestation
    dependency_tree: SourceTreeAttestation


@dataclass(frozen=True)
class _ContainerResource:
    name: str
    labels: tuple[tuple[str, str], ...]


class DependencyExecutor:
    """Causal Docker executor; use as a context manager so the retained volume is cleaned."""

    def __init__(
        self,
        plan_path: Path,
        *,
        policy: SandboxPolicy | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        if not isinstance(plan_path, Path):
            raise TypeError("DependencyExecutor requires a strict dependency-plan Path")
        plan = load_dependency_plan(plan_path)
        self.plan = plan
        self.policy = policy or SandboxPolicy(image=plan.runner_image)
        if self.policy.image != plan.runner_image:
            raise PolicyRejection(
                "benchmark_dependency_executor",
                "Sandbox policy image does not match the dependency plan.",
            )
        if runner is None:
            self.runner: CommandRunner = SubprocessDockerRunner()
            self._trusted_runner_for_handles = type(self.runner) is SubprocessDockerRunner
        else:
            self.runner = runner
            self._trusted_runner_for_handles = False
        self.state = ExecutionState.NEW
        self.state_history: list[ExecutionState] = [self.state]
        self._run_token = _safe_token(f"dep-{plan.case_id}-{uuid.uuid4().hex[:12]}")
        self._volumes: dict[str, VolumeSpec] = {}
        self._containers: dict[str, _ContainerResource] = {}
        self._anchors: dict[str, str] = {}
        self._entered = False
        self._resolved_image_id: str | None = None
        self._handle_capability = object()
        self._issued_handle: DependencyVolumeHandle | None = None
        self._execution_receipt_sha256: str | None = None

    def __enter__(self) -> DependencyExecutor:
        if self.state is not ExecutionState.NEW:
            raise ReproAssertError("dependency_state", "Dependency executor cannot be re-entered.")
        self._entered = True
        self._transition(ExecutionState.NEW, ExecutionState.ENTERED)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> Literal[False]:
        del exc_type, traceback
        try:
            self.cleanup()
        except BaseException as cleanup_error:
            if exc is not None:
                raise cleanup_error from exc
            raise
        return False

    def prepare(self, *, tool_git_sha: str) -> DependencyExecution:
        if not self._entered or self.state is not ExecutionState.ENTERED:
            raise ReproAssertError(
                "dependency_state", "Prepare must run once inside the executor context."
            )
        try:
            return self._prepare(tool_git_sha=tool_git_sha)
        except BaseException as exc:
            self._set_failed()
            try:
                self.cleanup()
            except BaseException as cleanup_error:
                raise cleanup_error from exc
            raise

    def cleanup(self) -> None:
        self._issued_handle = None
        self._execution_receipt_sha256 = None
        self._handle_capability = object()
        errors: list[str] = []
        for name in list(self._containers):
            try:
                self._remove_container_verified(name)
            except ReproAssertError as exc:
                errors.append(f"container {name}: {exc.message}")
        for role in list(self._volumes):
            try:
                self._remove_volume_verified(role)
            except ReproAssertError as exc:
                errors.append(f"volume {role}: {exc.message}")
        if errors:
            raise ReproAssertError(
                "dependency_cleanup_failed",
                "Label-verified dependency cleanup failed: " + "; ".join(errors),
            )
        if self.state is not ExecutionState.CLEANED:
            self.state = ExecutionState.CLEANED
            self.state_history.append(self.state)

    def _prepare(self, *, tool_git_sha: str) -> DependencyExecution:
        image_id = self._resolve_image_id()
        self._transition(ExecutionState.ENTERED, ExecutionState.IMAGE_RESOLVED)
        runtime_version = self._probe_runtime(image_id)
        if not _python_version_matches(self.plan.python_version, runtime_version):
            raise ReproAssertError(
                "dependency_runtime_mismatch",
                "Runner Python version does not match the dependency plan.",
            )

        self._create_role_volumes()
        self._start_volume_anchors(image_id)
        self._transition(ExecutionState.IMAGE_RESOLVED, ExecutionState.VOLUMES_CREATED)
        empty = {
            role: self._probe_volume(role, image_id=image_id)
            for role in ("input", "wheelhouse", "dependencies")
        }
        if any(probe.member_count != 0 for probe in empty.values()):
            raise ReproAssertError(
                "dependency_volume_not_empty", "A newly created dependency volume is not empty."
            )
        self._transition(ExecutionState.VOLUMES_CREATED, ExecutionState.VOLUMES_PROVEN_EMPTY)

        requirements = render_requirements_lock(self.plan)
        self._stage_requirements(requirements, image_id=image_id)
        input_probe = self._probe_volume("input", image_id=image_id)
        requirements_sha256 = hashlib.sha256(requirements).hexdigest()
        if (
            input_probe.member_count != 1
            or input_probe.file_count != 1
            or input_probe.directory_count != 0
            or input_probe.total_bytes != len(requirements)
            or input_probe.single_file_path != "requirements.lock"
            or input_probe.single_file_sha256 != requirements_sha256
        ):
            raise ReproAssertError(
                "dependency_input_mismatch",
                "Staged requirements do not match the reviewed dependency plan.",
            )
        self._transition(ExecutionState.VOLUMES_PROVEN_EMPTY, ExecutionState.INPUT_STAGED)

        download_policy, download_outcome = self._run_download(image_id)
        self._transition(ExecutionState.INPUT_STAGED, ExecutionState.DOWNLOAD_COMPLETED)
        wheel_probe_before = self._probe_volume("wheelhouse", image_id=image_id)
        wheelhouse_before = self._export_and_attest_wheelhouse(image_id, probe=wheel_probe_before)
        wheel_probe_after_attestation = self._probe_volume("wheelhouse", image_id=image_id)
        if wheel_probe_before != wheel_probe_after_attestation:
            raise ReproAssertError(
                "dependency_artifact_changed", "Wheelhouse changed during pre-install attestation."
            )
        self._transition(ExecutionState.DOWNLOAD_COMPLETED, ExecutionState.WHEELHOUSE_ATTESTED)

        dependency_preinstall = self._probe_volume("dependencies", image_id=image_id)
        if dependency_preinstall.member_count != 0:
            raise ReproAssertError(
                "dependency_volume_not_empty", "Dependency volume changed before installation."
            )
        install_policy, install_outcome = self._run_install(image_id)
        self._transition(ExecutionState.WHEELHOUSE_ATTESTED, ExecutionState.INSTALL_COMPLETED)

        input_final = self._probe_volume("input", image_id=image_id)
        wheel_probe_final = self._probe_volume("wheelhouse", image_id=image_id)
        dependency_probe_before = self._probe_volume("dependencies", image_id=image_id)
        wheelhouse_after = self._export_and_attest_wheelhouse(image_id, probe=wheel_probe_final)
        dependency_tree = self._export_and_attest_dependencies(image_id)
        wheel_probe_postexport = self._probe_volume("wheelhouse", image_id=image_id)
        dependency_probe_after = self._probe_volume("dependencies", image_id=image_id)
        if input_final != input_probe:
            raise ReproAssertError(
                "dependency_input_changed", "Requirements volume changed after staging."
            )
        if (
            wheel_probe_final != wheel_probe_before
            or wheel_probe_postexport != wheel_probe_before
            or wheelhouse_after != wheelhouse_before
        ):
            raise ReproAssertError(
                "dependency_artifact_changed", "Wheelhouse changed after trusted download."
            )
        if dependency_probe_before != dependency_probe_after:
            raise ReproAssertError(
                "dependency_artifact_changed", "Installed tree changed during attestation."
            )
        if (
            dependency_probe_after.member_count != dependency_tree.member_count
            or dependency_probe_after.file_count != dependency_tree.file_count
            or dependency_probe_after.directory_count != dependency_tree.directory_count
            or dependency_probe_after.total_bytes != dependency_tree.total_bytes
            or dependency_tree.file_count == 0
        ):
            raise ReproAssertError(
                "dependency_attestation_mismatch",
                "Volume probe and installed-tree attestation disagree.",
            )
        self._transition(ExecutionState.INSTALL_COMPLETED, ExecutionState.ARTIFACTS_ATTESTED)

        base_receipt = build_dependency_receipt(
            self.plan,
            runner_image_id=image_id,
            wheelhouse=wheelhouse_after,
            dependency_tree=dependency_tree,
            tool_git_sha=tool_git_sha,
            policy=self.policy,
        )
        volume_specs = dict(self._volumes)
        self._remove_volume_verified("input")
        self._remove_volume_verified("wheelhouse")
        receipt = _build_execution_receipt(
            base_receipt=base_receipt,
            image_id=image_id,
            runtime_version=runtime_version,
            volume_specs=volume_specs,
            empty_probes=empty,
            input_probe=input_probe,
            download_policy=download_policy,
            download_outcome=download_outcome,
            wheel_probe=wheel_probe_before,
            wheelhouse=wheelhouse_after,
            dependency_preinstall=dependency_preinstall,
            install_policy=install_policy,
            install_outcome=install_outcome,
            dependency_probe=dependency_probe_after,
            dependency_tree=dependency_tree,
        )
        canonical = _canonical_json_bytes(receipt) + b"\n"
        if len(canonical) > MAX_EXECUTION_RECEIPT_BYTES:
            raise ReproAssertError(
                "dependency_receipt_too_large", "Dependency execution receipt exceeds 1 MiB."
            )

        self._transition(ExecutionState.ARTIFACTS_ATTESTED, ExecutionState.READY)
        dependency_spec = self._require_volume("dependencies")
        dependency_handle = self._issue_dependency_handle(
            spec=dependency_spec,
            image_id=image_id,
            execution_receipt_sha256=hashlib.sha256(canonical).hexdigest(),
            volume_probe=dependency_probe_after,
            tree_attestation=dependency_tree,
        )
        return DependencyExecution(
            dependency_handle=dependency_handle,
            image_id=image_id,
            receipt=receipt,
            canonical_receipt=canonical,
            wheelhouse=wheelhouse_after,
            dependency_tree=dependency_tree,
        )

    def _resolve_image_id(self) -> str:
        if self._resolved_image_id is not None:
            return self._resolved_image_id
        result = self._run(["image", "inspect", self.plan.runner_image], timeout=20)
        payload = _json_list_one(result.output, "Docker image inspect")
        image_id = payload.get("Id")
        if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
            raise ReproAssertError(
                "dependency_image_invalid", "Docker image inspect returned no immutable image ID."
            )
        self._resolved_image_id = image_id
        return image_id

    def _create_role_volumes(self) -> None:
        sizes = {
            role: (size, max_inodes) for role, size, max_inodes in DEPENDENCY_VOLUME_QUOTA_CONTRACT
        }
        for role, (size, max_inodes) in sizes.items():
            name = _safe_token(f"reproassert-{self._run_token}-{role}-{uuid.uuid4().hex[:10]}")
            labels = tuple(sorted(self._labels(role).items()))
            spec = VolumeSpec(
                role=role,
                name=name,
                size_bytes=size,
                max_inodes=max_inodes,
                labels=labels,
            )
            self._volumes[role] = spec
            if self._inspect_optional(["volume", "inspect", name]) is not None:
                raise ReproAssertError(
                    "dependency_volume_preexisting",
                    "Refusing to reuse a pre-existing dependency volume.",
                )
            args = ["volume", "create"]
            for key, value in labels:
                args.extend(["--label", f"{key}={value}"])
            args.extend(
                [
                    "--driver",
                    "local",
                    "--opt",
                    "type=tmpfs",
                    "--opt",
                    "device=tmpfs",
                    "--opt",
                    f"o={spec.options['o']}",
                    name,
                ]
            )
            result = self._run(args, timeout=30)
            if result.output.strip() != name:
                raise ReproAssertError(
                    "dependency_volume_create", "Docker created an unexpected volume."
                )
            self._inspect_volume(spec)
        if len({spec.name for spec in self._volumes.values()}) != 3:
            raise ReproAssertError(
                "dependency_volume_collision", "Dependency role volumes are not distinct."
            )

    def _inspect_volume(self, spec: VolumeSpec) -> dict[str, object]:
        result = self._run(["volume", "inspect", spec.name], timeout=20)
        payload = _json_list_one(result.output, "Docker volume inspect")
        if (
            payload.get("Name") != spec.name
            or payload.get("Driver") != "local"
            or payload.get("Scope") != "local"
            or payload.get("Options") != spec.options
            or payload.get("Labels") != dict(spec.labels)
        ):
            raise ReproAssertError(
                "dependency_volume_policy", "Docker volume does not match its exact labeled quota."
            )
        return payload

    def _start_volume_anchors(self, image_id: str) -> None:
        for role in ("input", "wheelhouse", "dependencies"):
            spec = self._require_volume(role)
            name = self._create_helper(
                role=f"anchor-{role}",
                image_id=image_id,
                mounts=(MountExpectation(role, spec.name, "/data", False),),
                entrypoint="/usr/bin/env",
                command=(
                    "-i",
                    "HOME=/tmp/home",
                    "LANG=C.UTF-8",
                    "LC_ALL=C.UTF-8",
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                    "/usr/local/bin/python",
                    "-I",
                    "-c",
                    "import signal; signal.pause()",
                ),
            )
            self._anchors[role] = name
            self._run(["start", name], timeout=30)
            state = self._inspect_container_state(name)
            if (
                state.get("Status") != "running"
                or state.get("Running") is not True
                or state.get("Dead") is True
                or state.get("OOMKilled") is True
                or state.get("Error") not in {"", None}
            ):
                raise ReproAssertError(
                    "dependency_anchor_failed",
                    f"Read-only retention anchor for {role} did not remain running.",
                )

    def _probe_runtime(self, image_id: str) -> str:
        script = "import platform; print(platform.python_version())"
        result = self._run_helper(
            role="runtime-probe",
            image_id=image_id,
            mounts=(),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                script,
            ),
        )
        version = result.output.strip()
        if not re.fullmatch(r"3\.[0-9]{1,2}\.[0-9]{1,2}", version):
            raise ReproAssertError(
                "dependency_runtime_invalid", "Runner returned an invalid Python version."
            )
        return version

    def _probe_volume(self, role: str, *, image_id: str) -> VolumeProbe:
        spec = self._require_volume(role)
        limits = _probe_limits(role)
        result = self._run_helper(
            role=f"probe-{role}",
            image_id=image_id,
            mounts=(MountExpectation(role, spec.name, "/data", False),),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                _VOLUME_PROBE_SCRIPT,
                "/data",
                *(str(value) for value in limits),
                "1" if role in {"input", "wheelhouse"} else "0",
            ),
            max_output_bytes=256 * 1024 if role == "wheelhouse" else 64 * 1024,
        )
        return _parse_probe(result.output)

    def _stage_requirements(self, requirements: bytes, *, image_id: str) -> None:
        if not 1 <= len(requirements) <= MAX_PLAN_BYTES:
            raise ReproAssertError(
                "dependency_input_size", "Rendered requirements exceed the input volume policy."
            )
        spec = self._require_volume("input")
        container = self._create_helper(
            role="input-stage",
            image_id=image_id,
            mounts=(MountExpectation("input", spec.name, "/input", True),),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                _STAGE_REQUIREMENTS_SCRIPT,
                "/input/requirements.lock",
                str(MAX_PLAN_BYTES),
            ),
            interactive=True,
        )
        try:
            self._start_helper(
                container,
                role="input-stage",
                input_bytes=requirements,
            )
        finally:
            self._remove_container_verified(container)

    def _run_download(self, image_id: str) -> tuple[EffectivePhasePolicy, PhaseOutcome]:
        execution_plan = replace(self.plan, runner_image=image_id)
        execution_policy = replace(self.policy, image=image_id)
        name = self._new_container_name("download")
        args = dependency_download_create_args(
            execution_plan,
            name=name,
            input_volume=self._require_volume("input").name,
            wheelhouse_volume=self._require_volume("wheelhouse").name,
            run_id=self._run_token,
            policy=execution_policy,
        )
        mounts = (
            MountExpectation("input", self._require_volume("input").name, "/input", False),
            MountExpectation(
                "wheelhouse", self._require_volume("wheelhouse").name, "/wheelhouse", True
            ),
        )
        return self._create_inspect_start_phase("download", name, args, mounts, "bridge", image_id)

    def _run_install(self, image_id: str) -> tuple[EffectivePhasePolicy, PhaseOutcome]:
        execution_plan = replace(self.plan, runner_image=image_id)
        execution_policy = replace(self.policy, image=image_id)
        name = self._new_container_name("install")
        args = dependency_install_create_args(
            execution_plan,
            name=name,
            input_volume=self._require_volume("input").name,
            wheelhouse_volume=self._require_volume("wheelhouse").name,
            dependency_volume=self._require_volume("dependencies").name,
            run_id=self._run_token,
            policy=execution_policy,
        )
        mounts = (
            MountExpectation("input", self._require_volume("input").name, "/input", False),
            MountExpectation(
                "wheelhouse", self._require_volume("wheelhouse").name, "/wheelhouse", False
            ),
            MountExpectation(
                "dependencies",
                self._require_volume("dependencies").name,
                "/dependencies",
                True,
            ),
        )
        return self._create_inspect_start_phase("install", name, args, mounts, "none", image_id)

    def _create_inspect_start_phase(
        self,
        phase: str,
        name: str,
        args: list[str],
        mounts: tuple[MountExpectation, ...],
        network: str,
        image_id: str,
    ) -> tuple[EffectivePhasePolicy, PhaseOutcome]:
        labels = self._labels(phase)
        args = _inject_labels(args, labels)
        self._containers[name] = _ContainerResource(name, tuple(sorted(labels.items())))
        create_result = self._run(args, timeout=30)
        if _CONTAINER_ID.fullmatch(create_result.output.strip()) is None:
            raise ReproAssertError(
                "dependency_container_create", f"Docker did not create the {phase} container."
            )
        image_index = args.index(image_id)
        expected_command = tuple(args[image_index + 1 :])
        effective = self._inspect_container_policy(
            name,
            phase=phase,
            image_id=image_id,
            network=network,
            user="65532:65532",
            mounts=mounts,
            entrypoint="/usr/bin/env",
            command=expected_command,
            phase_resources=True,
        )
        attached = self.runner.run(
            ["start", "-a", name],
            timeout_seconds=self.policy.timeout_seconds,
            max_output_bytes=self.policy.max_output_bytes,
        )
        state = self._inspect_container_state(name)
        outcome = PhaseOutcome(
            phase=phase,
            exit_code=_required_int(state.get("ExitCode"), "container exit code"),
            oom_killed=state.get("OOMKilled") is True,
            timed_out=attached.timed_out,
            output_truncated=attached.output_truncated,
        )
        if (
            attached.returncode != 0
            or outcome.exit_code != 0
            or outcome.oom_killed
            or outcome.timed_out
            or outcome.output_truncated
            or state.get("Status") != "exited"
            or state.get("Running") is not False
            or state.get("Dead") is True
            or state.get("Error") not in {"", None}
        ):
            raise ReproAssertError(
                "dependency_phase_failed",
                f"Dependency {phase} phase failed its bounded outcome policy.",
            )
        self._remove_container_verified(name)
        return effective, outcome

    def _export_and_attest_wheelhouse(
        self, image_id: str, *, probe: VolumeProbe
    ) -> WheelhouseAttestation:
        if (
            probe.file_count != len(probe.files)
            or probe.directory_count != 0
            or not 1 <= probe.file_count <= 256
            or any(not _safe_wheel_filename(item.path) for item in probe.files)
        ):
            raise ReproAssertError(
                "dependency_wheelhouse_shape",
                "Wheelhouse must contain only enumerated flat regular wheel files.",
            )
        spec = self._require_volume("wheelhouse")
        name = self._create_helper(
            role="copy-wheel-files",
            image_id=image_id,
            mounts=(MountExpectation("wheelhouse", spec.name, "/data", False),),
            entrypoint="/bin/true",
            command=(),
        )
        try:
            with tempfile.TemporaryDirectory(prefix="reproassert-wheel-files-") as temporary:
                root = Path(temporary).resolve(strict=True)
                os.chmod(root, 0o700)
                for item in probe.files:
                    destination = root / item.path
                    self._run(
                        ["cp", f"{name}:/data/{item.path}", str(destination)],
                        timeout=120,
                    )
                    if _hash_copied_regular_file(destination) != item.sha256:
                        raise ReproAssertError(
                            "dependency_artifact_changed",
                            "Wheel changed during bounded per-file transfer.",
                        )
                attestation = attest_wheelhouse(root, self.plan)
        finally:
            self._remove_container_verified(name)
        copied = {item.filename: item.sha256 for item in attestation.files}
        expected = {item.path: item.sha256 for item in probe.files}
        if copied != expected or len(copied) != len(attestation.files):
            raise ReproAssertError(
                "dependency_attestation_mismatch",
                "Wheel attestation disagrees with the in-container enumeration.",
            )
        return attestation

    def _export_and_attest_dependencies(self, image_id: str) -> SourceTreeAttestation:
        limits = _DEPENDENCY_ATTESTATION_LIMITS
        result = self._run_helper(
            role="attest-dependencies",
            image_id=image_id,
            mounts=(
                MountExpectation(
                    "dependencies",
                    self._require_volume("dependencies").name,
                    "/data",
                    False,
                ),
            ),
            entrypoint="/usr/bin/env",
            command=(
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/python",
                "-I",
                "-c",
                DEPENDENCY_TREE_ATTESTOR_SCRIPT,
                "/data",
                str(limits.max_members),
                str(limits.max_files),
                str(limits.max_directories),
                str(limits.max_file_bytes),
                str(limits.max_total_bytes),
                str(limits.max_path_bytes),
                str(limits.max_component_bytes),
            ),
            max_output_bytes=16 * 1024,
        )
        return parse_container_tree_attestation(
            result.output,
            limits=_DEPENDENCY_ATTESTATION_LIMITS,
        )

    def _run_helper(
        self,
        *,
        role: str,
        image_id: str,
        mounts: tuple[MountExpectation, ...],
        entrypoint: str,
        command: tuple[str, ...],
        max_output_bytes: int | None = None,
    ) -> CommandResult:
        name = self._create_helper(
            role=role,
            image_id=image_id,
            mounts=mounts,
            entrypoint=entrypoint,
            command=command,
        )
        try:
            return self._start_helper(
                name,
                role=role,
                max_output_bytes=max_output_bytes,
            )
        finally:
            self._remove_container_verified(name)

    def _start_helper(
        self,
        name: str,
        *,
        role: str,
        max_output_bytes: int | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        start_args = ["start", "-a"]
        if input_bytes is not None:
            start_args.append("-i")
        start_args.append(name)
        attached = self.runner.run(
            start_args,
            timeout_seconds=min(self.policy.timeout_seconds, 60),
            max_output_bytes=max_output_bytes
            if max_output_bytes is not None
            else min(self.policy.max_output_bytes, 64 * 1024),
            input_bytes=input_bytes,
        )
        state = self._inspect_container_state(name)
        if (
            attached.returncode != 0
            or attached.timed_out
            or attached.output_truncated
            or state.get("ExitCode") != 0
            or state.get("OOMKilled") is True
            or state.get("Status") != "exited"
            or state.get("Running") is not False
            or state.get("Dead") is True
            or state.get("Error") not in {"", None}
        ):
            raise ReproAssertError(
                "dependency_helper_failed",
                (
                    f"Trusted dependency helper {role} failed "
                    f"(exit={state.get('ExitCode')}, oom={state.get('OOMKilled')}): "
                    f"{attached.output[:500]}"
                ),
            )
        return attached

    def _create_helper(
        self,
        *,
        role: str,
        image_id: str,
        mounts: tuple[MountExpectation, ...],
        entrypoint: str,
        command: tuple[str, ...],
        interactive: bool = False,
    ) -> str:
        name = self._new_container_name(role)
        labels = self._labels(role)
        args = [
            "create",
            "--name",
            name,
        ]
        for key, value in sorted(labels.items()):
            args.extend(["--label", f"{key}={value}"])
        if interactive:
            args.append("--interactive")
        args.extend(
            [
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
                "--pids-limit",
                "32",
                "--memory",
                str(256 * 1024 * 1024),
                "--memory-swap",
                str(256 * 1024 * 1024),
                "--cpus",
                "0.5",
                "--ulimit",
                "nofile=128:128",
                "--ulimit",
                "core=0:0",
                "--ulimit",
                f"fsize={MAX_WHEEL_BYTES}:{MAX_WHEEL_BYTES}",
                "--shm-size",
                "16m",
                "--init",
                "--tmpfs",
                _HELPER_TMPFS,
            ]
        )
        for mount in mounts:
            suffix = "" if mount.writable else ",readonly"
            args.extend(
                [
                    "--mount",
                    f"type=volume,src={mount.volume},dst={mount.destination}{suffix}",
                ]
            )
        args.extend(
            [
                "--workdir",
                _CONTAINER_TMP,
                "--log-driver",
                "local",
                "--log-opt",
                "max-size=128k",
                "--log-opt",
                "max-file=1",
                "--log-opt",
                "compress=false",
                "--entrypoint",
                entrypoint,
                image_id,
                *command,
            ]
        )
        self._containers[name] = _ContainerResource(name, tuple(sorted(labels.items())))
        result = self._run(args, timeout=30)
        if _CONTAINER_ID.fullmatch(result.output.strip()) is None:
            raise ReproAssertError(
                "dependency_container_create", f"Docker did not create helper {role}."
            )
        self._inspect_container_policy(
            name,
            phase=role,
            image_id=image_id,
            network="none",
            user="65532:65532",
            mounts=mounts,
            entrypoint=entrypoint,
            command=command,
            phase_resources=False,
            interactive=interactive,
        )
        return name

    def _inspect_container_policy(
        self,
        name: str,
        *,
        phase: str,
        image_id: str,
        network: str,
        user: str,
        mounts: tuple[MountExpectation, ...],
        entrypoint: str,
        command: tuple[str, ...],
        phase_resources: bool,
        interactive: bool = False,
    ) -> EffectivePhasePolicy:
        payload = self._inspect_container(name)
        host = _mapping(payload.get("HostConfig"), "container HostConfig")
        config = _mapping(payload.get("Config"), "container Config")
        actual_mounts = payload.get("Mounts")
        if not isinstance(actual_mounts, list):
            raise ReproAssertError(
                "dependency_container_policy", "Docker inspect omitted container mounts."
            )
        expected_mounts = {(mount.volume, mount.destination, mount.writable) for mount in mounts}
        observed_mounts = {
            (
                cast(str, _mapping(raw, "container mount").get("Name")),
                cast(str, _mapping(raw, "container mount").get("Destination")),
                _mapping(raw, "container mount").get("RW") is True,
            )
            for raw in actual_mounts
        }
        expected_labels = self._containers[name].labels
        labels = config.get("Labels")
        cap_drop_value = host.get("CapDrop")
        security_value = host.get("SecurityOpt")
        if not isinstance(cap_drop_value, list) or not isinstance(security_value, list):
            raise ReproAssertError(
                "dependency_container_policy",
                "Docker inspect omitted container security policy.",
            )
        cap_drop = tuple(sorted(str(value).upper() for value in cap_drop_value))
        security = {str(value) for value in security_value}
        expected_pids = self.policy.pids if phase_resources else 32
        expected_memory = self.policy.memory_bytes if phase_resources else 256 * 1024 * 1024
        expected_cpus = int((self.policy.cpus if phase_resources else 0.5) * 1_000_000_000)
        observed_entrypoint = config.get("Entrypoint")
        if isinstance(observed_entrypoint, str):
            observed_entrypoint = [observed_entrypoint]
        checks = {
            "image_id": payload.get("Image") == image_id,
            "labels": labels == dict(expected_labels),
            "network": host.get("NetworkMode") == network,
            "readonly_root": host.get("ReadonlyRootfs") is True,
            "user": config.get("User") == user,
            "cap_drop": cap_drop == ("ALL",),
            "cap_add": not host.get("CapAdd"),
            "no_new_privileges": "no-new-privileges=true" in security,
            "not_privileged": host.get("Privileged") is False,
            "pid_private": not host.get("PidMode"),
            "ipc_private": host.get("IpcMode") in {"", "private"},
            "pids": host.get("PidsLimit") == expected_pids,
            "memory": host.get("Memory") == expected_memory,
            "memory_swap": host.get("MemorySwap") == expected_memory,
            "cpus": host.get("NanoCpus") == expected_cpus,
            "no_devices": not host.get("Devices"),
            "no_binds": not host.get("Binds"),
            "mounts": observed_mounts == expected_mounts and len(actual_mounts) == len(mounts),
            "entrypoint": observed_entrypoint == [entrypoint],
            "command": _docker_command_matches(config.get("Cmd"), command),
            "interactive": config.get("OpenStdin") is interactive,
            "healthcheck_disabled": config.get("Healthcheck") == {"Test": ["NONE"]},
            "trusted_phase_command": not phase_resources
            or _trusted_phase_command_matches(phase, command),
            "workdir": config.get("WorkingDir") == _CONTAINER_TMP,
            "init": host.get("Init") is True,
            "shm": host.get("ShmSize") == (64 if phase_resources else 16) * 1024 * 1024,
            "tmpfs": _tmpfs_matches(host.get("Tmpfs"), phase_resources, self.policy),
            "ulimits": _ulimits_match(host.get("Ulimits"), phase_resources),
            "logs": _log_config_matches(host.get("LogConfig")),
        }
        failed = sorted(key for key, accepted in checks.items() if not accepted)
        if failed:
            raise ReproAssertError(
                "dependency_container_policy",
                f"Docker did not apply exact {phase} policy: {', '.join(failed)}",
            )
        normalized_mounts = tuple(
            sorted((mount.role, mount.destination, mount.writable) for mount in mounts)
        )
        command_sha256 = hashlib.sha256("\0".join(command).encode("utf-8")).hexdigest()
        normalized = {
            "phase": phase,
            "image_id": image_id,
            "network_mode": network,
            "user": user,
            "read_only_root": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "healthcheck_disabled": True,
            "trusted_phase_command": not phase_resources
            or _trusted_phase_command_matches(phase, command),
            "pids": expected_pids,
            "memory_bytes": expected_memory,
            "memory_swap_bytes": expected_memory,
            "nano_cpus": expected_cpus,
            "mounts": [list(item) for item in normalized_mounts],
            "command_sha256": command_sha256,
        }
        config_sha256 = hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest()
        return EffectivePhasePolicy(
            phase=phase,
            image_id=image_id,
            network_mode=network,
            user=user,
            read_only_root=True,
            cap_drop=("ALL",),
            no_new_privileges=True,
            healthcheck_disabled=True,
            trusted_phase_command=not phase_resources
            or _trusted_phase_command_matches(phase, command),
            pids=expected_pids,
            memory_bytes=expected_memory,
            memory_swap_bytes=expected_memory,
            nano_cpus=expected_cpus,
            mounts=normalized_mounts,
            command_sha256=command_sha256,
            config_sha256=config_sha256,
        )

    def _inspect_container(self, name: str) -> dict[str, object]:
        result = self._run(["inspect", name], timeout=20)
        return _json_list_one(result.output, "Docker container inspect")

    def _inspect_container_state(self, name: str) -> dict[str, object]:
        return _mapping(self._inspect_container(name).get("State"), "container state")

    def _remove_container_verified(self, name: str) -> None:
        resource = self._containers.get(name)
        if resource is None:
            return
        inspected = self._inspect_optional(["inspect", name])
        if inspected is not None:
            config = _mapping(inspected.get("Config"), "container Config")
            if config.get("Labels") != dict(resource.labels):
                raise ReproAssertError(
                    "dependency_cleanup_labels",
                    "Refusing to remove a container whose labels changed.",
                )
            self._run(["rm", "-f", name], timeout=30)
            if self._inspect_optional(["inspect", name]) is not None:
                raise ReproAssertError(
                    "dependency_cleanup_failed", "Dependency container remains after removal."
                )
        self._containers.pop(name, None)
        for role, anchor in list(self._anchors.items()):
            if anchor == name:
                self._anchors.pop(role, None)

    def _remove_volume_verified(self, role: str) -> None:
        spec = self._volumes.get(role)
        if spec is None:
            return
        anchor = self._anchors.get(role)
        if anchor is not None:
            self._remove_container_verified(anchor)
        inspected = self._inspect_optional(["volume", "inspect", spec.name])
        if inspected is not None:
            if inspected.get("Labels") != dict(spec.labels):
                raise ReproAssertError(
                    "dependency_cleanup_labels",
                    "Refusing to remove a volume whose labels changed.",
                )
            self._run(["volume", "rm", spec.name], timeout=30)
            if self._inspect_optional(["volume", "inspect", spec.name]) is not None:
                raise ReproAssertError(
                    "dependency_cleanup_failed", "Dependency volume remains after removal."
                )
        self._volumes.pop(role, None)

    def _inspect_optional(self, args: list[str]) -> dict[str, object] | None:
        result = self.runner.run(
            args,
            timeout_seconds=20,
            max_output_bytes=_CONTROL_OUTPUT_BYTES,
        )
        if result.timed_out or result.output_truncated:
            raise ReproAssertError(
                "dependency_docker_control", "Bounded Docker inspect did not complete."
            )
        if result.returncode != 0:
            if _DOCKER_OBJECT_MISSING.search(result.output) is None:
                raise ReproAssertError(
                    "dependency_docker_control",
                    f"Docker optional inspect failed: {result.output[:500]}",
                )
            self._prove_object_absent(args)
            return None
        return _json_list_one(result.output, "Docker optional inspect")

    def _prove_object_absent(self, inspect_args: list[str]) -> None:
        if len(inspect_args) == 2 and inspect_args[0] == "inspect":
            name = _safe_token(inspect_args[1])
            list_args = [
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{re.escape(name)}$",
                "--format",
                "{{.Names}}",
            ]
        elif len(inspect_args) == 3 and inspect_args[:2] == ["volume", "inspect"]:
            name = _safe_token(inspect_args[2])
            list_args = [
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"name=^{re.escape(name)}$",
            ]
        else:
            raise ReproAssertError(
                "dependency_docker_control", "Unsupported Docker absence proof request."
            )
        result = self.runner.run(
            list_args,
            timeout_seconds=20,
            max_output_bytes=_CONTROL_OUTPUT_BYTES,
        )
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_truncated
            or result.output.strip()
        ):
            raise ReproAssertError(
                "dependency_docker_control",
                "Docker could not prove exact object-name absence.",
            )

    def _run(self, args: Sequence[str], *, timeout: float) -> CommandResult:
        result = self.runner.run(
            args,
            timeout_seconds=timeout,
            max_output_bytes=_CONTROL_OUTPUT_BYTES,
        )
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise ReproAssertError(
                "dependency_docker_control",
                f"Docker {args[0]} failed under bounded execution: {result.output[:500]}",
            )
        return result

    def _labels(self, role: str) -> dict[str, str]:
        return {
            OWNER_LABEL_KEY: OWNER_LABEL_VALUE,
            RUN_LABEL_KEY: self._run_token,
            ROLE_LABEL_KEY: role,
            PLAN_LABEL_KEY: self.plan.canonical_sha256,
        }

    def _require_volume(self, role: str) -> VolumeSpec:
        try:
            return self._volumes[role]
        except KeyError as exc:
            raise ReproAssertError(
                "dependency_state", f"Dependency volume role {role!r} is unavailable."
            ) from exc

    def _revalidate_dependency_handle(
        self, handle: DependencyVolumeHandle
    ) -> DependencyVolumeValidation:
        if (
            type(handle) is not DependencyVolumeHandle
            or not self._entered
            or self.state is not ExecutionState.READY
            or handle._executor is not self
            or self._issued_handle is not handle
            or handle._capability is not self._handle_capability
            or handle.cleanup_ownership is not CleanupOwnership.EXECUTOR_CONTEXT
        ):
            raise ReproAssertError(
                "dependency_handle_state",
                "Dependency handle is not owned by an active ready executor.",
            )
        spec = self._require_volume("dependencies")
        if (
            handle.name != spec.name
            or handle.labels != spec.labels
            or handle.image_id != self._resolved_image_id
            or handle.execution_receipt_sha256 != self._execution_receipt_sha256
            or handle.quota != _quota_evidence(spec)
            or dict(handle.labels) != self._labels("dependencies")
        ):
            raise ReproAssertError(
                "dependency_handle_identity", "Dependency handle identity changed."
            )
        self._inspect_volume(spec)
        before = self._probe_volume("dependencies", image_id=handle.image_id)
        tree = self._export_and_attest_dependencies(handle.image_id)
        after = self._probe_volume("dependencies", image_id=handle.image_id)
        if before != after or after != handle.volume_probe or tree != handle.tree_attestation:
            raise ReproAssertError(
                "dependency_handle_attestation",
                "Dependency volume changed before verification mount.",
            )
        return DependencyVolumeValidation(
            name=handle.name,
            labels=handle.labels,
            image_id=handle.image_id,
            execution_receipt_sha256=handle.execution_receipt_sha256,
            quota=handle.quota,
            volume_probe=after,
            tree_attestation=tree,
        )

    def _issue_dependency_handle(
        self,
        *,
        spec: VolumeSpec,
        image_id: str,
        execution_receipt_sha256: str,
        volume_probe: VolumeProbe,
        tree_attestation: SourceTreeAttestation,
    ) -> DependencyVolumeHandle:
        if self.state is not ExecutionState.READY or self._issued_handle is not None:
            raise ReproAssertError(
                "dependency_handle_state", "Dependency handle cannot be issued in this state."
            )
        if type(self.runner) is not SubprocessDockerRunner or not self._trusted_runner_for_handles:
            raise ReproAssertError(
                "dependency_handle_runner",
                "Dependency handles require the concrete trusted Docker runner.",
            )
        if _SHA256.fullmatch(execution_receipt_sha256) is None:
            raise ReproAssertError(
                "dependency_handle_receipt", "Dependency execution receipt identity is invalid."
            )
        self._execution_receipt_sha256 = execution_receipt_sha256
        handle = object.__new__(DependencyVolumeHandle)
        values: dict[str, object] = {
            "name": spec.name,
            "labels": spec.labels,
            "image_id": image_id,
            "execution_receipt_sha256": execution_receipt_sha256,
            "quota": _quota_evidence(spec),
            "volume_probe": volume_probe,
            "tree_attestation": tree_attestation,
            "cleanup_ownership": CleanupOwnership.EXECUTOR_CONTEXT,
            "_executor": self,
            "_capability": self._handle_capability,
        }
        for field_name, value in values.items():
            object.__setattr__(handle, field_name, value)
        self._issued_handle = handle
        return handle

    def _new_container_name(self, role: str) -> str:
        return _safe_token(f"reproassert-{self._run_token}-{role}-{uuid.uuid4().hex[:10]}")

    def _transition(self, expected: ExecutionState, target: ExecutionState) -> None:
        if self.state is not expected:
            raise ReproAssertError(
                "dependency_state",
                f"Invalid dependency transition {self.state.value} -> {target.value}.",
            )
        self.state = target
        self.state_history.append(target)

    def _set_failed(self) -> None:
        if self.state not in {ExecutionState.CLEANED, ExecutionState.FAILED}:
            self.state = ExecutionState.FAILED
            self.state_history.append(self.state)


def _build_execution_receipt(
    *,
    base_receipt: dict[str, object],
    image_id: str,
    runtime_version: str,
    volume_specs: Mapping[str, VolumeSpec],
    empty_probes: Mapping[str, VolumeProbe],
    input_probe: VolumeProbe,
    download_policy: EffectivePhasePolicy,
    download_outcome: PhaseOutcome,
    wheel_probe: VolumeProbe,
    wheelhouse: WheelhouseAttestation,
    dependency_preinstall: VolumeProbe,
    install_policy: EffectivePhasePolicy,
    install_outcome: PhaseOutcome,
    dependency_probe: VolumeProbe,
    dependency_tree: SourceTreeAttestation,
) -> DependencyExecutionReceipt:
    events: list[dict[str, object]] = [
        {
            "ordinal": 1,
            "state": ExecutionState.VOLUMES_PROVEN_EMPTY.value,
            "input_probe_sha256": empty_probes["input"].tree_sha256,
            "wheelhouse_probe_sha256": empty_probes["wheelhouse"].tree_sha256,
            "dependency_probe_sha256": empty_probes["dependencies"].tree_sha256,
        },
        {
            "ordinal": 2,
            "state": ExecutionState.INPUT_STAGED.value,
            "input_probe_sha256": input_probe.tree_sha256,
            "requirements_sha256": input_probe.single_file_sha256,
        },
        {
            "ordinal": 3,
            "state": ExecutionState.DOWNLOAD_COMPLETED.value,
            "phase_policy_sha256": download_policy.config_sha256,
            "network": download_policy.network_mode,
            "exit_code": download_outcome.exit_code,
            "oom_killed": download_outcome.oom_killed,
        },
        {
            "ordinal": 4,
            "state": ExecutionState.WHEELHOUSE_ATTESTED.value,
            "volume_probe_sha256": wheel_probe.tree_sha256,
            "wheelhouse_sha256": wheelhouse.sha256,
        },
        {
            "ordinal": 5,
            "state": ExecutionState.INSTALL_COMPLETED.value,
            "phase_policy_sha256": install_policy.config_sha256,
            "network": install_policy.network_mode,
            "exit_code": install_outcome.exit_code,
            "oom_killed": install_outcome.oom_killed,
            "dependency_preinstall_sha256": dependency_preinstall.tree_sha256,
        },
        {
            "ordinal": 6,
            "state": ExecutionState.ARTIFACTS_ATTESTED.value,
            "input_probe_sha256": input_probe.tree_sha256,
            "wheelhouse_volume_probe_sha256": wheel_probe.tree_sha256,
            "dependency_probe_sha256": dependency_probe.tree_sha256,
            "dependency_tree_sha256": dependency_tree.tree_sha256,
            "wheelhouse_sha256": wheelhouse.sha256,
        },
    ]
    sequence_sha256 = hashlib.sha256(_canonical_json_bytes(events)).hexdigest()
    volume_policy = {
        role: {
            "driver": "local",
            "type": "tmpfs",
            "read_only_retention_anchor": True,
            "size_bytes": spec.size_bytes,
            "max_inodes": spec.max_inodes,
            "uid": 65532,
            "gid": 65532,
            "mode": "0700",
            "labels": [OWNER_LABEL_KEY, RUN_LABEL_KEY, ROLE_LABEL_KEY, PLAN_LABEL_KEY],
        }
        for role, spec in sorted(volume_specs.items())
    }
    return {
        "schema_version": DEPENDENCY_EXECUTION_SCHEMA_VERSION,
        "kind": "dependency_execution_receipt",
        "dependency_preparation": base_receipt,
        "execution": {
            "algorithm": DEPENDENCY_CAUSALITY_ALGORITHM,
            "runner": {
                "image_id": image_id,
                "python_version": runtime_version,
                "image_resolved_once_before_resource_creation": True,
            },
            "volume_policy": volume_policy,
            "download": _phase_receipt(download_policy, download_outcome),
            "install": _phase_receipt(install_policy, install_outcome),
            "causality": {
                "events": events,
                "sequence_sha256": sequence_sha256,
                "volumes_new_and_empty": True,
                "download_precedes_wheelhouse_attestation": True,
                "install_precedes_dependency_attestation": True,
                "wheelhouse_unchanged_across_install": True,
                "requirements_unchanged": True,
                "dependency_volume_rw_phase_count": 1,
                "download_source_mounted": False,
                "install_network": "none",
            },
            "cleanup": {
                "input_volume_removed": True,
                "wheelhouse_volume_removed": True,
                "dependency_volume_retained_inside_executor_context": True,
                "label_verification_required": True,
                "blind_force_volume_removal": False,
            },
        },
        "campaign_readiness_changed": False,
    }


def _phase_receipt(
    policy: EffectivePhasePolicy,
    outcome: PhaseOutcome,
) -> dict[str, object]:
    value = cast(dict[str, object], asdict(policy))
    value["cap_drop"] = list(policy.cap_drop)
    value["mounts"] = [list(item) for item in policy.mounts]
    value["outcome"] = asdict(outcome)
    return value


def _safe_wheel_filename(value: str) -> bool:
    return (
        value.isascii()
        and "/" not in value
        and "\\" not in value
        and _WHEEL_FILENAME.fullmatch(value) is not None
    )


def _hash_copied_regular_file(path: Path) -> str:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_WHEEL_BYTES
        ):
            raise ReproAssertError(
                "dependency_artifact_copy", "Copied wheel is not one bounded regular file."
            )
        with open_regular_file(path) as stream:
            opened = os.fstat(stream.fileno())
            digest = hashlib.sha256()
            observed = 0
            while chunk := stream.read(64 * 1024):
                observed += len(chunk)
                if observed > MAX_WHEEL_BYTES:
                    raise ReproAssertError(
                        "dependency_artifact_copy", "Copied wheel exceeds the byte limit."
                    )
                digest.update(chunk)
            final = os.fstat(stream.fileno())
    except OSError as exc:
        raise ReproAssertError(
            "dependency_artifact_copy", "Unable to inspect a copied wheel safely."
        ) from exc
    snapshots = (
        (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns),
        (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size, opened.st_mtime_ns),
        (final.st_dev, final.st_ino, final.st_mode, final.st_size, final.st_mtime_ns),
    )
    if snapshots[0] != snapshots[1] or snapshots[1] != snapshots[2] or observed != final.st_size:
        raise ReproAssertError(
            "dependency_artifact_copy", "Copied wheel changed while it was read."
        )
    return digest.hexdigest()


def _parse_probe(raw: str) -> VolumeProbe:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReproAssertError(
            "dependency_probe_invalid", "Dependency volume probe returned invalid JSON."
        ) from exc
    keys = {
        "algorithm",
        "tree_sha256",
        "member_count",
        "file_count",
        "directory_count",
        "total_bytes",
        "root_uid",
        "root_gid",
        "root_mode",
        "single_file_path",
        "single_file_sha256",
        "files",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ReproAssertError(
            "dependency_probe_invalid", "Dependency volume probe fields are invalid."
        )
    if value["algorithm"] != VOLUME_PROBE_ALGORITHM:
        raise ReproAssertError(
            "dependency_probe_invalid", "Dependency volume probe algorithm is invalid."
        )
    digest = value["tree_sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReproAssertError(
            "dependency_probe_invalid", "Dependency volume probe digest is invalid."
        )
    integers = {
        key: _required_int(value[key], f"probe {key}")
        for key in (
            "member_count",
            "file_count",
            "directory_count",
            "total_bytes",
            "root_uid",
            "root_gid",
            "root_mode",
        )
    }
    if (
        integers["member_count"] != integers["file_count"] + integers["directory_count"]
        or any(number < 0 for number in integers.values())
        or integers["root_uid"] != 65532
        or integers["root_gid"] != 65532
        or integers["root_mode"] != 0o700
    ):
        raise ReproAssertError(
            "dependency_probe_invalid", "Dependency volume probe invariants are invalid."
        )
    single_path = value["single_file_path"]
    single_hash = value["single_file_sha256"]
    if single_path is not None and not isinstance(single_path, str):
        raise ReproAssertError("dependency_probe_invalid", "Probe single-file path is invalid.")
    if single_hash is not None and (
        not isinstance(single_hash, str) or _SHA256.fullmatch(single_hash) is None
    ):
        raise ReproAssertError("dependency_probe_invalid", "Probe single-file hash is invalid.")
    raw_files = value["files"]
    if not isinstance(raw_files, list) or len(raw_files) > integers["file_count"]:
        raise ReproAssertError("dependency_probe_invalid", "Probe file evidence is invalid.")
    file_evidence: list[VolumeFileEvidence] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict) or set(raw_file) != {"path", "sha256"}:
            raise ReproAssertError("dependency_probe_invalid", "Probe file evidence is invalid.")
        path = raw_file["path"]
        sha256 = raw_file["sha256"]
        if (
            not isinstance(path, str)
            or not isinstance(sha256, str)
            or _SHA256.fullmatch(sha256) is None
        ):
            raise ReproAssertError("dependency_probe_invalid", "Probe file evidence is invalid.")
        file_evidence.append(VolumeFileEvidence(path=path, sha256=sha256))
    if file_evidence != sorted(file_evidence, key=lambda item: item.path) or len(
        {item.path for item in file_evidence}
    ) != len(file_evidence):
        raise ReproAssertError("dependency_probe_invalid", "Probe file evidence is not canonical.")
    if file_evidence and len(file_evidence) != integers["file_count"]:
        raise ReproAssertError("dependency_probe_invalid", "Probe file evidence is incomplete.")
    return VolumeProbe(
        algorithm=VOLUME_PROBE_ALGORITHM,
        tree_sha256=digest,
        member_count=integers["member_count"],
        file_count=integers["file_count"],
        directory_count=integers["directory_count"],
        total_bytes=integers["total_bytes"],
        root_uid=integers["root_uid"],
        root_gid=integers["root_gid"],
        root_mode=integers["root_mode"],
        single_file_path=single_path,
        single_file_sha256=single_hash,
        files=tuple(file_evidence),
    )


def _probe_limits(role: str) -> tuple[int, int, int, int, int, int, int]:
    if role == "input":
        return (1, 1, 1, MAX_PLAN_BYTES, _INPUT_VOLUME_BYTES, 4096, 255)
    if role == "wheelhouse":
        return (
            256,
            256,
            1,
            MAX_WHEEL_BYTES,
            MAX_WHEELHOUSE_BYTES,
            _PROBE_MAX_PATH_BYTES,
            _PROBE_MAX_COMPONENT_BYTES,
        )
    if role == "dependencies":
        return (
            _PROBE_MAX_MEMBERS,
            _PROBE_MAX_FILES,
            _PROBE_MAX_DIRECTORIES,
            MAX_WHEELHOUSE_UNPACKED_BYTES,
            _DEPENDENCY_VOLUME_BYTES,
            _PROBE_MAX_PATH_BYTES,
            _PROBE_MAX_COMPONENT_BYTES,
        )
    raise ReproAssertError("dependency_state", f"Unknown dependency volume role {role!r}.")


def _quota_evidence(spec: VolumeSpec) -> VolumeQuotaEvidence:
    return VolumeQuotaEvidence(
        driver="local",
        scope="local",
        type="tmpfs",
        device="tmpfs",
        size_bytes=spec.size_bytes,
        max_inodes=spec.max_inodes,
        uid=65532,
        gid=65532,
        mode=0o700,
    )


def _inject_labels(args: list[str], labels: Mapping[str, str]) -> list[str]:
    try:
        index = args.index("--pull")
    except ValueError as exc:
        raise ReproAssertError(
            "dependency_container_args", "Dependency container args lack pull policy."
        ) from exc
    extra: list[str] = []
    for key, value in sorted(labels.items()):
        if key in {OWNER_LABEL_KEY, RUN_LABEL_KEY}:
            continue
        extra.extend(["--label", f"{key}={value}"])
    return [*args[:index], *extra, *args[index:]]


def _trusted_phase_command_matches(phase: str, command: tuple[str, ...]) -> bool:
    if phase not in {"download", "install"}:
        return False
    trusted_phase = cast(Literal["download", "install"], phase)
    return command == dependency_phase_command(trusted_phase)


def _docker_command_matches(observed: object, expected: tuple[str, ...]) -> bool:
    if not expected:
        return observed is None or observed == []
    return observed == list(expected)


def _tmpfs_matches(value: object, phase_resources: bool, policy: SandboxPolicy) -> bool:
    if not isinstance(value, dict) or set(value) != {_CONTAINER_TMP}:
        return False
    options = value[_CONTAINER_TMP]
    if not isinstance(options, str):
        return False
    expected_size = policy.tmpfs_bytes if phase_resources else 16 * 1024 * 1024
    expected_inodes = policy.tmpfs_inodes if phase_resources else 1024
    tokens = set(options.split(","))
    return {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        f"size={expected_size}",
        f"nr_inodes={expected_inodes}",
    } <= tokens


def _ulimits_match(value: object, phase_resources: bool) -> bool:
    if not isinstance(value, list):
        return False
    expected_nofile = 256 if phase_resources else 128
    expected = {
        ("nofile", expected_nofile, expected_nofile),
        ("core", 0, 0),
        ("fsize", MAX_WHEEL_BYTES, MAX_WHEEL_BYTES),
    }
    observed = set()
    for raw in value:
        if not isinstance(raw, dict):
            return False
        observed.add((raw.get("Name"), raw.get("Soft"), raw.get("Hard")))
    return observed == expected


def _log_config_matches(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return value.get("Type") == "local" and value.get("Config") == {
        "max-size": "128k",
        "max-file": "1",
        "compress": "false",
    }


def _json_list_one(raw: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReproAssertError(
            "dependency_docker_inspect", f"{label} returned invalid JSON."
        ) from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ReproAssertError(
            "dependency_docker_inspect", f"{label} did not return exactly one object."
        )
    return cast(dict[str, object], value[0])


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReproAssertError("dependency_docker_inspect", f"{label} is not an object.")
    return cast(dict[str, object], value)


def _required_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReproAssertError("dependency_docker_inspect", f"{label} is not an integer.")
    return value


def _python_version_matches(planned: str, observed: str) -> bool:
    planned_parts = planned.split(".")
    observed_parts = observed.split(".")
    return observed_parts[: len(planned_parts)] == planned_parts


def _safe_token(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Docker token must be text")
    normalized = "".join(char for char in value if char.isalnum() or char in "_.-")[:128]
    if not normalized or _SAFE_TOKEN.fullmatch(normalized) is None:
        raise ValueError("Unable to construct a safe Docker token")
    return normalized


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReproAssertError(
            "dependency_receipt_invalid", "Execution receipt is not canonical JSON data."
        ) from exc


_STAGE_REQUIREMENTS_SCRIPT = r"""
import os
import stat
import sys

destination = sys.argv[1]
limit = int(sys.argv[2])
nofollow = getattr(os, "O_NOFOLLOW", 0)
if not nofollow:
    raise RuntimeError("nofollow-unavailable")
source = sys.stdin.buffer
try:
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | nofollow
        | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        observed = 0
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise RuntimeError("source-size")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise RuntimeError("destination-write")
                view = view[written:]
        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, 0o444)
        destination_stat = os.fstat(destination_descriptor)
    finally:
        os.close(destination_descriptor)
finally:
    source.close()
if not 1 <= observed <= limit:
    raise RuntimeError("source-size")
if not stat.S_ISREG(destination_stat.st_mode) or destination_stat.st_size != observed:
    raise RuntimeError("destination-invalid")
""".strip()


_VOLUME_PROBE_SCRIPT = r"""
import hashlib
import json
import os
import stat
import sys

root = sys.argv[1]
(
    max_members,
    max_files,
    max_dirs,
    max_file,
    max_total,
    max_path,
    max_component,
) = map(int, sys.argv[2:9])
emit_files = sys.argv[9] == "1"
root_stat = os.lstat(root)
if not stat.S_ISDIR(root_stat.st_mode):
    raise RuntimeError("root-not-directory")
queue = [(root, "")]
records = []
files = []
members = 0
file_count = 0
directory_count = 0
total = 0
while queue:
    directory, prefix = queue.pop()
    with os.scandir(directory) as scan:
        entries = sorted(scan, key=lambda item: item.name.encode("utf-8"))
    for entry in entries:
        name_bytes = entry.name.encode("utf-8")
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        path_bytes = relative.encode("utf-8")
        if len(name_bytes) > max_component or len(path_bytes) > max_path:
            raise RuntimeError("path-limit")
        metadata = entry.stat(follow_symlinks=False)
        members += 1
        if members > max_members:
            raise RuntimeError("member-limit")
        if stat.S_ISDIR(metadata.st_mode):
            directory_count += 1
            if directory_count > max_dirs:
                raise RuntimeError("directory-limit")
            records.append(
                (
                    b"D",
                    path_bytes,
                    stat.S_IMODE(metadata.st_mode),
                    0,
                    hashlib.sha256(b"").digest(),
                )
            )
            queue.append((entry.path, relative))
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise RuntimeError("hardlink")
            file_count += 1
            if file_count > max_files or metadata.st_size > max_file:
                raise RuntimeError("file-limit")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(entry.path, flags)
            try:
                opened = os.fstat(descriptor)
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_file or total + size > max_total:
                        raise RuntimeError("byte-limit")
                    digest.update(chunk)
                final = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            opened_identity = (opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns)
            final_identity = (final.st_ino, final.st_mtime_ns, final.st_ctime_ns)
            if size != opened.st_size or opened_identity != final_identity:
                raise RuntimeError("file-changed")
            total += size
            records.append(
                (b"F", path_bytes, stat.S_IMODE(final.st_mode), size, digest.digest())
            )
            files.append((relative, digest.hexdigest()))
        else:
            raise RuntimeError("special-entry")
digest = hashlib.sha256(b"reproassert-volume-probe-v1\0")
for kind, path, mode, size, content_hash in sorted(records, key=lambda item: (item[1], item[0])):
    digest.update(kind)
    digest.update(len(path).to_bytes(8, "big"))
    digest.update(path)
    digest.update(mode.to_bytes(4, "big"))
    digest.update(size.to_bytes(8, "big"))
    digest.update(content_hash)
files.sort(key=lambda item: item[0])
single_path, single_hash = files[0] if len(files) == 1 else (None, None)
payload = {
    "algorithm": "reproassert-volume-probe-v1",
    "tree_sha256": digest.hexdigest(),
    "member_count": members,
    "file_count": file_count,
    "directory_count": directory_count,
    "total_bytes": total,
    "root_uid": root_stat.st_uid,
    "root_gid": root_stat.st_gid,
    "root_mode": stat.S_IMODE(root_stat.st_mode),
    "single_file_path": single_path,
    "single_file_sha256": single_hash,
    "files": [
        {"path": path, "sha256": sha256} for path, sha256 in files
    ] if emit_files else [],
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
""".strip()
